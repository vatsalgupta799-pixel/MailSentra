"""Module 4: Authentication Protocols Analyzer (SPF, DKIM, DMARC, Policy Enforcer & Header Generator).

Architecture reference: MS-ARCH-SEC-2026-STEP-3-7-3C-PLAN
Standards: RFC 8601, RFC 7601, RFC 6008, RFC 5322, RFC 9989, RFC 7208, RFC 6376
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.modules.base import BaseDetectionModule
from app.modules.auth_protocols.config import AuthProtocolsConfig
from app.modules.auth_protocols.dns_resolver import AsyncDNSResolver, BaseDNSResolver
from app.modules.auth_protocols.executor import DKIMExecutor
from app.modules.auth_protocols.evaluators.spf import SPFEvaluator
from app.modules.auth_protocols.evaluators.dkim import DKIMVerifier
from app.modules.auth_protocols.evaluators.dmarc import DMARCEvaluator
from app.modules.auth_protocols.policy_enforcer import DMARCPolicyEnforcer
from app.modules.auth_protocols.evaluators.auth_results import (
    AuthResultsGenerator,
    AuthResultsTrustEvaluator,
)
from app.schemas.user import IngestionActor
from app.modules.contracts import (
    AlignmentMode,
    AnalysisCompletionStatus,
    AuthFinding,
    AuthProtocolsResult,
    CorroboratingThreatSignals,
    DKIMEvaluationState,
    DKIMSignatureResult,
    DMARCEnforcementDecision,
    DMARCPolicy,
    DMARCResult,
    ForwarderTrustEvidence,
    IngestionSource,
    LocalPolicyOverrideRule,
    ParsedAuthResultsHeader,
    ParsedEmail,
    ProtocolStatus,
    RawEmailPayload,
    SPFResult,
    TrustedSMTPMetadata,
)


class AuthProtocolsAnalyzer(BaseDetectionModule):
    """Core orchestrator for SPF, DKIM, DMARC, receiver-local policy enforcement, and Authentication-Results."""

    def __init__(
        self,
        config: Optional[AuthProtocolsConfig] = None,
        resolver: Optional[BaseDNSResolver] = None,
        dkim_executor: Optional[DKIMExecutor] = None,
        offline_mode: bool = False,
    ):
        if config is None:
            from app.core.config import settings
            self.config = AuthProtocolsConfig(
                local_authserv_id=settings.LOCAL_AUTHSERV_ID,
                dmarc_policy_enforcement_enabled=settings.DMARC_POLICY_ENFORCEMENT_ENABLED,
                offline_mode=offline_mode,
            )
        else:
            self.config = config
            if offline_mode:
                self.config.offline_mode = True
            if self.config.local_authserv_id is None:
                from app.core.config import settings
                if settings.LOCAL_AUTHSERV_ID:
                    self.config.local_authserv_id = settings.LOCAL_AUTHSERV_ID
        if self.config.offline_mode:
            from app.modules.auth_protocols.dns_resolver import OfflineBlockDNSResolver
            self.resolver = resolver or OfflineBlockDNSResolver(config=self.config)
        else:
            self.resolver = resolver or AsyncDNSResolver(config=self.config)
        self._owns_executor = dkim_executor is None
        self.dkim_executor = dkim_executor or DKIMExecutor(config=self.config)

        # Child evaluators
        self.spf_evaluator = SPFEvaluator(resolver=self.resolver, config=self.config)
        self.dkim_verifier = DKIMVerifier(
            dns_resolver=self.resolver,
            executor=self.dkim_executor,
            config=self.config,
        )
        self.dmarc_evaluator = DMARCEvaluator(resolver=self.resolver, config=self.config)
        self.policy_enforcer = DMARCPolicyEnforcer(config=self.config)
        self.trust_evaluator = AuthResultsTrustEvaluator(config=self.config)
        self.generator = AuthResultsGenerator(config=self.config)

    @property
    def module_name(self) -> str:
        return "auth_protocols"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def analyze(
        self,
        raw_payload: Optional[RawEmailPayload] = None,
        parsed_email: Optional[ParsedEmail] = None,
        trusted_smtp_metadata: Optional[TrustedSMTPMetadata] = None,
        corroborating_signals: Optional[CorroboratingThreatSignals] = None,
        admin_rules: Optional[Sequence[LocalPolicyOverrideRule]] = None,
        admin_actor: Optional[IngestionActor] = None,
        forwarder_evidence: Optional[ForwarderTrustEvidence] = None,
        tenant_id: Optional[str] = None,
        db: Optional[AsyncSession] = None,
        offline_mode: Optional[bool] = None,
    ) -> AuthProtocolsResult:
        """Coordinates full asynchronous authentication evaluation and header generation."""
        failed_evaluators: List[str] = []
        execution_telemetry: Dict[str, Any] = {}

        is_offline = (
            self.config.offline_mode
            if offline_mode is None
            else offline_mode
        )

        # -------------------------------------------------------------
        # 1. Determine Channel & Ingress Parameters
        # -------------------------------------------------------------
        effective_channel = (
            raw_payload.source
            if raw_payload and raw_payload.source
            else IngestionSource.DIRECT_UPLOAD
        )
        is_smtp_channel = effective_channel == IngestionSource.SMTP_RELAY
        effective_tenant = tenant_id or (raw_payload.tenant_id if raw_payload else "default") or "default"

        # HTTP / non-SMTP channels MUST NEVER rely on untrusted transport metadata (Step 3.7.3B Finding L3)
        effective_smtp_metadata: Optional[TrustedSMTPMetadata] = None
        if not is_offline and is_smtp_channel and trusted_smtp_metadata is not None and trusted_smtp_metadata.is_trusted_mta:
            effective_smtp_metadata = trusted_smtp_metadata

        # -------------------------------------------------------------
        # 2. Stage 1: Inbound Authentication-Results Trust Evaluation
        # -------------------------------------------------------------
        raw_auth_headers: List[str] = []
        if parsed_email and parsed_email.headers_map:
            raw_auth_headers = parsed_email.headers_map.get("authentication-results", [])

        parsed_auth_headers = self.trust_evaluator.evaluate_headers(
            headers=raw_auth_headers,
            config=self.config,
            trusted_smtp_metadata=effective_smtp_metadata,
            ingress_channel=effective_channel,
        )

        # -------------------------------------------------------------
        # 2B. Fast-Track P0.3: Explicit Offline Evaluation Path
        # -------------------------------------------------------------
        if is_offline:
            from_domain: Optional[str] = None
            if parsed_email and parsed_email.from_sender and parsed_email.from_sender.domain:
                from_domain = parsed_email.from_sender.domain

            findings = [
                AuthFinding(
                    code="OFFLINE_EVALUATION",
                    protocol="auth_protocols",
                    severity="INFO",
                    message="Authentication protocols evaluated in offline mode; live DNS resolution disabled and historical headers treated as untrusted.",
                )
            ]

            spf_details = SPFResult(
                status=ProtocolStatus.NOT_EVALUATED,
                scope="mfrom",
                domain=from_domain or "unknown",
                mechanism="none",
                explanation="Offline evaluation mode active; live DNS queries disabled.",
            )
            dkim_state = DKIMEvaluationState.EVALUATED_NO_SIGNATURES
            dmarc_details = DMARCResult(
                status=ProtocolStatus.NOT_EVALUATED,
                policy=DMARCPolicy.NOT_CONFIGURED,
                header_from_domain=from_domain or "unknown",
                published_domain=from_domain or "unknown",
                record_raw="",
            )

            return AuthProtocolsResult(
                spf_status=ProtocolStatus.NOT_EVALUATED,
                spf_domain=from_domain,
                dkim_status=ProtocolStatus.NOT_EVALUATED,
                dkim_domain=from_domain,
                dmarc_status=ProtocolStatus.NOT_EVALUATED,
                dmarc_policy=DMARCPolicy.NOT_CONFIGURED,
                dmarc_aligned_spf=False,
                dmarc_aligned_dkim=False,
                spf_details=spf_details,
                dkim_evaluation_state=dkim_state,
                dkim_signatures=[],
                dmarc_details=dmarc_details,
                dmarc_enforcement=None,
                parsed_auth_results=parsed_auth_headers,
                analysis_status=AnalysisCompletionStatus.COMPLETED,
                failed_evaluators=[],
                findings=findings,
                execution_telemetry={"offline_mode": True, "dns_queries_executed": 0},
            )
        # 3. Stage 2: Parallel Protocol Evaluation (SPF, DKIM, DMARC)
        # -------------------------------------------------------------
        # Extract identities
        from_domain: Optional[str] = None
        all_from_domains: Optional[List[str]] = None
        if parsed_email:
            if parsed_email.from_sender and parsed_email.from_sender.domain:
                from_domain = parsed_email.from_sender.domain
            if parsed_email.all_from_senders:
                all_from_domains = [
                    addr.domain for addr in parsed_email.all_from_senders if addr and addr.domain
                ]

        raw_bytes: Optional[bytes] = None
        if raw_payload and raw_payload.raw_bytes:
            raw_bytes = raw_payload.raw_bytes

        # Transport credentials for SPF
        spf_client_ip: Optional[str] = None
        spf_helo: Optional[str] = None
        spf_sender: Optional[str] = None
        if effective_smtp_metadata:
            spf_client_ip = effective_smtp_metadata.connecting_ip
            spf_helo = effective_smtp_metadata.helo_domain
            spf_sender = effective_smtp_metadata.mail_from_envelope

        # 3.1 SPF Evaluation
        spf_result: Optional[SPFResult] = None
        try:
            if effective_smtp_metadata and effective_smtp_metadata.is_trusted_mta:
                spf_result = await self.spf_evaluator.evaluate(
                    domain=None,
                    smtp_metadata=effective_smtp_metadata,
                )
            else:
                spf_result = SPFResult(
                    status=ProtocolStatus.NOT_EVALUATED,
                    error_reason="Missing or untrusted transport metadata on current channel",
                )
        except Exception as e_spf:
            logger.error("Unexpected error in SPFEvaluator: %s", str(e_spf), exc_info=True)
            failed_evaluators.append("spf")
            spf_result = SPFResult(
                status=ProtocolStatus.INDETERMINATE,
                error_reason=f"SPF internal evaluator exception: {type(e_spf).__name__}",
            )

        # 3.2 DKIM Evaluation
        dkim_signatures: List[DKIMSignatureResult] = []
        dkim_state = DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES
        try:
            if raw_bytes:
                dkim_signatures = await self.dkim_verifier.verify(
                    message_bytes=raw_bytes,
                    from_domain=from_domain,
                )
                dkim_state = (
                    DKIMEvaluationState.EVALUATED_COMPLETED
                    if dkim_signatures
                    else DKIMEvaluationState.EVALUATED_NO_SIGNATURES
                )
            else:
                dkim_state = DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES
        except Exception as e_dkim:
            logger.error("Unexpected error in DKIMVerifier: %s", str(e_dkim), exc_info=True)
            failed_evaluators.append("dkim")
            dkim_state = DKIMEvaluationState.INCOMPLETE_INTERNAL_ERROR

        # Determine composite DKIM status
        dkim_overall_status = ProtocolStatus.NONE
        primary_dkim_domain: Optional[str] = None
        if dkim_signatures:
            primary_dkim_domain = dkim_signatures[0].domain
            if any(s.status == ProtocolStatus.PASS for s in dkim_signatures):
                dkim_overall_status = ProtocolStatus.PASS
            elif any(s.status == ProtocolStatus.TEMPERROR for s in dkim_signatures):
                dkim_overall_status = ProtocolStatus.TEMPERROR
            elif any(s.status == ProtocolStatus.PERMERROR for s in dkim_signatures):
                dkim_overall_status = ProtocolStatus.PERMERROR
            elif any(s.status == ProtocolStatus.FAIL for s in dkim_signatures):
                dkim_overall_status = ProtocolStatus.FAIL
            else:
                dkim_overall_status = ProtocolStatus.NONE

        # 3.3 DMARC Evaluation
        dmarc_result: Optional[DMARCResult] = None
        try:
            if from_domain:
                dmarc_result = await self.dmarc_evaluator.evaluate(
                    from_domain=from_domain,
                    spf_result=spf_result,
                    dkim_results=dkim_signatures,
                    all_from_domains=all_from_domains,
                    dkim_evaluated=(dkim_state != DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES),
                    dkim_evaluation_state=dkim_state,
                )
            else:
                dmarc_result = DMARCResult(
                    status=ProtocolStatus.NOT_EVALUATED,
                    policy=DMARCPolicy.NOT_CONFIGURED,
                )
        except Exception as e_dmarc:
            logger.error("Unexpected error in DMARCEvaluator: %s", str(e_dmarc), exc_info=True)
            failed_evaluators.append("dmarc")
            dmarc_result = DMARCResult(
                status=ProtocolStatus.INDETERMINATE,
                policy=DMARCPolicy.NOT_CONFIGURED,
            )

        # -------------------------------------------------------------
        # 4. Stage 3–5: Receiver-Local Policy Enforcement
        # -------------------------------------------------------------
        enforcement_decision: Optional[DMARCEnforcementDecision] = None
        if getattr(self.config, "dmarc_policy_enforcement_enabled", True):
            try:
                enforcement_decision = self.policy_enforcer.enforce(
                    dmarc_result=dmarc_result,
                    spf_result=spf_result,
                    dkim_results=dkim_signatures,
                    parsed_email=parsed_email,
                    raw_payload=raw_payload,
                    channel=effective_channel,
                    trusted_smtp_metadata=effective_smtp_metadata,
                    admin_rules=admin_rules,
                    admin_actor=admin_actor,
                    forwarder_evidence=forwarder_evidence,
                    threat_signals=corroborating_signals,
                    tenant_id=effective_tenant,
                    dkim_evaluated=(dkim_state != DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES),
                )
            except Exception as e_enf:
                logger.error("Unexpected error in DMARCPolicyEnforcer: %s", str(e_enf), exc_info=True)
                failed_evaluators.append("policy_enforcer")
        else:
            logger.info("DMARC receiver-local policy enforcement is disabled by configuration (monitoring/staging mode).")
            execution_telemetry["policy_enforcement"] = "disabled"

        # -------------------------------------------------------------
        # 5. Stage 6: Authentication-Results Header Generation
        # -------------------------------------------------------------
        generated_header: Optional[str] = None
        try:
            generated_header = self.generator.generate(
                local_authserv_id=self.config.local_authserv_id,
                dmarc_result=dmarc_result,
                spf_result=spf_result,
                dkim_results=dkim_signatures,
                enforcement_decision=enforcement_decision,
                dkim_evaluated=(dkim_state != DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES),
            )
        except Exception as e_gen:
            logger.error("Unexpected error in AuthResultsGenerator: %s", str(e_gen), exc_info=True)
            failed_evaluators.append("auth_results_generator")

        # -------------------------------------------------------------
        # 6. Assemble Final AuthProtocolsResult Container
        # -------------------------------------------------------------
        dmarc_aligned_spf = False
        dmarc_aligned_dkim = False
        spf_aligned_relaxed = False
        spf_aligned_strict = False
        dkim_aligned_relaxed = False
        dkim_aligned_strict = False
        test_mode = False

        if dmarc_result:
            dmarc_aligned_spf = getattr(dmarc_result, "spf_aligned", False) or getattr(dmarc_result, "is_spf_aligned", False)
            dmarc_aligned_dkim = getattr(dmarc_result, "dkim_aligned", False) or getattr(dmarc_result, "is_dkim_aligned", False)
            spf_aligned_relaxed = getattr(dmarc_result, "spf_aligned_relaxed", False)
            spf_aligned_strict = getattr(dmarc_result, "spf_aligned_strict", False)
            dkim_aligned_relaxed = getattr(dmarc_result, "dkim_aligned_relaxed", False)
            dkim_aligned_strict = getattr(dmarc_result, "dkim_aligned_strict", False)
            test_mode = getattr(dmarc_result, "test_mode", False)

        completion_status = (
            AnalysisCompletionStatus.FAILED
            if len(failed_evaluators) >= 3
            else (
                AnalysisCompletionStatus.PARTIAL
                if failed_evaluators
                else AnalysisCompletionStatus.COMPLETED
            )
        )

        return AuthProtocolsResult(
            spf_status=spf_result.status if spf_result else ProtocolStatus.NOT_EVALUATED,
            spf_domain=spf_result.domain if spf_result else None,
            dkim_status=dkim_overall_status,
            dkim_domain=primary_dkim_domain,
            dmarc_status=dmarc_result.status if dmarc_result else ProtocolStatus.NOT_EVALUATED,
            dmarc_policy=dmarc_result.policy if dmarc_result else DMARCPolicy.NOT_CONFIGURED,
            dmarc_aligned_spf=dmarc_aligned_spf,
            dmarc_aligned_dkim=dmarc_aligned_dkim,
            raw_auth_results_header=raw_auth_headers[0] if raw_auth_headers else None,
            generated_auth_results_header=generated_header,
            spf_alignment_mode=AlignmentMode.RELAXED,
            dkim_alignment_mode=AlignmentMode.RELAXED,
            spf_aligned_relaxed=spf_aligned_relaxed,
            spf_aligned_strict=spf_aligned_strict,
            dkim_aligned_relaxed=dkim_aligned_relaxed,
            dkim_aligned_strict=dkim_aligned_strict,
            dmarc_test_mode=test_mode,
            spf_details=spf_result,
            dkim_evaluation_state=dkim_state,
            dkim_signatures=dkim_signatures,
            dmarc_details=dmarc_result,
            dmarc_enforcement=enforcement_decision,
            parsed_auth_results=parsed_auth_headers,
            analysis_status=completion_status,
            failed_evaluators=failed_evaluators,
            execution_telemetry=execution_telemetry,
        )

    async def shutdown(self) -> None:
        """Shuts down underlying resources if owned by this analyzer.
        
        Guarantees idempotent execution, catches exceptions per resource,
        and ensures complete shutdown of thread workers and resolver cache.
        """
        errors = []
        if self._owns_executor and self.dkim_executor:
            try:
                await self.dkim_executor.shutdown()
            except Exception as e_exec:
                logger.error("Error during DKIM executor shutdown: %s", str(e_exec), exc_info=True)
                errors.append(e_exec)

        if hasattr(self.resolver, "close"):
            try:
                await self.resolver.close()
            except Exception as e_res:
                logger.error("Error during DNS resolver close: %s", str(e_res), exc_info=True)
                errors.append(e_res)

        if errors:
            logger.warning(
                "AuthProtocolsAnalyzer shutdown completed with %d error(s).",
                len(errors),
            )
