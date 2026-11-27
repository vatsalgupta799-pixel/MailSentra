"""DMARC Receiver-Local Policy Interpretation and Disposition Engine (Step 3.7.3B).

Architecture reference: Revised STEP_3_7_3A_ARCHITECTURE_INSPECTION.md
Standards:
- RFC 9989 §§4.7, 4.10.1, 5.3.5, 5.3.6, 5.4, 7.2, 7.4, 8 (DMARCbis)
- RFC 8601 §§4, 5, 7 (Authentication-Results Trust Boundary)
- RFC 7960 §§2, 4.1.2 (Indirect Email Flows)
- RFC 7208 / RFC 6376 (Underlying SPF / DKIM Semantics)
- RFC 9990 §3.1.6 (Override Reason Vocabulary - telemetry only)

Design Invariants:
1. Strict Three-Tier Separation: Tier 1 (Published Policy), Tier 2 (Protocol Result),
   and Tier 3 (Receiver-Local Disposition) remain strictly separated; overrides and
   dispositions NEVER mutate SPF, DKIM, or DMARC authentication results.
2. Independent Two-Plane Arbitration: Authentication Plane (`t=y`, §7.4, forwarders,
   allowlists) operates orthogonally from the Threat / Hard-Security Plane (admin
   blocklists, confirmed malware/URLs, verified high-confidence impersonation). Hard
   security blocks CANNOT be bypassed by ordinary allowlists, DMARC PASS, t=y, or
   forwarder exemptions.
3. Module 3 Identity Advisory Rule: Module 3 boolean identity flags are preserved
   strictly in advisory telemetry until confidence, provenance, and evidence
   requirements are established.
4. Channel Separation: HTTP `.eml` uploads never claim SMTP 550/451 delivery actions
   and never mutate raw bytes; future SMTP integration receives a pure unexecuted
   pre-DATA-reply decision contract.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from typing import Any, Dict, List, Optional, Sequence, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import AuditLogger
from app.core.logging import logger
from app.models.user import UserRole
from app.modules.auth_protocols.config import AuthProtocolsConfig
from app.modules.contracts import (
    AuthProtocolsResult,
    CorroboratingThreatSignals,
    DKIMSignatureResult,
    DMARCDisposition,
    DMARCEnforcementDecision,
    DMARCPolicy,
    DMARCResult,
    ForwarderTrustEvidence,
    IngestionSource,
    LocalPolicyOverrideRule,
    OverrideRuleAction,
    ParsedEmail,
    PolicyOverrideType,
    ProtocolStatus,
    RawEmailPayload,
    SMTPAdapterDecisionContract,
    SPFResult,
    TrustedSMTPMetadata,
)
from app.modules.identity.domain_utils import is_subdomain_of, normalize_domain
from app.schemas.user import IngestionActor

_ALLOWED_ADMIN_ROLES = {UserRole.SUPER_ADMIN.value, UserRole.SOC_ANALYST.value}


class DMARCPolicyEnforcer:
    """Pure synchronous receiver-local DMARC policy enforcer (Stages 3–6)."""

    def __init__(self, config: Optional[AuthProtocolsConfig] = None) -> None:
        self._config = config or AuthProtocolsConfig()
        # Separate 256-bit instance secrets cryptographically isolate static server
        # config rules from dynamically attested interactive administrator rules.
        self._config_provenance_secret: bytes = secrets.token_bytes(32)
        self._admin_provenance_secret: bytes = secrets.token_bytes(32)
        self._verified_config_rules: List[LocalPolicyOverrideRule] = self._load_and_attest_config_rules()

    def _load_and_attest_config_rules(self) -> List[LocalPolicyOverrideRule]:
        """Internal config loader strictly scoped to AuthProtocolsConfig; inaccessible to request inputs."""
        verified: List[LocalPolicyOverrideRule] = []
        for item in self._config.local_override_rules:
            rule = (
                item
                if isinstance(item, LocalPolicyOverrideRule)
                else LocalPolicyOverrideRule.model_validate(item)
            )
            attested = self._attest_config_rule(rule)
            if attested is not None:
                verified.append(attested)
        return verified

    def _canonical_rule_bytes(
        self,
        rule: LocalPolicyOverrideRule,
        domain_prefix: bytes,
    ) -> bytes:
        payload = {
            "rule_id": (rule.rule_id or "").strip(),
            "action": rule.action.value,
            "match_from_domain": rule.match_from_domain,
            "match_org_domain": rule.match_org_domain,
            "match_sender_address": rule.match_sender_address,
            "match_ip_or_cidr": rule.match_ip_or_cidr,
            "require_aligned_dkim": bool(rule.require_aligned_dkim),
            "tenant_id": (rule.tenant_id or "").strip(),
            "configured_by_identity": (rule.configured_by_identity or "").strip(),
            "configured_by_role": rule.configured_by_role,
            "is_authenticated_admin_source": bool(rule.is_authenticated_admin_source),
            "reason": rule.reason,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return domain_prefix + encoded

    def _compute_rule_hmac(
        self,
        rule: LocalPolicyOverrideRule,
        secret: bytes,
        domain_prefix: bytes,
    ) -> str:
        return hmac.new(
            secret,
            self._canonical_rule_bytes(rule, domain_prefix),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _has_valid_server_provenance_fields(rule: LocalPolicyOverrideRule) -> bool:
        rule_id = (rule.rule_id or "").strip()
        tenant_id = (rule.tenant_id or "").strip()
        identity = (rule.configured_by_identity or "").strip()
        if not rule_id or not tenant_id or not identity or identity == "dev:unauthenticated":
            return False
        if rule.configured_by_role not in _ALLOWED_ADMIN_ROLES:
            return False
        if not rule.is_authenticated_admin_source:
            return False
        return True

    def _attest_config_rule(self, rule: LocalPolicyOverrideRule) -> Optional[LocalPolicyOverrideRule]:
        """Narrows actorless attestation exclusively to static server config loading in __init__."""
        if not self._has_valid_server_provenance_fields(rule):
            return None
        sig = self._compute_rule_hmac(
            rule,
            self._config_provenance_secret,
            b"CONFIG_RULE_V1:",
        )
        return rule.model_copy(update={"server_provenance_hmac": sig})

    def attest_server_rule(
        self,
        rule: LocalPolicyOverrideRule,
        authorizing_actor: Optional[IngestionActor] = None,
    ) -> Optional[LocalPolicyOverrideRule]:
        """Attests an interactive administrator override rule with strict actor identity/role/tenant binding.

        Rejects authorizing_actor=None, API-key actors (SYSTEM_AGENT), cross-tenant actors,
        and mismatched configured_by_identity / configured_by_role provenance fields.
        """
        if not self._has_valid_server_provenance_fields(rule):
            return None
        if authorizing_actor is None:
            return None
        actor_ident = (authorizing_actor.identity or "").strip()
        actor_tenant = (getattr(authorizing_actor, "tenant_id", None) or "").strip()
        rule_ident = (rule.configured_by_identity or "").strip()
        rule_tenant = (rule.tenant_id or "").strip()
        if (
            authorizing_actor.is_api_key
            or not actor_ident
            or actor_ident == "dev:unauthenticated"
            or authorizing_actor.role not in _ALLOWED_ADMIN_ROLES
            or not actor_tenant
            or actor_tenant != rule_tenant
            or actor_ident != rule_ident
            or authorizing_actor.role != rule.configured_by_role
        ):
            return None
        sig = self._compute_rule_hmac(
            rule,
            self._admin_provenance_secret,
            b"ADMIN_RULE_V1:",
        )
        return rule.model_copy(update={"server_provenance_hmac": sig})

    def _rule_has_verified_config_hmac(self, rule: LocalPolicyOverrideRule) -> bool:
        if not self._has_valid_server_provenance_fields(rule) or not rule.server_provenance_hmac:
            return False
        expected = self._compute_rule_hmac(
            rule,
            self._config_provenance_secret,
            b"CONFIG_RULE_V1:",
        )
        return hmac.compare_digest(rule.server_provenance_hmac, expected)

    def _rule_has_verified_admin_hmac(self, rule: LocalPolicyOverrideRule) -> bool:
        if not self._has_valid_server_provenance_fields(rule) or not rule.server_provenance_hmac:
            return False
        expected = self._compute_rule_hmac(
            rule,
            self._admin_provenance_secret,
            b"ADMIN_RULE_V1:",
        )
        return hmac.compare_digest(rule.server_provenance_hmac, expected)

    def enforce(
        self,
        dmarc_result: Optional[DMARCResult],
        spf_result: Optional[SPFResult] = None,
        dkim_results: Optional[List[DKIMSignatureResult]] = None,
        parsed_email: Optional[ParsedEmail] = None,
        raw_payload: Optional[RawEmailPayload] = None,
        channel: Optional[IngestionSource] = None,
        trusted_smtp_metadata: Optional[TrustedSMTPMetadata] = None,
        admin_rules: Optional[Sequence[LocalPolicyOverrideRule]] = None,
        admin_actor: Optional[IngestionActor] = None,
        forwarder_evidence: Optional[ForwarderTrustEvidence] = None,
        threat_signals: Optional[CorroboratingThreatSignals] = None,
        tenant_id: Optional[str] = None,
        dkim_evaluated: bool = True,
    ) -> DMARCEnforcementDecision:
        """Evaluates Tier 3 receiver-local disposition without mutating protocol results."""
        # Stage 1: Channel & Provenance Sanity Checks
        effective_channel = channel or (raw_payload.source if raw_payload else IngestionSource.DIRECT_UPLOAD)
        is_smtp_channel = effective_channel == IngestionSource.SMTP_RELAY
        channel_mode = "smtp_pre_data_contract" if is_smtp_channel else "http_inspection"
        effective_tenant_id = tenant_id or (raw_payload.tenant_id if raw_payload else "default") or "default"

        # HTTP / non-SMTP channels MUST NEVER rely on untrusted transport metadata
        effective_smtp_meta: Optional[TrustedSMTPMetadata] = None
        if is_smtp_channel and trusted_smtp_metadata is not None and trusted_smtp_metadata.is_trusted_mta:
            effective_smtp_meta = trusted_smtp_metadata

        raw_digest_before = None
        if raw_payload is not None:
            raw_digest_before = len(raw_payload.raw_bytes)

        # Stage 2: Extract immutable Tier 1 + Tier 2 protocol snapshot
        spf_status = spf_result.status if spf_result is not None else ProtocolStatus.NOT_EVALUATED
        dkim_status = self._summarize_dkim_status(dkim_results, dkim_evaluated=dkim_evaluated)
        dmarc_status = dmarc_result.status if dmarc_result is not None else ProtocolStatus.NOT_EVALUATED
        dmarc_rfc_status = dmarc_result.rfc_status if dmarc_result is not None else None

        from_domain = (
            dmarc_result.from_domain
            if dmarc_result and dmarc_result.from_domain
            else (parsed_email.from_sender.domain if parsed_email and parsed_email.from_sender else None)
        )
        org_domain = dmarc_result.org_domain if dmarc_result else None
        policy_domain = dmarc_result.policy_domain if dmarc_result else None

        published_applicable_policy = dmarc_result.policy if dmarc_result else DMARCPolicy.NOT_CONFIGURED
        record_p_policy = (
            dmarc_result.record_p_policy
            if dmarc_result and dmarc_result.record_p_policy is not None
            else published_applicable_policy
        )
        applicable_policy_tag = dmarc_result.applicable_policy_tag if dmarc_result else None
        policy_discovery_source = dmarc_result.policy_discovery_source if dmarc_result else None
        test_mode = bool(dmarc_result.test_mode) if dmarc_result else False

        # Stage 3: Published Policy Selection & DMARC Test Mode (t=y) Transformation
        test_mode_applied, effective_policy = self._apply_stage3_test_mode(
            dmarc_status=dmarc_status,
            published_applicable_policy=published_applicable_policy,
            test_mode=test_mode,
        )

        # Gather local rule inputs with strict authentication, server HMAC provenance, & tenant verification
        (
            matched_allow_rules,
            matched_block_rules,
            rejected_unauth_rules,
            rejected_rule_reasons,
        ) = self._match_authenticated_admin_rules(
            config_rules=self._verified_config_rules,
            dynamic_rules=list(admin_rules or []),
            admin_actor=admin_actor,
            from_domain=from_domain,
            org_domain=org_domain,
            parsed_email=parsed_email,
            trusted_smtp_meta=effective_smtp_meta,
            dkim_aligned=bool(dmarc_result and dmarc_result.dkim_aligned),
            scan_tenant_id=effective_tenant_id,
        )

        # Stage 4 & Stage 5 Inputs: Threat Signals & Indirect-Flow Evidence
        has_force_reject_block = any(r.action == OverrideRuleAction.FORCE_REJECT for r in matched_block_rules)
        has_force_quarantine_block = any(r.action == OverrideRuleAction.FORCE_QUARANTINE for r in matched_block_rules)

        (
            indirect_verified,
            indirect_type,
            indirect_details,
            unverified_indirect_ignored,
        ) = self._evaluate_indirect_flow_evidence(
            is_smtp_channel=is_smtp_channel,
            effective_channel=effective_channel,
            trusted_smtp_meta=effective_smtp_meta,
            forwarder_evidence=forwarder_evidence,
            parsed_email=parsed_email,
        )

        (
            threat_hard_block,
            threat_block_reject_level,
            threat_reasons,
            has_corroboration_for_reject,
            advisory_signals,
        ) = self._evaluate_threat_plane(
            threat_signals=threat_signals,
            has_force_reject_block=has_force_reject_block,
            has_force_quarantine_block=has_force_quarantine_block,
        )

        # Stage 4: RFC 9989 §7.4 Interoperability Protection & Verified Indirect Flows
        (
            post_interop_policy,
            interop_downgraded,
            interop_reason,
            forwarder_exempted,
            mailing_list_exempted,
        ) = self._apply_stage4_interoperability(
            dmarc_status=dmarc_status,
            effective_policy=effective_policy,
            indirect_verified=indirect_verified,
            indirect_type=indirect_type,
            has_corroboration_for_reject=has_corroboration_for_reject,
        )

        # Stage 5: Two-Plane Conflict Arbitration
        override_reasons: List[PolicyOverrideType] = []
        if test_mode_applied:
            override_reasons.append(PolicyOverrideType.POLICY_TEST_MODE)
        if forwarder_exempted:
            override_reasons.append(PolicyOverrideType.TRUSTED_FORWARDER)
        if mailing_list_exempted:
            override_reasons.append(PolicyOverrideType.MAILING_LIST)

        # Ordinary admin allowlist only acts on Authentication Plane
        allowlist_matched = len(matched_allow_rules) > 0
        final_auth_policy = post_interop_policy
        allowlist_exempted_dmarc = False
        if (
            dmarc_status == ProtocolStatus.FAIL
            and allowlist_matched
            and post_interop_policy in (DMARCPolicy.QUARANTINE, DMARCPolicy.REJECT)
        ):
            final_auth_policy = DMARCPolicy.NONE
            allowlist_exempted_dmarc = True
            override_reasons.append(PolicyOverrideType.LOCAL_POLICY)

        matched_rule_ids = [r.rule_id for r in matched_block_rules + matched_allow_rules]
        conflict_details: List[str] = []
        policy_conflict_detected = False

        if getattr(self._config, "dmarc_enforce_strict_reject_only_with_corroboration", True) is not True:
            logger.warning(
                "Unsafe configuration dmarc_enforce_strict_reject_only_with_corroboration=False ignored; "
                "RFC 9989 Section 7.4 remains strictly enforced."
            )
            policy_conflict_detected = True
            conflict_details.append(
                "RFC9989_7_4_UNSAFE_CONFIG_IGNORED: dmarc_enforce_strict_reject_only_with_corroboration=False cannot bypass §7.4"
            )

        if rejected_unauth_rules:
            policy_conflict_detected = True
            conflict_details.append(
                f"UNAUTHENTICATED_ADMIN_RULE_REJECTED: ignored unauthenticated/unverified rules {rejected_unauth_rules}"
            )

        if matched_block_rules and matched_allow_rules:
            policy_conflict_detected = True
            conflict_details.append(
                "ADMIN_POLICY_CONFLICT_DETECTED: Authenticated administrative blocklist supersedes allowlist"
            )

        if threat_hard_block and dmarc_status == ProtocolStatus.PASS:
            policy_conflict_detected = True
            conflict_details.append(
                "THREAT_OR_BLOCKLIST_OVERRIDES_DMARC_PASS: Local threat/blocklist enforces action while DMARC remains PASS"
            )

        if threat_hard_block and allowlist_matched:
            policy_conflict_detected = True
            conflict_details.append(
                "THREAT_OR_BLOCKLIST_OVERRIDES_ALLOWLIST: Hard security block cannot be bypassed by ordinary allowlist"
            )

        if threat_hard_block and (forwarder_exempted or mailing_list_exempted):
            policy_conflict_detected = True
            conflict_details.append(
                "THREAT_OR_BLOCKLIST_OVERRIDES_FORWARDER_EXEMPTION: Confirmed threat/blocklist supersedes indirect-flow exemption"
            )

        if threat_hard_block and test_mode_applied:
            policy_conflict_detected = True
            conflict_details.append(
                "THREAT_OR_BLOCKLIST_OVERRIDES_TEST_MODE: DMARC t=y cannot suppress independent threat findings or admin blocks"
            )

        if unverified_indirect_ignored:
            rej = indirect_details.get("rejected_reason") if isinstance(indirect_details, dict) else None
            detail_suffix = f" ({rej})" if rej else ""
            conflict_details.append(
                f"UNVERIFIED_INDIRECT_FLOW_CLAIM_IGNORED: Unverified or non-SMTP indirect-flow claim rejected{detail_suffix}"
            )

        # Stage 6: Channel-Specific Final Disposition Mapping
        (
            disposition,
            decision_reason,
            decision_summary,
            policy_applied,
            manual_review_recommended,
            retry_recommended,
            smtp_contract,
        ) = self._map_stage6_disposition(
            is_smtp_channel=is_smtp_channel,
            from_domain=from_domain,
            dmarc_result=dmarc_result,
            dmarc_status=dmarc_status,
            final_auth_policy=final_auth_policy,
            effective_policy=effective_policy,
            test_mode_applied=test_mode_applied,
            interop_downgraded=interop_downgraded,
            forwarder_exempted=forwarder_exempted,
            mailing_list_exempted=mailing_list_exempted,
            allowlist_exempted_dmarc=allowlist_exempted_dmarc,
            threat_hard_block=threat_hard_block,
            threat_block_reject_level=threat_block_reject_level,
            threat_reasons=threat_reasons,
            matched_block_rules=matched_block_rules,
        )

        # Domain-Owner testing mode (t=y) is a Stage 3 policy interpretation, NEVER a receiver-local override
        local_override_applied = bool(
            forwarder_exempted
            or mailing_list_exempted
            or allowlist_exempted_dmarc
            or bool(matched_block_rules)
        )

        # Guarantee uploaded bytes remained completely untouched
        raw_bytes_modified = False
        if raw_payload is not None and raw_digest_before is not None:
            raw_bytes_modified = (len(raw_payload.raw_bytes) != raw_digest_before)

        local_policy_inputs = {
            "tenant_id": effective_tenant_id,
            "channel": effective_channel.value,
            "trusted_smtp_present": effective_smtp_meta is not None,
            "authenticated_connector_id": (
                effective_smtp_meta.authenticated_connector_id if effective_smtp_meta else None
            ),
            "indirect_flow_verified": indirect_verified,
            "indirect_flow_details": indirect_details,
            "matched_allow_rule_ids": [r.rule_id for r in matched_allow_rules],
            "matched_block_rule_ids": [r.rule_id for r in matched_block_rules],
            "rejected_unauthenticated_rule_ids": rejected_unauth_rules,
            "rejected_rule_reasons": rejected_rule_reasons,
            "threat_reasons": threat_reasons,
        }

        diagnostic_evidence = {
            "tier1_record_p_policy": record_p_policy.value,
            "tier1_selected_applicable_policy": published_applicable_policy.value,
            "tier1_applicable_policy_tag": applicable_policy_tag,
            "tier1_discovery_source": policy_discovery_source,
            "tier1_subdomain_existence_status": dmarc_result.subdomain_existence_status if dmarc_result else None,
            "tier1_np_evaluation_skipped_reason": dmarc_result.np_evaluation_skipped_reason if dmarc_result else None,
            "tier2_dmarc_status": dmarc_status.value,
            "tier2_dmarc_rfc_status": dmarc_rfc_status,
            "tier2_spf_status": spf_status.value,
            "tier2_dkim_status": dkim_status.value,
            "stage3_test_mode_applied": test_mode_applied,
            "stage3_effective_policy": effective_policy.value,
            "stage4_post_interop_policy": post_interop_policy.value,
            "stage4_interop_downgrade_applied": interop_downgraded,
            "stage5_final_auth_policy": final_auth_policy.value,
            "stage5_local_override_applied": local_override_applied,
            "stage5_threat_block_applied": threat_hard_block,
            "unverified_indirect_flow_claim_ignored": unverified_indirect_ignored,
            "dmarc_diagnostics": dict(dmarc_result.diagnostics) if dmarc_result else {},
            "dmarc_error_reason": dmarc_result.error_reason if dmarc_result else None,
            "spf_error_reason": spf_result.error_reason if spf_result else None,
        }

        audit_metadata = self._build_audit_metadata(
            admin_actor=admin_actor,
            matched_block_rules=matched_block_rules,
            matched_allow_rules=matched_allow_rules,
            rejected_unauth_rules=rejected_unauth_rules,
            rejected_rule_reasons=rejected_rule_reasons,
            effective_tenant_id=effective_tenant_id,
            record_p_policy=record_p_policy,
            selected_applicable_policy=published_applicable_policy,
            test_mode_applied=test_mode_applied,
            local_override_applied=local_override_applied,
            indirect_flow_details=indirect_details,
        )

        # Deduplicate override_reasons deterministically preserving order
        dedup_overrides: List[PolicyOverrideType] = []
        for ov in override_reasons:
            if ov not in dedup_overrides:
                dedup_overrides.append(ov)

        return DMARCEnforcementDecision(
            spf_status=spf_status,
            dkim_status=dkim_status,
            dmarc_status=dmarc_status,
            dmarc_rfc_status=dmarc_rfc_status,
            from_domain=from_domain,
            org_domain=org_domain,
            policy_domain=policy_domain,
            record_p_policy=record_p_policy,
            selected_applicable_policy=published_applicable_policy,
            applicable_policy_tag=applicable_policy_tag,
            policy_discovery_source=policy_discovery_source,
            test_mode=test_mode,
            test_mode_applied=test_mode_applied,
            effective_policy=effective_policy,
            interoperability_downgrade_applied=interop_downgraded,
            interoperability_adjustment_reason=interop_reason,
            post_interop_policy=post_interop_policy,
            forwarder_exempted=forwarder_exempted,
            mailing_list_exempted=mailing_list_exempted,
            unverified_indirect_flow_claim_ignored=unverified_indirect_ignored,
            local_override_applied=local_override_applied,
            override_reasons=dedup_overrides,
            matched_rule_ids=matched_rule_ids,
            rejected_unauthenticated_rules=rejected_unauth_rules,
            policy_conflict_detected=policy_conflict_detected,
            conflict_details=conflict_details,
            threat_block_applied=threat_hard_block,
            advisory_signals=advisory_signals,
            local_policy_inputs=local_policy_inputs,
            channel=effective_channel,
            channel_mode=channel_mode,
            disposition=disposition,
            decision_reason=decision_reason,
            decision_summary=decision_summary,
            policy_applied=policy_applied,
            manual_review_recommended=manual_review_recommended,
            retry_recommended=retry_recommended,
            raw_bytes_modified=raw_bytes_modified,
            smtp_contract=smtp_contract,
            diagnostic_evidence=diagnostic_evidence,
            audit_metadata=audit_metadata,
        )

    @staticmethod
    def _summarize_dkim_status(
        dkim_results: Optional[List[DKIMSignatureResult]],
        dkim_evaluated: bool = True,
    ) -> ProtocolStatus:
        if not dkim_evaluated:
            return ProtocolStatus.NOT_EVALUATED
        if not dkim_results:
            return ProtocolStatus.NONE
        if any(s.status == ProtocolStatus.PASS and s.is_aligned_with_from for s in dkim_results):
            return ProtocolStatus.PASS
        if any(s.status == ProtocolStatus.PASS for s in dkim_results):
            return ProtocolStatus.PASS
        if any(s.status == ProtocolStatus.TEMPERROR for s in dkim_results):
            return ProtocolStatus.TEMPERROR
        if any(s.status in (ProtocolStatus.INDETERMINATE, ProtocolStatus.NOT_EVALUATED) for s in dkim_results):
            return ProtocolStatus.INDETERMINATE
        if any(s.status == ProtocolStatus.FAIL for s in dkim_results):
            return ProtocolStatus.FAIL
        return ProtocolStatus.PERMERROR

    @staticmethod
    def _apply_stage3_test_mode(
        dmarc_status: ProtocolStatus,
        published_applicable_policy: DMARCPolicy,
        test_mode: bool,
    ) -> Tuple[bool, DMARCPolicy]:
        """Applies RFC 9989 §4.7 t=y policy transformation strictly on completed DMARC FAIL."""
        if dmarc_status != ProtocolStatus.FAIL:
            return False, published_applicable_policy

        if not test_mode:
            return False, published_applicable_policy

        if published_applicable_policy == DMARCPolicy.REJECT:
            return True, DMARCPolicy.QUARANTINE
        if published_applicable_policy == DMARCPolicy.QUARANTINE:
            return True, DMARCPolicy.NONE
        return False, published_applicable_policy

    def _evaluate_indirect_flow_evidence(
        self,
        is_smtp_channel: bool,
        effective_channel: IngestionSource,
        trusted_smtp_meta: Optional[TrustedSMTPMetadata],
        forwarder_evidence: Optional[ForwarderTrustEvidence],
        parsed_email: Optional[ParsedEmail],
    ) -> Tuple[bool, Optional[PolicyOverrideType], Dict[str, Any], bool]:
        """Validates trusted-forwarder and mailing-list evidence strictly from verified SMTP relay provenance.

        NEVER accepts forwarder/mailing-list exemptions on DIRECT_UPLOAD or non-SMTP channels,
        NEVER trusts display names or List-Id/X-Original-From/Authentication-Results headers alone,
        NEVER allows caller Booleans to bypass MTA provenance, and requires both connector ID
        and relay IP allowlists plus consistent verified relay context (no field compensation).
        """
        verified = False
        flow_type: Optional[PolicyOverrideType] = None
        details: Dict[str, Any] = {
            "verified": False,
            "channel": effective_channel.value,
        }
        unverified_claim_detected = False

        if not is_smtp_channel:
            if forwarder_evidence is not None and (
                forwarder_evidence.is_verified_forwarder
                or forwarder_evidence.is_verified_mailing_list
                or forwarder_evidence.is_server_verified
                or bool((forwarder_evidence.connector_id or "").strip())
                or bool((forwarder_evidence.relay_ip or "").strip())
            ):
                unverified_claim_detected = True
                details["rejected_reason"] = "NON_SMTP_CHANNEL_FORWARDER_EVIDENCE_REJECTED"
                details["claimed_connector_id"] = forwarder_evidence.connector_id
                details["claimed_relay_ip"] = forwarder_evidence.relay_ip
            elif parsed_email is not None:
                disp = (
                    parsed_email.from_sender.display_name or ""
                    if parsed_email.from_sender
                    else ""
                ).lower()
                has_via_display = bool(re.search(r"\bvia\b", disp))
                has_list_headers = any(
                    k in parsed_email.headers_map
                    for k in ("list-id", "list-post", "x-original-from", "resent-from")
                )
                if has_via_display or has_list_headers:
                    unverified_claim_detected = True
                    details["rejected_reason"] = "UNVERIFIED_HEADER_OR_DISPLAY_INDIRECT_FLOW_HINT"
            return verified, flow_type, details, unverified_claim_detected

        # SMTP_RELAY channel: require authenticated server MTA provenance first
        mta_provenance_valid = (
            trusted_smtp_meta is not None
            and bool(trusted_smtp_meta.is_trusted_mta)
            and bool(trusted_smtp_meta.mta_sanitization_guaranteed)
        )
        conn_id = (trusted_smtp_meta.authenticated_connector_id or "").strip() if trusted_smtp_meta else ""
        conn_ip = (trusted_smtp_meta.connecting_ip or "").strip() if trusted_smtp_meta else ""
        mta_ip_obj: Optional[ipaddress.IPv4Address | ipaddress.IPv6Address] = None
        if conn_ip:
            try:
                mta_ip_obj = ipaddress.ip_address(conn_ip)
            except ValueError:
                mta_ip_obj = None

        configured_connectors = {
            c.strip() for c in self._config.trusted_forwarder_connector_ids if (c or "").strip()
        } | {
            k.strip() for k in self._config.trusted_forwarder_bindings.keys() if (k or "").strip()
        }
        connector_matched = bool(conn_id and conn_id in configured_connectors)
        ip_matched = bool(
            conn_ip and mta_ip_obj is not None and self._ip_matches_allowlist(conn_ip, self._config.trusted_forwarder_ips)
        )
        bindings = self._config.trusted_forwarder_bindings
        if bindings:
            bound_ips = bindings.get(conn_id, [])
            binding_matched = bool(connector_matched and conn_ip and self._ip_matches_allowlist(conn_ip, bound_ips))
        else:
            binding_matched = True

        # Check whether forwarder/list claim was presented (either via explicit evidence or partial relay match)
        relay_claimed = (
            forwarder_evidence is not None
            or connector_matched
            or ip_matched
        )

        if not mta_provenance_valid or not conn_id or mta_ip_obj is None:
            if relay_claimed:
                unverified_claim_detected = True
                details["rejected_reason"] = "MISSING_OR_UNAUTHENTICATED_MTA_PROVENANCE"
            return verified, flow_type, details, unverified_claim_detected

        if not (connector_matched and ip_matched and binding_matched):
            if relay_claimed:
                unverified_claim_detected = True
                if connector_matched and not ip_matched:
                    details["rejected_reason"] = "UNTRUSTED_FORWARDER_RELAY_IP"
                elif ip_matched and not connector_matched:
                    details["rejected_reason"] = "UNKNOWN_OR_UNTRUSTED_FORWARDER_CONNECTOR"
                else:
                    details["rejected_reason"] = "FORWARDER_CONNECTOR_RELAY_BINDING_MISMATCH"
                details["connector_id"] = conn_id
                details["relay_ip"] = conn_ip
            return verified, flow_type, details, unverified_claim_detected

        if forwarder_evidence is not None:
            ev_conn = (forwarder_evidence.connector_id or "").strip()
            ev_ip = (forwarder_evidence.relay_ip or "").strip()
            ev_ip_obj: Optional[ipaddress.IPv4Address | ipaddress.IPv6Address] = None
            if ev_ip:
                try:
                    ev_ip_obj = ipaddress.ip_address(ev_ip)
                except ValueError:
                    ev_ip_obj = None

            if not (
                forwarder_evidence.is_server_verified
                and (forwarder_evidence.is_verified_forwarder or forwarder_evidence.is_verified_mailing_list)
            ):
                unverified_claim_detected = True
                details["rejected_reason"] = "UNVERIFIED_FORWARDER_EVIDENCE_OBJECT"
                return verified, flow_type, details, unverified_claim_detected

            if not ev_conn or ev_conn != conn_id or ev_ip_obj is None or ev_ip_obj != mta_ip_obj:
                unverified_claim_detected = True
                details["rejected_reason"] = "FORWARDER_EVIDENCE_RELAY_CONTEXT_MISMATCH"
                details["mta_connector_id"] = conn_id
                details["mta_relay_ip"] = conn_ip
                details["evidence_connector_id"] = ev_conn or None
                details["evidence_relay_ip"] = ev_ip or None
                return verified, flow_type, details, unverified_claim_detected

            verified = True
            flow_type = (
                PolicyOverrideType.MAILING_LIST
                if forwarder_evidence.is_verified_mailing_list
                else PolicyOverrideType.TRUSTED_FORWARDER
            )
            details = {
                "verified": True,
                "channel": effective_channel.value,
                "source": forwarder_evidence.evidence_source or "verified_smtp_relay_and_evidence",
                "connector_id": conn_id,
                "relay_ip": conn_ip,
                "mta_sanitization_guaranteed": True,
                "exemption_reason": (
                    "Verified mailing list over authenticated allowlisted SMTP relay"
                    if flow_type == PolicyOverrideType.MAILING_LIST
                    else "Verified forwarder over authenticated allowlisted SMTP relay"
                ),
            }
            return verified, flow_type, details, False

        # Valid authenticated allowlisted SMTP_RELAY without conflicting evidence object
        verified = True
        flow_type = PolicyOverrideType.TRUSTED_FORWARDER
        details = {
            "verified": True,
            "channel": effective_channel.value,
            "source": "verified_smtp_connector_and_ip",
            "connector_id": conn_id,
            "relay_ip": conn_ip,
            "mta_sanitization_guaranteed": True,
            "exemption_reason": "Authenticated and allowlisted SMTP forwarder connector + relay IP",
        }
        return verified, flow_type, details, False

    @staticmethod
    def _ip_matches_allowlist(ip_str: str, entries: Sequence[str]) -> bool:
        try:
            addr = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False
        for entry in entries:
            cand = (entry or "").strip()
            if not cand:
                continue
            try:
                if "/" in cand:
                    if addr in ipaddress.ip_network(cand, strict=False):
                        return True
                elif addr == ipaddress.ip_address(cand):
                    return True
            except ValueError:
                continue
        return False

    def _match_authenticated_admin_rules(
        self,
        config_rules: Sequence[LocalPolicyOverrideRule],
        dynamic_rules: Sequence[LocalPolicyOverrideRule],
        admin_actor: Optional[IngestionActor],
        from_domain: Optional[str],
        org_domain: Optional[str],
        parsed_email: Optional[ParsedEmail],
        trusted_smtp_meta: Optional[TrustedSMTPMetadata],
        dkim_aligned: bool,
        scan_tenant_id: str,
    ) -> Tuple[
        List[LocalPolicyOverrideRule],
        List[LocalPolicyOverrideRule],
        List[str],
        Dict[str, str],
    ]:
        """Matches rules only with unforgeable server provenance, actor auth, and strict tenant match."""
        matched_allow: List[LocalPolicyOverrideRule] = []
        matched_block: List[LocalPolicyOverrideRule] = []
        rejected_unauth: List[str] = []
        rejected_reasons: Dict[str, str] = {}

        effective_scan_tenant = (scan_tenant_id or "").strip()

        actor_ident = (admin_actor.identity or "").strip() if admin_actor is not None else ""
        actor_tenant = (getattr(admin_actor, "tenant_id", None) or "").strip() if admin_actor is not None else ""
        actor_authenticated = (
            admin_actor is not None
            and bool(actor_ident)
            and actor_ident != "dev:unauthenticated"
        )
        actor_tenant_matches = (
            actor_authenticated
            and bool(actor_tenant)
            and bool(effective_scan_tenant)
            and (actor_tenant == effective_scan_tenant)
        )
        actor_is_human_admin = (
            actor_authenticated
            and not admin_actor.is_api_key
            and admin_actor.role in _ALLOWED_ADMIN_ROLES
        )
        actor_is_system_agent = (
            actor_authenticated
            and bool(admin_actor.is_api_key)
            and admin_actor.role == UserRole.SYSTEM_AGENT.value
        )

        norm_from = normalize_domain(from_domain) if from_domain else ""
        norm_org = normalize_domain(org_domain) if org_domain else ""
        from_addr = (
            parsed_email.from_sender.address.strip().lower()
            if parsed_email and parsed_email.from_sender and parsed_email.from_sender.address
            else ""
        )
        trusted_ip = (
            trusted_smtp_meta.connecting_ip.strip()
            if trusted_smtp_meta and trusted_smtp_meta.is_trusted_mta and trusted_smtp_meta.connecting_ip
            else ""
        )

        tagged_rules = [(r, True) for r in config_rules] + [(r, False) for r in dynamic_rules]
        for rule, from_server_config in tagged_rules:
            if not self._rule_matches_target(
                rule=rule,
                norm_from=norm_from,
                norm_org=norm_org,
                from_addr=from_addr,
                trusted_ip=trusted_ip,
                dkim_aligned=dkim_aligned,
            ):
                continue

            rid = (rule.rule_id or "<unnamed>").strip()
            rule_tenant = (rule.tenant_id or "").strip()
            if not effective_scan_tenant or not rule_tenant or rule_tenant != effective_scan_tenant:
                rejected_unauth.append(rid)
                rejected_reasons[rid] = "RULE_TENANT_MISMATCH_OR_MISSING"
                continue

            # Rule must prove domain-separated HMAC provenance (config secret vs dynamic admin secret)
            hmac_valid = (
                self._rule_has_verified_config_hmac(rule)
                if from_server_config
                else self._rule_has_verified_admin_hmac(rule)
            )
            if not hmac_valid:
                rejected_unauth.append(rid)
                rejected_reasons[rid] = "UNAUTHENTICATED_OR_FORGED_RULE_PROVENANCE"
                continue

            # Separate actor authorization from rule provenance and separate SYSTEM_AGENT vs human admin
            if not actor_authenticated:
                rejected_unauth.append(rid)
                rejected_reasons[rid] = "MISSING_OR_UNAUTHENTICATED_ACTOR"
                continue

            if not actor_tenant_matches:
                rejected_unauth.append(rid)
                rejected_reasons[rid] = "ACTOR_TENANT_MISMATCH_OR_MISSING"
                continue

            if from_server_config:
                if not (actor_is_human_admin or actor_is_system_agent):
                    rejected_unauth.append(rid)
                    rejected_reasons[rid] = "UNAUTHORIZED_ACTOR_ROLE_FOR_CONFIG_RULE"
                    continue
            else:
                if not actor_is_human_admin:
                    rejected_unauth.append(rid)
                    rejected_reasons[rid] = "HUMAN_ADMIN_REQUIRED_FOR_DYNAMIC_OVERRIDE"
                    continue

            if rule.action == OverrideRuleAction.EXEMPT_ACCEPT:
                matched_allow.append(rule)
            else:
                matched_block.append(rule)

        return matched_allow, matched_block, rejected_unauth, rejected_reasons

    def _rule_matches_target(
        self,
        rule: LocalPolicyOverrideRule,
        norm_from: str,
        norm_org: str,
        from_addr: str,
        trusted_ip: str,
        dkim_aligned: bool,
    ) -> bool:
        has_selector = False

        if rule.match_sender_address:
            has_selector = True
            if not from_addr or from_addr != rule.match_sender_address.strip().lower():
                return False

        if rule.match_from_domain:
            has_selector = True
            target = normalize_domain(rule.match_from_domain)
            if not norm_from or not (norm_from == target or is_subdomain_of(norm_from, target)):
                return False

        if rule.match_org_domain:
            has_selector = True
            target_org = normalize_domain(rule.match_org_domain)
            if not norm_org or norm_org != target_org:
                return False

        if rule.match_ip_or_cidr:
            has_selector = True
            # Never match IP rules against Received headers or unverified HTTP client IPs
            if not trusted_ip or not self._ip_matches_allowlist(trusted_ip, [rule.match_ip_or_cidr]):
                return False

        if not has_selector:
            return False

        if rule.require_aligned_dkim and not dkim_aligned:
            return False

        return True

    @staticmethod
    def _evaluate_threat_plane(
        threat_signals: Optional[CorroboratingThreatSignals],
        has_force_reject_block: bool,
        has_force_quarantine_block: bool,
    ) -> Tuple[bool, bool, List[str], bool, Dict[str, Any]]:
        """Evaluates orthogonal Threat/Hard-Security signals while isolating Module 3 Booleans."""
        threat_reasons: List[str] = []
        advisory_signals: Dict[str, Any] = {}
        hard_block = False
        reject_level = False
        corroboration_for_reject = False

        if has_force_reject_block:
            hard_block = True
            reject_level = True
            corroboration_for_reject = True
            threat_reasons.append("ADMIN_BLOCKLIST_FORCE_REJECT")
        elif has_force_quarantine_block:
            hard_block = True
            threat_reasons.append("ADMIN_BLOCKLIST_FORCE_QUARANTINE")

        if threat_signals is not None:
            if threat_signals.confirmed_malicious_attachment:
                hard_block = True
                reject_level = True
                corroboration_for_reject = True
                threat_reasons.append("CONFIRMED_MALICIOUS_ATTACHMENT")

            if threat_signals.confirmed_malicious_url:
                hard_block = True
                reject_level = True
                corroboration_for_reject = True
                threat_reasons.append("CONFIRMED_MALICIOUS_URL")

            if threat_signals.threat_intel_confirmed_malicious:
                hard_block = True
                reject_level = True
                corroboration_for_reject = True
                threat_reasons.append("CONFIRMED_THREAT_INTEL_HIT")

            # Impersonation qualifies ONLY when provenance AND confidence threshold (>= 0.85) hold
            if threat_signals.high_confidence_impersonation:
                conf = threat_signals.impersonation_confidence or 0.0
                if threat_signals.impersonation_provenance_verified and conf >= 0.85:
                    hard_block = True
                    corroboration_for_reject = True
                    threat_reasons.append("VERIFIED_HIGH_CONFIDENCE_IMPERSONATION")
                else:
                    advisory_signals["unverified_impersonation_signal_held_advisory"] = {
                        "provenance_verified": threat_signals.impersonation_provenance_verified,
                        "confidence": conf,
                    }

            if threat_signals.verified_corroborating_signals:
                corroboration_for_reject = True

            # Preserve Module 3 IdentityAnalysisResult strictly as advisory telemetry
            if threat_signals.advisory_identity_analysis is not None:
                ident = threat_signals.advisory_identity_analysis
                advisory_signals["module3_identity_analysis"] = {
                    "advisory_only": True,
                    "used_for_hard_block": False,
                    "used_for_rfc7_4_corroboration": False,
                    "display_name_spoofed": ident.display_name_spoofed,
                    "typosquatting_detected": ident.typosquatting_detected,
                    "punycode_detected": ident.punycode_detected,
                    "homoglyph_detected": ident.homoglyph_detected,
                    "envelope_header_match": ident.envelope_header_match,
                    "analysis_status": ident.analysis_status,
                }

        return hard_block, reject_level, threat_reasons, corroboration_for_reject, advisory_signals

    @staticmethod
    def _apply_stage4_interoperability(
        dmarc_status: ProtocolStatus,
        effective_policy: DMARCPolicy,
        indirect_verified: bool,
        indirect_type: Optional[PolicyOverrideType],
        has_corroboration_for_reject: bool,
    ) -> Tuple[DMARCPolicy, bool, Optional[str], bool, bool]:
        """Applies RFC 9989 §7.4 p=reject protection and verified indirect-flow handling."""
        if dmarc_status != ProtocolStatus.FAIL:
            return effective_policy, False, None, False, False

        forwarder_exempted = False
        mailing_list_exempted = False
        current_policy = effective_policy

        if indirect_verified and current_policy in (DMARCPolicy.QUARANTINE, DMARCPolicy.REJECT):
            if indirect_type == PolicyOverrideType.MAILING_LIST:
                mailing_list_exempted = True
            else:
                forwarder_exempted = True
            current_policy = DMARCPolicy.NONE

        interop_downgraded = False
        interop_reason: Optional[str] = None
        if current_policy == DMARCPolicy.REJECT and not has_corroboration_for_reject:
            # RFC 9989 §7.4 & §8: Mail Receivers MUST NOT reject incoming messages solely on the basis
            # of a "p=reject" policy; treat failing mail as "p=quarantine" absent other knowledge/analysis.
            current_policy = DMARCPolicy.QUARANTINE
            interop_downgraded = True
            interop_reason = (
                "RFC 9989 Section 7.4: Mail Receivers MUST NOT reject solely due to published p=reject "
                "without corroborating knowledge and analysis; treated as p=quarantine"
            )

        return current_policy, interop_downgraded, interop_reason, forwarder_exempted, mailing_list_exempted

    def _map_stage6_disposition(
        self,
        is_smtp_channel: bool,
        from_domain: Optional[str],
        dmarc_result: Optional[DMARCResult],
        dmarc_status: ProtocolStatus,
        final_auth_policy: DMARCPolicy,
        effective_policy: DMARCPolicy,
        test_mode_applied: bool,
        interop_downgraded: bool,
        forwarder_exempted: bool,
        mailing_list_exempted: bool,
        allowlist_exempted_dmarc: bool,
        threat_hard_block: bool,
        threat_block_reject_level: bool,
        threat_reasons: List[str],
        matched_block_rules: List[LocalPolicyOverrideRule],
    ) -> Tuple[
        DMARCDisposition,
        str,
        str,
        bool,
        bool,
        bool,
        Optional[SMTPAdapterDecisionContract],
    ]:
        domain_label = from_domain or "unknown"

        # Threat / Hard-Security Plane takes strict precedence across all protocol statuses
        if threat_hard_block:
            reject_level = (
                threat_block_reject_level
                or (dmarc_status == ProtocolStatus.FAIL and final_auth_policy == DMARCPolicy.REJECT)
                or any(r.action == OverrideRuleAction.FORCE_REJECT for r in matched_block_rules)
            )
            if is_smtp_channel:
                if reject_level:
                    smtp_contract = SMTPAdapterDecisionContract(
                        action="REJECT_550",
                        smtp_reply_code=550,
                        enhanced_status_code="5.7.1",
                        reply_text=f"550 5.7.1 Email rejected per security policy ({','.join(threat_reasons)}) for {domain_label}",
                        pre_data_reply_required=True,
                        executed=False,
                    )
                    return (
                        DMARCDisposition.REJECT,
                        f"THREAT_OR_ADMIN_BLOCK_REJECT:{','.join(threat_reasons)}",
                        f"Hard security block ({', '.join(threat_reasons)}) recommends synchronous SMTP 550 5.7.1 rejection.",
                        True,
                        False,
                        False,
                        smtp_contract,
                    )
                smtp_contract = SMTPAdapterDecisionContract(
                    action="QUARANTINE_HOLD",
                    smtp_reply_code=250,
                    enhanced_status_code="2.0.0",
                    reply_text=f"250 2.0.0 Accepted into security quarantine ({','.join(threat_reasons)})",
                    pre_data_reply_required=True,
                    executed=False,
                )
                return (
                    DMARCDisposition.QUARANTINE,
                    f"THREAT_OR_ADMIN_BLOCK_QUARANTINE:{','.join(threat_reasons)}",
                    f"Hard security block ({', '.join(threat_reasons)}) places message into quarantine.",
                    True,
                    False,
                    False,
                    smtp_contract,
                )

            # HTTP inspection channel: never claims SMTP execution
            disp = (
                DMARCDisposition.RECOMMEND_REJECT
                if reject_level
                else DMARCDisposition.QUARANTINE
            )
            return (
                disp,
                f"THREAT_OR_ADMIN_BLOCK_{disp.value}:{','.join(threat_reasons)}",
                f"Inspection flagged hard security block ({', '.join(threat_reasons)}) without modifying uploaded bytes or claiming SMTP actions.",
                True,
                False,
                False,
                None,
            )

        # Protocol evaluation did not complete cleanly or yielded non-FAIL
        if dmarc_status == ProtocolStatus.PASS:
            smtp_contract = (
                SMTPAdapterDecisionContract(
                    action="ACCEPT_250",
                    smtp_reply_code=250,
                    enhanced_status_code="2.0.0",
                    reply_text="250 2.0.0 DMARC pass",
                    pre_data_reply_required=True,
                    executed=False,
                )
                if is_smtp_channel
                else None
            )
            return (
                DMARCDisposition.ACCEPT,
                "DMARC_PASS",
                "DMARC passed via aligned authenticated identifier.",
                False,
                False,
                False,
                smtp_contract,
            )

        if dmarc_status == ProtocolStatus.NONE:
            smtp_contract = (
                SMTPAdapterDecisionContract(
                    action="ACCEPT_250",
                    smtp_reply_code=250,
                    enhanced_status_code="2.0.0",
                    reply_text="250 2.0.0 No DMARC policy record applies",
                    pre_data_reply_required=True,
                    executed=False,
                )
                if is_smtp_channel
                else None
            )
            return (
                DMARCDisposition.ACCEPT,
                "DMARC_NO_APPLICABLE_POLICY",
                "No DMARC policy record found; DMARC mechanism does not apply (RFC 9989 §5.3.2).",
                False,
                False,
                False,
                smtp_contract,
            )

        if dmarc_status == ProtocolStatus.PERMERROR:
            smtp_contract = (
                SMTPAdapterDecisionContract(
                    action="ACCEPT_250",
                    smtp_reply_code=250,
                    enhanced_status_code="2.0.0",
                    reply_text="250 2.0.0 DMARC permerror; policy not applied",
                    pre_data_reply_required=True,
                    executed=False,
                )
                if is_smtp_channel
                else None
            )
            return (
                DMARCDisposition.ACCEPT,
                "DMARC_PERMERROR_POLICY_NOT_APPLIED",
                "Permanent DMARC discovery or From-header error; Domain Owner Assessment Policy not applied.",
                False,
                True,
                False,
                smtp_contract,
            )

        if dmarc_status == ProtocolStatus.TEMPERROR:
            if not is_smtp_channel:
                return (
                    DMARCDisposition.RETRY_RECOMMENDED,
                    "DMARC_TEMPERROR_HTTP_RETRY_RECOMMENDED",
                    "Transient DNS error prevented DMARC completion; retry evaluation recommended (no SMTP 451 claimed on HTTP upload).",
                    False,
                    False,
                    True,
                    None,
                )
            if self._config.dmarc_temperror_smtp_action == "accept":
                smtp_contract = SMTPAdapterDecisionContract(
                    action="ACCEPT_250",
                    smtp_reply_code=250,
                    enhanced_status_code="2.0.0",
                    reply_text="250 2.0.0 DMARC temperror; fail-open accept per local policy",
                    pre_data_reply_required=True,
                    executed=False,
                )
                return (
                    DMARCDisposition.ACCEPT,
                    "DMARC_TEMPERROR_SMTP_FAIL_OPEN_ACCEPT",
                    "Transient DNS error during DMARC validation; configured fail-open SMTP policy.",
                    False,
                    False,
                    False,
                    smtp_contract,
                )
            smtp_contract = SMTPAdapterDecisionContract(
                action="DEFER_451",
                smtp_reply_code=451,
                enhanced_status_code="4.7.1",
                reply_text=f"451 4.7.1 Temporary DNS error resolving DMARC policy for {domain_label}; please try again later",
                pre_data_reply_required=True,
                executed=False,
            )
            return (
                DMARCDisposition.DEFER,
                "DMARC_TEMPERROR_SMTP_DEFER_451",
                "Transient DNS error prevented DMARC validation; default SMTP contract recommends DEFER (451 4.7.1) without applying Domain Owner policy.",
                False,
                False,
                True,
                smtp_contract,
            )

        if dmarc_status in (ProtocolStatus.INDETERMINATE, ProtocolStatus.NOT_EVALUATED):
            if not is_smtp_channel:
                return (
                    DMARCDisposition.MANUAL_REVIEW_INCOMPLETE,
                    "DMARC_INCOMPLETE_MANUAL_REVIEW",
                    "Evaluation incomplete (e.g. missing SMTP context for SPF or internal error); DMARC policy frozen under MailSentra safety model.",
                    False,
                    True,
                    False,
                    None,
                )
            smtp_contract = SMTPAdapterDecisionContract(
                action="DEFER_451",
                smtp_reply_code=451,
                enhanced_status_code="4.7.1",
                reply_text=f"451 4.7.1 Incomplete DMARC evaluation for {domain_label}; manual review or retry required",
                pre_data_reply_required=True,
                executed=False,
            )
            return (
                DMARCDisposition.DEFER,
                "DMARC_INCOMPLETE_SMTP_DEFER_451",
                "DMARC evaluation incomplete; Domain Owner policy frozen.",
                False,
                True,
                True,
                smtp_contract,
            )

        # Completed DMARC FAIL: map Stage 4/5 final_auth_policy
        if final_auth_policy == DMARCPolicy.NONE:
            if allowlist_exempted_dmarc:
                reason_code = "DMARC_FAIL_LOCAL_ALLOWLIST_OVERRIDE"
                summary = "DMARC failed, accepted per authenticated local allowlist override (dmarc_status preserved as FAIL)."
            elif forwarder_exempted:
                reason_code = "DMARC_FAIL_TRUSTED_FORWARDER_OVERRIDE"
                summary = "DMARC failed, accepted per server-verified trusted forwarder evidence (RFC 7960 / §7.4)."
            elif mailing_list_exempted:
                reason_code = "DMARC_FAIL_MAILING_LIST_OVERRIDE"
                summary = "DMARC failed, accepted per server-verified mailing list evidence (RFC 7960 / §7.4)."
            elif test_mode_applied:
                reason_code = "DMARC_FAIL_TEST_MODE_STEPPED_DOWN_TO_NONE"
                summary = "DMARC failed with quarantine policy and t=y; stepped down to none (policy_test_mode)."
            else:
                reason_code = "DMARC_FAIL_POLICY_NONE"
                summary = "DMARC failed under published p=none monitoring policy (RFC 9989 §5.4)."

            smtp_contract = (
                SMTPAdapterDecisionContract(
                    action="ACCEPT_250",
                    smtp_reply_code=250,
                    enhanced_status_code="2.0.0",
                    reply_text="250 2.0.0 Accepted per local DMARC disposition",
                    pre_data_reply_required=True,
                    executed=False,
                )
                if is_smtp_channel
                else None
            )
            return (
                DMARCDisposition.ACCEPT,
                reason_code,
                summary,
                False,
                False,
                False,
                smtp_contract,
            )

        if final_auth_policy == DMARCPolicy.QUARANTINE:
            if interop_downgraded:
                reason_code = "RFC9989_7_4_REJECT_DOWNGRADED_TO_QUARANTINE"
                summary = (
                    "DMARC failed under p=reject without corroborating threat/sending-pattern analysis; "
                    "RFC 9989 §7.4 requires quarantine rather than rejecting solely on p=reject."
                )
            elif test_mode_applied:
                reason_code = "DMARC_FAIL_TEST_MODE_STEPPED_DOWN_TO_QUARANTINE"
                summary = "DMARC failed under reject policy with t=y; stepped down to quarantine (policy_test_mode)."
            else:
                reason_code = "DMARC_FAIL_POLICY_QUARANTINE"
                summary = "DMARC failed under applicable quarantine policy."

            smtp_contract = (
                SMTPAdapterDecisionContract(
                    action="QUARANTINE_HOLD",
                    smtp_reply_code=250,
                    enhanced_status_code="2.0.0",
                    reply_text=f"250 2.0.0 Quarantined per DMARC policy for {domain_label}",
                    pre_data_reply_required=True,
                    executed=False,
                )
                if is_smtp_channel
                else None
            )
            return (
                DMARCDisposition.QUARANTINE,
                reason_code,
                summary,
                True,
                False,
                False,
                smtp_contract,
            )

        # final_auth_policy == DMARCPolicy.REJECT (with corroborated knowledge & analysis)
        if not is_smtp_channel:
            return (
                DMARCDisposition.RECOMMEND_REJECT,
                "DMARC_FAIL_CORROBORATED_RECOMMEND_REJECT",
                "DMARC failed under reject policy with corroborating threat/analysis evidence (HTTP upload recommends reject without claiming SMTP 550).",
                True,
                False,
                False,
                None,
            )

        smtp_contract = SMTPAdapterDecisionContract(
            action="REJECT_550",
            smtp_reply_code=550,
            enhanced_status_code="5.7.1",
            reply_text=f"550 5.7.1 Email rejected per DMARC policy for {domain_label}",
            pre_data_reply_required=True,
            executed=False,
        )
        return (
            DMARCDisposition.REJECT,
            "DMARC_FAIL_CORROBORATED_SMTP_REJECT_550",
            "DMARC failed under reject policy corroborated by independent analysis (future SMTP pre-DATA 550 5.7.1 contract).",
            True,
            False,
            False,
            smtp_contract,
        )

    @staticmethod
    def _build_audit_metadata(
        admin_actor: Optional[IngestionActor],
        matched_block_rules: List[LocalPolicyOverrideRule],
        matched_allow_rules: List[LocalPolicyOverrideRule],
        rejected_unauth_rules: List[str],
        rejected_rule_reasons: Dict[str, str],
        effective_tenant_id: str,
        record_p_policy: DMARCPolicy,
        selected_applicable_policy: DMARCPolicy,
        test_mode_applied: bool,
        local_override_applied: bool,
        indirect_flow_details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Captures explicit administrative, test-mode, indirect-flow, and actor provenance without leaking secrets."""
        limitations: List[str] = []
        actor_ident = (admin_actor.identity or "").strip() if admin_actor is not None else ""
        if admin_actor is None or not actor_ident or actor_ident == "dev:unauthenticated":
            actor_type = "unauthenticated"
            limitations.append(
                "No authenticated IngestionActor supplied to policy enforcer; unauthenticated contexts cannot authorize overrides."
            )
        elif admin_actor.is_api_key:
            actor_type = "api_key_system_agent"
        else:
            actor_type = "human_user"

        return {
            "tenant_id": effective_tenant_id,
            "actor_identity": actor_ident or None,
            "actor_role": admin_actor.role if admin_actor else None,
            "actor_tenant_id": getattr(admin_actor, "tenant_id", None) if admin_actor else None,
            "actor_is_api_key": admin_actor.is_api_key if admin_actor else None,
            "actor_type": actor_type,
            "domain_owner_record_p_policy": record_p_policy.value,
            "domain_owner_selected_policy": selected_applicable_policy.value,
            "domain_owner_policy_preserved": True,
            "test_mode_applied": test_mode_applied,
            "local_override_applied": local_override_applied,
            "indirect_flow_evidence": dict(indirect_flow_details or {}),
            "authenticated_block_rules": [
                {
                    "rule_id": r.rule_id,
                    "configured_by": r.configured_by_identity,
                    "role": r.configured_by_role,
                }
                for r in matched_block_rules
            ],
            "authenticated_allow_rules": [
                {
                    "rule_id": r.rule_id,
                    "configured_by": r.configured_by_identity,
                    "role": r.configured_by_role,
                }
                for r in matched_allow_rules
            ],
            "rejected_unauthenticated_rules": rejected_unauth_rules,
            "rejected_rule_reasons": rejected_rule_reasons,
            "limitations": limitations,
        }


def _redact_email_identity(value: Optional[str]) -> Optional[str]:
    """Redacts non-system local-parts from email/DKIM identities while preserving domain attribution."""
    if value is None or not isinstance(value, str):
        return value
    s = value.strip()
    if "@" not in s:
        return s
    cleaned = s.strip("<> ")
    if "@" not in cleaned:
        return s
    local, dom = cleaned.split("@", 1)
    if not local or local.lower() == "postmaster":
        return cleaned
    return f"***@{dom}"


def _minimize_spf_telemetry(spf_result: Optional[SPFResult]) -> Optional[Dict[str, Any]]:
    """Serializes SPF telemetry while redacting non-system mailbox local-parts."""
    if spf_result is None:
        return None
    data = spf_result.model_dump(mode="json")
    data["identity"] = _redact_email_identity(data.get("identity"))
    return data


def _minimize_dkim_telemetry(dkim_results: Optional[List[DKIMSignatureResult]]) -> List[Dict[str, Any]]:
    """Serializes DKIM telemetry while redacting local-parts in DKIM i= identities."""
    minimized: List[Dict[str, Any]] = []
    for sig in dkim_results or []:
        data = sig.model_dump(mode="json")
        data["identity"] = _redact_email_identity(data.get("identity"))
        minimized.append(data)
    return minimized


def build_dmarc_enforcement_telemetry(
    dmarc_result: DMARCResult,
    decision: DMARCEnforcementDecision,
    spf_result: Optional[SPFResult] = None,
    dkim_results: Optional[List[DKIMSignatureResult]] = None,
    auth_result: Optional[AuthProtocolsResult] = None,
    audit_fingerprint: Optional[str] = None,
) -> Dict[str, Any]:
    """Builds serializable telemetry payload preserving Tier 1, Tier 2, and Tier 3 cleanly with PII minimization."""
    dmarc_dump = dmarc_result.model_dump(mode="json")
    if isinstance(dmarc_dump.get("from_domain"), str) and "@" in dmarc_dump["from_domain"]:
        dmarc_dump["from_domain"] = _redact_email_identity(dmarc_dump["from_domain"])
    payload: Dict[str, Any] = {
        "spf": _minimize_spf_telemetry(spf_result),
        "dkim_signatures": _minimize_dkim_telemetry(dkim_results),
        "dmarc": dmarc_dump,
        "dmarc_enforcement": decision.model_dump(mode="json"),
    }
    if audit_fingerprint is not None:
        payload["audit_fingerprint"] = audit_fingerprint
    if auth_result is not None:
        auth_dump = auth_result.model_dump(mode="json")
        if isinstance(auth_dump.get("spf_details"), dict):
            auth_dump["spf_details"]["identity"] = _redact_email_identity(
                auth_dump["spf_details"].get("identity")
            )
        if isinstance(auth_dump.get("dkim_signatures"), list):
            for entry in auth_dump["dkim_signatures"]:
                if isinstance(entry, dict):
                    entry["identity"] = _redact_email_identity(entry.get("identity"))
        payload["auth_protocols_summary"] = auth_dump
    return payload


def _compute_decision_audit_fingerprint(
    incident: Any,
    decision: DMARCEnforcementDecision,
    resolved_actor_id: str,
    actor_type: str,
    action_name: str,
    actor_role: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> str:
    payload = {
        "scan_uuid": getattr(incident, "scan_uuid", None),
        "tenant_id": (getattr(incident, "tenant_id", None) or "").strip() or None,
        "action": action_name,
        "actor_id": resolved_actor_id,
        "actor_type": actor_type,
        "actor_role": actor_role,
        "ip_address": (ip_address or "").strip() or None,
        "spf_status": decision.spf_status.value,
        "dkim_status": decision.dkim_status.value,
        "dmarc_status": decision.dmarc_status.value,
        "dmarc_rfc_status": decision.dmarc_rfc_status,
        "record_p_policy": decision.record_p_policy.value,
        "selected_applicable_policy": decision.selected_applicable_policy.value,
        "applicable_policy_tag": decision.applicable_policy_tag,
        "policy_domain": decision.policy_domain,
        "effective_policy": decision.effective_policy.value,
        "post_interop_policy": decision.post_interop_policy.value,
        "interoperability_downgrade_applied": bool(decision.interoperability_downgrade_applied),
        "test_mode_applied": bool(decision.test_mode_applied),
        "local_override_applied": bool(decision.local_override_applied),
        "forwarder_exempted": bool(decision.forwarder_exempted),
        "mailing_list_exempted": bool(decision.mailing_list_exempted),
        "threat_block_applied": bool(decision.threat_block_applied),
        "policy_conflict_detected": bool(decision.policy_conflict_detected),
        "disposition": decision.disposition.value,
        "decision_reason": decision.decision_reason,
        "override_reasons": [ov.value for ov in decision.override_reasons],
        "matched_rule_ids": list(decision.matched_rule_ids),
        "rejected_unauthenticated_rules": list(decision.rejected_unauthenticated_rules),
        "conflict_details": list(decision.conflict_details),
        "channel": decision.channel.value,
        "channel_mode": decision.channel_mode,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


async def record_dmarc_decision_on_incident(
    incident: Any,
    dmarc_result: DMARCResult,
    decision: DMARCEnforcementDecision,
    spf_result: Optional[SPFResult] = None,
    dkim_results: Optional[List[DKIMSignatureResult]] = None,
    db: Optional[AsyncSession] = None,
    actor: Optional[IngestionActor] = None,
    ip_address: Optional[str] = None,
) -> Dict[str, Any]:
    """Attaches DMARC decision telemetry to an existing ScanIncident with transaction safety.

    Persistence and Delivery Guarantees:
    - Validates tenant consistency before mutating incident state.
    - Commits ScanIncident.telemetry + deduplicated AuditRecord atomically within the SQLAlchemy
      session transaction; on DB failure, rolls back cleanly, emits PERSISTENCE_FAILED, and re-raises.
    - Secondary structured AuditLogger.log_event() executes post-commit on a best-effort log stream
      (NOT atomic with the DB transaction). A post-commit logger failure never rolls back or misreports
      the already-committed DB transaction; instead audit_delivery_status reports
      'SECONDARY_LOG_FAILED_DB_COMMITTED' along with sanitized error metadata.
    """
    incident_tenant = (getattr(incident, "tenant_id", None) or "").strip()
    decision_tenant = (decision.audit_metadata.get("tenant_id") or "").strip() if decision.audit_metadata else ""

    if decision_tenant and incident_tenant and decision_tenant != incident_tenant:
        raise PermissionError(
            f"Decision tenant '{decision_tenant}' does not match incident tenant '{incident_tenant}'."
        )

    actor_ident = (actor.identity or "").strip() if actor is not None else ""
    actor_is_authenticated = (
        actor is not None
        and bool(actor_ident)
        and actor_ident != "dev:unauthenticated"
    )
    if actor_is_authenticated:
        actor_tenant = (getattr(actor, "tenant_id", None) or "").strip()
        if not actor_tenant or not incident_tenant or actor_tenant != incident_tenant:
            try:
                AuditLogger.log_event(
                    actor_id=actor_ident[:100],
                    action="DMARC_DECISION_RECORD_DENIED",
                    resource_type="scan_incident",
                    resource_id=str(getattr(incident, "id", None) or getattr(incident, "scan_uuid", "")),
                    status="DENIED_TENANT_MISMATCH",
                    ip_address=ip_address,
                    details={
                        "scan_uuid": getattr(incident, "scan_uuid", None),
                        "actor_tenant": actor_tenant or None,
                        "incident_tenant": incident_tenant or None,
                    },
                )
            except Exception as log_exc:
                logger.warning("Failed to log tenant denial event (%s)", type(log_exc).__name__)
            raise PermissionError(
                f"Actor tenant '{actor_tenant}' does not match incident tenant '{incident_tenant}'."
            )

    if not actor_is_authenticated:
        resolved_actor_id = "system:unauthenticated_context"
        actor_type = "unauthenticated"
        actor_role = actor.role if actor is not None else None
        audit_status = "UNAUTHENTICATED_CONTEXT"
    elif actor is not None and actor.is_api_key:
        resolved_actor_id = actor_ident[:100]
        actor_type = "api_key_system_agent"
        actor_role = actor.role
        audit_status = "SUCCESS"
    else:
        resolved_actor_id = actor_ident[:100]
        actor_type = "human_user"
        actor_role = actor.role if actor is not None else None
        audit_status = "SUCCESS"

    if decision.local_override_applied:
        action_name = "DMARC_POLICY_OVERRIDE_APPLIED"
    elif decision.test_mode_applied:
        action_name = "DMARC_TEST_MODE_APPLIED"
    else:
        action_name = "DMARC_POLICY_ENFORCED"

    fingerprint = _compute_decision_audit_fingerprint(
        incident=incident,
        decision=decision,
        resolved_actor_id=resolved_actor_id,
        actor_type=actor_type,
        action_name=action_name,
        actor_role=actor_role,
        ip_address=ip_address,
    )
    telemetry_block = build_dmarc_enforcement_telemetry(
        dmarc_result=dmarc_result,
        decision=decision,
        spf_result=spf_result,
        dkim_results=dkim_results,
        audit_fingerprint=fingerprint,
    )

    indirect_ev = (
        decision.audit_metadata.get("indirect_flow_evidence")
        if isinstance(decision.audit_metadata, dict)
        else None
    )
    audit_details = {
        "scan_uuid": getattr(incident, "scan_uuid", None),
        "tenant_id": incident_tenant,
        "spf_status": decision.spf_status.value,
        "dkim_status": decision.dkim_status.value,
        "dmarc_status": decision.dmarc_status.value,
        "dmarc_rfc_status": decision.dmarc_rfc_status,
        "record_p_policy": decision.record_p_policy.value,
        "selected_applicable_policy": decision.selected_applicable_policy.value,
        "applicable_policy_tag": decision.applicable_policy_tag,
        "effective_policy": decision.effective_policy.value,
        "test_mode": decision.test_mode,
        "test_mode_applied": decision.test_mode_applied,
        "local_override_applied": decision.local_override_applied,
        "forwarder_exempted": decision.forwarder_exempted,
        "mailing_list_exempted": decision.mailing_list_exempted,
        "indirect_flow_evidence": indirect_ev or {},
        "domain_owner_policy_preserved": True,
        "disposition": decision.disposition.value,
        "decision_reason": decision.decision_reason,
        "override_reasons": [ov.value for ov in decision.override_reasons],
        "matched_rule_ids": list(decision.matched_rule_ids),
        "rejected_unauthenticated_rules": list(decision.rejected_unauthenticated_rules),
        "policy_conflict_detected": decision.policy_conflict_detected,
        "channel_mode": decision.channel_mode,
        "actor_type": actor_type,
        "actor_role": actor_role,
        "decision_fingerprint": fingerprint,
    }

    prior_telemetry = copy.deepcopy(getattr(incident, "telemetry", None))
    initial_scan_uuid = getattr(incident, "scan_uuid", None)
    initial_resource_id = str(getattr(incident, "id", None) or initial_scan_uuid or "")
    existing_telemetry = dict(prior_telemetry or {})
    existing_telemetry["auth_protocols"] = telemetry_block

    if db is not None:
        from sqlalchemy.orm.attributes import set_committed_value
        from app.models.audit import AuditRecord

        resource_id = initial_resource_id
        try:
            incident.telemetry = existing_telemetry
            db.add(incident)
            await db.flush()
            resource_id = str(getattr(incident, "id", None) or initial_scan_uuid or "")

            existing_audits = (
                await db.execute(
                    select(AuditRecord).where(
                        AuditRecord.resource_type == "scan_incident",
                        AuditRecord.resource_id == resource_id,
                        AuditRecord.action == action_name,
                    )
                )
            ).scalars().all()
            is_duplicate = any(
                row.actor_id == resolved_actor_id
                and isinstance(row.details, dict)
                and row.details.get("decision_fingerprint") == fingerprint
                for row in existing_audits
            )

            if not is_duplicate:
                persisted_details = dict(audit_details)
                persisted_details["durable_db_persisted"] = True
                audit_record = AuditRecord(
                    actor_id=resolved_actor_id,
                    action=action_name,
                    resource_type="scan_incident",
                    resource_id=resource_id,
                    status=audit_status,
                    ip_address=ip_address,
                    details=persisted_details,
                )
                db.add(audit_record)

            await db.commit()
            await db.refresh(incident)
        except Exception as exc:
            await db.rollback()
            # Refresh inside coroutine if still persistent; otherwise clear expired ORM state
            # without triggering synchronous lazy-load I/O (MissingGreenlet).
            try:
                await db.refresh(incident)
            except Exception:
                try:
                    set_committed_value(
                        incident,
                        "telemetry",
                        prior_telemetry if prior_telemetry is not None else {},
                    )
                except Exception:
                    pass
            try:
                AuditLogger.log_event(
                    actor_id=resolved_actor_id,
                    action=action_name,
                    resource_type="scan_incident",
                    resource_id=resource_id,
                    status="PERSISTENCE_FAILED",
                    ip_address=ip_address,
                    details={
                        "scan_uuid": initial_scan_uuid,
                        "error_type": type(exc).__name__,
                        "durable_db_persisted": False,
                    },
                )
            except Exception as log_exc:
                logger.warning("Failed to log PERSISTENCE_FAILED event (%s)", type(log_exc).__name__)
            raise

        # Primary DB transaction succeeded atomically; secondary structured logging is post-commit best-effort.
        post_commit_details = dict(audit_details)
        post_commit_details["durable_db_persisted"] = True
        post_commit_details["audit_deduplicated"] = is_duplicate
        audit_delivery_status = "DELIVERED"
        audit_delivery_error: Optional[str] = None
        try:
            AuditLogger.log_event(
                actor_id=resolved_actor_id,
                action=action_name,
                resource_type="scan_incident",
                resource_id=resource_id,
                status=audit_status if not is_duplicate else "DEDUPLICATED_NOOP",
                ip_address=ip_address,
                details=post_commit_details,
            )
        except Exception as log_exc:
            audit_delivery_status = "SECONDARY_LOG_FAILED_DB_COMMITTED"
            audit_delivery_error = f"Secondary audit log delivery failed ({type(log_exc).__name__})"
            logger.warning(
                "Post-commit secondary AuditLogger failure after DB commit succeeded (resource_id=%s, err=%s)",
                resource_id,
                type(log_exc).__name__,
            )

        telemetry_block["durable_db_persisted"] = True
        telemetry_block["audit_deduplicated"] = is_duplicate
        telemetry_block["audit_delivery_status"] = audit_delivery_status
        telemetry_block["audit_delivery_error"] = audit_delivery_error
    else:
        incident.telemetry = existing_telemetry
        mem_details = dict(audit_details)
        mem_details["durable_db_persisted"] = False
        audit_delivery_status = "SECONDARY_LOG_ONLY_IN_MEMORY"
        audit_delivery_error = None
        try:
            AuditLogger.log_event(
                actor_id=resolved_actor_id,
                action=action_name,
                resource_type="scan_incident",
                resource_id=initial_resource_id,
                status="IN_MEMORY_ONLY_NOT_PERSISTED",
                ip_address=ip_address,
                details=mem_details,
            )
        except Exception as log_exc:
            audit_delivery_status = "SECONDARY_LOG_FAILED_IN_MEMORY"
            audit_delivery_error = f"Secondary audit log delivery failed ({type(log_exc).__name__})"
            logger.warning("In-memory secondary AuditLogger failure (%s)", type(log_exc).__name__)

        telemetry_block["durable_db_persisted"] = False
        telemetry_block["audit_deduplicated"] = False
        telemetry_block["audit_delivery_status"] = audit_delivery_status
        telemetry_block["audit_delivery_error"] = audit_delivery_error

    return telemetry_block
