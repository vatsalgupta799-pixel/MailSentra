"""Strongly typed data contracts for all MailSentra detection and operational modules.

These immutable Pydantic models represent the pure domain contracts across:
1. Ingestion
2. Parser & Normalizer
3. Sender Identity & Impersonation
4. SPF, DKIM, DMARC Protocols
5. URL Security
6. Attachment Security
7. Social Engineering & BEC
8. Threat Intelligence
9. Risk Scoring & Decision Engine
10. Alerting & Notification
11. Admin & Telemetry
12. Authentication & Authorization
13. Audit Logging
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator


# ==========================================
# 1. Ingestion Module Contract
# ==========================================
class IngestionSource(str, Enum):
    DIRECT_UPLOAD = "DIRECT_UPLOAD"
    RAW_PAYLOAD = "RAW_PAYLOAD"
    SMTP_RELAY = "SMTP_RELAY"
    GRAPH_API = "GRAPH_API"
    IMAP_COLLECTOR = "IMAP_COLLECTOR"


class RawEmailPayload(BaseModel):
    raw_bytes: bytes
    source: IngestionSource = IngestionSource.DIRECT_UPLOAD
    filename: Optional[str] = None
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: Optional[str] = None
    tenant_id: str = "default"
    content_type: Optional[str] = "message/rfc822"
    size_bytes: int = 0

    model_config = ConfigDict(arbitrary_types_allowed=True)


# ==========================================
# 2. Parsing & Normalization Module Contract
# ==========================================
class EmailAddress(BaseModel):
    raw: str
    display_name: Optional[str] = None
    address: str
    domain: str


class EmailHeader(BaseModel):
    name: str
    value: str
    raw_value: Optional[str] = None


class ReceivedHop(BaseModel):
    hop_number: int
    raw: str
    by: Optional[str] = None
    from_host: Optional[str] = None
    ip: Optional[str] = None
    protocol: Optional[str] = None
    date: Optional[str] = None


class ExtractedUrl(BaseModel):
    original_url: str
    normalized_url: str
    defanged_url: str
    visible_text: Optional[str] = None
    source_location: str = "body"  # "plain_text", "html_href", "html_area", "html_iframe", "html_form", "html_text"
    source_tag: Optional[str] = None
    source_attribute: Optional[str] = None
    is_duplicate: bool = False
    occurrence_count: int = 1


class AttachmentMetadata(BaseModel):
    filename: str
    original_filename: str
    content_type: str
    file_extension: str
    is_double_extension: bool = False
    size_bytes: int
    sha256_hash: str
    content_disposition: str = "attachment"
    content_id: Optional[str] = None
    is_inline: bool = False
    raw_payload: Optional[bytes] = Field(default=None, repr=False, exclude=True)
    is_truncated: bool = False
    declared_size_bytes: Optional[int] = None
    actual_payload_size: Optional[int] = None


class ParsedEmail(BaseModel):
    # Core Metadata
    message_id: Optional[str] = None
    subject: Optional[str] = None
    date_raw: Optional[str] = None
    date_utc: Optional[datetime] = None
    processing_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Sender & Identity Headers
    from_sender: Optional[EmailAddress] = None
    reply_to: Optional[EmailAddress] = None
    return_path: Optional[str] = None  # Envelope-From
    all_from_senders: List[EmailAddress] = Field(default_factory=list)
    all_reply_to: List[EmailAddress] = Field(default_factory=list)

    # Recipients
    to_recipients: List[EmailAddress] = Field(default_factory=list)
    cc_recipients: List[EmailAddress] = Field(default_factory=list)
    bcc_recipients: List[EmailAddress] = Field(default_factory=list)

    # Headers
    headers: List[EmailHeader] = Field(default_factory=list)
    headers_map: Dict[str, List[str]] = Field(default_factory=dict)
    received_hops: List[ReceivedHop] = Field(default_factory=list)

    # Cryptographic / Security Authentication Headers
    authentication_results: List[str] = Field(default_factory=list)
    received_spf: List[str] = Field(default_factory=list)
    dkim_signatures: List[str] = Field(default_factory=list)

    # Body Content
    body_plain: Optional[str] = None
    body_html: Optional[str] = None
    body_extracted_text: Optional[str] = None  # Text cleanly extracted from HTML

    # Extracted Artifacts
    urls: List[ExtractedUrl] = Field(default_factory=list)
    attachments: List[AttachmentMetadata] = Field(default_factory=list)

    # Diagnostics & Warnings
    parsing_warnings: List[str] = Field(default_factory=list)


# ==========================================
# 3. Sender Identity Verification Contract
# ==========================================
class ImpersonationFinding(BaseModel):
    indicator: str
    target_name: Optional[str] = None
    similarity_score: float = 0.0
    description: str
    is_vip: bool = False


class IdentityAnalysisResult(BaseModel):
    envelope_header_match: Optional[bool] = None  # None: unavailable/empty Return-Path; True: aligned; False: unaligned
    display_name_spoofed: bool = False
    typosquatting_detected: bool = False
    punycode_homoglyph_detected: bool = False  # Legacy composite field preserved for backward compatibility
    punycode_detected: bool = False  # RFC 3492/5891 Punycode domain detected
    homoglyph_detected: bool = False  # Mixed-script or visual lookalike detected
    analysis_status: str = "COMPLETED"  # "COMPLETED", "PARTIAL", "FAILED"
    failed_rules: List[str] = Field(default_factory=list)
    findings: List[ImpersonationFinding] = Field(default_factory=list)


# ==========================================
# 4. SPF, DKIM, DMARC Protocols Contract
# ==========================================
class ProtocolStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SOFTFAIL = "SOFTFAIL"
    NEUTRAL = "NEUTRAL"
    NONE = "NONE"
    PERMERROR = "PERMERROR"
    TEMPERROR = "TEMPERROR"
    NOT_EVALUATED = "NOT_EVALUATED"
    INDETERMINATE = "INDETERMINATE"


class DMARCPolicy(str, Enum):
    NONE = "none"
    QUARANTINE = "quarantine"
    REJECT = "reject"
    NOT_CONFIGURED = "not_configured"


class AnalysisCompletionStatus(str, Enum):
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class AlignmentMode(str, Enum):
    RELAXED = "r"
    STRICT = "s"


class AuthResultsTrustProvenance(str, Enum):
    LOCALLY_VERIFIED = "LOCALLY_VERIFIED"
    TRUSTED_UPSTREAM = "TRUSTED_UPSTREAM"
    UNTRUSTED_SENDER = "UNTRUSTED_SENDER"


class DKIMEvaluationState(str, Enum):
    """Explicit typed DKIM evaluation completeness states separating missing raw bytes, empty signatures, failures, and internal errors."""

    NOT_EVALUATED_MISSING_RAW_BYTES = "NOT_EVALUATED_MISSING_RAW_BYTES"
    EVALUATED_NO_SIGNATURES = "EVALUATED_NO_SIGNATURES"
    EVALUATED_COMPLETED = "EVALUATED_COMPLETED"
    INCOMPLETE_INTERNAL_ERROR = "INCOMPLETE_INTERNAL_ERROR"
    INCOMPLETE_TRANSIENT_ERROR = "INCOMPLETE_TRANSIENT_ERROR"


class TrustedSMTPMetadata(BaseModel):
    connecting_ip: Optional[str] = None
    helo_domain: Optional[str] = None
    mail_from_envelope: Optional[str] = None
    is_trusted_mta: bool = False
    authenticated_connector_id: Optional[str] = None
    mta_sanitization_guaranteed: bool = False


class DKIMSignatureResult(BaseModel):
    index: int = 0
    selector: Optional[str] = None
    domain: Optional[str] = None
    identity: Optional[str] = None
    algorithm: Optional[str] = None
    signature_b_prefix: Optional[str] = None
    status: ProtocolStatus = ProtocolStatus.NONE
    evaluation_state: Optional[DKIMEvaluationState] = None
    reason_code: Optional[str] = None
    error_reason: Optional[str] = None
    canonicalization: Optional[str] = None
    key_size_bits: Optional[int] = None
    is_aligned_with_from: bool = False
    aligned_relaxed: bool = False
    aligned_strict: bool = False
    alignment_source: str = "uncomputed"
    alignment_is_authoritative: bool = False
    standalone_psl_aligned_relaxed: Optional[bool] = None


class SPFResult(BaseModel):
    status: ProtocolStatus = ProtocolStatus.NOT_EVALUATED
    domain: Optional[str] = None
    scope: str = "mfrom"
    identity: Optional[str] = None
    is_null_reverse_path: bool = False
    is_synthesized_mfrom: bool = False
    is_standalone_helo: bool = False
    evaluated_record: Optional[str] = None
    mechanisms_evaluated: int = 0
    dns_terms_queried: int = 0
    void_lookups: int = 0
    client_ip: Optional[str] = None
    error_reason: Optional[str] = None


class DMARCResult(BaseModel):
    status: ProtocolStatus = ProtocolStatus.NOT_EVALUATED
    standard_status: Optional[str] = None
    internal_status: Optional[ProtocolStatus] = None
    policy: DMARCPolicy = DMARCPolicy.NOT_CONFIGURED  # Selected policy per RFC 9989 §4.10.1 (np/sp/p)
    record_p_policy: Optional[DMARCPolicy] = None  # Literal 'p=' tag from the discovered DNS record
    subdomain_policy: Optional[DMARCPolicy] = None  # Literal 'sp=' tag from the discovered DNS record
    non_existent_subdomain_policy: Optional[DMARCPolicy] = None  # Literal 'np=' tag from the discovered DNS record
    applicable_policy_tag: Optional[str] = None
    policy_discovery_source: Optional[str] = None
    policy_domain: Optional[str] = None
    is_psd_policy: bool = False
    is_subdomain: bool = False
    is_subdomain_non_existent: Optional[bool] = None
    subdomain_existence_probe_enabled: bool = False
    subdomain_existence_status: Optional[str] = None
    np_evaluation_skipped_reason: Optional[str] = None
    test_mode: bool = False
    org_domain: Optional[str] = None
    from_domain: Optional[str] = None
    evaluated_record: Optional[str] = None
    raw_tags: Dict[str, str] = Field(default_factory=dict)
    tree_walk_queries: int = 0
    psd_type: Optional[str] = None
    spf_aligned: bool = False
    dkim_aligned: bool = False
    spf_alignment_mode: AlignmentMode = AlignmentMode.RELAXED
    dkim_alignment_mode: AlignmentMode = AlignmentMode.RELAXED
    spf_aligned_relaxed: bool = False
    spf_aligned_strict: bool = False
    dkim_aligned_relaxed: bool = False
    dkim_aligned_strict: bool = False
    error_reason: Optional[str] = None
    diagnostics: Dict[str, Any] = Field(default_factory=dict)

    @computed_field
    @property
    def rfc_status(self) -> Optional[str]:
        """Returns the IANA RFC 9989 Section 9.2 standardized DMARC result code.

        Returns:
            One of 'pass', 'fail', 'none', 'permerror', 'temperror' for actual completed
            evaluations, or None if the evaluation did not complete to a standardized
            result (e.g. query limit exhaustion / INDETERMINATE or NOT_EVALUATED).
            Internal diagnostic states are never silently converted into fail or none.
        """
        if self.standard_status is not None:
            return self.standard_status
        if self.status == ProtocolStatus.PASS:
            return "pass"
        if self.status == ProtocolStatus.FAIL:
            return "fail"
        if self.status == ProtocolStatus.NONE:
            return "none"
        if self.status == ProtocolStatus.PERMERROR:
            return "permerror"
        if self.status == ProtocolStatus.TEMPERROR:
            return "temperror"
        # Incomplete evaluations (INDETERMINATE, NOT_EVALUATED) have no standardized RFC 9989 result
        return None


class DMARCDisposition(str, Enum):
    """Receiver-local disposition outcomes (separate from RFC protocol authentication results)."""

    ACCEPT = "ACCEPT"
    QUARANTINE = "QUARANTINE"
    REJECT = "REJECT"
    RECOMMEND_REJECT = "RECOMMEND_REJECT"
    DEFER = "DEFER"
    MANUAL_REVIEW_INCOMPLETE = "MANUAL_REVIEW_INCOMPLETE"
    RETRY_RECOMMENDED = "RETRY_RECOMMENDED"


class PolicyOverrideType(str, Enum):
    """Standardized policy-override categories aligned with RFC 9990 Section 3.1.6."""

    LOCAL_POLICY = "local_policy"
    MAILING_LIST = "mailing_list"
    TRUSTED_FORWARDER = "trusted_forwarder"
    POLICY_TEST_MODE = "policy_test_mode"
    OTHER = "other"


class OverrideRuleAction(str, Enum):
    """Configured receiver-local administrative rule actions."""

    EXEMPT_ACCEPT = "EXEMPT_ACCEPT"
    FORCE_QUARANTINE = "FORCE_QUARANTINE"
    FORCE_REJECT = "FORCE_REJECT"


class LocalPolicyOverrideRule(BaseModel):
    """Server-side authenticated administrative override or blocklist rule."""

    rule_id: str
    action: OverrideRuleAction
    match_from_domain: Optional[str] = None
    match_org_domain: Optional[str] = None
    match_sender_address: Optional[str] = None
    match_ip_or_cidr: Optional[str] = None
    require_aligned_dkim: bool = False
    tenant_id: str = "default"
    configured_by_identity: Optional[str] = None
    configured_by_role: Optional[str] = None
    # Note: this Boolean alone is NEVER trusted as proof of authentication when
    # supplied dynamically; server HMAC provenance is verified by DMARCPolicyEnforcer.
    is_authenticated_admin_source: bool = False
    server_provenance_hmac: Optional[str] = None
    reason: Optional[str] = None


class ForwarderTrustEvidence(BaseModel):
    """Server-verified indirect mail flow evidence (RFC 9989 §7.4 & RFC 7960)."""

    is_verified_forwarder: bool = False
    is_verified_mailing_list: bool = False
    connector_id: Optional[str] = None
    relay_ip: Optional[str] = None
    evidence_source: Optional[str] = None
    is_server_verified: bool = False


class CorroboratingThreatSignals(BaseModel):
    """Independent security signals consumed by Stage 4/5 without mutating auth results."""

    confirmed_malicious_attachment: bool = False
    confirmed_malicious_url: bool = False
    high_confidence_impersonation: bool = False
    impersonation_confidence: Optional[float] = None
    impersonation_provenance_verified: bool = False
    threat_intel_confirmed_malicious: bool = False
    verified_corroborating_signals: List[str] = Field(default_factory=list)
    advisory_identity_analysis: Optional[IdentityAnalysisResult] = None
    threat_module_provenance: Optional[str] = None


class SMTPAdapterDecisionContract(BaseModel):
    """Pure pre-DATA-reply SMTP disposition contract for future MTA integration (unexecuted)."""

    action: str  # "ACCEPT_250", "QUARANTINE_HOLD", "DEFER_451", "REJECT_550"
    smtp_reply_code: int
    enhanced_status_code: str
    reply_text: str
    pre_data_reply_required: bool = True
    executed: bool = False


class DMARCEnforcementDecision(BaseModel):
    """Tier 3 receiver-local policy interpretation and disposition output with complete provenance."""

    # Preserved Tier 2 Authentication Results (never rewritten)
    spf_status: ProtocolStatus = ProtocolStatus.NOT_EVALUATED
    dkim_status: ProtocolStatus = ProtocolStatus.NONE
    dmarc_status: ProtocolStatus = ProtocolStatus.NOT_EVALUATED
    dmarc_rfc_status: Optional[str] = None
    from_domain: Optional[str] = None
    org_domain: Optional[str] = None
    policy_domain: Optional[str] = None

    # Tier 1 Policy Record Tags & Stage 3 Transformation
    record_p_policy: DMARCPolicy = DMARCPolicy.NOT_CONFIGURED  # Literal 'p=' tag from DNS record
    selected_applicable_policy: DMARCPolicy = DMARCPolicy.NOT_CONFIGURED  # RFC 9989 §4.10.1 selection (np/sp/p)
    applicable_policy_tag: Optional[str] = None
    policy_discovery_source: Optional[str] = None
    test_mode: bool = False
    test_mode_applied: bool = False
    effective_policy: DMARCPolicy = DMARCPolicy.NOT_CONFIGURED  # Stage 3 policy after t=y transformation

    # Stage 4 RFC 9989 §7.4 & Indirect Flow Interoperability
    interoperability_downgrade_applied: bool = False
    interoperability_adjustment_reason: Optional[str] = None
    post_interop_policy: DMARCPolicy = DMARCPolicy.NOT_CONFIGURED
    forwarder_exempted: bool = False
    mailing_list_exempted: bool = False
    unverified_indirect_flow_claim_ignored: bool = False

    # Stage 5 Local Policy & Conflict Arbitration
    local_override_applied: bool = False
    override_reasons: List[PolicyOverrideType] = Field(default_factory=list)
    matched_rule_ids: List[str] = Field(default_factory=list)
    rejected_unauthenticated_rules: List[str] = Field(default_factory=list)
    policy_conflict_detected: bool = False
    conflict_details: List[str] = Field(default_factory=list)
    threat_block_applied: bool = False
    advisory_signals: Dict[str, Any] = Field(default_factory=dict)
    local_policy_inputs: Dict[str, Any] = Field(default_factory=dict)

    # Stage 6 Channel Mapping & Audit Evidence
    channel: IngestionSource = IngestionSource.DIRECT_UPLOAD
    channel_mode: str = "http_inspection"
    disposition: DMARCDisposition = DMARCDisposition.ACCEPT
    decision_reason: str = "DMARC_NOT_EVALUATED"
    decision_summary: str = ""
    policy_applied: bool = False
    manual_review_recommended: bool = False
    retry_recommended: bool = False
    raw_bytes_modified: bool = False
    smtp_contract: Optional[SMTPAdapterDecisionContract] = None
    diagnostic_evidence: Dict[str, Any] = Field(default_factory=dict)
    audit_metadata: Dict[str, Any] = Field(default_factory=dict)


class ParsedAuthResultItem(BaseModel):
    method: str
    status: ProtocolStatus = ProtocolStatus.NONE
    reason: Optional[str] = None
    header_property: Optional[str] = None
    property_value: Optional[str] = None
    properties: Dict[str, str] = Field(default_factory=dict)


class ParsedAuthResultsHeader(BaseModel):
    authserv_id: str
    version: Optional[int] = None
    provenance: AuthResultsTrustProvenance = AuthResultsTrustProvenance.UNTRUSTED_SENDER
    is_trusted: bool = False
    authserv_id_matched_config: bool = False
    authenticated_connector_id: Optional[str] = None
    mta_sanitization_guaranteed: bool = False
    trust_evidence_reason: str = "Unverified sender-supplied header or missing MTA trust boundary"
    results: List[ParsedAuthResultItem] = Field(default_factory=list)
    raw_header: str

    @model_validator(mode="after")
    def validate_trust_boundary(self) -> "ParsedAuthResultsHeader":
        if self.provenance == AuthResultsTrustProvenance.LOCALLY_VERIFIED:
            self.is_trusted = True
            if not self.trust_evidence_reason or self.trust_evidence_reason.startswith("Unverified"):
                self.trust_evidence_reason = "Locally verified by MailSentra"
        elif self.provenance == AuthResultsTrustProvenance.TRUSTED_UPSTREAM:
            # RFC 8601 Section 5: authserv-id match alone NEVER establishes trust.
            # Must satisfy all three mandatory conditions:
            # 1. Matching configured trusted authserv-id
            # 2. Authenticated upstream connector identity
            # 3. Explicit MTA sanitization / trust-boundary guarantee
            if not (
                self.authserv_id_matched_config
                and self.authenticated_connector_id
                and self.mta_sanitization_guaranteed
            ):
                self.provenance = AuthResultsTrustProvenance.UNTRUSTED_SENDER
                self.is_trusted = False
                self.trust_evidence_reason = (
                    "Insufficient trust evidence: authserv-id match without authenticated connector "
                    "and MTA sanitization guarantee remains untrusted."
                )
            else:
                self.is_trusted = True
                if not self.trust_evidence_reason or self.trust_evidence_reason.startswith("Unverified"):
                    self.trust_evidence_reason = (
                        f"Trusted upstream from connector '{self.authenticated_connector_id}' "
                        "with MTA sanitization guarantee."
                    )
        else:
            self.provenance = AuthResultsTrustProvenance.UNTRUSTED_SENDER
            self.is_trusted = False
            if not self.trust_evidence_reason or self.trust_evidence_reason.startswith("Locally"):
                self.trust_evidence_reason = (
                    "Unverified sender-supplied header or missing MTA trust boundary"
                )
        return self


class AuthFinding(BaseModel):
    code: str
    protocol: str
    severity: str = "INFO"
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)


class AuthProtocolsResult(BaseModel):
    # Core Protocol Statuses (preserved for backward compatibility)
    spf_status: ProtocolStatus = ProtocolStatus.NONE
    spf_domain: Optional[str] = None
    dkim_status: ProtocolStatus = ProtocolStatus.NONE
    dkim_domain: Optional[str] = None
    dmarc_status: ProtocolStatus = ProtocolStatus.NONE
    dmarc_policy: DMARCPolicy = DMARCPolicy.NOT_CONFIGURED
    dmarc_aligned_spf: bool = False
    dmarc_aligned_dkim: bool = False
    raw_auth_results_header: Optional[str] = None
    generated_auth_results_header: Optional[str] = None

    # Extended Alignment Outcomes
    spf_alignment_mode: AlignmentMode = AlignmentMode.RELAXED
    dkim_alignment_mode: AlignmentMode = AlignmentMode.RELAXED
    spf_aligned_relaxed: bool = False
    spf_aligned_strict: bool = False
    dkim_aligned_relaxed: bool = False
    dkim_aligned_strict: bool = False
    dmarc_test_mode: bool = False

    # Detailed Evaluator Structures
    spf_details: Optional[SPFResult] = None
    dkim_evaluation_state: Optional[DKIMEvaluationState] = None
    dkim_signatures: List[DKIMSignatureResult] = Field(default_factory=list)
    dmarc_details: Optional[DMARCResult] = None
    dmarc_enforcement: Optional[DMARCEnforcementDecision] = None
    parsed_auth_results: List[ParsedAuthResultsHeader] = Field(default_factory=list)

    # Completion and Failure Telemetry
    analysis_status: AnalysisCompletionStatus = AnalysisCompletionStatus.COMPLETED
    failed_evaluators: List[str] = Field(default_factory=list)
    findings: List[AuthFinding] = Field(default_factory=list)
    execution_telemetry: Dict[str, Any] = Field(default_factory=dict)

    def get_trusted_auth_results(self) -> List[ParsedAuthResultsHeader]:
        """Returns only headers verified locally or received from authenticated upstream connectors.

        Untrusted sender-supplied headers (UNTRUSTED_SENDER) are strictly filtered out to
        prevent attacker-controlled headers from overriding or influencing security decisions.
        """
        return [h for h in self.parsed_auth_results if h.is_trusted]

    def has_untrusted_spoofed_auth_results(self) -> bool:
        """Returns True if any Authentication-Results header claims a matching authserv-id
        or successful authentication but lacks authenticated connector evidence."""
        return any(
            not h.is_trusted
            and (
                h.authserv_id_matched_config
                or any(item.status == ProtocolStatus.PASS for item in h.results)
            )
            for h in self.parsed_auth_results
        )


# ==========================================
# 5. URL Security Analysis Contract
# ==========================================
class UrlRiskSeverity(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class UrlFinding(BaseModel):
    url: str
    defanged_url: str
    resolved_ip: Optional[str] = None
    is_ip_host: bool = False
    is_suspicious_tld: bool = False
    is_open_redirect: bool = False
    redirect_chain: List[str] = Field(default_factory=list)
    severity: UrlRiskSeverity = UrlRiskSeverity.SAFE
    reason: str = ""


class UrlAnalysisResult(BaseModel):
    total_urls_scanned: int = 0
    highest_severity: UrlRiskSeverity = UrlRiskSeverity.SAFE
    findings: List[UrlFinding] = Field(default_factory=list)


# ==========================================
# 6. Attachment Security Contract
# ==========================================
class AttachmentFinding(BaseModel):
    filename: str
    declared_type: str
    detected_mime: str
    magic_byte_mismatch: bool = False
    is_executable_or_script: bool = False
    has_macros: bool = False
    is_encrypted_archive: bool = False
    sha256_hash: str
    severity: str = "SAFE"
    details: str = ""
    detected_format: Optional[str] = None
    is_double_extension: bool = False
    is_archive: bool = False
    archive_has_traversal: bool = False
    extracted_archive_names: List[str] = Field(default_factory=list)
    analysis_status: str = "COMPLETED"
    error_message: Optional[str] = None
    is_truncated: bool = False


class AttachmentAnalysisResult(BaseModel):
    total_attachments: int = 0
    suspicious_count: int = 0
    malicious_count: int = 0
    highest_severity: str = "SAFE"
    analysis_status: str = "COMPLETED"
    findings: List[AttachmentFinding] = Field(default_factory=list)


# ==========================================
# 7. Social Engineering & BEC Contract
# ==========================================
class SemanticFinding(BaseModel):
    category: str
    matched_phrase: str
    confidence: float
    description: str


class SocialEngineeringResult(BaseModel):
    urgency_detected: bool = False
    financial_request_detected: bool = False
    credential_harvesting_intent: bool = False
    bec_risk_score: float = 0.0
    findings: List[SemanticFinding] = Field(default_factory=list)


# ==========================================
# 8. Threat Intelligence Contract
# ==========================================
class ObservableType(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    FILE_HASH = "FILE_HASH"


class ObservableReputation(BaseModel):
    observable_type: ObservableType
    value: str
    reputation_score: float = 0.0
    vendor_hits: int = 0
    total_vendors: int = 0
    threat_classification: Optional[str] = None
    cached: bool = False


class ThreatIntelResult(BaseModel):
    observables_queried: int = 0
    malicious_hits: int = 0
    reputations: List[ObservableReputation] = Field(default_factory=list)


# ==========================================
# 9. Risk Scoring & Decision Engine Contract
# ==========================================
class DecisionTier(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"


class ScoredFactor(BaseModel):
    category: str
    rule_id: str
    weight: float
    score_delta: float
    justification: str


class RiskDecisionReport(BaseModel):
    composite_score: float
    tier: DecisionTier
    confidence: float
    primary_threat_vector: str
    explanation_summary: str
    contributing_factors: List[ScoredFactor] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ==========================================
# 10. Alert & Notification Contract
# ==========================================
class AlertDispatchResult(BaseModel):
    alert_id: Optional[str] = None
    dispatched_to_siem: bool = False
    dispatched_to_webhook: bool = False
    channels: List[str] = Field(default_factory=list)
    dispatch_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ==========================================
# 13. Audit Logging Contract
# ==========================================
class AuditEvent(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor_id: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    status: str = "SUCCESS"
    ip_address: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
