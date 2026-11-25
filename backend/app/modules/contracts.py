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
from pydantic import BaseModel, ConfigDict, Field


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
    source_location: str = "body"  # "plain_text", "html_href", or "html_text"
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


class DMARCPolicy(str, Enum):
    NONE = "none"
    QUARANTINE = "quarantine"
    REJECT = "reject"
    NOT_CONFIGURED = "not_configured"


class AuthProtocolsResult(BaseModel):
    spf_status: ProtocolStatus = ProtocolStatus.NONE
    spf_domain: Optional[str] = None
    dkim_status: ProtocolStatus = ProtocolStatus.NONE
    dkim_domain: Optional[str] = None
    dmarc_status: ProtocolStatus = ProtocolStatus.NONE
    dmarc_policy: DMARCPolicy = DMARCPolicy.NOT_CONFIGURED
    dmarc_aligned_spf: bool = False
    dmarc_aligned_dkim: bool = False
    raw_auth_results_header: Optional[str] = None


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


class AttachmentAnalysisResult(BaseModel):
    total_attachments: int = 0
    suspicious_count: int = 0
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
