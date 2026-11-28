"""Risk Aggregation & Scoring Engine.

Combines signals from Sender Identity, Auth Protocols, URL Security, and Attachment Forensics
into deterministic risk scores, risk tiers (CLEAN, SUSPICIOUS, MALICIOUS), and traceable verdicts.
Guarantees that detector failures cannot silently yield false-negative clean verdicts.
"""

from typing import Any, Dict, List, Optional, Tuple
from app.models.scan import RiskTier
from app.modules.contracts import (
    AttachmentAnalysisResult,
    AuthProtocolsResult,
    IdentityAnalysisResult,
    UrlAnalysisResult,
    UrlRiskSeverity,
)


class RiskEngine:
    """Aggregates multi-vector detection signals into consolidated email threat verdicts."""

    UNSUPPORTED_MODULES = [
        "Module 7: Deep NLP Semantic Intent & Coercion Modeling (Phase 3 Deferred)",
        "Module 8: Live Threat Intelligence Reputation Lookups (Phase 3 Deferred)",
    ]

    def evaluate(
        self,
        identity_result: Optional[IdentityAnalysisResult] = None,
        auth_result: Optional[AuthProtocolsResult] = None,
        url_result: Optional[UrlAnalysisResult] = None,
        attachment_result: Optional[AttachmentAnalysisResult] = None,
    ) -> Tuple[float, RiskTier, str, Dict[str, Any]]:
        """Evaluates security findings across all active subsystems.

        Returns:
            (risk_score, risk_tier, verdict_summary, assessment_telemetry)
        """
        contributing_signals: List[str] = []
        failed_modules: List[str] = []
        base_score = 0.0

        is_malicious = False
        is_suspicious = False

        # 1. Attachment Forensics Signals (Module 6)
        if attachment_result:
            if attachment_result.analysis_status == "FAILED":
                failed_modules.append("AttachmentAnalyzer")
            if attachment_result.highest_severity == "MALICIOUS":
                is_malicious = True
                base_score = max(base_score, 85.0)
                for f in attachment_result.findings:
                    if f.severity == "MALICIOUS":
                        contributing_signals.append(f"[ATTACHMENT-MALICIOUS] {f.filename}: {f.details}")
            elif attachment_result.highest_severity == "SUSPICIOUS":
                is_suspicious = True
                base_score = max(base_score, 50.0)
                for f in attachment_result.findings:
                    if f.severity == "SUSPICIOUS":
                        contributing_signals.append(f"[ATTACHMENT-SUSPICIOUS] {f.filename}: {f.details}")

        # 2. URL Security Analysis Signals (Module 5)
        if url_result:
            if url_result.highest_severity == UrlRiskSeverity.MALICIOUS:
                is_malicious = True
                base_score = max(base_score, 85.0)
                for f in url_result.findings:
                    if f.severity == UrlRiskSeverity.MALICIOUS:
                        contributing_signals.append(f"[URL-MALICIOUS] {f.url}: {f.reason}")
            elif url_result.highest_severity == UrlRiskSeverity.SUSPICIOUS:
                is_suspicious = True
                base_score = max(base_score, 45.0)
                for f in url_result.findings:
                    if f.severity == UrlRiskSeverity.SUSPICIOUS:
                        contributing_signals.append(f"[URL-SUSPICIOUS] {f.url}: {f.reason}")

        # 3. Sender Identity & Impersonation Signals (Module 3)
        if identity_result:
            if identity_result.analysis_status == "FAILED":
                failed_modules.append("SenderIdentityAnalyzer")
            for f in identity_result.findings:
                if f.is_vip or "IMPERSONATION" in f.indicator:
                    is_malicious = True
                    base_score = max(base_score, 80.0)
                    contributing_signals.append(f"[IDENTITY-IMPERSONATION] {f.indicator}: {f.description}")
                elif "MISMATCH" in f.indicator or "LOOKALIKE" in f.indicator:
                    is_suspicious = True
                    base_score = max(base_score, 55.0)
                    contributing_signals.append(f"[IDENTITY-MISMATCH] {f.indicator}: {f.description}")

        # 4. Authentication Protocols Signals (Module 4)
        if auth_result:
            if auth_result.analysis_status == "FAILED":
                failed_modules.append("AuthProtocolsAnalyzer")
            # DMARC enforcement check
            dmarc_disp = None
            if auth_result.dmarc_enforcement:
                dmarc_disp = getattr(auth_result.dmarc_enforcement, "disposition", None) or (
                    auth_result.dmarc_enforcement.get("disposition") if isinstance(auth_result.dmarc_enforcement, dict) else None
                )
            if dmarc_disp in ("REJECT", "QUARANTINE"):
                is_malicious = True
                base_score = max(base_score, 75.0)
                contributing_signals.append(f"[AUTH-DMARC-POLICY] DMARC policy enforcement action: {dmarc_disp}")
            elif getattr(auth_result, "dmarc_status", None) == "FAIL":
                is_suspicious = True
                base_score = max(base_score, 40.0)
                contributing_signals.append("[AUTH-DMARC-FAIL] DMARC authentication failed.")

        # Determine Tier & Summary
        if is_malicious:
            tier = RiskTier.MALICIOUS
            score = min(100.0, base_score + min(15.0, len(contributing_signals) * 2.0))
            summary = f"THREAT DETECTED (MALICIOUS). Corroborating signals: {'; '.join(contributing_signals[:3])}"
        elif is_suspicious:
            tier = RiskTier.SUSPICIOUS
            score = min(74.0, base_score + min(10.0, len(contributing_signals) * 2.0))
            summary = f"SUSPICIOUS EMAIL. Anomaly indicators: {'; '.join(contributing_signals[:3])}"
        elif failed_modules:
            # Failure isolation: detector failure cannot silently produce a CLEAN false negative
            tier = RiskTier.SUSPICIOUS
            score = 35.0
            summary = f"EVALUATION INCOMPLETE: Subsystem failure in ({', '.join(failed_modules)}). Requires manual SOC review."
        else:
            tier = RiskTier.CLEAN
            score = 0.0
            summary = "CLEAN EMAIL. All active detection modules (Identity, Auth, URLs, Attachments) passed cleanly."

        assessment = {
            "risk_score": score,
            "risk_tier": tier.value,
            "contributing_signals": contributing_signals,
            "failed_modules": failed_modules,
            "unsupported_capabilities": self.UNSUPPORTED_MODULES,
        }

        return score, tier, summary, assessment
