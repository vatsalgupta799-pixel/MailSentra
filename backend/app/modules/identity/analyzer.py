"""Sender Identity and Impersonation Analysis Engine (Module 3).

Analyzes ParsedEmail payloads to detect header anomalies, address alignment discrepancies,
display-name spoofing, and lookalike domain attacks.
Implements rule-level failure isolation and deterministic findings synthesis.
"""

from typing import List, Optional
from app.core.logging import logger
from app.modules.base import BaseDetectionModule
from app.modules.contracts import IdentityAnalysisResult, ImpersonationFinding, ParsedEmail
from app.modules.identity.config import IdentityAnalysisConfig
from app.modules.identity.rules.address_alignment import check_address_alignment
from app.modules.identity.rules.display_name import check_display_name
from app.modules.identity.rules.header_integrity import check_header_integrity
from app.modules.identity.rules.lookalike_domain import check_lookalike_domains


class SenderIdentityAnalyzer(BaseDetectionModule):
    """Core analytical module for Sender Identity Verification and Impersonation Detection."""

    def __init__(self, default_config: Optional[IdentityAnalysisConfig] = None):
        self.default_config = default_config or IdentityAnalysisConfig()

    @property
    def module_name(self) -> str:
        return "identity_analyzer"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def analyze(
        self,
        parsed_email: ParsedEmail,
        config: Optional[IdentityAnalysisConfig] = None,
    ) -> IdentityAnalysisResult:
        """Asynchronous analysis interface implementing BaseDetectionModule."""
        return self.analyze_sync(parsed_email, config=config)

    def analyze_sync(
        self,
        parsed_email: ParsedEmail,
        config: Optional[IdentityAnalysisConfig] = None,
    ) -> IdentityAnalysisResult:
        """Executes the deterministic sender identity verification rules offline with failure isolation."""
        cfg = config or self.default_config
        failed_rules: List[str] = []
        raw_findings: List[ImpersonationFinding] = []

        # 1. Header Integrity Checks
        try:
            header_findings = check_header_integrity(parsed_email, cfg)
            raw_findings.extend(header_findings)
        except Exception as e_hdr:
            logger.error(f"Rule 'header_integrity' failed: {str(e_hdr)}", exc_info=True)
            failed_rules.append("header_integrity")

        # 2. Address Alignment Checks (From vs Reply-To, From vs Return-Path)
        envelope_match: Optional[bool] = None
        try:
            envelope_match, alignment_findings = check_address_alignment(parsed_email, cfg)
            raw_findings.extend(alignment_findings)
        except Exception as e_align:
            logger.error(f"Rule 'address_alignment' failed: {str(e_align)}", exc_info=True)
            failed_rules.append("address_alignment")

        # 3. Display-Name Impersonation Checks
        name_spoofed = False
        try:
            name_spoofed, display_findings = check_display_name(parsed_email, cfg)
            raw_findings.extend(display_findings)
        except Exception as e_disp:
            logger.error(f"Rule 'display_name' failed: {str(e_disp)}", exc_info=True)
            failed_rules.append("display_name")

        # 4. Lookalike & Typosquatting Domain Checks
        punycode_detected = False
        homoglyph_detected = False
        typosquat_detected = False
        try:
            (
                punycode_detected,
                homoglyph_detected,
                typosquat_detected,
                lookalike_findings,
            ) = check_lookalike_domains(parsed_email, cfg)
            raw_findings.extend(lookalike_findings)
        except Exception as e_look:
            logger.error(f"Rule 'lookalike_domain' failed: {str(e_look)}", exc_info=True)
            failed_rules.append("lookalike_domain")

        # Determine composite execution status
        total_rules = 4
        if len(failed_rules) == 0:
            analysis_status = "COMPLETED"
        elif len(failed_rules) == total_rules:
            analysis_status = "FAILED"
        else:
            analysis_status = "PARTIAL"

        # Format and normalize findings
        sanitized_findings = []
        for finding in raw_findings:
            desc = finding.description[: cfg.max_description_length]
            target = finding.target_name[: cfg.max_input_length] if finding.target_name else None
            sanitized_findings.append(
                ImpersonationFinding(
                    indicator=finding.indicator,
                    target_name=target,
                    similarity_score=round(finding.similarity_score, 3),
                    description=desc,
                    is_vip=finding.is_vip,
                )
            )

        # Deterministic sorting (indicator, target, description)
        sanitized_findings.sort(
            key=lambda f: (f.indicator, f.target_name or "", f.description)
        )

        # Bounded finding count (at most max_findings, default 20)
        bounded_findings = sanitized_findings[: cfg.max_findings]

        return IdentityAnalysisResult(
            envelope_header_match=envelope_match,
            display_name_spoofed=name_spoofed,
            typosquatting_detected=typosquat_detected,
            punycode_homoglyph_detected=(punycode_detected or homoglyph_detected),
            punycode_detected=punycode_detected,
            homoglyph_detected=homoglyph_detected,
            analysis_status=analysis_status,
            failed_rules=failed_rules,
            findings=bounded_findings,
        )
