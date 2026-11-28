"""Main analytical module for URL Security Analysis (Module 5).

Evaluates ExtractedUrl collections or raw URL strings using deterministic
offline static detection rules, hostname analysis, and evidence aggregation.
"""

from typing import List, Optional
from app.core.logging import logger
from app.modules.base import BaseDetectionModule
from app.modules.contracts import (
    ExtractedUrl,
    ParsedEmail,
    UrlAnalysisResult,
    UrlFinding,
    UrlRiskSeverity,
)
from app.modules.url_analysis.config import UrlAnalysisConfig
from app.modules.url_analysis.hostname_analyzer import HostnameAnalyzer
from app.modules.url_analysis.normalizer import UrlNormalizer
from app.modules.url_analysis.risk_scorer import RiskScorer
from app.modules.url_analysis.url_detectors import SuspicionEngine


class UrlAnalyzer(BaseDetectionModule):
    """Static URL Security Analyzer implementing BaseDetectionModule."""

    def __init__(self, config: Optional[UrlAnalysisConfig] = None):
        self.config = config or UrlAnalysisConfig()
        self._normalizer = UrlNormalizer()
        self._host_analyzer = HostnameAnalyzer()
        self._suspicion_engine = SuspicionEngine()
        self._risk_scorer = RiskScorer()

    @property
    def module_name(self) -> str:
        return "url_analyzer"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def analyze(
        self,
        parsed_email: ParsedEmail,
        config: Optional[UrlAnalysisConfig] = None,
    ) -> UrlAnalysisResult:
        """Asynchronous analysis entrypoint implementing BaseDetectionModule."""
        return self.analyze_sync(parsed_email, config=config)

    def analyze_sync(
        self,
        parsed_email: ParsedEmail,
        config: Optional[UrlAnalysisConfig] = None,
    ) -> UrlAnalysisResult:
        """Executes offline deterministic URL analysis on all URLs in a ParsedEmail."""
        cfg = config or self.config
        raw_urls = parsed_email.urls or []

        bounded_urls = raw_urls[: cfg.max_urls_to_analyze]
        total_scanned = len(raw_urls)

        findings: List[UrlFinding] = []
        highest_severity = UrlRiskSeverity.SAFE

        for item in bounded_urls:
            url_str = item.original_url if isinstance(item, ExtractedUrl) else str(item)
            try:
                finding = self.analyze_url(url_str, config=cfg)
                if finding:
                    if finding.severity != UrlRiskSeverity.SAFE:
                        findings.append(finding)
                        if finding.severity == UrlRiskSeverity.MALICIOUS:
                            highest_severity = UrlRiskSeverity.MALICIOUS
                        elif finding.severity == UrlRiskSeverity.SUSPICIOUS and highest_severity != UrlRiskSeverity.MALICIOUS:
                            highest_severity = UrlRiskSeverity.SUSPICIOUS
            except Exception as e:
                logger.error(f"Error evaluating URL '{url_str[:100]}': {e}", exc_info=True)

        return UrlAnalysisResult(
            total_urls_scanned=total_scanned,
            highest_severity=highest_severity,
            findings=findings,
        )

    def analyze_url(self, url: str, config: Optional[UrlAnalysisConfig] = None) -> Optional[UrlFinding]:
        """Analyzes a single URL string and returns a typed UrlFinding."""
        cfg = config or self.config

        # 1. Parsing & Normalization
        parsed = self._normalizer.parse(url, max_url_length=cfg.max_url_length)
        defanged = self._normalizer.defang(url)

        # 2. Hostname / IP Analysis
        host_analysis = self._host_analyzer.analyze(parsed.host_stripped, config=cfg)

        # 3. Static Suspicion Rules
        signals = self._suspicion_engine.evaluate(parsed, host_analysis, config=cfg)

        # 4. Risk Scoring & Evidence Synthesis
        severity, reason = self._risk_scorer.score(signals)

        # Determine boolean contract attributes
        is_suspicious_tld = any(
            (host_analysis.registered_domain or parsed.host_stripped).endswith(tld)
            for tld in cfg.suspicious_tld_list
        )
        is_open_redirect = any(s.signal.value == "OPEN_REDIRECT_PARAM" for s in signals)

        return UrlFinding(
            url=url,
            defanged_url=defanged,
            resolved_ip=host_analysis.resolved_ip,
            is_ip_host=host_analysis.is_ip_host,
            is_suspicious_tld=is_suspicious_tld,
            is_open_redirect=is_open_redirect,
            redirect_chain=[],
            severity=severity,
            reason=reason,
        )

    async def shutdown(self) -> None:
        """Resource disposal hook."""
        pass
