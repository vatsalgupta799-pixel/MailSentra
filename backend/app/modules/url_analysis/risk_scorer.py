"""Deterministic risk scoring and evidence aggregation for URL security analysis."""

from typing import List, Tuple
from app.modules.contracts import UrlRiskSeverity
from app.modules.url_analysis.url_detectors import DetectedSignal


class RiskScorer:
    """Combines detected signals into an explainable verdict and rationale string."""

    def score(self, signals: List[DetectedSignal]) -> Tuple[UrlRiskSeverity, str]:
        """Calculates severity and synthesizes evidence rationale.

        Verdict rules:
        - Any CRITICAL signal (weight >= 10) -> MALICIOUS
        - 2+ HIGH signals (weight >= 6) -> MALICIOUS
        - 1 HIGH signal + 2+ MEDIUM signals (or total weight >= 10) -> MALICIOUS
        - Any other detected signal(s) -> SUSPICIOUS (weak signals never become MALICIOUS)
        - Zero signals -> SAFE
        """
        if not signals:
            return UrlRiskSeverity.SAFE, "No suspicious static indicators detected"

        critical_signals = [s for s in signals if s.weight >= 10]
        high_signals = [s for s in signals if 6 <= s.weight < 10]
        medium_signals = [s for s in signals if 4 <= s.weight < 6]
        low_signals = [s for s in signals if s.weight < 4]

        total_weight = sum(s.weight for s in signals)

        if critical_signals:
            severity = UrlRiskSeverity.MALICIOUS
        elif len(high_signals) >= 2:
            severity = UrlRiskSeverity.MALICIOUS
        elif len(high_signals) >= 1 and (len(medium_signals) >= 2 or total_weight >= 10):
            severity = UrlRiskSeverity.MALICIOUS
        else:
            severity = UrlRiskSeverity.SUSPICIOUS

        # Build clean deterministic rationale
        evidence_items = [f"[{s.signal.value}] {s.evidence}" for s in signals]
        reason_str = "; ".join(evidence_items)

        return severity, reason_str
