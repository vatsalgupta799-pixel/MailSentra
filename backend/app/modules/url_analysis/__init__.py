"""Module 5: URL Security Analysis Module.

Provides deterministic, offline static analysis of extracted email URLs.
Detects IP hosts, obfuscated IPs, suspicious TLDs, open redirects, typosquatting,
homoglyphs, zero-width characters, dangerous extensions, and embedded credentials.
"""

from app.modules.url_analysis.analyzer import UrlAnalyzer
from app.modules.url_analysis.config import UrlAnalysisConfig
from app.modules.url_analysis.hostname_analyzer import HostAnalysisResult, HostnameAnalyzer
from app.modules.url_analysis.normalizer import UrlNormalizer, UrlParseResult
from app.modules.url_analysis.risk_scorer import RiskScorer
from app.modules.url_analysis.url_detectors import DetectedSignal, SuspicionEngine, SuspicionSignal

__all__ = [
    "UrlAnalyzer",
    "UrlAnalysisConfig",
    "UrlNormalizer",
    "UrlParseResult",
    "HostnameAnalyzer",
    "HostAnalysisResult",
    "SuspicionEngine",
    "SuspicionSignal",
    "DetectedSignal",
    "RiskScorer",
]
