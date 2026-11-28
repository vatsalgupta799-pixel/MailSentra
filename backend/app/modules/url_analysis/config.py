"""Configuration model for Module 5: URL Security Analysis."""

from typing import List
from pydantic import BaseModel, Field


class UrlAnalysisConfig(BaseModel):
    """Configuration settings for deterministic static URL analysis."""

    max_urls_to_analyze: int = 200
    enable_network_probe: bool = False
    max_redirect_hops: int = 5
    probe_timeout_seconds: float = 5.0
    max_response_bytes: int = 65536
    max_url_length: int = 2000

    suspicious_tld_list: List[str] = Field(
        default_factory=lambda: [
            ".xyz", ".top", ".tk", ".zip", ".mov", ".pw", ".gq", ".cf", ".ga", ".ml",
            ".cn", ".ru", ".su", ".club", ".work", ".loan", ".win", ".review", ".trade",
            ".stream", ".download", ".racing", ".accountant", ".bid", ".date", ".faith", ".party"
        ]
    )

    shortener_domains: List[str] = Field(
        default_factory=lambda: [
            "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
            "adf.ly", "bit.do", "cutt.ly", "rebrand.ly", "short.io", "tiny.cc",
            "smarturl.it", "clickmeter.com", "yourls.org", "clck.ru", "bc.vc"
        ]
    )

    open_redirect_params: List[str] = Field(
        default_factory=lambda: [
            "redirect", "redirect_to", "redirect_url", "url", "next", "goto",
            "return", "return_url", "forward", "dest", "destination", "location",
            "redir", "ref", "out", "target", "link", "continue", "callback",
            "returnurl", "returnto"
        ]
    )

    suspicious_file_extensions: List[str] = Field(
        default_factory=lambda: [
            ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr", ".hta",
            ".pif", ".reg", ".com", ".msi", ".dll", ".sh", ".py", ".rb", ".pl"
        ]
    )

    protected_domains: List[str] = Field(default_factory=list)
    typosquatting_max_distance: int = 2
    typosquatting_min_similarity: float = 0.75
    typosquatting_min_domain_length: int = 5
    max_subdomain_labels: int = 4
