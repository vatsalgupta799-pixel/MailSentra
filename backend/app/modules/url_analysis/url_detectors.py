"""Independent static detection rules for URL security analysis."""

import math
import re
import urllib.parse
from dataclasses import dataclass
from enum import Enum
from typing import List

from app.modules.identity.domain_utils import detect_suspicious_unicode
from app.modules.url_analysis.config import UrlAnalysisConfig
from app.modules.url_analysis.hostname_analyzer import HostAnalysisResult
from app.modules.url_analysis.normalizer import UrlParseResult


class SuspicionSignal(str, Enum):
    # Critical (weight=10)
    IP_HOST_PRIVATE = "IP_HOST_PRIVATE"
    IP_HOST_LOOPBACK = "IP_HOST_LOOPBACK"
    IP_HOST_LINK_LOCAL = "IP_HOST_LINK_LOCAL"
    IP_HOST_RESERVED = "IP_HOST_RESERVED"
    IP_HOST_UNSPECIFIED = "IP_HOST_UNSPECIFIED"
    UNSUPPORTED_SCHEME = "UNSUPPORTED_SCHEME"

    # High (weight=6-7)
    IP_HOST_ENCODED = "IP_HOST_ENCODED"
    IP_HOST_PUBLIC = "IP_HOST_PUBLIC"
    HOMOGRAPH_HOSTNAME = "HOMOGRAPH_HOSTNAME"
    ZERO_WIDTH_UNICODE = "ZERO_WIDTH_UNICODE"
    TYPOSQUATTING_HOSTNAME = "TYPOSQUATTING_HOSTNAME"
    SUBDOMAIN_BRAND_IMPERSONATION = "SUBDOMAIN_BRAND_IMPERSONATION"
    EMBEDDED_CREDENTIALS = "EMBEDDED_CREDENTIALS"

    # Medium (weight=4)
    SUSPICIOUS_TLD = "SUSPICIOUS_TLD"
    OPEN_REDIRECT_PARAM = "OPEN_REDIRECT_PARAM"
    USERINFO_PRESENT = "USERINFO_PRESENT"
    SUSPICIOUS_FILE_EXT = "SUSPICIOUS_FILE_EXT"

    # Low (weight=2-3)
    URL_ENCODING_OBFUSCATION = "URL_ENCODING_OBFUSCATION"
    SUSPICIOUS_QUERY_PARAM = "SUSPICIOUS_QUERY_PARAM"
    KNOWN_SHORTENER = "KNOWN_SHORTENER"
    PUNYCODE_DETECTED = "PUNYCODE_DETECTED"
    EXCESSIVE_URL_LENGTH = "EXCESSIVE_URL_LENGTH"
    HIGH_ENTROPY_PATH = "HIGH_ENTROPY_PATH"
    EXCESSIVE_SUBDOMAINS = "EXCESSIVE_SUBDOMAINS"
    NON_STANDARD_PORT = "NON_STANDARD_PORT"
    MALFORMED_URL = "MALFORMED_URL"


SIGNAL_WEIGHTS = {
    SuspicionSignal.IP_HOST_PRIVATE: 10,
    SuspicionSignal.IP_HOST_LOOPBACK: 10,
    SuspicionSignal.IP_HOST_LINK_LOCAL: 10,
    SuspicionSignal.IP_HOST_RESERVED: 10,
    SuspicionSignal.IP_HOST_UNSPECIFIED: 10,
    SuspicionSignal.UNSUPPORTED_SCHEME: 10,
    SuspicionSignal.IP_HOST_ENCODED: 7,
    SuspicionSignal.IP_HOST_PUBLIC: 6,
    SuspicionSignal.HOMOGRAPH_HOSTNAME: 6,
    SuspicionSignal.ZERO_WIDTH_UNICODE: 6,
    SuspicionSignal.TYPOSQUATTING_HOSTNAME: 6,
    SuspicionSignal.SUBDOMAIN_BRAND_IMPERSONATION: 6,
    SuspicionSignal.EMBEDDED_CREDENTIALS: 6,
    SuspicionSignal.SUSPICIOUS_TLD: 4,
    SuspicionSignal.OPEN_REDIRECT_PARAM: 4,
    SuspicionSignal.USERINFO_PRESENT: 4,
    SuspicionSignal.SUSPICIOUS_FILE_EXT: 4,
    SuspicionSignal.URL_ENCODING_OBFUSCATION: 3,
    SuspicionSignal.SUSPICIOUS_QUERY_PARAM: 3,
    SuspicionSignal.KNOWN_SHORTENER: 2,
    SuspicionSignal.PUNYCODE_DETECTED: 2,
    SuspicionSignal.EXCESSIVE_URL_LENGTH: 2,
    SuspicionSignal.HIGH_ENTROPY_PATH: 2,
    SuspicionSignal.EXCESSIVE_SUBDOMAINS: 2,
    SuspicionSignal.NON_STANDARD_PORT: 2,
    SuspicionSignal.MALFORMED_URL: 2,
}


@dataclass
class DetectedSignal:
    """Individual security signal detected on a URL."""
    signal: SuspicionSignal
    weight: int
    evidence: str


def _calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class SuspicionEngine:
    """Evaluates URL components and hostname features against static detection rules."""

    def evaluate(
        self,
        parsed: UrlParseResult,
        host_analysis: HostAnalysisResult,
        config: UrlAnalysisConfig,
    ) -> List[DetectedSignal]:
        signals: List[DetectedSignal] = []

        def add_sig(sig: SuspicionSignal, evidence: str):
            signals.append(DetectedSignal(signal=sig, weight=SIGNAL_WEIGHTS[sig], evidence=evidence))

        # 1. Scheme Analysis (Checked first so unsupported schemes like javascript: or data: are immediately flagged)
        if parsed.scheme and parsed.scheme not in {"http", "https"}:
            add_sig(
                SuspicionSignal.UNSUPPORTED_SCHEME,
                f"Unsupported URL scheme '{parsed.scheme}://' (only HTTP/HTTPS accepted)",
            )

        # 2. Malformed / Parse Error
        if not parsed.is_valid or parsed.parse_error:
            add_sig(SuspicionSignal.MALFORMED_URL, f"URL parse failure: {parsed.parse_error}")

        # 3. IP Literal Host Analysis (Order matters: loopback/link_local/unspecified/reserved must take precedence over generic is_private)
        if host_analysis.is_ip_host:
            if host_analysis.ip_is_loopback:
                add_sig(SuspicionSignal.IP_HOST_LOOPBACK, f"Host uses loopback IP address: {host_analysis.resolved_ip}")
            elif host_analysis.ip_is_link_local:
                add_sig(SuspicionSignal.IP_HOST_LINK_LOCAL, f"Host uses link-local/cloud-metadata IP: {host_analysis.resolved_ip}")
            elif host_analysis.ip_is_unspecified:
                add_sig(SuspicionSignal.IP_HOST_UNSPECIFIED, f"Host uses unspecified (0.0.0.0) IP: {host_analysis.resolved_ip}")
            elif host_analysis.ip_is_reserved or host_analysis.ip_is_multicast:
                add_sig(SuspicionSignal.IP_HOST_RESERVED, f"Host uses reserved/multicast IP address: {host_analysis.resolved_ip}")
            elif host_analysis.ip_is_private:
                add_sig(SuspicionSignal.IP_HOST_PRIVATE, f"Host uses RFC 1918 private IP: {host_analysis.resolved_ip}")
            else:
                add_sig(SuspicionSignal.IP_HOST_PUBLIC, f"Host uses raw public IP address: {host_analysis.resolved_ip}")

            if host_analysis.is_encoded_ip:
                add_sig(SuspicionSignal.IP_HOST_ENCODED, f"Host uses obfuscated hex/octal/integer IP: {parsed.host_stripped}")

        # 4. Embedded Credentials
        if parsed.userinfo:
            add_sig(SuspicionSignal.EMBEDDED_CREDENTIALS, f"Embedded user credentials detected in authority: {parsed.userinfo}")

        # 5. Suspicious TLD
        host_to_check = host_analysis.registered_domain or parsed.host_stripped
        for tld in config.suspicious_tld_list:
            if host_to_check.endswith(tld):
                add_sig(SuspicionSignal.SUSPICIOUS_TLD, f"Hostname ends with high-risk TLD: '{tld}'")
                break

        # 6. Known URL Shortener
        if host_analysis.is_shortener:
            add_sig(SuspicionSignal.KNOWN_SHORTENER, f"Known URL shortener service domain: '{host_to_check}'")

        # 7. Open Redirect Parameters
        if parsed.query:
            try:
                params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                for param_name in params:
                    if param_name.lower() in config.open_redirect_params:
                        add_sig(SuspicionSignal.OPEN_REDIRECT_PARAM, f"Open redirect query parameter detected: '{param_name}'")
                        break
            except Exception:
                pass

        # 8. Suspicious File Extensions in Path
        if parsed.path:
            clean_path = parsed.path.lower().rstrip("/")
            for ext in config.suspicious_file_extensions:
                if clean_path.endswith(ext) or f"{ext}?" in clean_path or f"{ext}/" in clean_path:
                    add_sig(SuspicionSignal.SUSPICIOUS_FILE_EXT, f"Dangerous executable/script download extension: '{ext}'")
                    break

        # 9. Excessive Subdomains
        if host_analysis.subdomain_labels > config.max_subdomain_labels:
            add_sig(
                SuspicionSignal.EXCESSIVE_SUBDOMAINS,
                f"Excessive subdomain depth ({host_analysis.subdomain_labels} labels, limit {config.max_subdomain_labels})",
            )

        # 10. Non-Standard Port
        if parsed.port is not None and parsed.port not in {80, 443, 8080, 8443}:
            add_sig(SuspicionSignal.NON_STANDARD_PORT, f"Non-standard HTTP port used: {parsed.port}")

        # 11. Excessive URL Length
        if len(parsed.original) > config.max_url_length:
            add_sig(
                SuspicionSignal.EXCESSIVE_URL_LENGTH,
                f"URL length ({len(parsed.original)}) exceeds safe threshold ({config.max_url_length})",
            )

        # 12. Homograph / Mixed Scripts
        if host_analysis.has_mixed_script:
            add_sig(
                SuspicionSignal.HOMOGRAPH_HOSTNAME,
                f"Mixed Unicode scripts detected in hostname: {', '.join(host_analysis.mixed_scripts)}",
            )

        # 13. Zero-Width / Invisible Unicode Characters
        has_unicode_body, susp_body_chars = detect_suspicious_unicode(parsed.original)
        if host_analysis.has_suspicious_unicode or has_unicode_body:
            detected_chars = list(set(host_analysis.suspicious_unicode_chars + susp_body_chars))
            add_sig(
                SuspicionSignal.ZERO_WIDTH_UNICODE,
                f"Zero-width or invisible Unicode characters in URL: {', '.join(detected_chars)}",
            )

        # 14. Punycode Label Detected
        if host_analysis.is_punycode:
            add_sig(
                SuspicionSignal.PUNYCODE_DETECTED,
                f"Punycode encoded international domain label: {parsed.host_stripped} -> {host_analysis.decoded_hostname}",
            )

        # 15. Typosquatting of Protected Domains
        if host_analysis.typosquat_target:
            add_sig(
                SuspicionSignal.TYPOSQUATTING_HOSTNAME,
                f"Domain '{host_analysis.registered_domain}' closely resembles protected brand '{host_analysis.typosquat_target}' "
                f"(similarity: {host_analysis.typosquat_similarity:.2f})",
            )

        # 16. Subdomain Brand Impersonation
        if host_analysis.subdomain_brand_target:
            add_sig(
                SuspicionSignal.SUBDOMAIN_BRAND_IMPERSONATION,
                host_analysis.subdomain_brand_evidence
                or f"Subdomain impersonates protected brand '{host_analysis.subdomain_brand_target}' "
                f"under unrelated domain '{host_analysis.registered_domain}'",
            )

        # 16. High-Entropy Path Segment
        if parsed.path:
            segments = [s for s in parsed.path.split("/") if len(s) >= 40]
            for seg in segments:
                entropy = _calculate_entropy(seg)
                if entropy >= 4.2:
                    add_sig(SuspicionSignal.HIGH_ENTROPY_PATH, f"High-entropy obfuscated path segment detected (entropy: {entropy:.2f})")
                    break

        # 17. URL Encoding Obfuscation
        orig = parsed.original
        if "%25" in orig or "%00" in orig or (re.search(r"%[0-9a-fA-F]{2}%[0-9a-fA-F]{2}", orig) and orig.count("%") > 8):
            add_sig(SuspicionSignal.URL_ENCODING_OBFUSCATION, "Excessive or double-encoded percentage sequences in URL")

        # 18. Suspicious Query Parameters (Command injection / shell scripts)
        if parsed.query:
            query_lower = parsed.query.lower()
            susp_tokens = ["cmd=", "exec=", "shell=", "powershell=", "eval=", "base64,"]
            for token in susp_tokens:
                if token in query_lower:
                    add_sig(SuspicionSignal.SUSPICIOUS_QUERY_PARAM, f"Suspicious command/execution token in query: '{token}'")
                    break

        return signals
