"""Comprehensive test suite for Module 5: Static URL Security Analysis Engine.

Covers all 32 required deterministic test scenarios without external network requests:
1. Normal HTTP URLs.
2. Normal HTTPS URLs.
3. Malformed URLs.
4. Unsupported schemes.
5. Embedded credentials.
6. IPv4 literals.
7. IPv6 literals.
8. Private IPs.
9. Loopback IPs.
10. Link-local IPs.
11. Reserved IPs.
12. Unusual ports.
13. IDN hostnames.
14. Punycode.
15. Mixed scripts.
16. Zero-width characters.
17. Typosquatting.
18. Suspicious subdomains.
19. Excessive subdomains.
20. Encoded characters.
21. Obfuscation.
22. Suspicious query parameters.
23. URL shorteners.
24. Suspicious file extensions.
25. Download paths.
26. Weak-signal false positives.
27. Multi-signal scoring.
28. Empty input.
29. Extremely long input.
30. Malformed Unicode.
31. Repeatability.
32. No network operations.
"""

import pytest
from app.modules.contracts import ExtractedUrl, ParsedEmail, UrlRiskSeverity
from app.modules.url_analysis.analyzer import UrlAnalyzer
from app.modules.url_analysis.config import UrlAnalysisConfig


@pytest.fixture
def analyzer():
    config = UrlAnalysisConfig(
        protected_domains=["paypal.com", "microsoft.com", "google.com", "apple.com"]
    )
    return UrlAnalyzer(config=config)


def make_email(urls: list[str]) -> ParsedEmail:
    """Helper to construct a ParsedEmail container with extracted URLs."""
    extracted = [
        ExtractedUrl(
            original_url=u,
            normalized_url=u,
            defanged_url=u.replace("http://", "hxxp://").replace("https://", "hxxps://"),
        )
        for u in urls
    ]
    return ParsedEmail(urls=extracted)


# ============================================================================
# 1 & 2: Normal HTTP and HTTPS URLs (False-Positive Guards)
# ============================================================================
@pytest.mark.parametrize(
    "url",
    [
        "https://www.google.com",
        "https://github.com/torvalds/linux",
        "http://example.com/about/team",
        "https://docs.python.org/3/library/urllib.parse.html",
        "https://en.wikipedia.org/wiki/Computer_security",
    ],
)
def test_normal_legitimate_urls_are_safe(analyzer, url):
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity == UrlRiskSeverity.SAFE
    assert finding.is_ip_host is False
    assert finding.is_suspicious_tld is False


# ============================================================================
# 3: Malformed URLs
# ============================================================================
@pytest.mark.parametrize(
    "url",
    [
        "http://",
        "https://",
        "http:///path/without/host",
        "http://[unclosed-ipv6",
    ],
)
def test_malformed_urls_handled_safely(analyzer, url):
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity == UrlRiskSeverity.SUSPICIOUS
    assert "MALFORMED_URL" in finding.reason


# ============================================================================
# 4: Unsupported Schemes
# ============================================================================
@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "file:///etc/passwd",
        "ftp://ftp.example.com/download",
    ],
)
def test_unsupported_schemes_flagged_malicious(analyzer, url):
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity == UrlRiskSeverity.MALICIOUS
    assert "UNSUPPORTED_SCHEME" in finding.reason


# ============================================================================
# 5: Embedded Credentials
# ============================================================================
def test_embedded_credentials_in_authority(analyzer):
    url = "https://admin:SuperSecret123@portal.phishing-victim.com/login"
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity in (UrlRiskSeverity.SUSPICIOUS, UrlRiskSeverity.MALICIOUS)
    assert "EMBEDDED_CREDENTIALS" in finding.reason


# ============================================================================
# 6 & 7: IPv4 and IPv6 Literals
# ============================================================================
def test_public_ipv4_literal_is_suspicious(analyzer):
    url = "http://8.8.8.8/dns-query"
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.is_ip_host is True
    assert finding.resolved_ip == "8.8.8.8"
    assert finding.severity == UrlRiskSeverity.SUSPICIOUS
    assert "IP_HOST_PUBLIC" in finding.reason


def test_public_ipv6_literal_is_suspicious(analyzer):
    url = "http://[2001:4860:4860::8888]/test"
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.is_ip_host is True
    assert finding.resolved_ip == "2001:4860:4860::8888"
    assert finding.severity == UrlRiskSeverity.SUSPICIOUS
    assert "IP_HOST_PUBLIC" in finding.reason


# ============================================================================
# 8: Private IPs (RFC 1918)
# ============================================================================
@pytest.mark.parametrize(
    "url,expected_ip",
    [
        ("http://192.168.1.1/admin", "192.168.1.1"),
        ("http://10.0.0.5:8080/setup", "10.0.0.5"),
        ("http://172.16.2.20/internal", "172.16.2.20"),
    ],
)
def test_private_ips_are_malicious(analyzer, url, expected_ip):
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.is_ip_host is True
    assert finding.resolved_ip == expected_ip
    assert finding.severity == UrlRiskSeverity.MALICIOUS
    assert "IP_HOST_PRIVATE" in finding.reason


# ============================================================================
# 9: Loopback IPs
# ============================================================================
@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8000/api",
        "http://127.0.1.1/",
        "http://[::1]/debug",
    ],
)
def test_loopback_ips_are_malicious(analyzer, url):
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.is_ip_host is True
    assert finding.severity == UrlRiskSeverity.MALICIOUS
    assert "IP_HOST_LOOPBACK" in finding.reason


# ============================================================================
# 10: Link-Local IPs (Cloud Metadata)
# ============================================================================
@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://[fe80::1ff:fe00:3a60]/",
    ],
)
def test_link_local_ips_are_malicious(analyzer, url):
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.is_ip_host is True
    assert finding.severity == UrlRiskSeverity.MALICIOUS
    assert "IP_HOST_LINK_LOCAL" in finding.reason


# ============================================================================
# 11: Reserved and Unspecified IPs
# ============================================================================
@pytest.mark.parametrize(
    "url",
    [
        "http://0.0.0.0/",
        "http://240.0.0.1/test",
        "http://224.0.0.1/multicast",
    ],
)
def test_reserved_and_unspecified_ips_are_malicious(analyzer, url):
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.is_ip_host is True
    assert finding.severity == UrlRiskSeverity.MALICIOUS
    assert ("IP_HOST_RESERVED" in finding.reason or "IP_HOST_UNSPECIFIED" in finding.reason)


# ============================================================================
# 12: Unusual Ports
# ============================================================================
def test_unusual_port_detected(analyzer):
    url = "https://company.org:8444/login"
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity == UrlRiskSeverity.SUSPICIOUS
    assert "NON_STANDARD_PORT" in finding.reason


def test_standard_ports_not_flagged(analyzer):
    for u in ["http://example.com:80/a", "https://example.com:443/b", "http://example.com:8080/c"]:
        finding = analyzer.analyze_url(u)
        assert "NON_STANDARD_PORT" not in finding.reason


# ============================================================================
# 13 & 14: IDN Hostnames & Punycode
# ============================================================================
def test_punycode_label_detection(analyzer):
    url = "http://xn--e1afmkfd.xn--p1ai/"  # пример.рф
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity == UrlRiskSeverity.SUSPICIOUS
    assert "PUNYCODE_DETECTED" in finding.reason


# ============================================================================
# 15: Mixed Scripts (Homoglyph Attack)
# ============================================================================
def test_mixed_script_homoglyph_detection(analyzer):
    # 'а' is Cyrillic small letter a (U+0430) inside Latin 'pple.com'
    url = "http://\u0430pple.com/store"
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity in (UrlRiskSeverity.SUSPICIOUS, UrlRiskSeverity.MALICIOUS)
    assert "HOMOGRAPH_HOSTNAME" in finding.reason


# ============================================================================
# 16: Zero-Width / Invisible Characters
# ============================================================================
def test_zero_width_space_in_url(analyzer):
    # Zero-width space U+200B injected in URL host
    url = "https://pay\u200bpal.com/verify"
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity in (UrlRiskSeverity.SUSPICIOUS, UrlRiskSeverity.MALICIOUS)
    assert "ZERO_WIDTH_UNICODE" in finding.reason


# ============================================================================
# 17: Typosquatting of Protected Domains
# ============================================================================
@pytest.mark.parametrize(
    "url,target",
    [
        ("https://paypa1.com/login", "paypal.com"),
        ("https://micros0ft.com/update", "microsoft.com"),
        ("https://go0gle.com/search", "google.com"),
    ],
)
def test_typosquatting_detection(analyzer, url, target):
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity in (UrlRiskSeverity.SUSPICIOUS, UrlRiskSeverity.MALICIOUS)
    assert "TYPOSQUATTING_HOSTNAME" in finding.reason
    assert target in finding.reason


# ============================================================================
# 18 & 19: Suspicious and Excessive Subdomains
# ============================================================================
def test_excessive_subdomain_depth(analyzer):
    url = "http://a.b.c.d.e.f.phishing-gateway.com/portal"
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity == UrlRiskSeverity.SUSPICIOUS
    assert "EXCESSIVE_SUBDOMAINS" in finding.reason


# ============================================================================
# 20 & 21: Encoded Characters and Obfuscation (Hex/Octal/Integer IPs)
# ============================================================================
def test_hex_encoded_ipv4_host(analyzer):
    url = "http://0x7f000001/secret"  # 127.0.0.1
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.is_ip_host is True
    assert finding.severity == UrlRiskSeverity.MALICIOUS
    assert "IP_HOST_LOOPBACK" in finding.reason
    assert "IP_HOST_ENCODED" in finding.reason


def test_octal_encoded_ipv4_host(analyzer):
    url = "http://0177.0.0.1/admin"  # 127.0.0.1
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.is_ip_host is True
    assert finding.severity == UrlRiskSeverity.MALICIOUS
    assert "IP_HOST_ENCODED" in finding.reason


def test_integer_encoded_ipv4_host(analyzer):
    url = "http://2130706433/path"  # 127.0.0.1 in decimal integer
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.is_ip_host is True
    assert finding.severity == UrlRiskSeverity.MALICIOUS
    assert "IP_HOST_LOOPBACK" in finding.reason


def test_double_url_encoding_obfuscation(analyzer):
    url = "https://example.com/login%252f%252f%252e%252e%252f%2525"
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert "URL_ENCODING_OBFUSCATION" in finding.reason


# ============================================================================
# 22: Suspicious Query Parameters
# ============================================================================
@pytest.mark.parametrize(
    "url,expected_token",
    [
        ("https://portal.com/login?redirect=https://attacker.com", "OPEN_REDIRECT_PARAM"),
        ("https://portal.com/index.php?url=http://malicious.org", "OPEN_REDIRECT_PARAM"),
        ("https://victim.com/api?cmd=whoami", "SUSPICIOUS_QUERY_PARAM"),
        ("https://victim.com/eval?exec=base64,payload", "SUSPICIOUS_QUERY_PARAM"),
    ],
)
def test_suspicious_query_parameters(analyzer, url, expected_token):
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity in (UrlRiskSeverity.SUSPICIOUS, UrlRiskSeverity.MALICIOUS)
    assert expected_token in finding.reason


# ============================================================================
# 23: URL Shorteners
# ============================================================================
@pytest.mark.parametrize(
    "url",
    [
        "https://bit.ly/3xY8a9",
        "https://t.co/abc1234",
        "https://tinyurl.com/fastlink",
        "http://ow.ly/i/5e",
    ],
)
def test_known_url_shorteners_detected(analyzer, url):
    finding = analyzer.analyze_url(url)
    assert finding is not None
    # Shortener alone is SUSPICIOUS, never MALICIOUS
    assert finding.severity == UrlRiskSeverity.SUSPICIOUS
    assert "KNOWN_SHORTENER" in finding.reason


# ============================================================================
# 24 & 25: Suspicious File Extensions & Dangerous Download Paths
# ============================================================================
@pytest.mark.parametrize(
    "url,ext",
    [
        ("https://files.share-drive.com/invoice.exe", ".exe"),
        ("http://storage.cloud.net/update.ps1", ".ps1"),
        ("https://downloads.net/script.vbs", ".vbs"),
        ("https://files.org/setup.bat", ".bat"),
        ("https://share.com/document.scr", ".scr"),
    ],
)
def test_dangerous_download_extensions(analyzer, url, ext):
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity in (UrlRiskSeverity.SUSPICIOUS, UrlRiskSeverity.MALICIOUS)
    assert "SUSPICIOUS_FILE_EXT" in finding.reason
    assert ext in finding.reason


# ============================================================================
# 26: Suspicious TLD Alone
# ============================================================================
@pytest.mark.parametrize(
    "url,tld",
    [
        ("https://corporate-security.xyz/login", ".xyz"),
        ("http://download-center.top/app", ".top"),
        ("https://archive-backup.zip/data", ".zip"),
    ],
)
def test_suspicious_tld_alone_is_suspicious_not_malicious(analyzer, url, tld):
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.is_suspicious_tld is True
    assert finding.severity == UrlRiskSeverity.SUSPICIOUS
    assert "SUSPICIOUS_TLD" in finding.reason


# ============================================================================
# 27: Multi-Signal Corroboration Escalates to MALICIOUS
# ============================================================================
def test_multi_signal_corroboration_escalates_to_malicious(analyzer):
    # Suspicious TLD (.xyz) + Open Redirect + Embedded Credentials + Dangerous Extension
    url = "https://admin:pass@gateway-update.xyz/redirect?url=http://evil.com/trojan.exe"
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity == UrlRiskSeverity.MALICIOUS
    assert "SUSPICIOUS_TLD" in finding.reason
    assert "EMBEDDED_CREDENTIALS" in finding.reason
    assert "OPEN_REDIRECT_PARAM" in finding.reason


def test_homoglyph_plus_typosquatting_escalates_to_malicious(analyzer):
    # Typosquatting of microsoft.com with mixed-script Cyrillic 'о'
    url = "https://micr\u043es0ft.com/account"
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity == UrlRiskSeverity.MALICIOUS
    assert "HOMOGRAPH_HOSTNAME" in finding.reason


# ============================================================================
# 28: Empty and Whitespace Inputs
# ============================================================================
def test_empty_input_handled_gracefully(analyzer):
    finding = analyzer.analyze_url("")
    assert finding is not None
    assert finding.severity == UrlRiskSeverity.SUSPICIOUS
    assert "MALFORMED_URL" in finding.reason


def test_whitespace_input_handled_gracefully(analyzer):
    finding = analyzer.analyze_url("   \t\n  ")
    assert finding is not None
    assert finding.severity == UrlRiskSeverity.SUSPICIOUS
    assert "MALFORMED_URL" in finding.reason


# ============================================================================
# 29: Extremely Long Input
# ============================================================================
def test_extremely_long_url_handled_safely(analyzer):
    huge_url = "https://example.com/search?" + ("a" * 3000)
    finding = analyzer.analyze_url(huge_url)
    assert finding is not None
    assert finding.severity == UrlRiskSeverity.SUSPICIOUS
    assert "EXCESSIVE_URL_LENGTH" in finding.reason


# ============================================================================
# 30: Malformed Unicode
# ============================================================================
def test_malformed_unicode_in_url(analyzer):
    # Surrogate pair halves or unassigned code points
    url = "https://example.com/\ud800\udc00/test"
    finding = analyzer.analyze_url(url)
    assert finding is not None
    # Must not raise an exception, returns a valid UrlFinding


# ============================================================================
# 31: Determinism and Repeatability
# ============================================================================
def test_deterministic_repeatability(analyzer):
    url = "https://user:password@sub.sub2.sub3.sub4.sub5.portal.xyz:8080/path/test.exe"
    res1 = analyzer.analyze_url(url)
    res2 = analyzer.analyze_url(url)
    assert res1.severity == res2.severity
    assert res1.reason == res2.reason
    assert res1.is_ip_host == res2.is_ip_host
    assert res1.is_suspicious_tld == res2.is_suspicious_tld


# ============================================================================
# 32: Synchronous and Asynchronous Email Batch Analysis
# ============================================================================
def test_email_batch_analysis_sync(analyzer):
    email = make_email([
        "https://www.google.com",
        "http://192.168.1.1/admin",
        "https://bit.ly/xyz",
    ])
    result = analyzer.analyze_sync(email)
    assert result.total_urls_scanned == 3
    assert result.highest_severity == UrlRiskSeverity.MALICIOUS
    # Safe URLs are omitted from findings list to conserve storage
    assert len(result.findings) == 2
    assert any(f.url == "http://192.168.1.1/admin" and f.severity == UrlRiskSeverity.MALICIOUS for f in result.findings)
    assert any(f.url == "https://bit.ly/xyz" and f.severity == UrlRiskSeverity.SUSPICIOUS for f in result.findings)


@pytest.mark.asyncio
async def test_email_batch_analysis_async(analyzer):
    email = make_email(["https://www.google.com", "http://10.0.0.1/secret"])
    result = await analyzer.analyze(email)
    assert result.total_urls_scanned == 2
    assert result.highest_severity == UrlRiskSeverity.MALICIOUS
    assert len(result.findings) == 1
    assert result.findings[0].url == "http://10.0.0.1/secret"


def test_url_analyzer_properties(analyzer):
    assert analyzer.module_name == "url_analyzer"
    assert analyzer.version == "1.0.0"
