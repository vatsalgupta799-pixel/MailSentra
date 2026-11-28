"""Focused Regression Tests for Subdomain Brand Impersonation Detection (Priority 2).

Covers all 12 required scenarios from the implementation plan:
1. Canonical brand domains are not flagged.
2. Brand domains embedded in subdomains are detected.
3. Multiple brands are handled correctly.
4. Arbitrary substring matches are not flagged.
5. Registered-domain boundaries are respected.
6. Multi-label brand domains are handled correctly.
7. Case normalization works.
8. Trailing-dot hostnames are handled safely.
9. IP addresses do not cause crashes or false brand matches.
10. Malformed URLs fail safely.
11. Existing typosquatting detection remains unchanged.
12. Existing URL risk scoring remains unchanged for unrelated URLs.
13. RiskEngine integration: brand subdomain findings produce appropriate threat verdicts.
"""

import pytest
from app.models.scan import RiskTier
from app.modules.contracts import ExtractedUrl, ParsedEmail, UrlRiskSeverity
from app.modules.risk_engine.engine import RiskEngine
from app.modules.url_analysis.analyzer import UrlAnalyzer
from app.modules.url_analysis.config import UrlAnalysisConfig


@pytest.fixture
def analyzer():
    config = UrlAnalysisConfig(
        protected_domains=[
            "paypal.com",
            "microsoft.com",
            "google.com",
            "apple.com",
            "ebay.com",
            "chase.com",
            "nationalcity.com",
        ]
    )
    return UrlAnalyzer(config=config)


@pytest.fixture
def risk_engine():
    return RiskEngine()


# ============================================================================
# 1. Canonical Brand Domains Are Not Flagged
# ============================================================================
@pytest.mark.parametrize(
    "url",
    [
        "https://www.paypal.com/login",
        "https://paypal.com/signin",
        "https://checkout.paypal.com/pay",
        "https://www.google.com",
        "https://mail.google.com/mail",
        "https://login.microsoft.com/oauth",
        "https://apple.com/iphone",
        "https://developer.apple.com/documentation",
    ],
)
def test_01_canonical_brand_domains_not_flagged(analyzer, url):
    """Canonical domains matching the brand itself are never flagged as impersonation."""
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity == UrlRiskSeverity.SAFE
    assert "SUBDOMAIN_BRAND_IMPERSONATION" not in finding.reason


# ============================================================================
# 2. Brand Domains Embedded in Subdomains Are Detected
# ============================================================================
@pytest.mark.parametrize(
    "url,brand",
    [
        ("https://paypal.com.example.org/login", "paypal.com"),
        ("https://signin.ebay.com.evil-example.org/login", "ebay.com"),
        ("https://secure.chase.com.attacker.net/login", "chase.com"),
        ("http://account.microsoft.com.phishingsite.co/verify", "microsoft.com"),
        ("https://auth.google.com.malicious-portal.info/accounts", "google.com"),
    ],
)
def test_02_brand_domains_embedded_in_subdomains_detected(analyzer, url, brand):
    """Full brand domains embedded as subdomain sequences in unrelated domains are detected."""
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity in (UrlRiskSeverity.SUSPICIOUS, UrlRiskSeverity.MALICIOUS)
    assert "SUBDOMAIN_BRAND_IMPERSONATION" in finding.reason
    assert brand in finding.reason


# ============================================================================
# 3. Multiple Brands Are Handled Correctly
# ============================================================================
def test_03_multiple_brands_handled_correctly(analyzer):
    """Different distinct brands in subdomains each correctly report their respective brand target."""
    finding_ebay = analyzer.analyze_url("https://signin.ebay.com.evil.org/auth")
    assert finding_ebay is not None
    assert "ebay.com" in finding_ebay.reason

    finding_chase = analyzer.analyze_url("https://secure.chase.com.evil.org/auth")
    assert finding_chase is not None
    assert "chase.com" in finding_chase.reason

    finding_paypal = analyzer.analyze_url("https://paypal.com.evil.org/auth")
    assert finding_paypal is not None
    assert "paypal.com" in finding_paypal.reason


# ============================================================================
# 4. Arbitrary Substring Matches Are Not Flagged
# ============================================================================
@pytest.mark.parametrize(
    "url",
    [
        "https://example-paypal.com/login",
        "https://paypalsupport.com/login",
        "https://chasebankersassociation.org/index",
        "https://ebaymotorsparts.net/catalog",
        "https://pineapples.com/fruit",
    ],
)
def test_04_arbitrary_substring_matches_not_flagged(analyzer, url):
    """Compound or hyphenated hostnames containing brand substrings are NOT flagged."""
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert "SUBDOMAIN_BRAND_IMPERSONATION" not in finding.reason


# ============================================================================
# 5. Registered-Domain Boundaries Are Respected
# ============================================================================
def test_05_registered_domain_boundaries_respected(analyzer):
    """Unrelated registered domains without brand subdomains remain SAFE; standalone brand subdomains flag."""
    # Plain unrelated domain -> SAFE
    finding_unrelated = analyzer.analyze_url("https://example.org/login")
    assert finding_unrelated is not None
    assert finding_unrelated.severity == UrlRiskSeverity.SAFE
    assert "SUBDOMAIN_BRAND_IMPERSONATION" not in finding_unrelated.reason

    # Normal subdomains on unrelated domain -> SAFE
    finding_normal_sub = analyzer.analyze_url("https://portal.service.example.org/path")
    assert finding_normal_sub is not None
    assert finding_normal_sub.severity == UrlRiskSeverity.SAFE
    assert "SUBDOMAIN_BRAND_IMPERSONATION" not in finding_normal_sub.reason

    # Standalone exact brand-name token in subdomain (paypal.example.org) -> FLAGGED
    finding_brand_sub = analyzer.analyze_url("https://paypal.example.org/login")
    assert finding_brand_sub is not None
    assert finding_brand_sub.severity in (UrlRiskSeverity.SUSPICIOUS, UrlRiskSeverity.MALICIOUS)
    assert "SUBDOMAIN_BRAND_IMPERSONATION" in finding_brand_sub.reason
    assert "paypal" in finding_brand_sub.reason


# ============================================================================
# 6. Multi-Label Brand Domains Handled Correctly
# ============================================================================
def test_06_multi_label_brand_domains_handled_correctly(analyzer):
    """Multi-label brand domain sequences like nationalcity.com from Nazario corpus are detected."""
    # Authentic Nazario phishing sample pattern
    url = "http://session-424368524.nationalcity.com.trenkst.jp/index.html"
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert finding.severity in (UrlRiskSeverity.SUSPICIOUS, UrlRiskSeverity.MALICIOUS)
    assert "SUBDOMAIN_BRAND_IMPERSONATION" in finding.reason
    assert "nationalcity.com" in finding.reason


# ============================================================================
# 7. Case Normalization Works
# ============================================================================
@pytest.mark.parametrize(
    "url",
    [
        "https://PAYPAL.COM.EVIL-EXAMPLE.ORG/LOGIN",
        "https://SignIn.EBay.COM.Attacker.NET/auth",
        "https://SECURE.CHASE.COM.evil.com/verify",
    ],
)
def test_07_case_normalization_works(analyzer, url):
    """Mixed or upper-case URLs are normalized and properly detected."""
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert "SUBDOMAIN_BRAND_IMPERSONATION" in finding.reason


# ============================================================================
# 8. Trailing-Dot Hostnames Handled Safely
# ============================================================================
def test_08_trailing_dot_hostnames_handled_safely(analyzer):
    """Trailing dot FQDN notation is normalized safely for both canonical and attack URLs."""
    # Canonical with trailing dot -> SAFE
    finding_canon = analyzer.analyze_url("https://www.paypal.com./login")
    assert finding_canon is not None
    assert finding_canon.severity == UrlRiskSeverity.SAFE

    # Attack with trailing dot -> FLAGGED
    finding_attack = analyzer.analyze_url("https://paypal.com.example.org./login")
    assert finding_attack is not None
    assert "SUBDOMAIN_BRAND_IMPERSONATION" in finding_attack.reason


# ============================================================================
# 9. IP Addresses Do Not Cause Crashes or False Brand Matches
# ============================================================================
@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.1.1/login",
        "http://104.244.42.1/paypal.com/login",  # Brand in path, not hostname
        "http://[::1]/login",
        "http://0x7f000001/verify",
    ],
)
def test_09_ip_addresses_do_not_cause_crashes_or_false_brand_matches(analyzer, url):
    """IP addresses are evaluated by IP rules and never trigger false subdomain brand findings."""
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert "SUBDOMAIN_BRAND_IMPERSONATION" not in finding.reason


# ============================================================================
# 10. Malformed URLs Fail Safely
# ============================================================================
@pytest.mark.parametrize(
    "url",
    [
        "http://",
        "http://[unclosed-bracket",
        "http://paypal.com@/",
        "",
        "   ",
    ],
)
def test_10_malformed_urls_fail_safely(analyzer, url):
    """Malformed or empty URLs fail safely without uncaught exceptions."""
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert "SUBDOMAIN_BRAND_IMPERSONATION" not in finding.reason


# ============================================================================
# 11. Existing Typosquatting Detection Remains Unchanged
# ============================================================================
@pytest.mark.parametrize(
    "url,target",
    [
        ("https://paypa1.com/login", "paypal.com"),
        ("https://micros0ft.com/update", "microsoft.com"),
        ("https://go0gle.com/search", "google.com"),
    ],
)
def test_11_existing_typosquatting_detection_unchanged(analyzer, url, target):
    """Existing typosquatting on registered domains continues to function identically."""
    finding = analyzer.analyze_url(url)
    assert finding is not None
    assert "TYPOSQUATTING_HOSTNAME" in finding.reason
    assert target in finding.reason


# ============================================================================
# 12. Existing URL Risk Scoring Unchanged for Unrelated URLs
# ============================================================================
def test_12_existing_url_risk_scoring_unchanged_for_unrelated_urls(analyzer):
    """Existing security rules (suspicious TLD, executable extension, shorteners) remain unchanged."""
    # Suspicious TLD alone -> SUSPICIOUS
    finding_tld = analyzer.analyze_url("https://corporate-security.xyz/login")
    assert finding_tld is not None
    assert finding_tld.severity == UrlRiskSeverity.SUSPICIOUS
    assert "SUSPICIOUS_TLD" in finding_tld.reason

    # Suspicious file extension alone -> SUSPICIOUS
    finding_ext = analyzer.analyze_url("https://downloads.net/setup.exe")
    assert finding_ext is not None
    assert finding_ext.severity == UrlRiskSeverity.SUSPICIOUS
    assert "SUSPICIOUS_FILE_EXT" in finding_ext.reason


# ============================================================================
# 13. RiskEngine Integration
# ============================================================================
def test_13_risk_engine_integration_with_subdomain_impersonation(analyzer, risk_engine):
    """Subdomain brand impersonation produces appropriate SUSPICIOUS tier in RiskEngine."""
    parsed_email = ParsedEmail(
        urls=[
            ExtractedUrl(
                original_url="https://signin.ebay.com.evil-example.org/login",
                normalized_url="https://signin.ebay.com.evil-example.org/login",
                defanged_url="hxxps://signin.ebay.com.evil-example[.]org/login",
            )
        ]
    )
    url_result = analyzer.analyze_sync(parsed_email)
    assert url_result.highest_severity == UrlRiskSeverity.SUSPICIOUS

    score, tier, summary, assessment = risk_engine.evaluate(url_result=url_result)

    assert tier == RiskTier.SUSPICIOUS
    assert 45.0 <= score <= 74.0
    signals = assessment["contributing_signals"]
    assert any("[URL-SUSPICIOUS]" in s and "SUBDOMAIN_BRAND_IMPERSONATION" in s for s in signals)
    assert "SUSPICIOUS EMAIL" in summary
