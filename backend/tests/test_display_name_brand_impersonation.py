"""Focused Regression and Verification Test Suite for Priority 3:
Display-Name Brand Impersonation Detection.

Covers:
1. Positive brand impersonation cases (PayPal, Microsoft, Amazon, Chase, BofA, etc.).
2. Legitimate brand-domain cases (canonical, subdomains, ccTLDs, service domains).
3. Benign brand mentions and ambiguous personal names (Chase Miller, Fiona Apple, topical reviews).
4. Unknown external senders (no brand claim -> CLEAN).
5. Malformed and adversarial display names (Unicode fullwidth, zero-width spaces, empty, missing, long).
6. Duplicate findings and cross-analyzer deduplication with URL analyzer.
7. Full RiskEngine integration and deterministic scoring.
"""

import pytest
from app.models.scan import RiskTier
from app.modules.contracts import (
    ExtractedUrl,
    IdentityAnalysisResult,
    ImpersonationFinding,
    ParsedEmail,
    RawEmailPayload,
    UrlAnalysisResult,
    UrlFinding,
    UrlRiskSeverity,
)
from app.modules.identity.analyzer import SenderIdentityAnalyzer
from app.modules.identity.config import IdentityAnalysisConfig, ProtectedBrand
from app.modules.parser.parser import EmailParser
from app.modules.risk_engine.engine import RiskEngine
from app.modules.url_analysis.analyzer import UrlAnalyzer


@pytest.fixture
def parser():
    return EmailParser()


@pytest.fixture
def analyzer():
    return SenderIdentityAnalyzer()


@pytest.fixture
def risk_engine():
    return RiskEngine()


# ============================================================================
# 1. Positive Brand Impersonation Cases
# ============================================================================
@pytest.mark.parametrize(
    "display_name,from_addr,expected_brand",
    [
        ("PayPal Security Team", "security@attacker.example", "PayPal"),
        ("Microsoft Account Support", "support@unrelated.example", "Microsoft"),
        ("Amazon Billing Department", "billing@attacker.example", "Amazon"),
        ("Chase Card Services", "alerts@phishing-bank.net", "Chase"),
        ("Bank of America Fraud Alert", "verify@bofa-update.org", "Bank of America"),
        ("BofA Online Security", "notice@bad-actor.com", "Bank of America"),
        ("Apple ID Verification", "no-reply@icloud-recovery.cc", "Apple"),
        ("Netflix Membership Team", "billing@streaming-account.biz", "Netflix"),
        ("Google Account Recovery", "support@gmail-support.info", "Google"),
        ("Wells Fargo Fraud Dept", "security@banking-notice.org", "Wells Fargo"),
        ("National City Online Banking", "session@attacker.jp", "National City"),
        ("eBay Customer Support", "support@ebay-disputes.com.attacker.org", "eBay"),
        ("Service: PayPal Verification", "verify@suspicious.net", "PayPal"),
    ],
)
def test_positive_brand_impersonation_detected(parser, analyzer, display_name, from_addr, expected_brand):
    """Display names claiming protected brands from unauthorized domains are flagged."""
    eml = f"""From: "{display_name}" <{from_addr}>
To: victim@company.com
Subject: Urgent Action Required
Date: Wed, 28 Nov 2026 10:00:00 +0000

Please verify your credentials immediately.
""".encode()
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert result.display_name_spoofed is True
    brand_findings = [f for f in result.findings if f.indicator == "DISPLAY_NAME_BRAND_IMPERSONATION"]
    assert len(brand_findings) >= 1
    assert any(f.target_name == expected_brand for f in brand_findings)
    assert any(from_addr.split("@")[1] in f.description for f in brand_findings)


def test_custom_brand_impersonation(parser, analyzer):
    """User-configured custom protected brand in IdentityAnalysisConfig is detected."""
    custom_cfg = IdentityAnalysisConfig(
        custom_protected_brands=[
            ProtectedBrand(
                name="AcmeFin",
                variations=["acmefin", "acme finance"],
                domains=["acmefin.com"],
            )
        ]
    )
    eml = b"""From: "AcmeFin Support" <support@malicious.com>
To: client@company.com
Subject: Account Statement
Date: Wed, 28 Nov 2026 10:00:00 +0000

Statement details inside.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed, config=custom_cfg)

    assert result.display_name_spoofed is True
    assert any(f.indicator == "DISPLAY_NAME_BRAND_IMPERSONATION" and f.target_name == "AcmeFin" for f in result.findings)


def test_organization_name_impersonation(parser, analyzer):
    """Protected organization_names mapped to protected_domains are detected as brands."""
    org_cfg = IdentityAnalysisConfig(
        organization_names=["TechCorp Global", "TechCorp"],
        protected_domains=["techcorp.com"],
    )
    eml = b"""From: "TechCorp Global IT Helpdesk" <helpdesk@evil-phish.net>
To: user@techcorp.com
Subject: System Maintenance Notice
Date: Wed, 28 Nov 2026 10:00:00 +0000

Mandatory password reset.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed, config=org_cfg)

    assert result.display_name_spoofed is True
    assert any(f.indicator == "DISPLAY_NAME_BRAND_IMPERSONATION" for f in result.findings)


# ============================================================================
# 2. Legitimate Brand-Domain Cases (Must NOT Flag)
# ============================================================================
@pytest.mark.parametrize(
    "display_name,from_addr",
    [
        ("PayPal Security Team", "security@paypal.com"),
        ("PayPal Support", "service@mail.paypal.com"),
        ("PayPal UK Services", "support@paypal.co.uk"),
        ("PayPal Australia", "info@paypal.com.au"),
        ("Microsoft Account Support", "account-security-noreply@accountprotection.microsoft.com"),
        ("Microsoft Office 365", "no-reply@microsoft.com"),
        ("Amazon Billing Department", "auto-confirm@amazon.com"),
        ("Amazon AWS Notifications", "no-reply@amazonses.com"),
        ("Amazon UK Store", "order-update@amazon.co.uk"),
        ("Apple Support", "support@apple.com"),
        ("Apple iCloud Team", "noreply@icloud.com"),
        ("Chase Bank", "no.reply@chase.com"),
        ("JPMorgan Chase Operations", "client-service@jpmorganchase.com"),
        ("Dropbox Notifications", "no-reply@dropboxmail.com"),
        ("Facebook", "notification@facebookmail.com"),
        ("LinkedIn Alerts", "messages-noreply@e.linkedin.com"),
        ("Google Security Alert", "no-reply@accounts.google.com"),
    ],
)
def test_legitimate_brand_domains_not_flagged(parser, analyzer, display_name, from_addr):
    """Legitimate brand emails from canonical domains, subdomains, ccTLDs, or service domains are clean."""
    eml = f"""From: "{display_name}" <{from_addr}>
To: user@company.com
Subject: Account Update
Date: Wed, 28 Nov 2026 10:00:00 +0000

Official notification from our team.
""".encode()
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    brand_findings = [f for f in result.findings if f.indicator == "DISPLAY_NAME_BRAND_IMPERSONATION"]
    assert len(brand_findings) == 0


# ============================================================================
# 3. Benign Brand Mentions and Ambiguous Personal Names
# ============================================================================
@pytest.mark.parametrize(
    "display_name,from_addr",
    [
        ("Chase Miller", "chase.miller@gmail.com"),
        ("Chase Adams", "chase.adams@techfirm.org"),
        ("Chase Gallagher", "chase@freelance.net"),
        ("Fiona Apple", "fiona@music-label.com"),
        ("Apple Martin", "apple.martin@personal-mail.org"),
        ("David Apple", "dapple@engineering-firm.com"),
    ],
)
def test_ambiguous_personal_names_not_flagged(parser, analyzer, display_name, from_addr):
    """Ordinary personal names resembling brand terms (Chase, Apple) are NOT flagged."""
    eml = f"""From: "{display_name}" <{from_addr}>
To: user@company.com
Subject: Coffee Catchup
Date: Wed, 28 Nov 2026 10:00:00 +0000

Let's meet tomorrow.
""".encode()
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    brand_findings = [f for f in result.findings if f.indicator == "DISPLAY_NAME_BRAND_IMPERSONATION"]
    assert len(brand_findings) == 0


@pytest.mark.parametrize(
    "display_name,from_addr",
    [
        ("Discussion on PayPal API", "developer@independent-forum.org"),
        ("Review of Amazon Products", "reviews@shopper-blog.net"),
        ("Newsletter on Microsoft Windows", "editor@tech-digest.com"),
        ("Survey on Cloud Services", "survey@research-group.org"),
        ("Amazon Reviewers Club", "contact@reviewers-club.org"),
        ("Apple Developers Discussion Group", "moderator@dev-group.org"),
    ],
)
def test_non_impersonation_contexts_not_flagged(parser, analyzer, display_name, from_addr):
    """Topical, discussion, and review display names mentioning brands in non-impersonation contexts are safe."""
    eml = f"""From: "{display_name}" <{from_addr}>
To: user@company.com
Subject: Weekly Digest
Date: Wed, 28 Nov 2026 10:00:00 +0000

Here is the weekly discussion roundup.
""".encode()
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    brand_findings = [f for f in result.findings if f.indicator == "DISPLAY_NAME_BRAND_IMPERSONATION"]
    assert len(brand_findings) == 0


# ============================================================================
# 4. Unknown External Senders (Must Remain CLEAN)
# ============================================================================
@pytest.mark.parametrize(
    "display_name,from_addr",
    [
        ("Alice Walker", "alice@unknown-startup.io"),
        ("Bob Contractor", "bob@freemail.net"),
        ("Consulting Partner", "partner@consulting-services.biz"),
        ("Dr. John Watson", "jwatson@bakerstreet.co.uk"),
    ],
)
def test_unknown_external_senders_remain_clean(parser, analyzer, risk_engine, display_name, from_addr):
    """Unknown external senders without brand/VIP claims must NOT be classified as malicious."""
    eml = f"""From: "{display_name}" <{from_addr}>
To: user@company.com
Subject: Project Inquiry
Date: Wed, 28 Nov 2026 10:00:00 +0000

Hello, following up on our project.
""".encode()
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    id_result = analyzer.analyze_sync(parsed)

    brand_findings = [f for f in id_result.findings if f.indicator == "DISPLAY_NAME_BRAND_IMPERSONATION"]
    assert len(brand_findings) == 0

    score, tier, summary, assessment = risk_engine.evaluate(identity_result=id_result)
    assert tier == RiskTier.CLEAN
    assert score == 0.0
    assert "CLEAN EMAIL" in summary


# ============================================================================
# 5. Malformed and Adversarial Display Names
# ============================================================================
def test_fullwidth_unicode_brand_impersonation(parser, analyzer):
    """Fullwidth Unicode brand display name (NFKC normalization) is detected."""
    eml = b"""From: "\xef\xbc\xb0\xef\xbd\x81\xef\xbd\x99\xef\xbc\xb0\xef\xbd\x81\xef\xbd\x8c Security" <security@attacker.example>
To: victim@company.com
Subject: Account Verification
Date: Wed, 28 Nov 2026 10:00:00 +0000

Verify account now.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert result.display_name_spoofed is True
    assert any(f.indicator == "DISPLAY_NAME_BRAND_IMPERSONATION" and f.target_name == "PayPal" for f in result.findings)


def test_zero_width_space_in_brand_name(parser, analyzer):
    """Display name with zero-width space injected into brand token is safely normalized and detected."""
    eml = b'From: "Pay\xe2\x80\x8bPal Security Team" <security@attacker.example>\r\nTo: v@c.com\r\nSubject: Test\r\n\r\nMsg'
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert result.display_name_spoofed is True
    assert any(f.indicator == "DISPLAY_NAME_BRAND_IMPERSONATION" and f.target_name == "PayPal" for f in result.findings)


def test_uppercase_brand_name(parser, analyzer):
    """Case variations like all-uppercase brand name are normalized and detected."""
    eml = b'From: "PAYPAL SECURITY TEAM" <security@attacker.example>\r\nTo: v@c.com\r\nSubject: Test\r\n\r\nMsg'
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert result.display_name_spoofed is True
    assert any(f.indicator == "DISPLAY_NAME_BRAND_IMPERSONATION" and f.target_name == "PayPal" for f in result.findings)


@pytest.mark.parametrize(
    "raw_header",
    [
        b"From: <nobody@attacker.example>\r\n",  # Missing display name
        b'From: "" <nobody@attacker.example>\r\n',  # Empty display name
        b'From: "   " <nobody@attacker.example>\r\n',  # Whitespace display name
        b'From: "???!!!" <nobody@attacker.example>\r\n',  # Punctuation-only display name
        b'From: "@@@###$$$" <nobody@attacker.example>\r\n',
    ],
)
def test_missing_or_malformed_display_names_handled_safely(parser, analyzer, raw_header):
    """Missing or malformed display names fail safely without exceptions or false brand findings."""
    eml = raw_header + b"To: v@c.com\r\nSubject: Test\r\n\r\nEmpty display name test"
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert not any(f.indicator == "DISPLAY_NAME_BRAND_IMPERSONATION" for f in result.findings)


def test_excessively_long_display_name_handled_safely(parser, analyzer):
    """Extremely long display name is truncated safely without buffer or regex failure."""
    long_name = "PayPal Security " + "A" * 2000
    eml = f'From: "{long_name}" <sec@attacker.example>\r\nTo: v@c.com\r\nSubject: Test\r\n\r\nMsg'.encode()
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert result.display_name_spoofed is True
    assert any(f.indicator == "DISPLAY_NAME_BRAND_IMPERSONATION" for f in result.findings)


# ============================================================================
# 6. Duplicate Signal Prevention & Cross-Analyzer Deduplication
# ============================================================================
def test_duplicate_brand_findings_deduplicated_in_identity(risk_engine):
    """Multiple identical brand findings for the same sender do not inflate RiskEngine score."""
    id_result = IdentityAnalysisResult(
        analysis_status="COMPLETED",
        findings=[
            ImpersonationFinding(
                indicator="DISPLAY_NAME_BRAND_IMPERSONATION",
                target_name="PayPal",
                similarity_score=1.0,
                description="Sender display name 'PayPal Security Team' claims protected brand 'PayPal'...",
                is_vip=False,
            ),
            ImpersonationFinding(
                indicator="DISPLAY_NAME_BRAND_IMPERSONATION",
                target_name="PayPal",
                similarity_score=1.0,
                description="Sender display name 'PayPal Security Team' claims protected brand 'PayPal'...",
                is_vip=False,
            ),
        ],
    )
    score, tier, summary, assessment = risk_engine.evaluate(identity_result=id_result)

    # Standalone brand mismatch is SUSPICIOUS (not automatically MALICIOUS)
    assert tier == RiskTier.SUSPICIOUS
    # Base score 60.0 + 1 signal * 2.0 = 62.0 (deduplicated, NOT 64.0)
    assert score == 62.0
    signals = assessment["contributing_signals"]
    brand_signals = [s for s in signals if "DISPLAY_NAME_BRAND_IMPERSONATION" in s]
    assert len(brand_signals) == 1


def test_cross_analyzer_brand_deduplication(risk_engine):
    """When UrlAnalyzer and IdentityAnalyzer report the same underlying brand, signal count is not duplicated."""
    url_res = UrlAnalysisResult(
        total_urls_scanned=1,
        highest_severity=UrlRiskSeverity.SUSPICIOUS,
        findings=[
            UrlFinding(
                url="http://signin.paypal.com.evil.org/login",
                defanged_url="hxxp://signin.paypal[.]com.evil.org/login",
                severity=UrlRiskSeverity.SUSPICIOUS,
                reason="[SUBDOMAIN_BRAND_IMPERSONATION] Subdomain contains embedded brand domain 'paypal.com' under unrelated domain 'evil.org'",
            )
        ],
    )
    id_res = IdentityAnalysisResult(
        analysis_status="COMPLETED",
        findings=[
            ImpersonationFinding(
                indicator="DISPLAY_NAME_BRAND_IMPERSONATION",
                target_name="PayPal",
                similarity_score=1.0,
                description="Sender display name 'PayPal Security Team' claims protected brand 'PayPal' under unrelated domain 'evil.org'.",
                is_vip=False,
            )
        ],
    )
    score, tier, summary, assessment = risk_engine.evaluate(url_result=url_res, identity_result=id_res)

    assert tier == RiskTier.SUSPICIOUS
    signals = assessment["contributing_signals"]
    # URL signal is recorded; Identity signal targeting same brand is recognized as duplicate underlying threat
    # Base score 60.0 + 1 * 2.0 = 62.0 (NOT 64.0)
    assert score == 62.0
    assert len(signals) == 1


# ============================================================================
# 7. RiskEngine Integration & Risk-Based Scoring Verification (Risk A)
# ============================================================================
def test_brand_impersonation_alone_is_suspicious_not_malicious(parser, analyzer, risk_engine):
    """Display-name mismatch alone is classified as SUSPICIOUS (not automatically MALICIOUS)."""
    eml = b"""From: "PayPal Security Team" <security@attacker.example>
To: victim@company.com
Subject: Account Inquiry
Date: Wed, 28 Nov 2026 10:00:00 +0000

Please review your transaction.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    id_result = analyzer.analyze_sync(parsed)

    score, tier, summary, assessment = risk_engine.evaluate(identity_result=id_result)

    assert tier == RiskTier.SUSPICIOUS
    assert score == 62.0  # base_score 60.0 + 1 signal * 2.0
    assert "SUSPICIOUS EMAIL" in summary
    assert any("[IDENTITY-BRAND-MISMATCH] DISPLAY_NAME_BRAND_IMPERSONATION" in s for s in assessment["contributing_signals"])


def test_brand_impersonation_corroborated_by_malicious_url_elevates_to_malicious(parser, analyzer, risk_engine):
    """When brand impersonation is corroborated by a malicious URL, it elevates to MALICIOUS."""
    eml = b"""From: "PayPal Security Team" <security@attacker.example>
To: victim@company.com
Subject: Account Suspended
Date: Wed, 28 Nov 2026 10:00:00 +0000

Click here to resolve.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    id_result = analyzer.analyze_sync(parsed)

    malicious_url_res = UrlAnalysisResult(
        total_urls_scanned=1,
        highest_severity=UrlRiskSeverity.MALICIOUS,
        findings=[
            UrlFinding(
                url="http://malicious-phish.biz/credential-stealer",
                defanged_url="hxxp://malicious-phish[.]biz/credential-stealer",
                severity=UrlRiskSeverity.MALICIOUS,
                reason="Known malicious phishing payload endpoint",
            )
        ],
    )

    score, tier, summary, assessment = risk_engine.evaluate(
        identity_result=id_result,
        url_result=malicious_url_res,
    )

    assert tier == RiskTier.MALICIOUS
    assert score >= 85.0
    assert "THREAT DETECTED (MALICIOUS)" in summary


# ============================================================================
# 8. Implicit Domain Authorization Rejection (Risk B)
# ============================================================================
def test_implicit_stem_sharing_domains_rejected(parser, analyzer):
    """Domains sharing brand stems (e.g. paypal.evil-fake.org, paypal-update.biz) are NOT authorized."""
    eml = b"""From: "PayPal Billing" <billing@paypal.evil-fake.org>
To: victim@company.com
Subject: Invoice
Date: Wed, 28 Nov 2026 10:00:00 +0000

Attached invoice.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert result.display_name_spoofed is True
    assert any(f.indicator == "DISPLAY_NAME_BRAND_IMPERSONATION" and f.target_name == "PayPal" for f in result.findings)


def test_verified_authorized_sender_relationship_respected(parser):
    """Explicitly configured allowed subdomains or third-party sending domains are respected."""
    cfg = IdentityAnalysisConfig(
        custom_protected_brands=[
            ProtectedBrand(
                name="AcmeCorp",
                variations=["acme"],
                domains=["acme.com"],
                allowed_subdomains=["sendgrid.net", "acme-mail.custhelp.com"],
            )
        ]
    )
    from app.modules.identity.analyzer import SenderIdentityAnalyzer
    custom_analyzer = SenderIdentityAnalyzer(default_config=cfg)

    eml = b"""From: "Acme Support" <support@acme-mail.custhelp.com>
To: customer@company.com
Subject: Ticket #1234
Date: Wed, 28 Nov 2026 10:00:00 +0000

Your ticket has been updated.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = custom_analyzer.analyze_sync(parsed)

    # Authorized via allowed_subdomains, should NOT be flagged as brand impersonation
    assert not any(f.indicator == "DISPLAY_NAME_BRAND_IMPERSONATION" for f in result.findings)
