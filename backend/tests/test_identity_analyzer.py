"""Comprehensive verification test suite for Module 3: Sender Identity Analysis.

Covers all 22 required initial evaluation scenarios, scan service integration,
and all 11 targeted remediation scenarios:
1. Valid internal sender.
2. Missing From.
3. Malformed From.
4. Duplicate From headers.
5. Duplicate Reply-To headers.
6. Multiple From mailboxes with a valid Sender.
7. Multiple From mailboxes without Sender.
8. From and Reply-To mismatch.
9. Legitimate third-party Return-Path.
10. From and Return-Path mismatch.
11. Embedded email address in display name.
12. Configured VIP impersonation.
13. Configured organization role impersonation.
14. Punycode domain indicator.
15. Mixed-script domain indicator.
16. Configured typosquatting detection.
17. Legitimate protected domain.
18. Unicode control characters.
19. Excessively long input.
20. Finding-count limit.
21. Missing optional headers.
22. Deterministic repeated analysis.
23. ScanService telemetry integration.
Remediation test scenarios:
24. Subdomain typosquatting lookalike (login.standford.edu vs stanford.edu).
25. Subdomain typosquatting inverted (login.stanford.edu vs standford.edu).
26. Subdomain legitimate clean (login.stanford.edu vs stanford.edu).
27. Multi-level public suffix typosquatting (.co.uk).
28. Unrelated legitimate domain typosquatting.
29. Role impersonation false-positive elimination (John Smith matching IT, Dean Martin matching Dean).
30. Role impersonation true-positive authority claims (IT Administrator, University Dean).
31. RFC-compliant mailbox validation (quoted local-parts, plus-tagging, malformed quotes).
32. Inspection of all From and Reply-To mailboxes (secondary mailbox attacks).
33. Rule-level failure isolation in analyzer (partial status and failed rule tracking).
34. Delegated sender and mailing-list semantics (Sender header mismatch observation).
35. ScanService failure telemetry error masking and non-clean representation.
"""

from unittest.mock import patch
import pytest
from app.modules.contracts import IngestionSource, RawEmailPayload
from app.modules.identity.analyzer import SenderIdentityAnalyzer
from app.modules.identity.config import IdentityAnalysisConfig, VIPIdentity
from app.modules.parser.parser import EmailParser
from app.services.scan_service import scan_service


@pytest.fixture
def parser():
    return EmailParser()


@pytest.fixture
def analyzer():
    return SenderIdentityAnalyzer()


# ============================================================================
# Scenario 1: Valid Internal Sender
# ============================================================================
def test_01_valid_internal_sender(parser, analyzer):
    eml = b"""From: Alice Engineer <alice@techcorp.com>
To: Bob Manager <bob@techcorp.com>
Subject: Project Status Update
Return-Path: <alice@techcorp.com>
Reply-To: Alice Engineer <alice@techcorp.com>
Date: Wed, 25 Nov 2026 10:00:00 +0000

All tests are passing.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    config = IdentityAnalysisConfig(protected_domains=["techcorp.com"])
    result = analyzer.analyze_sync(parsed, config=config)

    assert result.envelope_header_match is True
    assert result.display_name_spoofed is False
    assert result.typosquatting_detected is False
    assert result.punycode_homoglyph_detected is False
    assert result.analysis_status == "COMPLETED"
    assert len(result.findings) == 0


# ============================================================================
# Scenario 2: Missing From Header
# ============================================================================
def test_02_missing_from(parser, analyzer):
    eml = b"""To: recipient@techcorp.com
Subject: System Automated Alert
Date: Wed, 25 Nov 2026 10:00:00 +0000

Notice without a From header field.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert any(f.indicator == "MISSING_FROM_HEADER" for f in result.findings)
    assert result.envelope_header_match is None


# ============================================================================
# Scenario 3: Malformed From
# ============================================================================
def test_03_malformed_from(parser, analyzer):
    eml = b"""From: <<<Invalid Sender Box Without Domain>>>
To: recipient@techcorp.com
Subject: Malformed Sender Address
Date: Wed, 25 Nov 2026 10:00:00 +0000

Testing malformed sender syntax.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert any(f.indicator == "MALFORMED_SENDER_ADDRESS" for f in result.findings)


# ============================================================================
# Scenario 4: Duplicate From Headers
# ============================================================================
def test_04_duplicate_from_headers(parser, analyzer):
    eml = b"""From: Legitimate Team <team@corp.com>
From: Attacker Injected <attacker@evil.com>
To: user@corp.com
Subject: Multi-From Header Test
Date: Wed, 25 Nov 2026 10:00:00 +0000

Email with two From headers.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert any(f.indicator == "DUPLICATE_FROM_HEADER" for f in result.findings)


# ============================================================================
# Scenario 5: Duplicate Reply-To Headers
# ============================================================================
def test_05_duplicate_reply_to_headers(parser, analyzer):
    eml = b"""From: service@corp.com
Reply-To: support1@corp.com
Reply-To: support2@corp.com
To: user@corp.com
Subject: Duplicate Reply-To Test
Date: Wed, 25 Nov 2026 10:00:00 +0000

Testing duplicate Reply-To headers.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert any(f.indicator == "DUPLICATE_REPLY_TO_HEADER" for f in result.findings)


# ============================================================================
# Scenario 6: Multiple From Mailboxes with a Valid Sender
# ============================================================================
def test_06_multiple_from_mailboxes_with_valid_sender(parser, analyzer):
    eml = b"""From: Alice <alice@corp.com>, Bob <bob@corp.com>
Sender: Agent <agent@corp.com>
To: user@corp.com
Subject: Joint Declaration
Date: Wed, 25 Nov 2026 10:00:00 +0000

RFC 5322 compliant joint message with designated Sender.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert any(f.indicator == "MULTIPLE_FROM_MAILBOXES" for f in result.findings)
    assert not any(f.indicator == "MISSING_SENDER_HEADER" for f in result.findings)


# ============================================================================
# Scenario 7: Multiple From Mailboxes Without Sender
# ============================================================================
def test_07_multiple_from_mailboxes_without_sender(parser, analyzer):
    eml = b"""From: Alice <alice@corp.com>, Bob <bob@corp.com>
To: user@corp.com
Subject: Missing Mandatory Sender
Date: Wed, 25 Nov 2026 10:00:00 +0000

From field has multiple mailboxes but no Sender header.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert any(f.indicator == "MISSING_SENDER_HEADER" for f in result.findings)


# ============================================================================
# Scenario 8: From and Reply-To Domain Mismatch
# ============================================================================
def test_08_from_and_reply_to_mismatch(parser, analyzer):
    eml = b"""From: Bank Support <no-reply@chase.com>
Reply-To: Fraud Assistance <chase-support@secure-resolve-tickets.net>
To: client@corp.com
Subject: Urgent Security Notice
Date: Wed, 25 Nov 2026 10:00:00 +0000

Please reply to resolve your account suspension.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert any(f.indicator == "FROM_REPLYTO_MISMATCH" for f in result.findings)
    mismatch_finding = next(f for f in result.findings if f.indicator == "FROM_REPLYTO_MISMATCH")
    assert "secure-resolve-tickets.net" in mismatch_finding.target_name


# ============================================================================
# Scenario 9: Legitimate Third-Party Return-Path (ESP Bounce Domain)
# ============================================================================
def test_09_legitimate_third_party_return_path(parser, analyzer):
    eml = b"""From: Weekly Newsletter <newsletter@company.com>
Return-Path: <bounces+12345-abc@sendgrid.net>
To: subscriber@corp.com
Subject: Weekly Digest
Date: Wed, 25 Nov 2026 10:00:00 +0000

Here is your weekly update.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    config = IdentityAnalysisConfig(recognized_esp_bounce_domains=["sendgrid.net"])
    result = analyzer.analyze_sync(parsed, config=config)

    # Per Requirement 8: ESP bounce domain does NOT authenticate the sender and does not match company.com
    assert result.envelope_header_match is False
    assert any(f.indicator == "RECOGNIZED_ESP_RETURN_PATH" for f in result.findings)
    assert not any(f.indicator == "FROM_RETURN_PATH_MISMATCH" for f in result.findings)


# ============================================================================
# Scenario 10: From and Return-Path Inconsistency (Unrecognized Return-Path)
# ============================================================================
def test_10_from_and_return_path_mismatch(parser, analyzer):
    eml = b"""From: Security Team <alerts@trustedbank.com>
Return-Path: <bounce@unrelated-malicious-domain.xyz>
To: victim@corp.com
Subject: Critical Alert
Date: Wed, 25 Nov 2026 10:00:00 +0000

Verify your password immediately.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert result.envelope_header_match is False
    assert any(f.indicator == "FROM_RETURN_PATH_MISMATCH" for f in result.findings)


# ============================================================================
# Scenario 11: Embedded Email Address in Display Name
# ============================================================================
def test_11_embedded_email_address_in_display_name(parser, analyzer):
    eml = b"""From: "PayPal Support <security@paypal.com>" <scammer123@free-mail-relay.org>
To: victim@corp.com
Subject: Account Limited
Date: Wed, 25 Nov 2026 10:00:00 +0000

Your account has been restricted.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert result.display_name_spoofed is True
    assert any(f.indicator == "DISPLAY_NAME_EMAIL_MISMATCH" for f in result.findings)
    embed_finding = next(f for f in result.findings if f.indicator == "DISPLAY_NAME_EMAIL_MISMATCH")
    assert embed_finding.target_name == "security@paypal.com"
    assert embed_finding.similarity_score == 1.0


# ============================================================================
# Scenario 12: Configured VIP Impersonation
# ============================================================================
def test_12_configured_vip_impersonation(parser, analyzer):
    eml = b"""From: "Marc Tessier-Lavigne (President)" <executive-office-temp@fast-free-mail.org>
To: cfo@targetcorp.com
Subject: Urgent Confidential Request
Date: Wed, 25 Nov 2026 10:00:00 +0000

Are you at your desk? Wire transfer required.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    config = IdentityAnalysisConfig(
        vip_identities=[
            VIPIdentity(
                name="Marc Tessier-Lavigne",
                titles=["President"],
                allowed_domains=["stanford.edu"],
            )
        ]
    )
    result = analyzer.analyze_sync(parsed, config=config)

    assert result.display_name_spoofed is True
    assert any(f.indicator == "VIP_IMPERSONATION" for f in result.findings)
    vip_finding = next(f for f in result.findings if f.indicator == "VIP_IMPERSONATION")
    assert vip_finding.is_vip is True
    assert vip_finding.target_name == "Marc Tessier-Lavigne"


# ============================================================================
# Scenario 13: Configured Organization Role Impersonation
# ============================================================================
def test_13_configured_organization_role_impersonation(parser, analyzer):
    eml = b"""From: "Office of the Dean" <admin@external-unauthorized.xyz>
To: student@university.edu
Subject: Important Faculty Notice
Date: Wed, 25 Nov 2026 10:00:00 +0000

Please review the attached academic notice.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    config = IdentityAnalysisConfig(
        protected_domains=["university.edu"],
        organizational_roles=["Office of the Dean", "IT Helpdesk"],
    )
    result = analyzer.analyze_sync(parsed, config=config)

    assert result.display_name_spoofed is True
    assert any(f.indicator == "ORGANIZATIONAL_ROLE_IMPERSONATION" for f in result.findings)
    role_finding = next(f for f in result.findings if f.indicator == "ORGANIZATIONAL_ROLE_IMPERSONATION")
    assert role_finding.target_name == "Office of the Dean"
    assert role_finding.is_vip is False


# ============================================================================
# Scenario 14: Punycode Domain Indicator
# ============================================================================
def test_14_punycode_domain_indicator(parser, analyzer):
    eml = b"""From: Security Team <alerts@xn--pple-43d.com>
To: user@corp.com
Subject: Security Verification
Date: Wed, 25 Nov 2026 10:00:00 +0000

Punycode encoded domain.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert result.punycode_detected is True
    assert result.punycode_homoglyph_detected is True
    assert any(f.indicator == "PUNYCODE_DOMAIN_LABEL" for f in result.findings)


# ============================================================================
# Scenario 15: Mixed-Script Domain Indicator
# ============================================================================
def test_15_mixed_script_domain_indicator(parser, analyzer):
    # Domain with Cyrillic 'о' (U+043E) embedded in Latin characters
    eml = "From: Account Verification <support@g\u043e\u043egle.com>\nTo: user@corp.com\nSubject: Security\n\nVerify now.".encode("utf-8")
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert result.homoglyph_detected is True
    assert any(f.indicator == "MIXED_SCRIPT_DOMAIN" for f in result.findings)


# ============================================================================
# Scenario 16: Configured Typosquatting Detection
# ============================================================================
def test_16_configured_typosquatting_detection(parser, analyzer):
    eml = b"""From: Registrar <registrar@standford.edu>
To: student@stanford.edu
Subject: Registration Schedule
Date: Wed, 25 Nov 2026 10:00:00 +0000

Review the final exam schedule.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    config = IdentityAnalysisConfig(protected_domains=["stanford.edu"])
    result = analyzer.analyze_sync(parsed, config=config)

    assert result.typosquatting_detected is True
    assert any(f.indicator == "TYPOSQUATTING_LOOKALIKE_DOMAIN" for f in result.findings)
    typo_finding = next(f for f in result.findings if f.indicator == "TYPOSQUATTING_LOOKALIKE_DOMAIN")
    assert typo_finding.target_name == "stanford.edu"
    assert typo_finding.similarity_score >= 0.80


# ============================================================================
# Scenario 17: Legitimate Protected Domain (No False Positive Typosquat)
# ============================================================================
def test_17_legitimate_protected_domain(parser, analyzer):
    eml = b"""From: Registrar <registrar@stanford.edu>
To: student@stanford.edu
Subject: Genuine Schedule
Return-Path: <registrar@stanford.edu>
Date: Wed, 25 Nov 2026 10:00:00 +0000

Authentic announcement.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    config = IdentityAnalysisConfig(protected_domains=["stanford.edu"])
    result = analyzer.analyze_sync(parsed, config=config)

    assert result.typosquatting_detected is False
    assert not any(f.indicator == "TYPOSQUATTING_LOOKALIKE_DOMAIN" for f in result.findings)


# ============================================================================
# Scenario 18: Unicode Control Characters
# ============================================================================
def test_18_unicode_control_characters(parser, analyzer):
    # Right-to-Left Override (U+202E) inside display name
    eml = "From: \"IT Support\u202epdf.exe\" <admin@corp.com>\nTo: user@corp.com\nSubject: Test\n\nBody".encode("utf-8")
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert any(f.indicator == "SUSPICIOUS_UNICODE_CHARACTERS" for f in result.findings)


# ============================================================================
# Scenario 19: Excessively Long Input (Safe Bounding)
# ============================================================================
def test_19_excessively_long_input(parser, analyzer):
    giant_name = "A" * 5000
    eml = f"From: \"{giant_name}\" <user@domain.com>\nSubject: Stress Test\n\nBody".encode("utf-8")
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    for f in result.findings:
        assert len(f.description) <= 500
        if f.target_name:
            assert len(f.target_name) <= 255


# ============================================================================
# Scenario 20: Finding-Count Limit (Capped at max_findings)
# ============================================================================
def test_20_finding_count_limit(parser, analyzer):
    eml = b"""From: "Marc Tessier <sec@paypal.com>" <scammer@standford.edu>
From: Injected <other@evil.com>
Reply-To: r1@evil.com
Reply-To: r2@evil.com
Return-Path: <bounce@unrelated.net>
Subject: Multi Anomaly
Date: Wed, 25 Nov 2026 10:00:00 +0000

Testing findings cap.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    config = IdentityAnalysisConfig(
        max_findings=3,
        protected_domains=["stanford.edu"],
        vip_identities=[VIPIdentity(name="Marc Tessier", allowed_domains=["stanford.edu"])],
    )
    result = analyzer.analyze_sync(parsed, config=config)

    assert len(result.findings) == 3


# ============================================================================
# Scenario 21: Missing Optional Headers (Safe Degradation & Unavailable Return-Path)
# ============================================================================
def test_21_missing_optional_headers(parser, analyzer):
    eml = b"""From: simple@domain.com

Minimal message with no Subject, Date, Message-ID, Reply-To, or Return-Path.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    assert result is not None
    # Per Requirement 5: Return-Path is missing/empty, so envelope_header_match is None (unavailable)
    assert result.envelope_header_match is None
    assert any(f.indicator == "EMPTY_RETURN_PATH" for f in result.findings)
    assert isinstance(result.findings, list)


# ============================================================================
# Scenario 22: Deterministic Repeated Analysis
# ============================================================================
def test_22_deterministic_repeated_analysis(parser, analyzer):
    eml = b"""From: "Support Team" <support@chase.com>
Reply-To: tickets@resolve-center.org
Return-Path: <bounce@untrusted.xyz>
Subject: Repeated Determinism Test
Date: Wed, 25 Nov 2026 10:00:00 +0000

Deterministic output verification.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    config = IdentityAnalysisConfig(
        protected_domains=["chase.com"],
        organizational_roles=["Support Team"],
    )

    result_1 = analyzer.analyze_sync(parsed, config=config)
    result_2 = analyzer.analyze_sync(parsed, config=config)

    assert result_1.model_dump() == result_2.model_dump()


# ============================================================================
# Scenario 23: ScanService Telemetry Integration
# ============================================================================
@pytest.mark.asyncio
async def test_23_scan_service_telemetry_integration(db_session):
    eml = b"""From: "Dean Office" <dean@fake-university-login.xyz>
Reply-To: collector@free-inbox.net
To: faculty@stanford.edu
Subject: Faculty Mandatory Survey
Return-Path: <bounce-99@fake-university-login.xyz>
Date: Wed, 25 Nov 2026 10:00:00 +0000

Please review the link below.
"""
    incident, parsed = await scan_service.ingest_and_parse(
        raw_bytes=eml,
        filename="dean_spoof.eml",
        source=IngestionSource.DIRECT_UPLOAD,
        db=db_session,
    )

    assert incident is not None
    assert "identity_analysis" in incident.telemetry
    identity_data = incident.telemetry["identity_analysis"]
    assert identity_data["analysis_status"] == "COMPLETED"
    assert identity_data["envelope_header_match"] is True
    assert "display_name_spoofed" in identity_data
    assert isinstance(identity_data["findings"], list)
    indicators = [f["indicator"] for f in identity_data["findings"]]
    assert "FROM_REPLYTO_MISMATCH" in indicators


# ============================================================================
# Scenario 24: Subdomain Typosquatting (login.standford.edu vs stanford.edu)
# ============================================================================
def test_24_subdomain_typosquatting_lookalike(parser, analyzer):
    eml = b"""From: Portal <auth@login.standford.edu>
To: user@stanford.edu
Subject: Security Verification
Date: Wed, 25 Nov 2026 10:00:00 +0000

Click here to verify.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    config = IdentityAnalysisConfig(protected_domains=["stanford.edu"])
    result = analyzer.analyze_sync(parsed, config=config)

    assert result.typosquatting_detected is True
    assert any(f.indicator == "TYPOSQUATTING_LOOKALIKE_DOMAIN" for f in result.findings)
    finding = next(f for f in result.findings if f.indicator == "TYPOSQUATTING_LOOKALIKE_DOMAIN")
    assert finding.target_name == "stanford.edu"
    assert "standford.edu" in finding.description


# ============================================================================
# Scenario 25: Subdomain Typosquatting Inverted (login.stanford.edu vs standford.edu)
# ============================================================================
def test_25_subdomain_typosquatting_inverted(parser, analyzer):
    eml = b"""From: Stanford Admin <admin@login.stanford.edu>
To: user@standford.edu
Subject: Notice
Date: Wed, 25 Nov 2026 10:00:00 +0000

Notice text.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    config = IdentityAnalysisConfig(protected_domains=["standford.edu"])
    result = analyzer.analyze_sync(parsed, config=config)

    assert result.typosquatting_detected is True
    assert any(f.indicator == "TYPOSQUATTING_LOOKALIKE_DOMAIN" for f in result.findings)


# ============================================================================
# Scenario 26: Legitimate Subdomain (login.stanford.edu vs stanford.edu is CLEAN)
# ============================================================================
def test_26_subdomain_legitimate_clean(parser, analyzer):
    eml = b"""From: Stanford Single Sign-On <sso@login.stanford.edu>
To: student@stanford.edu
Subject: Login Confirmation
Date: Wed, 25 Nov 2026 10:00:00 +0000

Login confirmed.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    config = IdentityAnalysisConfig(protected_domains=["stanford.edu"])
    result = analyzer.analyze_sync(parsed, config=config)

    assert result.typosquatting_detected is False
    assert not any(f.indicator == "TYPOSQUATTING_LOOKALIKE_DOMAIN" for f in result.findings)


# ============================================================================
# Scenario 27: Multi-Level Public Suffix Typosquatting (.co.uk)
# ============================================================================
def test_27_multilevel_public_suffix_typosquatting(parser, analyzer):
    # login.standford.co.uk vs stanford.co.uk -> TYPOSQUAT
    eml_bad = b"""From: UK Office <admin@login.standford.co.uk>
To: user@stanford.co.uk
Subject: UK Schedule
Date: Wed, 25 Nov 2026 10:00:00 +0000

Schedule attached.
"""
    parsed_bad = parser.parse(RawEmailPayload(raw_bytes=eml_bad))
    config = IdentityAnalysisConfig(protected_domains=["stanford.co.uk"])
    result_bad = analyzer.analyze_sync(parsed_bad, config=config)

    assert result_bad.typosquatting_detected is True
    assert any(f.indicator == "TYPOSQUATTING_LOOKALIKE_DOMAIN" for f in result_bad.findings)

    # login.stanford.co.uk vs stanford.co.uk -> LEGITIMATE SUBDOMAIN
    eml_good = b"""From: UK Portal <portal@login.stanford.co.uk>
To: user@stanford.co.uk
Subject: UK Portal
Date: Wed, 25 Nov 2026 10:00:00 +0000

Portal update.
"""
    parsed_good = parser.parse(RawEmailPayload(raw_bytes=eml_good))
    result_good = analyzer.analyze_sync(parsed_good, config=config)

    assert result_good.typosquatting_detected is False
    assert not any(f.indicator == "TYPOSQUATTING_LOOKALIKE_DOMAIN" for f in result_good.findings)


# ============================================================================
# Scenario 28: Unrelated Legitimate Domain (No False Positive Typosquat)
# ============================================================================
def test_28_unrelated_domain_typosquatting(parser, analyzer):
    eml = b"""From: Google Workspace <workspace-noreply@google.com>
To: admin@stanford.edu
Subject: Cloud Billing
Date: Wed, 25 Nov 2026 10:00:00 +0000

Invoice available.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    config = IdentityAnalysisConfig(protected_domains=["stanford.edu"])
    result = analyzer.analyze_sync(parsed, config=config)

    assert result.typosquatting_detected is False
    assert not any(f.indicator == "TYPOSQUATTING_LOOKALIKE_DOMAIN" for f in result.findings)


# ============================================================================
# Scenario 29: Role Impersonation False Positive Elimination (John Smith & Dean Martin)
# ============================================================================
def test_29_role_impersonation_false_positives(parser, analyzer):
    # 'John Smith' matching 'IT' role
    eml_smith = b"""From: "John Smith" <john.smith@gmail.com>
To: user@corp.com
Subject: Personal Hello
Date: Wed, 25 Nov 2026 10:00:00 +0000

Hello from John Smith.
"""
    parsed_smith = parser.parse(RawEmailPayload(raw_bytes=eml_smith))
    config_it = IdentityAnalysisConfig(
        protected_domains=["corp.com"],
        organizational_roles=["IT"],
    )
    result_smith = analyzer.analyze_sync(parsed_smith, config=config_it)

    assert result_smith.display_name_spoofed is False
    assert not any(f.indicator == "ORGANIZATIONAL_ROLE_IMPERSONATION" for f in result_smith.findings)

    # 'Dean Martin' matching 'Dean' role
    eml_dean = b"""From: "Dean Martin" <dean.martin@gmail.com>
To: user@corp.com
Subject: Singer Track
Date: Wed, 25 Nov 2026 10:00:00 +0000

Music notes.
"""
    parsed_dean = parser.parse(RawEmailPayload(raw_bytes=eml_dean))
    config_dean = IdentityAnalysisConfig(
        protected_domains=["corp.com"],
        organizational_roles=["Dean"],
    )
    result_dean = analyzer.analyze_sync(parsed_dean, config=config_dean)

    assert result_dean.display_name_spoofed is False
    assert not any(f.indicator == "ORGANIZATIONAL_ROLE_IMPERSONATION" for f in result_dean.findings)


# ============================================================================
# Scenario 30: Role Impersonation True Positives (IT Administrator, University Dean)
# ============================================================================
def test_30_role_impersonation_true_positives(parser, analyzer):
    # 'IT Administrator'
    eml_it = b"""From: "IT Administrator" <support@external-phish.net>
To: employee@corp.com
Subject: Password Expiry
Date: Wed, 25 Nov 2026 10:00:00 +0000

Reset immediately.
"""
    parsed_it = parser.parse(RawEmailPayload(raw_bytes=eml_it))
    config = IdentityAnalysisConfig(
        protected_domains=["corp.com"],
        organizational_roles=["IT", "Dean"],
    )
    result_it = analyzer.analyze_sync(parsed_it, config=config)

    assert result_it.display_name_spoofed is True
    assert any(f.indicator == "ORGANIZATIONAL_ROLE_IMPERSONATION" for f in result_it.findings)

    # 'University Dean'
    eml_dean = b"""From: "University Dean" <dean@external-phish.net>
To: student@corp.com
Subject: Academic Standing
Date: Wed, 25 Nov 2026 10:00:00 +0000

Review standing.
"""
    parsed_dean = parser.parse(RawEmailPayload(raw_bytes=eml_dean))
    result_dean = analyzer.analyze_sync(parsed_dean, config=config)

    assert result_dean.display_name_spoofed is True
    assert any(f.indicator == "ORGANIZATIONAL_ROLE_IMPERSONATION" for f in result_dean.findings)


# ============================================================================
# Scenario 31: RFC-Compliant Mailbox Syntax (Quoted Local-Part & Validation)
# ============================================================================
def test_31_rfc_compliant_mailbox_validation(parser, analyzer):
    # Valid: Quoted local-part with space
    eml_quoted = b"""From: "john smith"@example.com
To: user@corp.com
Subject: Quoted Local Part
Date: Wed, 25 Nov 2026 10:00:00 +0000

Testing RFC 5322 quoted local-part.
"""
    parsed_quoted = parser.parse(RawEmailPayload(raw_bytes=eml_quoted))
    result_quoted = analyzer.analyze_sync(parsed_quoted)
    assert not any(f.indicator == "MALFORMED_SENDER_ADDRESS" for f in result_quoted.findings)

    # Valid: Plus-tagging / subaddressing
    eml_tag = b"""From: john+security@example.com
To: user@corp.com
Subject: Tagged Address
Date: Wed, 25 Nov 2026 10:00:00 +0000

Testing plus-tagged address.
"""
    parsed_tag = parser.parse(RawEmailPayload(raw_bytes=eml_tag))
    result_tag = analyzer.analyze_sync(parsed_tag)
    assert not any(f.indicator == "MALFORMED_SENDER_ADDRESS" for f in result_tag.findings)

    # Invalid: Double @ symbol
    eml_double = b"""From: invalid@@example.com
To: user@corp.com
Subject: Double At
Date: Wed, 25 Nov 2026 10:00:00 +0000

Testing double @.
"""
    parsed_double = parser.parse(RawEmailPayload(raw_bytes=eml_double))
    result_double = analyzer.analyze_sync(parsed_double)
    assert any(f.indicator == "MALFORMED_SENDER_ADDRESS" for f in result_double.findings)

    # Invalid: Missing domain (john@)
    eml_nodom = b"""From: john@
To: user@corp.com
Subject: No Domain
Date: Wed, 25 Nov 2026 10:00:00 +0000

Testing no domain.
"""
    parsed_nodom = parser.parse(RawEmailPayload(raw_bytes=eml_nodom))
    result_nodom = analyzer.analyze_sync(parsed_nodom)
    assert any(f.indicator == "MALFORMED_SENDER_ADDRESS" for f in result_nodom.findings)


# ============================================================================
# Scenario 32: Inspect All From and Reply-To Mailboxes (Secondary Mailbox Checks)
# ============================================================================
def test_32_inspect_all_mailboxes_secondary_attack(parser, analyzer):
    # From has legitimate first address, but second address is typosquat!
    eml_from = b"""From: Alice <alice@stanford.edu>, Attacker <infiltrator@standford.edu>
Sender: Agent <agent@stanford.edu>
To: user@stanford.edu
Subject: Multi From Injection
Date: Wed, 25 Nov 2026 10:00:00 +0000

Testing secondary From inspection.
"""
    parsed_from = parser.parse(RawEmailPayload(raw_bytes=eml_from))
    config = IdentityAnalysisConfig(protected_domains=["stanford.edu"])
    result_from = analyzer.analyze_sync(parsed_from, config=config)

    # Even though first From address is stanford.edu, second From address standford.edu triggers typosquat!
    assert result_from.typosquatting_detected is True
    assert any(f.indicator == "TYPOSQUATTING_LOOKALIKE_DOMAIN" for f in result_from.findings)

    # Reply-To has legitimate first address, but second address is phish mismatch!
    eml_rt = b"""From: Support <support@company.com>
Reply-To: Support Desk <support@company.com>, Harvest <credential-harvester@phish.net>
To: user@company.com
Subject: Account Update
Date: Wed, 25 Nov 2026 10:00:00 +0000

Testing secondary Reply-To inspection.
"""
    parsed_rt = parser.parse(RawEmailPayload(raw_bytes=eml_rt))
    result_rt = analyzer.analyze_sync(parsed_rt)

    assert any(f.indicator == "FROM_REPLYTO_MISMATCH" for f in result_rt.findings)
    mismatch_findings = [f for f in result_rt.findings if f.indicator == "FROM_REPLYTO_MISMATCH"]
    assert any("phish.net" in f.target_name for f in mismatch_findings)


# ============================================================================
# Scenario 33: Rule-Level Failure Isolation in Analyzer
# ============================================================================
def test_33_rule_level_failure_isolation(parser, analyzer):
    eml = b"""From: "Marc Tessier" <marc@fast-mail.org>
Reply-To: collector@evil.com
Subject: Test Isolation
Date: Wed, 25 Nov 2026 10:00:00 +0000

Testing failure isolation.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    config = IdentityAnalysisConfig(
        vip_identities=[VIPIdentity(name="Marc Tessier", allowed_domains=["stanford.edu"])]
    )

    # Mock check_header_integrity to simulate unexpected runtime crash
    with patch(
        "app.modules.identity.analyzer.check_header_integrity",
        side_effect=RuntimeError("Simulated header integrity database fault"),
    ):
        result = analyzer.analyze_sync(parsed, config=config)

        # Status must be PARTIAL, not crashed
        assert result.analysis_status == "PARTIAL"
        assert "header_integrity" in result.failed_rules
        # Other rules must have executed successfully!
        assert result.display_name_spoofed is True
        assert any(f.indicator == "VIP_IMPERSONATION" for f in result.findings)
        assert any(f.indicator == "FROM_REPLYTO_MISMATCH" for f in result.findings)


# ============================================================================
# Scenario 34: Delegated Sender and Mailing-List Semantics
# ============================================================================
def test_34_delegated_sender_mailing_list_semantics(parser, analyzer):
    eml = b"""From: Author <author@gmail.com>
Sender: IETF List <list-bounces@ietf.org>
To: subscribers@ietf.org
Subject: [IETF] Working Group Draft
Date: Wed, 25 Nov 2026 10:00:00 +0000

Draft text.
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    result = analyzer.analyze_sync(parsed)

    # Discrepancy between author and transmitting agent is noted as observation, not malice
    assert any(f.indicator == "SENDER_FROM_MISMATCH" for f in result.findings)
    mismatch_finding = next(f for f in result.findings if f.indicator == "SENDER_FROM_MISMATCH")
    assert "ietf.org" in mismatch_finding.target_name or "list-bounces@ietf.org" in mismatch_finding.target_name
    assert "delegation" in mismatch_finding.description.lower() or "mailing list" in mismatch_finding.description.lower()


# ============================================================================
# Scenario 35: ScanService Failure Telemetry Masks Raw Error and Sets Status
# ============================================================================
@pytest.mark.asyncio
async def test_35_scan_service_failure_telemetry_masking(db_session):
    eml = b"""From: user@example.com
To: target@example.com
Subject: Failure Masking Test
Date: Wed, 25 Nov 2026 10:00:00 +0000

Testing failure telemetry.
"""
    # Mock analyzer.analyze to simulate fatal exception
    with patch.object(
        scan_service.identity_analyzer,
        "analyze",
        side_effect=Exception("Database password in stack: secret_db_pass_1234"),
    ):
        incident, parsed = await scan_service.ingest_and_parse(
            raw_bytes=eml,
            filename="fail_test.eml",
            db=db_session,
        )

        assert incident is not None
        assert "identity_analysis" in incident.telemetry
        identity_telemetry = incident.telemetry["identity_analysis"]

        # Failure status is explicit, not represented as clean
        assert identity_telemetry["analysis_status"] == "FAILED"
        assert identity_telemetry["envelope_header_match"] is None
        assert identity_telemetry["failed_rules"] == ["identity_analyzer"]
        # Raw internal exception / credentials must NOT be in client telemetry
        assert "secret_db_pass" not in identity_telemetry["error"]
        assert "internal error" in identity_telemetry["error"].lower()
