"""Focused Regression Tests for RiskEngine Header Integrity Signal Integration.

Verifies:
1. Malformed sender address contributes an appropriate risk signal.
2. Duplicate From header contributes an appropriate risk signal.
3. Missing From header is handled correctly as a structural defect.
4. Absent Return-Path alone does not automatically classify an email as malicious or suspicious.
5. Normal email with valid headers remains CLEAN when no other suspicious signals exist.
6. Existing VIP impersonation, domain mismatch, and URL-risk behavior remains unchanged.
7. Findings are not counted twice (deduplication of redundant findings for the same underlying issue).
8. Multiple distinct header anomalies contribute distinct corroborating signals.
9. Structural header integrity signals corroborate without overriding higher-severity MALICIOUS tiers.
"""

import pytest
from app.models.scan import RiskTier
from app.modules.contracts import (
    IdentityAnalysisResult,
    ImpersonationFinding,
    RawEmailPayload,
    UrlAnalysisResult,
    UrlFinding,
    UrlRiskSeverity,
)
from app.modules.identity.analyzer import SenderIdentityAnalyzer
from app.modules.identity.config import IdentityAnalysisConfig, VIPIdentity
from app.modules.parser.parser import EmailParser
from app.modules.risk_engine.engine import RiskEngine


@pytest.fixture
def parser():
    return EmailParser()


@pytest.fixture
def identity_analyzer():
    return SenderIdentityAnalyzer(
        default_config=IdentityAnalysisConfig(
            vip_identities=[
                VIPIdentity(
                    name="Marc Tessier-Lavigne",
                    titles=["President"],
                    allowed_domains=["stanford.edu"],
                )
            ],
            protected_domains=["corp.com", "stanford.edu"],
        )
    )


@pytest.fixture
def risk_engine():
    return RiskEngine()


# ============================================================================
# 1. Malformed Sender Address Contributes Risk Signal
# ============================================================================
def test_malformed_sender_address_contributes_risk_signal(parser, identity_analyzer, risk_engine):
    """Adversarial email with XSS/angle-bracket injection in From address is flagged SUSPICIOUS."""
    eml = (
        b'From: <"test<marquee onstart=alert(/xss/)></marquee>@attack.com">\r\n'
        b"To: victim@corp.com\r\n"
        b"Subject: Urgent Account Notification\r\n"
        b"Date: Wed, 28 Nov 2026 10:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please review your account immediately."
    )
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    id_result = identity_analyzer.analyze_sync(parsed)

    assert any(f.indicator == "MALFORMED_SENDER_ADDRESS" for f in id_result.findings)

    score, tier, summary, assessment = risk_engine.evaluate(identity_result=id_result)

    assert tier == RiskTier.SUSPICIOUS
    assert 55.0 <= score <= 74.0
    signals = assessment["contributing_signals"]
    assert any("[IDENTITY-HEADER-INTEGRITY] MALFORMED_SENDER_ADDRESS" in s for s in signals)
    assert "SUSPICIOUS EMAIL" in summary


# ============================================================================
# 2. Duplicate From Header Contributes Risk Signal
# ============================================================================
def test_duplicate_from_header_contributes_risk_signal(parser, identity_analyzer, risk_engine):
    """Adversarial email with duplicate From header lines is flagged SUSPICIOUS."""
    eml = (
        b"From: Legitimate Team <team@corp.com>\r\n"
        b"From: Attacker Injected <attacker@evil.com>\r\n"
        b"To: user@corp.com\r\n"
        b"Subject: Multi-From Header Test\r\n"
        b"Date: Wed, 28 Nov 2026 10:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Notice the double From header injection."
    )
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    id_result = identity_analyzer.analyze_sync(parsed)

    assert any(f.indicator == "DUPLICATE_FROM_HEADER" for f in id_result.findings)

    score, tier, summary, assessment = risk_engine.evaluate(identity_result=id_result)

    assert tier == RiskTier.SUSPICIOUS
    assert 55.0 <= score <= 74.0
    signals = assessment["contributing_signals"]
    assert any("[IDENTITY-HEADER-INTEGRITY] DUPLICATE_FROM_HEADER" in s for s in signals)
    assert "SUSPICIOUS EMAIL" in summary


# ============================================================================
# 3. Missing From Header Contributes Risk Signal
# ============================================================================
def test_missing_from_header_contributes_risk_signal(parser, identity_analyzer, risk_engine):
    """Email missing the mandatory RFC 5322 From header is flagged SUSPICIOUS."""
    eml = (
        b"To: user@corp.com\r\n"
        b"Subject: Orphan Email Without Sender\r\n"
        b"Date: Wed, 28 Nov 2026 10:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Message body with no From header present."
    )
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    id_result = identity_analyzer.analyze_sync(parsed)

    assert any(f.indicator == "MISSING_FROM_HEADER" for f in id_result.findings)

    score, tier, summary, assessment = risk_engine.evaluate(identity_result=id_result)

    assert tier == RiskTier.SUSPICIOUS
    assert 55.0 <= score <= 74.0
    signals = assessment["contributing_signals"]
    assert any("[IDENTITY-HEADER-INTEGRITY] MISSING_FROM_HEADER" in s for s in signals)


# ============================================================================
# 4. Absent Return-Path Alone Does Not Classify Email as Suspicious/Malicious
# ============================================================================
def test_absent_return_path_alone_remains_clean(parser, identity_analyzer, risk_engine):
    """Normal email without Return-Path emits EMPTY_RETURN_PATH but MUST remain CLEAN."""
    eml = (
        b"From: Alice Smith <alice@corp.com>\r\n"
        b"To: bob@corp.com\r\n"
        b"Subject: Project Status Update\r\n"
        b"Date: Wed, 28 Nov 2026 10:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Here is the weekly update. Everything is on schedule."
    )
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    id_result = identity_analyzer.analyze_sync(parsed)

    # Confirm analyzer noted the absent return-path
    assert any(f.indicator == "EMPTY_RETURN_PATH" for f in id_result.findings)

    # Confirm risk engine does NOT penalize absent Return-Path
    score, tier, summary, assessment = risk_engine.evaluate(identity_result=id_result)

    assert tier == RiskTier.CLEAN
    assert score == 0.0
    assert assessment["contributing_signals"] == []
    assert "CLEAN EMAIL" in summary


# ============================================================================
# 5. Normal Email With Valid Headers Remains CLEAN
# ============================================================================
def test_normal_email_with_valid_headers_remains_clean(parser, identity_analyzer, risk_engine):
    """Completely normal email with valid headers evaluates as CLEAN with 0.0 score."""
    eml = (
        b"Return-Path: <alice@corp.com>\r\n"
        b"From: Alice Smith <alice@corp.com>\r\n"
        b"To: bob@corp.com\r\n"
        b"Subject: Team Sync Notes\r\n"
        b"Date: Wed, 28 Nov 2026 10:00:00 +0000\r\n"
        b"Message-ID: <msg12345@corp.com>\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Notes from today's discussion."
    )
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    id_result = identity_analyzer.analyze_sync(parsed)

    assert len(id_result.findings) == 0

    score, tier, summary, assessment = risk_engine.evaluate(identity_result=id_result)

    assert tier == RiskTier.CLEAN
    assert score == 0.0
    assert assessment["contributing_signals"] == []
    assert "CLEAN EMAIL" in summary


# ============================================================================
# 6. Existing Impersonation & Mismatch Scoring Remains Unchanged
# ============================================================================
def test_existing_vip_impersonation_scoring_unchanged(parser, identity_analyzer, risk_engine):
    """VIP impersonation continues to score as MALICIOUS with base score 80.0+."""
    eml = (
        b'From: "Marc Tessier-Lavigne (President)" <executive-office-temp@fast-free-mail.org>\r\n'
        b"To: employee@corp.com\r\n"
        b"Subject: Immediate Wire Transfer Required\r\n"
        b"Date: Wed, 28 Nov 2026 10:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please execute the attached invoice immediately."
    )
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    id_result = identity_analyzer.analyze_sync(parsed)

    assert any(f.indicator == "VIP_IMPERSONATION" for f in id_result.findings)

    score, tier, summary, assessment = risk_engine.evaluate(identity_result=id_result)

    assert tier == RiskTier.MALICIOUS
    assert score >= 80.0
    assert any("[IDENTITY-IMPERSONATION] VIP_IMPERSONATION" in s for s in assessment["contributing_signals"])


def test_existing_from_replyto_mismatch_scoring_unchanged(parser, identity_analyzer, risk_engine):
    """From and Reply-To mismatch continues to score as SUSPICIOUS with base score 55.0+."""
    eml = (
        b"From: Billing Support <support@corp.com>\r\n"
        b"Reply-To: Payment Collector <collector@unrelated-external.net>\r\n"
        b"To: client@corp.com\r\n"
        b"Subject: Invoice Dispute Resolution\r\n"
        b"Date: Wed, 28 Nov 2026 10:00:00 +0000\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please reply to this message regarding your invoice."
    )
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    id_result = identity_analyzer.analyze_sync(parsed)

    assert any(f.indicator == "FROM_REPLYTO_MISMATCH" for f in id_result.findings)

    score, tier, summary, assessment = risk_engine.evaluate(identity_result=id_result)

    assert tier == RiskTier.SUSPICIOUS
    assert 55.0 <= score <= 74.0
    assert any("[IDENTITY-MISMATCH] FROM_REPLYTO_MISMATCH" in s for s in assessment["contributing_signals"])


# ============================================================================
# 7. Existing URL-Risk Behavior Remains Unchanged
# ============================================================================
def test_existing_url_risk_behavior_unchanged(risk_engine):
    """Standalone URL analysis findings continue to produce expected risk tiers."""
    # Malicious URL
    mal_url_res = UrlAnalysisResult(
        total_urls=1,
        highest_severity=UrlRiskSeverity.MALICIOUS,
        analysis_status="COMPLETED",
        findings=[
            UrlFinding(
                url="http://credential-harvest.com/login",
                defanged_url="hxxp://credential-harvest[.]com/login",
                severity=UrlRiskSeverity.MALICIOUS,
                reason="Credential harvesting lure detected",
            )
        ],
    )
    score, tier, summary, assessment = risk_engine.evaluate(url_result=mal_url_res)
    assert tier == RiskTier.MALICIOUS
    assert score >= 85.0
    assert any("[URL-MALICIOUS]" in s for s in assessment["contributing_signals"])

    # Suspicious URL
    susp_url_res = UrlAnalysisResult(
        total_urls=1,
        highest_severity=UrlRiskSeverity.SUSPICIOUS,
        analysis_status="COMPLETED",
        findings=[
            UrlFinding(
                url="http://suspicious-redirect.com/link",
                defanged_url="hxxp://suspicious-redirect[.]com/link",
                severity=UrlRiskSeverity.SUSPICIOUS,
                reason="Suspicious redirect chain",
            )
        ],
    )
    score, tier, summary, assessment = risk_engine.evaluate(url_result=susp_url_res)
    assert tier == RiskTier.SUSPICIOUS
    assert 45.0 <= score <= 74.0
    assert any("[URL-SUSPICIOUS]" in s for s in assessment["contributing_signals"])


# ============================================================================
# 8. Findings Are Not Counted Twice (Deduplication)
# ============================================================================
def test_findings_are_not_counted_twice(risk_engine):
    """Redundant findings for the same underlying header defect do not inflate score or signals."""
    # Simulate an IdentityAnalysisResult with 2 MALFORMED_SENDER_ADDRESS findings
    # (e.g. from_sender raw representation vs all_from_senders parsed representation)
    id_result = IdentityAnalysisResult(
        analysis_status="COMPLETED",
        findings=[
            ImpersonationFinding(
                indicator="MALFORMED_SENDER_ADDRESS",
                target_name='"test<marquee>@attack.com"',
                similarity_score=0.0,
                description="Sender address '\"test<marquee>@attack.com\"' does not conform to RFC 5322 mailbox syntax.",
                is_vip=False,
            ),
            ImpersonationFinding(
                indicator="MALFORMED_SENDER_ADDRESS",
                target_name="test<marquee>@attack.com",
                similarity_score=0.0,
                description="Sender address 'test<marquee>@attack.com' does not conform to RFC 5322 mailbox syntax.",
                is_vip=False,
            ),
        ],
    )

    score, tier, summary, assessment = risk_engine.evaluate(identity_result=id_result)

    assert tier == RiskTier.SUSPICIOUS
    signals = assessment["contributing_signals"]
    malformed_signals = [s for s in signals if "MALFORMED_SENDER_ADDRESS" in s]
    # Proves exactly one signal was added, not two
    assert len(malformed_signals) == 1
    assert len(signals) == 1
    # Proves score is 55.0 + 1 * 2.0 = 57.0, NOT 59.0 (which would occur if double-counted)
    assert score == 57.0


# ============================================================================
# 9. Multiple Distinct Header Anomalies Contribute Distinct Signals
# ============================================================================
def test_multiple_distinct_header_anomalies_contribute_distinct_signals(risk_engine):
    """Two distinct header anomalies each contribute their own signal and increment score."""
    id_result = IdentityAnalysisResult(
        analysis_status="COMPLETED",
        findings=[
            ImpersonationFinding(
                indicator="MALFORMED_SENDER_ADDRESS",
                target_name="bad@@domain.com",
                similarity_score=0.0,
                description="Sender address 'bad@@domain.com' does not conform to RFC 5322 mailbox syntax.",
                is_vip=False,
            ),
            ImpersonationFinding(
                indicator="DUPLICATE_FROM_HEADER",
                target_name=None,
                similarity_score=0.0,
                description="Email contains 2 separate 'From' headers.",
                is_vip=False,
            ),
        ],
    )

    score, tier, summary, assessment = risk_engine.evaluate(identity_result=id_result)

    assert tier == RiskTier.SUSPICIOUS
    signals = assessment["contributing_signals"]
    assert len(signals) == 2
    assert any("MALFORMED_SENDER_ADDRESS" in s for s in signals)
    assert any("DUPLICATE_FROM_HEADER" in s for s in signals)
    # Base 55.0 + 2 * 2.0 = 59.0
    assert score == 59.0


# ============================================================================
# 10. Header Integrity Signals Do Not Override Higher Severity MALICIOUS Tier
# ============================================================================
def test_header_integrity_does_not_override_malicious_tier(risk_engine):
    """A header integrity finding corroborates but does not downgrade a MALICIOUS tier."""
    id_result = IdentityAnalysisResult(
        analysis_status="COMPLETED",
        findings=[
            ImpersonationFinding(
                indicator="MALFORMED_SENDER_ADDRESS",
                target_name="bad@@domain.com",
                similarity_score=0.0,
                description="Sender address 'bad@@domain.com' does not conform to RFC 5322 mailbox syntax.",
                is_vip=False,
            ),
        ],
    )
    url_result = UrlAnalysisResult(
        total_urls=1,
        highest_severity=UrlRiskSeverity.MALICIOUS,
        analysis_status="COMPLETED",
        findings=[
            UrlFinding(
                url="http://malicious-exploit-kit.com/pay",
                defanged_url="hxxp://malicious-exploit-kit[.]com/pay",
                severity=UrlRiskSeverity.MALICIOUS,
                reason="Known malicious exploit delivery link",
            )
        ],
    )

    score, tier, summary, assessment = risk_engine.evaluate(
        identity_result=id_result,
        url_result=url_result,
    )

    # Must remain MALICIOUS
    assert tier == RiskTier.MALICIOUS
    assert score >= 85.0
    signals = assessment["contributing_signals"]
    # Both signals are present
    assert any("[URL-MALICIOUS]" in s for s in signals)
    assert any("[IDENTITY-HEADER-INTEGRITY] MALFORMED_SENDER_ADDRESS" in s for s in signals)
    assert "THREAT DETECTED (MALICIOUS)" in summary
