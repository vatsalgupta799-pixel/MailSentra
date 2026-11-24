"""Tests for module data contracts and serialization."""

import pytest
from app.modules.contracts import (
    AuthProtocolsResult,
    DecisionTier,
    DMARCPolicy,
    IdentityAnalysisResult,
    ParsedEmail,
    ProtocolStatus,
    RiskDecisionReport,
    ScoredFactor,
    UrlAnalysisResult,
    UrlFinding,
    UrlRiskSeverity,
)


def test_contracts_initialization_and_serialization():
    # 1. ParsedEmail contract
    parsed = ParsedEmail(
        message_id="<test@domain.com>",
        subject="Urgent: Wire Transfer Request",
        sender_header="CEO <ceo@legitcorp.com>",
        sender_address="ceo@legitcorp.com",
        sender_domain="legitcorp.com",
        recipient_addresses=["cfo@legitcorp.com"],
        body_plain="Please wire the invoice funds immediately.",
    )
    assert parsed.subject == "Urgent: Wire Transfer Request"
    assert len(parsed.urls) == 0

    # 2. AuthProtocolsResult contract
    auth_res = AuthProtocolsResult(
        spf_status=ProtocolStatus.PASS,
        spf_domain="legitcorp.com",
        dkim_status=ProtocolStatus.PASS,
        dmarc_status=ProtocolStatus.PASS,
        dmarc_policy=DMARCPolicy.REJECT,
    )
    assert auth_res.spf_status == ProtocolStatus.PASS

    # 3. UrlAnalysisResult contract
    url_finding = UrlFinding(
        url="http://192.168.1.1/login",
        defanged_url="hxxp[://]192[.]168[.]1[.]1/login",
        is_ip_host=True,
        severity=UrlRiskSeverity.SUSPICIOUS,
        reason="Direct IP address in URL host",
    )
    url_res = UrlAnalysisResult(
        total_urls_scanned=1,
        highest_severity=UrlRiskSeverity.SUSPICIOUS,
        findings=[url_finding],
    )
    assert len(url_res.findings) == 1
    assert url_res.findings[0].is_ip_host is True

    # 4. RiskDecisionReport contract
    report = RiskDecisionReport(
        composite_score=85.0,
        tier=DecisionTier.MALICIOUS,
        confidence=0.95,
        primary_threat_vector="Direct IP Phishing",
        explanation_summary="High-risk IP URL detected with mismatched sender.",
        contributing_factors=[
            ScoredFactor(
                category="URL_SECURITY",
                rule_id="IP_HOST_DETECTED",
                weight=1.0,
                score_delta=40.0,
                justification="Raw IP address used as URL host",
            )
        ],
    )
    assert report.tier == DecisionTier.MALICIOUS
    assert report.composite_score == 85.0
    assert len(report.contributing_factors) == 1
