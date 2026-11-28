"""Unit tests for Link Consequence Analysis and Post-Click User Guidance Subsystem."""

import pytest
from app.modules.contracts import UrlRiskSeverity
from app.modules.url_analysis.consequences import (
    ConsequenceEvaluator,
    ThreatCategory,
    PostClickScenario,
)


def test_safe_url_returns_no_consequences():
    evaluator = ConsequenceEvaluator()
    res = evaluator.evaluate("https://www.google.com", UrlRiskSeverity.SAFE, "No signals")
    assert res is None


def test_phishing_credential_theft_consequences():
    evaluator = ConsequenceEvaluator()
    res = evaluator.evaluate(
        "https://signin.paypal.com.evil-phishing.org/login",
        UrlRiskSeverity.MALICIOUS,
        "[SUBDOMAIN_BRAND_IMPERSONATION] Legitimate brand 'paypal' spoofed in subdomain",
        ["SUBDOMAIN_BRAND_IMPERSONATION"],
    )
    assert res is not None
    assert res.threat_category == ThreatCategory.PHISHING_CREDENTIAL_THEFT
    assert "Phishing" in res.category_title
    assert any("username and password" in item for item in res.what_could_happen)
    assert any("not compromise your account" in dist for dist in res.risk_distinctions)


def test_malware_executable_download_consequences():
    evaluator = ConsequenceEvaluator()
    res = evaluator.evaluate(
        "http://192.168.1.50/setup.exe",
        UrlRiskSeverity.MALICIOUS,
        "[IP_HOST_PRIVATE] Private IP host; [SUSPICIOUS_FILE_EXT] Executable .exe extension",
        ["IP_HOST_PRIVATE", "SUSPICIOUS_FILE_EXT"],
    )
    assert res is not None
    assert res.threat_category == ThreatCategory.MALWARE_DOWNLOAD
    assert "Malicious Software" in res.category_title
    assert any("download a suspicious file" in item for item in res.what_could_happen)
    assert any("does not immediately infect your system" in dist for dist in res.risk_distinctions)


def test_ransomware_evidence_consequences():
    evaluator = ConsequenceEvaluator()
    res = evaluator.evaluate(
        "https://dark-decryptor.onion.top/wannacry_payment",
        UrlRiskSeverity.MALICIOUS,
        "[RANSOMWARE] Known ransomware payment portal reference",
        ["RANSOMWARE"],
    )
    assert res is not None
    assert res.threat_category == ThreatCategory.RANSOMWARE
    assert "Ransomware" in res.category_title
    assert any("encrypt or lock" in item for item in res.what_could_happen)


def test_payment_fraud_consequences():
    evaluator = ConsequenceEvaluator()
    res = evaluator.evaluate(
        "https://secure-invoice-billing-chase.tk/checkout",
        UrlRiskSeverity.SUSPICIOUS,
        "[SUSPICIOUS_TLD] High-risk TLD .tk with brand billing indicators",
        ["SUSPICIOUS_TLD"],
    )
    assert res is not None
    assert res.threat_category == ThreatCategory.PAYMENT_FRAUD
    assert "Payment" in res.category_title
    assert any("credit/debit card" in item for item in res.what_could_happen)


def test_tracking_reconnaissance_consequences():
    evaluator = ConsequenceEvaluator()
    res = evaluator.evaluate(
        "https://bit.ly/3xY7z9",
        UrlRiskSeverity.SUSPICIOUS,
        "[KNOWN_SHORTENER] Shortener obscures final destination",
        ["KNOWN_SHORTENER"],
    )
    assert res is not None
    assert res.threat_category == ThreatCategory.TRACKING_RECONNAISSANCE
    assert "Tracking" in res.category_title
    assert any("verify that your email address is active" in item for item in res.what_could_happen)


def test_post_click_scenarios_comprehensive():
    evaluator = ConsequenceEvaluator()
    scenarios = evaluator.get_all_post_click_scenarios()
    assert len(scenarios) == 5

    scenario_keys = [s.scenario for s in scenarios]
    assert PostClickScenario.VISITED_NO_INPUT in scenario_keys
    assert PostClickScenario.ENTERED_PASSWORD in scenario_keys
    assert PostClickScenario.DOWNLOADED_FILE in scenario_keys
    assert PostClickScenario.ENTERED_PAYMENT in scenario_keys
    assert PostClickScenario.GRANTED_ACCESS in scenario_keys

    # Verify no credentials or secrets are requested
    for s in scenarios:
        assert all("enter your password here" not in a.lower() for a in s.recommended_actions)
        assert len(s.recommended_actions) > 0
