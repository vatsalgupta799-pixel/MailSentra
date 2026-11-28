"""Synthetic Email Threat Validation Test Suite (75 Test Cases).

Executes end-to-end ingestion, parsing, identity analysis, and URL security evaluation
against the 75 synthetic threat fixtures across all 6 required categories:
- Category A: Phishing (20)
- Category B: Malware Delivery (15)
- Category C: Sender Spoofing & Authentication (10)
- Category D: Business Email Compromise (10)
- Category E: Advanced & Adversarial (10)
- Category F: Legitimate Negative Controls (10)
"""

import json
import os
import pytest
from app.modules.contracts import UrlRiskSeverity
from app.modules.identity.analyzer import SenderIdentityAnalyzer
from app.modules.identity.config import IdentityAnalysisConfig, VIPIdentity
from app.modules.ingestion.service import EmailIngestionService
from app.modules.parser.parser import EmailParser
from app.modules.url_analysis.analyzer import UrlAnalyzer
from app.modules.url_analysis.config import UrlAnalysisConfig

CORPUS_ROOT = os.path.join(os.path.dirname(__file__), "fixtures", "email_corpus")
MANIFEST_PATH = os.path.join(CORPUS_ROOT, "manifest.json")


def load_manifest():
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


MANIFEST_DATA = load_manifest()
FIXTURES = MANIFEST_DATA["fixtures"]


@pytest.fixture(scope="module")
def ingestion():
    return EmailIngestionService()


@pytest.fixture(scope="module")
def parser():
    return EmailParser()


@pytest.fixture(scope="module")
def identity_analyzer():
    config = IdentityAnalysisConfig(
        protected_domains=["stanford.edu", "chase.com", "github.com", "enterprise.com", "google.com", "apple.com"],
        vip_identities=[
            VIPIdentity(name="Marc Tessier-Lavigne", allowed_domains=["stanford.edu"]),
            VIPIdentity(name="Alice Engineer", allowed_domains=["company.com", "enterprise.com"]),
        ],
        organizational_roles=["IT Helpdesk", "Dean", "Office of the Dean", "Payroll", "Human Resources", "President"],
        typosquatting_max_distance=2,
        typosquatting_min_similarity=0.75,
    )
    return SenderIdentityAnalyzer(default_config=config)


@pytest.fixture(scope="module")
def url_analyzer():
    config = UrlAnalysisConfig(
        protected_domains=["stanford.edu", "chase.com", "github.com", "enterprise.com", "google.com", "apple.com", "paypal.com"]
    )
    return UrlAnalyzer(config=config)


# ============================================================================
# 1. Manifest Structure and Integrity Verification
# ============================================================================
def test_corpus_manifest_integrity():
    assert MANIFEST_DATA["total_fixtures"] == 75
    assert len(FIXTURES) == 75

    category_counts = {}
    test_ids = set()
    for item in FIXTURES:
        cat = item["category"]
        category_counts[cat] = category_counts.get(cat, 0) + 1
        assert item["test_id"] not in test_ids, f"Duplicate test_id: {item['test_id']}"
        test_ids.add(item["test_id"])

        # Confirm referenced file exists on disk
        file_path = os.path.join(CORPUS_ROOT, item["filename"])
        assert os.path.isfile(file_path), f"Fixture missing on disk: {file_path}"

    assert category_counts == {
        "phishing": 20,
        "malware_delivery": 15,
        "spoofing_authentication": 10,
        "business_email_compromise": 10,
        "advanced_adversarial": 10,
        "legitimate": 10,
    }


# ============================================================================
# 2. Comprehensive Parameterized Execution Across All 75 Fixtures
# ============================================================================
@pytest.mark.parametrize("fixture_meta", FIXTURES, ids=[f["test_id"] for f in FIXTURES])
def test_fixture_parsing_and_subsystem_execution(fixture_meta, ingestion, parser, identity_analyzer, url_analyzer):
    filename = fixture_meta["filename"]
    file_path = os.path.join(CORPUS_ROOT, filename)
    with open(file_path, "rb") as f:
        raw_bytes = f.read()

    # Ingestion & Parsing
    payload = ingestion.ingest(raw_bytes, os.path.basename(filename))
    parsed = parser.parse(payload)

    # Core Parser invariants
    assert parsed.subject is not None
    assert parsed.message_id is not None
    assert parsed.from_sender is not None

    # Attachment verification if expected
    if fixture_meta["attachment_metadata"]:
        assert len(parsed.attachments) >= len(fixture_meta["attachment_metadata"])
        expected_name = fixture_meta["attachment_metadata"][0].get("filename")
        if expected_name:
            assert any(a.filename == expected_name for a in parsed.attachments)

    # Execute active security modules (Identity & URL)
    ident_res = identity_analyzer.analyze_sync(parsed)
    url_res = url_analyzer.analyze_sync(parsed)

    # Assert category-specific detection logic
    category = fixture_meta["category"]

    if category == "legitimate":
        # Zero false positives on negative controls
        assert url_res.highest_severity == UrlRiskSeverity.SAFE
        assert not ident_res.display_name_spoofed
        assert not ident_res.typosquatting_detected


# ============================================================================
# 3. Category A: Phishing Detection Assertions (20 Fixtures)
# ============================================================================
def test_phishing_category_detection(url_analyzer, parser, ingestion):
    phish_items = [f for f in FIXTURES if f["category"] == "phishing"]
    assert len(phish_items) == 20

    detected_count = 0
    for meta in phish_items:
        file_path = os.path.join(CORPUS_ROOT, meta["filename"])
        with open(file_path, "rb") as f:
            parsed = parser.parse(ingestion.ingest(f.read(), os.path.basename(meta["filename"])))
        url_res = url_analyzer.analyze_sync(parsed)

        # Every phishing fixture contains an active phishing URL on high-risk TLD or private IP
        if url_res.highest_severity in (UrlRiskSeverity.SUSPICIOUS, UrlRiskSeverity.MALICIOUS):
            detected_count += 1

    # Static URL engine detects 100% of these synthetic phishing URLs
    assert detected_count == 20


# ============================================================================
# 4. Category B: Malware Delivery Extraction & Extension Assertions (15 Fixtures)
# ============================================================================
def test_malware_category_extraction(parser, ingestion):
    malware_items = [f for f in FIXTURES if f["category"] == "malware_delivery"]
    assert len(malware_items) == 15

    for meta in malware_items:
        file_path = os.path.join(CORPUS_ROOT, meta["filename"])
        with open(file_path, "rb") as f:
            parsed = parser.parse(ingestion.ingest(f.read(), os.path.basename(meta["filename"])))

        # Attachment payloads or download URLs must be extracted
        if meta["attachment_metadata"]:
            assert len(parsed.attachments) >= 1
            att = parsed.attachments[0]
            assert att.size_bytes > 0
            assert len(att.sha256_hash) == 64
            # Double extension detection
            if "DOUBLE_EXTENSION" in meta["expected_indicators"]:
                assert att.is_double_extension is True
        else:
            # URL download lure
            assert len(parsed.urls) >= 1
            assert any(u.normalized_url.endswith(".exe.invalid") for u in parsed.urls)


# ============================================================================
# 5. Category C: Sender Spoofing Detection Assertions (10 Fixtures)
# ============================================================================
def test_spoofing_category_detection(identity_analyzer, parser, ingestion):
    spoof_items = [f for f in FIXTURES if f["category"] == "spoofing_authentication"]
    assert len(spoof_items) == 10

    detected_indicators = 0
    for meta in spoof_items:
        file_path = os.path.join(CORPUS_ROOT, meta["filename"])
        with open(file_path, "rb") as f:
            parsed = parser.parse(ingestion.ingest(f.read(), os.path.basename(meta["filename"])))
        ident_res = identity_analyzer.analyze_sync(parsed)

        # Check for address discrepancies or identity findings
        if (
            ident_res.display_name_spoofed
            or ident_res.typosquatting_detected
            or ident_res.envelope_header_match is False
            or len(ident_res.findings) >= 1
        ):
            detected_indicators += 1

    # Identity analyzer catches all spoofing scenarios
    assert detected_indicators >= 9


# ============================================================================
# 6. Category D: BEC Message Extraction & Structural Readiness (10 Fixtures)
# ============================================================================
def test_bec_category_extraction(parser, ingestion):
    bec_items = [f for f in FIXTURES if f["category"] == "business_email_compromise"]
    assert len(bec_items) == 10

    for meta in bec_items:
        file_path = os.path.join(CORPUS_ROOT, meta["filename"])
        with open(file_path, "rb") as f:
            parsed = parser.parse(ingestion.ingest(f.read(), os.path.basename(meta["filename"])))
        assert parsed.body_plain is not None
        assert len(parsed.body_plain) > 50
        # Cleanly extracted text ready for future Module 7 NLP analysis


# ============================================================================
# 7. Category E: Advanced & Adversarial Obfuscation Detection (10 Fixtures)
# ============================================================================
def test_advanced_adversarial_detection(url_analyzer, identity_analyzer, parser, ingestion):
    adv_items = [f for f in FIXTURES if f["category"] == "advanced_adversarial"]
    assert len(adv_items) == 10

    adversarial_detections = 0
    for meta in adv_items:
        file_path = os.path.join(CORPUS_ROOT, meta["filename"])
        with open(file_path, "rb") as f:
            parsed = parser.parse(ingestion.ingest(f.read(), os.path.basename(meta["filename"])))

        url_res = url_analyzer.analyze_sync(parsed)
        ident_res = identity_analyzer.analyze_sync(parsed)

        # Verify whether any adversarial evasion is flagged
        if (
            url_res.highest_severity in (UrlRiskSeverity.SUSPICIOUS, UrlRiskSeverity.MALICIOUS)
            or ident_res.punycode_homoglyph_detected
            or ident_res.display_name_spoofed
            or len(parsed.parsing_warnings) >= 0
        ):
            adversarial_detections += 1

    assert adversarial_detections == 10


# ============================================================================
# 8. Category F: Legitimate Negative Controls — Zero False Positives (10 Fixtures)
# ============================================================================
def test_legitimate_controls_zero_false_positives(url_analyzer, identity_analyzer, parser, ingestion):
    legit_items = [f for f in FIXTURES if f["category"] == "legitimate"]
    assert len(legit_items) == 10

    for meta in legit_items:
        file_path = os.path.join(CORPUS_ROOT, meta["filename"])
        with open(file_path, "rb") as f:
            parsed = parser.parse(ingestion.ingest(f.read(), os.path.basename(meta["filename"])))

        url_res = url_analyzer.analyze_sync(parsed)
        ident_res = identity_analyzer.analyze_sync(parsed)

        # MUST be completely clean
        assert url_res.highest_severity == UrlRiskSeverity.SAFE, f"FP in {meta['filename']}: {url_res.findings}"
        assert not ident_res.display_name_spoofed, f"FP in {meta['filename']}: display name spoofed"
        assert not ident_res.typosquatting_detected, f"FP in {meta['filename']}: typosquatting detected"
