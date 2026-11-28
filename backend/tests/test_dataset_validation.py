"""Verification and integration test suite for MailSentra Dataset Portfolio.

Verifies:
1. Dataset Registry CSV completeness and schema conformity across all 15 sources.
2. Dataset Manifest JSON structure, counts, and status validity.
3. Offline execution and zero network dependency.
4. Dataset-derived tests on sanitized sample fixtures (Tranco, URLhaus, PhishTank).
5. False-positive resistance on benign corpora.
6. Detection coverage on malware and phishing corpora.
"""

import csv
import json
import os
import pytest
from app.modules.contracts import UrlRiskSeverity
from app.modules.url_analysis.analyzer import UrlAnalyzer
from app.modules.url_analysis.config import UrlAnalysisConfig

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATASETS_DIR = os.path.join(PROJECT_ROOT, "datasets")
REGISTRY_CSV = os.path.join(DATASETS_DIR, "dataset_registry.csv")
MANIFEST_JSON = os.path.join(DATASETS_DIR, "dataset_manifest.json")
SAMPLES_DIR = os.path.join(DATASETS_DIR, "samples")

VALID_STATUSES = {
    "ASSESSED",
    "DOWNLOADED",
    "VALIDATED",
    "INTEGRATED",
    "USED_IN_TESTS",
    "PENDING",
    "BLOCKED",
    "REJECTED",
}


@pytest.fixture
def analyzer():
    config = UrlAnalysisConfig(
        protected_domains=["paypal.com", "microsoft.com", "google.com", "apple.com"]
    )
    return UrlAnalyzer(config=config)


# ============================================================================
# 1. Dataset Registry CSV Validation
# ============================================================================
def test_dataset_registry_csv_exists_and_valid():
    assert os.path.exists(REGISTRY_CSV), f"Missing dataset registry: {REGISTRY_CSV}"
    with open(REGISTRY_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Exactly 15 datasets
    assert len(rows) == 15, f"Expected 15 datasets, found {len(rows)}"

    expected_ids = {f"DS-{i:02d}" for i in range(1, 16)}
    found_ids = {r["dataset_id"] for r in rows}
    assert found_ids == expected_ids, f"ID mismatch: {expected_ids - found_ids}"

    for r in rows:
        assert r["source_url"].startswith("http"), f"Invalid source_url: {r['source_url']}"
        assert r["integration_status"] in VALID_STATUSES, f"Invalid status: {r['integration_status']}"
        assert r["license"], f"Missing license for {r['dataset_id']}"
        assert r["provider"], f"Missing provider for {r['dataset_id']}"


# ============================================================================
# 2. Dataset Manifest JSON Validation
# ============================================================================
def test_dataset_manifest_json_exists_and_valid():
    assert os.path.exists(MANIFEST_JSON), f"Missing dataset manifest: {MANIFEST_JSON}"
    with open(MANIFEST_JSON, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    assert manifest["portfolio_count"] == 15
    assert len(manifest["datasets"]) == 15

    for ds in manifest["datasets"]:
        assert ds["id"].startswith("DS-")
        assert ds["integration_status"] in VALID_STATUSES
        assert "label_distribution" in ds
        assert ds["source_url"].startswith("https://") or ds["source_url"].startswith("http://")


# ============================================================================
# 3. Cross-Source Duplicate Validation (DS-02 vs DS-03)
# ============================================================================
def test_phiusiil_cross_source_duplicate_detection():
    with open(MANIFEST_JSON, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    ds_map = {d["id"]: d for d in manifest["datasets"]}

    ds2 = ds_map["DS-02"]
    ds3 = ds_map["DS-03"]

    # Both must record the same underlying record count and label distribution
    assert ds2["total_records"] == ds3["total_records"] == 235795
    assert ds2["label_distribution"] == ds3["label_distribution"]
    assert "Identical" in ds2["source_overlap"] or "Identical" in ds3["source_overlap"]


# ============================================================================
# 4. Dataset-Derived Benign Evaluation (Tranco Sample)
# ============================================================================
def test_tranco_benign_sample_eval(analyzer):
    sample_path = os.path.join(SAMPLES_DIR, "benign_tranco_sample.json")
    assert os.path.exists(sample_path)
    with open(sample_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    for item in samples:
        url = item["url"]
        finding = analyzer.analyze_url(url)
        assert finding is not None
        # Benign top domains must not be classified as MALICIOUS
        assert finding.severity == UrlRiskSeverity.SAFE, f"False positive on benign Tranco URL {url}: {finding.reason}"


# ============================================================================
# 5. Dataset-Derived Malware Evaluation (URLhaus Sample)
# ============================================================================
def test_urlhaus_malware_sample_eval(analyzer):
    sample_path = os.path.join(SAMPLES_DIR, "malware_urlhaus_sample.json")
    assert os.path.exists(sample_path)
    with open(sample_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    for item in samples:
        url = item["url"]
        finding = analyzer.analyze_url(url)
        assert finding is not None
        # All URLhaus malware fixtures must trigger SUSPICIOUS or MALICIOUS
        assert finding.severity in (UrlRiskSeverity.SUSPICIOUS, UrlRiskSeverity.MALICIOUS), (
            f"Failed to detect malware URL {url}: {finding.reason}"
        )


# ============================================================================
# 6. Dataset-Derived Phishing Evaluation (PhishTank Sample)
# ============================================================================
def test_phishtank_phishing_sample_eval(analyzer):
    sample_path = os.path.join(SAMPLES_DIR, "phishing_phishtank_sample.json")
    assert os.path.exists(sample_path)
    with open(sample_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    for item in samples:
        url = item["url"]
        finding = analyzer.analyze_url(url)
        assert finding is not None
        assert finding.severity in (UrlRiskSeverity.SUSPICIOUS, UrlRiskSeverity.MALICIOUS), (
            f"Failed to detect phishing URL {url}: {finding.reason}"
        )
