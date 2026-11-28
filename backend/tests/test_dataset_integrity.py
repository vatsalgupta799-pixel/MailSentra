"""Automated integrity tests for MailSentra Dataset Ecosystem.

Validates:
1. Dataset registry schema and required fields.
2. Source URL presence and validity across all datasets.
3. Category manifests structure and shortfall calculation.
4. Duplicate provenance detection and rejection (DS-PE-11, DS-PE-12, etc.).
5. Category routing and canonical label normalization.
6. Group-aware train/test split isolation without hash leakage.
7. Evaluation execution on URL, Attachment, and Email samples.
8. Non-overwriting integrity and rejection of falsely marked datasets.
"""

import os
import json
import pytest
from app.datasets.contracts import (
    DatasetCategory,
    DatasetLifecycleStatus,
    DatasetLifecycleError,
    ProvenanceNature,
    ALLOWED_TRANSITIONS,
    validate_lifecycle_state,
    validate_lifecycle_transition,
    CanonicalThreatLabel,
    VerificationStatus,
)
from app.datasets.adapters import EmailDatasetAdapter, UrlDatasetAdapter, AttachmentDatasetAdapter
from app.datasets.pipeline import DatasetValidationPipeline
from app.datasets.evaluator import DatasetEvaluator


DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
REGISTRY_PATH = os.path.join(DATA_DIR, "dataset_registry.json")
MANIFESTS_DIR = os.path.join(DATA_DIR, "manifests")
RAW_DIR = os.path.join(DATA_DIR, "raw")


@pytest.fixture
def registry():
    assert os.path.exists(REGISTRY_PATH), f"Missing registry at {REGISTRY_PATH}"
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test_registry_schema_and_integrity(registry):
    assert registry["total_categories"] == 8
    assert registry["target_per_category"] == 15
    assert registry["global_target"] == 120
    assert len(registry["datasets"]) == registry["total_candidates"]
    assert "PARTIALLY_VERIFIED" in registry["audit_verdict"]
    assert registry["total_evaluated"] == 0

    for ds in registry["datasets"]:
        assert ds["dataset_id"].startswith("DS-")
        assert ds["dataset_name"]
        assert ds["source_url"].startswith("http")
        assert ds["publisher"]
        assert ds["license"]
        assert ds["intended_module"]
        assert ds["verification_status"] in [v.value for v in VerificationStatus]
        assert ds["lifecycle_status"] in [s.value for s in DatasetLifecycleStatus]
        # Validate that every registry dataset passes the lifecycle state machine
        validate_lifecycle_state(ds)


def test_category_manifests_exist_and_conform():
    categories = [c.value for c in DatasetCategory]
    for cat in categories:
        manifest_file = os.path.join(MANIFESTS_DIR, f"{cat}.json")
        assert os.path.exists(manifest_file), f"Missing manifest for {cat}"
        with open(manifest_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["category"] == cat
        assert data["target_datasets"] == 15
        assert len(data["datasets"]) == data["candidate_count"]
        # Verify shortfall calculation honesty
        assert data["documented_shortfall"] == max(0, 15 - data["verified_count"])


def test_duplicate_provenance_detection_and_rejection(registry):
    """Verifies that repackaged copies of the same corpus are marked REJECTED."""
    rejected_duplicates = [
        ds for ds in registry["datasets"]
        if ds.get("duplicate_of") is not None
    ]
    assert len(rejected_duplicates) >= 4
    for ds in rejected_duplicates:
        assert ds["verification_status"] == "REJECTED"
        assert ds["integration_status"] == "REJECTED"


def test_synthetic_and_domain_level_rejection(registry):
    """Verifies synthetic datasets and domain-level posture datasets are rejected from message-level email."""
    stackscan = next(ds for ds in registry["datasets"] if ds["dataset_id"] == "DS-SS-07")
    assert stackscan["verification_status"] == "REJECTED"
    assert "Domain-level DNS" in stackscan["provenance"]

    ibm_synth = next(ds for ds in registry["datasets"] if ds["dataset_id"] == "DS-PE-14")
    assert ibm_synth["verification_status"] == "REJECTED"
    assert "Synthetic" in ibm_synth["provenance"]


def test_adapter_canonical_normalization():
    adapter = EmailDatasetAdapter("DS-TEST-01", DatasetCategory.PHISHING_EMAIL, "Module 1/2")
    raw = {"subject": "Urgent", "body": "Click here to login", "label": "phishing"}
    norm = adapter.normalize_record(raw)
    assert norm["canonical_label"] == CanonicalThreatLabel.PHISHING.value
    assert norm["target_module"] == "Module 1/2"
    assert norm["content_sha256"]


def test_split_isolation_no_duplicate_hash_leakage():
    pipeline = DatasetValidationPipeline()
    adapter = EmailDatasetAdapter("DS-TEST-SPLIT", DatasetCategory.SPAM_EMAIL, "Module 1/2")
    records = [
        {"subject": f"Offer {i}", "body": f"Buy item {i} now!", "label": "spam"}
        for i in range(50)
    ]
    processed = pipeline.ingest_records(adapter, records)
    train_set, test_set = pipeline.split_records(processed, train_ratio=0.7, test_ratio=0.3)

    train_hashes = {r["content_sha256"] for r in train_set}
    test_hashes = {r["content_sha256"] for r in test_set}

    # Zero overlap between train and test hashes
    assert len(train_hashes.intersection(test_hashes)) == 0
    assert len(train_set) + len(test_set) == 50


def test_pipeline_deduplication():
    pipeline = DatasetValidationPipeline()
    adapter = UrlDatasetAdapter("DS-URL-DEDUP", DatasetCategory.MALICIOUS_URLS, "Module 4")
    records = [
        {"url": "http://evil.com/phish", "label": "phishing"},
        {"url": "http://evil.com/phish", "label": "phishing"},  # Duplicate
        {"url": "http://safe.com/home", "label": "benign"},
    ]
    processed = pipeline.ingest_records(adapter, records)
    assert pipeline.duplicates_found == 1
    assert processed[0]["is_duplicate"] is False
    assert processed[1]["is_duplicate"] is True
    assert processed[2]["is_duplicate"] is False


def test_evaluation_runs_on_url_samples():
    raw_path = os.path.join(RAW_DIR, "malicious_urls_samples.json")
    assert os.path.exists(raw_path)
    with open(raw_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    evaluator = DatasetEvaluator()
    results = evaluator.evaluate_url_dataset(samples)
    assert results["category"] == "malicious_urls"
    assert results["total_tested"] >= 1
    assert "precision" in results
    assert "recall" in results
    assert "f1" in results


def test_evaluation_runs_on_attachment_samples():
    raw_path = os.path.join(RAW_DIR, "malware_attachments_samples.json")
    assert os.path.exists(raw_path)
    with open(raw_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    evaluator = DatasetEvaluator()
    results = evaluator.evaluate_attachment_dataset(samples)
    assert results["category"] == "malware_attachments"
    assert results["total_tested"] >= 1
    assert results["precision"] >= 0.5


def test_evaluation_runs_on_email_samples():
    raw_path = os.path.join(RAW_DIR, "phishing_email_samples.json")
    assert os.path.exists(raw_path)
    with open(raw_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    evaluator = DatasetEvaluator()
    results = evaluator.evaluate_email_dataset(DatasetCategory.PHISHING_EMAIL, samples)
    assert results["category"] == "phishing_email"
    assert results["total_tested"] >= 1
    assert "module_telemetry" in results
    telem = results["module_telemetry"]
    assert telem["records_parsed"] >= 1
    assert telem["records_identity"] >= 1
    assert telem["records_auth"] >= 1
    assert telem["records_url"] >= 1
    assert telem["records_attachment"] >= 1
    assert telem["records_risk"] >= 1
    assert telem["offline_auth_enforced"] is True


def test_group_aware_campaign_cluster_splitting():
    """Verifies that records sharing a campaign_cluster_id are strictly grouped into the same split."""
    pipeline = DatasetValidationPipeline()
    records = [
        {"record_id": f"rec_{i}", "campaign_cluster_id": "CAMP_A", "content_sha256": f"hash_{i}"}
        for i in range(10)
    ] + [
        {"record_id": f"rec_{i}", "campaign_cluster_id": "CAMP_B", "content_sha256": f"hash_{i}"}
        for i in range(10, 20)
    ]
    train_set, test_set = pipeline.split_records(records, train_ratio=0.5, test_ratio=0.5)

    train_camps = {r["campaign_cluster_id"] for r in train_set}
    test_camps = {r["campaign_cluster_id"] for r in test_set}

    # Zero campaign overlap between train and test
    assert len(train_camps.intersection(test_camps)) == 0
    assert len(train_set) + len(test_set) == 20


def test_epvme_lexical_phishing_benchmark_prohibition():
    """Verifies that EPVME (DS-SS-01) is strictly blocked from general lexical phishing benchmarking."""
    pipeline = DatasetValidationPipeline()
    records = [
        {"record_id": "epvme_1", "dataset_id": "DS-SS-01", "content_sha256": "h1"}
    ]
    with pytest.raises(ValueError, match=r"EPVME \(DS-SS-01\).*prohibited"):
        pipeline.split_records(records, benchmark_target="phishing_lexical")


# ============================================================================
# Lifecycle State Machine & Evaluated Gate Integrity Tests (Phase 1)
# ============================================================================

def test_zero_datasets_falsely_marked_evaluated(registry):
    """Proves that zero datasets in the registry carry EVALUATED status without execution."""
    evaluated = [d for d in registry["datasets"] if d["lifecycle_status"] == DatasetLifecycleStatus.EVALUATED.value]
    assert len(evaluated) == 0, f"Found {len(evaluated)} datasets falsely marked EVALUATED"
    assert registry["total_evaluated"] == 0


def test_evaluated_gate_rejects_missing_file_or_records():
    """Proves that validate_lifecycle_state strictly prevents marking EVALUATED without local files & records."""
    fake_entry = {
        "dataset_id": "DS-TEST-EVAL-FAIL",
        "publisher": "Test Publisher",
        "source_url": "https://example.com/data",
        "license": "MIT",
        "lifecycle_status": DatasetLifecycleStatus.EVALUATED.value,
        "local_file_path": None,
        "raw_record_count": 0,
        "evaluated_record_count": 0,
        "applicable_production_module": "Module 1",
    }
    with pytest.raises(DatasetLifecycleError, match="no local_file_path"):
        validate_lifecycle_state(fake_entry)

    # Path does not exist
    fake_entry["raw_record_count"] = 10
    fake_entry["local_file_path"] = "backend/data/raw/non_existent_file_12345.json"
    with pytest.raises(DatasetLifecycleError, match="does not exist on disk"):
        validate_lifecycle_state(fake_entry)

    # Path exists but evaluated_record_count is 0
    fake_entry["local_file_path"] = os.path.join(RAW_DIR, "malicious_urls_samples.json")
    fake_entry["evaluated_record_count"] = 0
    with pytest.raises(DatasetLifecycleError, match="evaluated_record_count is 0"):
        validate_lifecycle_state(fake_entry)

    # Missing run id
    fake_entry["evaluated_record_count"] = 10
    with pytest.raises(DatasetLifecycleError, match="missing evaluation_run_id"):
        validate_lifecycle_state(fake_entry)

    # Missing evidence location
    fake_entry["evaluation_run_id"] = "RUN-TEST-001"
    with pytest.raises(DatasetLifecycleError, match="missing evidence_location"):
        validate_lifecycle_state(fake_entry)

    # Fully valid evaluated entry succeeds
    fake_entry["evidence_location"] = "reports/eval_test.json"
    validate_lifecycle_state(fake_entry)  # Should not raise


def test_duplicate_provenance_cannot_be_approved_or_evaluated():
    """Proves duplicate datasets are forbidden from reaching APPROVED or EVALUATED."""
    fake_duplicate = {
        "dataset_id": "DS-TEST-DUP",
        "publisher": "Test Mirror",
        "source_url": "https://example.com/mirror",
        "license": "MIT",
        "duplicate_of": "DS-PE-01",
        "lifecycle_status": DatasetLifecycleStatus.APPROVED.value,
    }
    with pytest.raises(DatasetLifecycleError, match="is a duplicate of"):
        validate_lifecycle_state(fake_duplicate)

    fake_duplicate["lifecycle_status"] = DatasetLifecycleStatus.EVALUATED.value
    with pytest.raises(DatasetLifecycleError, match="is a duplicate of"):
        validate_lifecycle_state(fake_duplicate)


def test_downloaded_gate_enforcement():
    """Proves that DOWNLOADED status requires valid local file path and genuine external records."""
    fake_dl = {
        "dataset_id": "DS-TEST-DL",
        "publisher": "Test Publisher",
        "source_url": "https://example.com/data",
        "license": "MIT",
        "lifecycle_status": DatasetLifecycleStatus.DOWNLOADED.value,
        "local_file_path": None,
        "raw_record_count": 0,
        "external_records_count": 0,
    }
    with pytest.raises(DatasetLifecycleError, match="no local_file_path"):
        validate_lifecycle_state(fake_dl)

    fake_dl["local_file_path"] = "some/path.csv"
    fake_dl["raw_record_count"] = 10
    fake_dl["external_records_count"] = 0
    with pytest.raises(DatasetLifecycleError, match="external_records_count <= 0"):
        validate_lifecycle_state(fake_dl)

    fake_dl["external_records_count"] = 10
    fake_dl["raw_record_count"] = 0
    with pytest.raises(DatasetLifecycleError, match="raw_record_count <= 0"):
        validate_lifecycle_state(fake_dl)


# ============================================================================
# Phase 1 Corrective Remediation Tests (Transition Enforcement & Provenance)
# ============================================================================

def test_lifecycle_allowed_transitions_graph_integrity():
    """Verifies that all 9 lifecycle statuses have entries in ALLOWED_TRANSITIONS graph."""
    assert len(ALLOWED_TRANSITIONS) == len(DatasetLifecycleStatus)
    for status in DatasetLifecycleStatus:
        assert status in ALLOWED_TRANSITIONS
    # Terminal states
    assert len(ALLOWED_TRANSITIONS[DatasetLifecycleStatus.EVALUATED]) == 0
    assert len(ALLOWED_TRANSITIONS[DatasetLifecycleStatus.REJECTED]) == 0


def test_illegal_lifecycle_transitions_rejected():
    """Proves illegal jumps are strictly blocked by validate_lifecycle_transition."""
    base_entry = {
        "dataset_id": "DS-TEST-TRANS",
        "publisher": "Test Publisher",
        "source_url": "https://example.com/data",
        "license": "MIT",
        "applicable_production_module": "Module 1",
        "local_file_path": os.path.join(RAW_DIR, "malicious_urls_samples.json"),
        "raw_record_count": 3,
        "external_records_count": 3,
        "evaluated_record_count": 3,
        "evaluation_run_id": "RUN-001",
        "evidence_location": "evidence/run_001.json",
    }

    # 1. DISCOVERED -> EVALUATED (Illegal jump)
    with pytest.raises(DatasetLifecycleError, match="cannot transition directly from 'DISCOVERED' to 'EVALUATED'"):
        validate_lifecycle_transition(DatasetLifecycleStatus.DISCOVERED, DatasetLifecycleStatus.EVALUATED, base_entry)

    # 2. REJECTED -> APPROVED (Illegal jump: REJECTED is terminal)
    with pytest.raises(DatasetLifecycleError, match="cannot transition directly from 'REJECTED' to 'APPROVED'"):
        validate_lifecycle_transition(DatasetLifecycleStatus.REJECTED, DatasetLifecycleStatus.APPROVED, base_entry)

    # 3. LICENSE_VERIFIED -> INTEGRATED (Illegal jump: must pass APPROVED and DOWNLOADED)
    with pytest.raises(DatasetLifecycleError, match="cannot transition directly from 'LICENSE_VERIFIED' to 'INTEGRATED'"):
        validate_lifecycle_transition(DatasetLifecycleStatus.LICENSE_VERIFIED, DatasetLifecycleStatus.INTEGRATED, base_entry)

    # 4. EVALUATED -> APPROVED (Illegal jump: EVALUATED is terminal)
    with pytest.raises(DatasetLifecycleError, match="cannot transition directly from 'EVALUATED' to 'APPROVED'"):
        validate_lifecycle_transition(DatasetLifecycleStatus.EVALUATED, DatasetLifecycleStatus.APPROVED, base_entry)

    # 5. DISCOVERED -> INTEGRATED (Illegal jump)
    with pytest.raises(DatasetLifecycleError, match="cannot transition directly from 'DISCOVERED' to 'INTEGRATED'"):
        validate_lifecycle_transition(DatasetLifecycleStatus.DISCOVERED, DatasetLifecycleStatus.INTEGRATED, base_entry)

    # 6. APPROVED -> EVALUATED (Illegal jump)
    with pytest.raises(DatasetLifecycleError, match="cannot transition directly from 'APPROVED' to 'EVALUATED'"):
        validate_lifecycle_transition(DatasetLifecycleStatus.APPROVED, DatasetLifecycleStatus.EVALUATED, base_entry)


def test_legal_lifecycle_transitions_succeed():
    """Proves legal transitions succeed when gate requirements are satisfied."""
    valid_entry = {
        "dataset_id": "DS-TEST-LEGAL",
        "publisher": "Test Publisher",
        "source_url": "https://example.com/legal_dataset",
        "license": "Apache-2.0",
        "applicable_production_module": "Module 4 (Static URL Analysis)",
        "local_file_path": os.path.join(RAW_DIR, "malicious_urls_samples.json"),
        "raw_record_count": 3,
        "external_records_count": 3,
        "evaluated_record_count": 3,
        "evaluation_run_id": "RUN-TEST-002",
        "evidence_location": "evidence/run_002.json",
    }

    # DISCOVERED -> PROVENANCE_VERIFIED
    validate_lifecycle_transition(DatasetLifecycleStatus.DISCOVERED, DatasetLifecycleStatus.PROVENANCE_VERIFIED, valid_entry)

    # PROVENANCE_VERIFIED -> LICENSE_VERIFIED
    validate_lifecycle_transition(DatasetLifecycleStatus.PROVENANCE_VERIFIED, DatasetLifecycleStatus.LICENSE_VERIFIED, valid_entry)

    # LICENSE_VERIFIED -> APPROVED
    validate_lifecycle_transition(DatasetLifecycleStatus.LICENSE_VERIFIED, DatasetLifecycleStatus.APPROVED, valid_entry)

    # LICENSE_VERIFIED -> CONDITIONALLY_APPROVED
    validate_lifecycle_transition(DatasetLifecycleStatus.LICENSE_VERIFIED, DatasetLifecycleStatus.CONDITIONALLY_APPROVED, valid_entry)

    # CONDITIONALLY_APPROVED -> APPROVED
    validate_lifecycle_transition(DatasetLifecycleStatus.CONDITIONALLY_APPROVED, DatasetLifecycleStatus.APPROVED, valid_entry)

    # APPROVED -> DOWNLOADED
    validate_lifecycle_transition(DatasetLifecycleStatus.APPROVED, DatasetLifecycleStatus.DOWNLOADED, valid_entry)

    # DOWNLOADED -> INTEGRATED
    validate_lifecycle_transition(DatasetLifecycleStatus.DOWNLOADED, DatasetLifecycleStatus.INTEGRATED, valid_entry)

    # INTEGRATED -> EVALUATED
    validate_lifecycle_transition(DatasetLifecycleStatus.INTEGRATED, DatasetLifecycleStatus.EVALUATED, valid_entry)

    # Any non-terminal state -> REJECTED
    validate_lifecycle_transition(DatasetLifecycleStatus.DISCOVERED, DatasetLifecycleStatus.REJECTED, valid_entry)
    validate_lifecycle_transition(DatasetLifecycleStatus.PROVENANCE_VERIFIED, DatasetLifecycleStatus.REJECTED, valid_entry)
    validate_lifecycle_transition(DatasetLifecycleStatus.APPROVED, DatasetLifecycleStatus.REJECTED, valid_entry)


def test_provenance_classification_honesty(registry):
    """Verifies that external acquisition counts reflect genuine downloaded records (DS-PE-01: 2279, DS-SP-01: 1397, DS-SS-01: 1496)."""
    assert registry["external_records_count"] == 5172
    assert registry["external_downloaded_count"] == 0
    assert registry["external_evaluated_count"] == 0
    assert registry["synthetic_fixture_datasets"] == 18
    assert registry["synthetic_fixture_records"] == 18

    ds_pe_01 = next(d for d in registry["datasets"] if d["dataset_id"] == "DS-PE-01")
    assert ds_pe_01["external_records_count"] == 2279
    assert ds_pe_01["is_synthetic_fixture"] is False
    assert ds_pe_01["provenance_nature"] == ProvenanceNature.EXTERNAL_ACQUIRED.value
    assert ds_pe_01["checksum_sha256"] == "b29336d2e31c2dff19639415e98ed2aced5b4d63675ea5e29bea1a7d4e452841"

    ds_sp_01 = next(d for d in registry["datasets"] if d["dataset_id"] == "DS-SP-01")
    assert ds_sp_01["external_records_count"] == 1397
    assert ds_sp_01["is_synthetic_fixture"] is False
    assert ds_sp_01["provenance_nature"] == ProvenanceNature.EXTERNAL_ACQUIRED.value
    assert ds_sp_01["checksum_sha256"] == "44280a0e28bf7645b2279e8e42659271ad82c6f40bf8d364dbda7f1df344a765"

    ds_ss_01 = next(d for d in registry["datasets"] if d["dataset_id"] == "DS-SS-01")
    assert ds_ss_01["external_records_count"] == 1496
    assert ds_ss_01["is_synthetic_fixture"] is False
    assert ds_ss_01["provenance_nature"] == ProvenanceNature.TRANSFORMED_DERIVATIVE.value
    assert ds_ss_01["checksum_sha256"] == "3e4e18371f2dc08a9668b1c0309c91e19a612a5068021e245cb6005e92958b97"

    for ds in registry["datasets"]:
        if ds["dataset_id"] in ("DS-PE-01", "DS-SP-01", "DS-SS-01"):
            continue
        assert ds["external_records_count"] == 0
        if ds["is_synthetic_fixture"]:
            assert ds["synthetic_records_count"] > 0
            assert ds["provenance_nature"] in (
                ProvenanceNature.SYNTHETIC_FIXTURE_MOCK.value,
                ProvenanceNature.TRANSFORMED_DERIVATIVE.value,
            )
            assert ds["transformation_notes"] is not None
        else:
            assert ds["synthetic_records_count"] == 0


def test_nazario_mbox_acquisition_and_ingestion_integrity():
    """Verifies the complete acquisition and parsing integrity of Nazario phishing3.mbox."""
    raw_mbox = os.path.join(DATA_DIR, "raw", "phishing_email", "nazario", "phishing3.mbox")
    assert os.path.exists(raw_mbox), f"Missing raw MBOX at {raw_mbox}"
    assert os.path.getsize(raw_mbox) == 20067215

    # Check raw SHA-256
    import hashlib
    with open(raw_mbox, "rb") as f:
        hasher = hashlib.sha256()
        while chunk := f.read(65536):
            hasher.update(chunk)
    assert hasher.hexdigest() == "b29336d2e31c2dff19639415e98ed2aced5b4d63675ea5e29bea1a7d4e452841"

    # Check provenance manifest
    manifest_file = os.path.join(DATA_DIR, "raw", "phishing_email", "nazario", "provenance_manifest.json")
    assert os.path.exists(manifest_file)
    with open(manifest_file, "r", encoding="utf-8") as f:
        p_manifest = json.load(f)
    assert p_manifest["dataset_id"] == "DS-PE-01"
    assert p_manifest["license"] == "CC BY 4.0"
    assert "Jose Nazario" in p_manifest["attribution"]
    assert p_manifest["file_size_bytes"] == 20067215
    assert p_manifest["sha256"] == "b29336d2e31c2dff19639415e98ed2aced5b4d63675ea5e29bea1a7d4e452841"

    # Check processed records
    processed_records = os.path.join(DATA_DIR, "processed", "phishing_email", "nazario_phishing3_records.jsonl")
    assert os.path.exists(processed_records)
    line_count = 0
    with open(processed_records, "r", encoding="utf-8") as f:
        for line in f:
            line_count += 1
            if line_count == 1:
                rec0 = json.loads(line)
                assert rec0["dataset_id"] == "DS-PE-01"
                assert rec0["canonical_label"] == "PHISHING"
                assert rec0["auth_status"] == "UNKNOWN"
                assert "UNVERIFIED_HISTORICAL_HEADER" in rec0["auth_status_note"]
                assert "redacted_preview" in rec0
    assert line_count == 2279

    # Check summary
    summary_file = os.path.join(DATA_DIR, "processed", "phishing_email", "nazario_phishing3_summary.json")
    assert os.path.exists(summary_file)
    with open(summary_file, "r", encoding="utf-8") as f:
        summary = json.load(f)
    assert summary["total_discovered"] == 2279
    assert summary["total_parsed"] == 2279
    assert summary["total_malformed"] == 0
    assert summary["exact_duplicates"] == 0
    assert summary["campaign_near_duplicates"] == 288
    assert summary["unique_content_records"] == 1991
    assert summary["mime_anomaly_warnings_count"] == 5
    assert summary["empty_body_classifications"]["NORMAL"] == 2253
    assert summary["empty_body_classifications"]["ATTACHMENT_ONLY"] == 3
    assert summary["empty_body_classifications"]["WHITESPACE_ONLY"] == 23
    assert summary["empty_body_classifications"]["EMPTY_MESSAGE"] == 0
    assert summary["empty_body_classifications"]["BODY_EXTRACTION_FAILURE"] == 0


def test_processed_data_git_exclusion():
    """Verifies processed corpus data is explicitly excluded by .gitignore."""
    import subprocess
    cmd = ["git", "check-ignore", "-v", "backend/data/processed/phishing_email/nazario_phishing3_records.jsonl"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0
    assert "backend/data/processed" in res.stdout


def test_pii_redaction_comprehensive_cases():
    """Verifies enhanced PII redaction pipeline across edge cases and negative controls."""
    from app.datasets.mbox_adapter import redact_pii

    # Positive cases
    assert redact_pii("Contact victim@example.com immediately") == "Contact v***@example.com immediately"
    assert redact_pii('<a href="mailto:support@secure-bank.com">Click</a>') == '<a href="mailto:s***@secure-bank.com">Click</a>'
    assert redact_pii("From: =?utf-8?q?victim=40domain=2Ecom?=") == "From: v***@domain.com"
    assert redact_pii("User test_user=40bank.com locked") == "User t***@bank.com locked"
    assert redact_pii("http://evil.com/verify?email=target.user%40company.com") == "http://evil.com/verify?email=t***@company.com"
    assert redact_pii("Call +1 (800) 555-1234 today") == "Call [REDACTED_PHONE] today"
    assert redact_pii("Call 1-800-555-1234 now") == "Call [REDACTED_PHONE] now"
    assert redact_pii("Call (800) 555-1234 now") == "Call [REDACTED_PHONE] now"
    assert redact_pii("Call 800-555-1234 now") == "Call [REDACTED_PHONE] now"
    assert redact_pii("Call 800.555.1234 now") == "Call [REDACTED_PHONE] now"
    assert redact_pii("UK Support: +44 20 7946 0958") == "UK Support: [REDACTED_PHONE]"
    assert redact_pii("FR Support: +33 1 23 45 67 89") == "FR Support: [REDACTED_PHONE]"
    assert redact_pii("DE Support: +49 30 1234 5678") == "DE Support: [REDACTED_PHONE]"

    # Negative controls (False-positive protections)
    assert redact_pii("Connected to host 192.168.1.1 on port 80") == "Connected to host 192.168.1.1 on port 80"
    assert redact_pii("Notice timestamp: 2005-06-16 12:00:00") == "Notice timestamp: 2005-06-16 12:00:00"
    assert redact_pii("Using MailSentra version v1.2.3 and Python 3.13.7") == "Using MailSentra version v1.2.3 and Python 3.13.7"
    assert redact_pii("Patched against CVE-2024-1234") == "Patched against CVE-2024-1234"
    assert redact_pii("Total wire transfer amount: $84,500.00") == "Total wire transfer amount: $84,500.00"
    assert redact_pii("Hardware token Model-3000-AB verified") == "Hardware token Model-3000-AB verified"


def test_mime_anomaly_recovery_and_warnings():
    """Verifies deterministic recovery and parser warnings for historical Content-Type folding."""
    processed_records = os.path.join(DATA_DIR, "processed", "phishing_email", "nazario_phishing3_records.jsonl")
    warnings_found = []
    with open(processed_records, "r", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if r.get("parser_warnings"):
                warnings_found.extend(r["parser_warnings"])

    assert len(warnings_found) == 5
    for w in warnings_found:
        assert w["warning_type"] == "MALFORMED_CONTENT_TYPE_FOLDING"
        assert w["recovered_content_type"] == "text/html"
        assert w["recovered_transfer_encoding"] == "8bit"


def test_empty_body_classification_reconciliation():
    """Verifies that all 26 empty-body records are properly categorized with evidence."""
    processed_records = os.path.join(DATA_DIR, "processed", "phishing_email", "nazario_phishing3_records.jsonl")
    classifications = {}
    attachment_only_records = []
    with open(processed_records, "r", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            cat = r.get("body_classification")
            assert cat in ("NORMAL", "ATTACHMENT_ONLY", "WHITESPACE_ONLY", "EMPTY_MESSAGE", "BODY_EXTRACTION_FAILURE")
            classifications[cat] = classifications.get(cat, 0) + 1
            if cat == "ATTACHMENT_ONLY":
                attachment_only_records.append(r)

    assert classifications["NORMAL"] == 2253
    assert classifications["ATTACHMENT_ONLY"] == 3
    assert classifications["WHITESPACE_ONLY"] == 23
    assert classifications.get("EMPTY_MESSAGE", 0) == 0
    assert classifications.get("BODY_EXTRACTION_FAILURE", 0) == 0

    # Verify attachment-only records have actual attachment evidence
    for a_rec in attachment_only_records:
        assert len(a_rec["attachment_filenames"]) > 0
        assert any(".zip" in fn for fn in a_rec["attachment_filenames"])


def test_ember_and_transformed_derivatives_documentation(registry):
    """Verifies explicit documentation for EMBER and transformed Tranco record."""
    ember = next(d for d in registry["datasets"] if d["dataset_id"] == "DS-MA-01")
    assert ember["is_synthetic_fixture"] is True
    assert ember["provenance_nature"] == ProvenanceNature.SYNTHETIC_FIXTURE_MOCK.value
    assert "2,381-dimension JSONL" in ember["transformation_notes"]
    assert "NOT executable PE payload bytes" in ember["transformation_notes"]

    tranco = next(d for d in registry["datasets"] if d["dataset_id"] == "DS-URL-07")
    assert tranco["is_synthetic_fixture"] is True
    assert tranco["provenance_nature"] == ProvenanceNature.TRANSFORMED_DERIVATIVE.value
    assert "Transformed derivative record" in tranco["transformation_notes"]
    assert "Tranco Top 1M" in tranco["transformation_notes"]
