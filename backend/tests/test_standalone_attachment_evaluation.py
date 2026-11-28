"""
Regression and validation test suite for Standalone Attachment Evaluation in DatasetEvaluator
and Attachment Forensics Security Remediations.

Covers:
1. Original standalone attachment evaluation pipeline tests.
2. The 12 mandatory security regression scenarios:
   - Scenario 1: Declared size 500 bytes with actual payload > 25 MB (effective_size 30MB -> SKIPPED_OVERSIZED)
   - Scenario 2: Actual payload > 25 MB with no declared size (SKIPPED_OVERSIZED)
   - Scenario 3: Declared size larger than actual payload (30MB declared, 500B payload -> SKIPPED_OVERSIZED)
   - Scenario 4: Oversized Base64 input rejected before decoding (check pre-decode bound, verify OVERSIZED_BASE64)
   - Scenario 5: Malformed Base64 safely handled (payload_warning set, zero crash)
   - Scenario 6: Base64-valid ordinary text handled according to explicit contract (bare string 'test' rejected as STRING_NOT_BINARY)
   - Scenario 7: Oversized adapter input does not duplicate payload in memory
   - Scenario 8: Original payload hash remains distinguishable from truncated-buffer hash
   - Scenario 9: Truncated ZIP payload is not treated as a complete archive (Truncated archive buffer cannot be safely decompressed)
   - Scenario 10: Empty benchmark test split does not silently evaluate training records (EMPTY_TEST_PARTITION)
   - Scenario 11: Explicit fixture fallback works only when fixture_mode=True is enabled
   - Scenario 12: Evaluation output clearly indicates whether fixture fallback was used (partition_fallback_applied)
"""

import base64
import email.message
import hashlib
import io
import os
import pytest
import zipfile

from app.datasets.adapters import AttachmentDatasetAdapter
from app.datasets.contracts import CanonicalThreatLabel, DatasetCategory
from app.datasets.evaluator import DatasetEvaluator
from app.modules.attachment_analysis.analyzer import AttachmentAnalyzer
from app.modules.contracts import AttachmentMetadata


@pytest.fixture
def evaluator():
    """Default evaluator with offline auth enabled and fixture_mode=True for unit sample evaluation."""
    return DatasetEvaluator(offline_auth=True, fixture_mode=True)


@pytest.fixture
def benchmark_evaluator():
    """Benchmark evaluator with fixture_mode=False to enforce strict split rules."""
    return DatasetEvaluator(offline_auth=True, fixture_mode=False)


# ============================================================================
# Original Suite: Standalone Attachment Evaluation Core Functionality
# ============================================================================

def test_real_binary_attachment_bytes_reach_analyzer(evaluator):
    """Verifies that raw bytes passed in a record are handed off to AttachmentAnalyzer."""
    pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
    records = [
        {
            "id": "TEST-BIN-01",
            "filename": "payload.bin",
            "file_type": "UNKNOWN",
            "raw_bytes": pe_header,
            "label": "malware",
        }
    ]
    results = evaluator.evaluate_attachment_dataset(records)
    assert results["total_tested"] == 1
    detail = results["details"][0]
    assert detail["has_raw_payload"] is True
    assert "Binary" in detail["detected_format"] or "Executable" in detail["detected_format"]
    assert detail["severity"] == "MALICIOUS"
    assert detail["detected"] is True


def test_valid_zip_attachment_inspected_using_actual_bytes(evaluator):
    """Verifies that an authentic in-memory ZIP archive is parsed and its inner entries flagged."""
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("benign_note.txt", "Please find the requested file.")
        zf.writestr("hidden_installer.exe", b"MZ" + b"\x00" * 64)

    raw_zip_bytes = zip_buf.getvalue()
    records = [
        {
            "id": "TEST-ZIP-01",
            "filename": "archive_bundle.zip",
            "content_type": "application/zip",
            "raw_bytes": raw_zip_bytes,
            "label": "malware",
        }
    ]
    results = evaluator.evaluate_attachment_dataset(records)
    assert results["total_tested"] == 1
    detail = results["details"][0]
    assert detail["has_raw_payload"] is True
    assert "ZIP" in detail["detected_format"]
    assert detail["severity"] == "MALICIOUS"
    assert "hidden_installer.exe" in detail["details"]


def test_metadata_only_records_continue_to_work(evaluator):
    """Verifies that records without raw_bytes evaluate cleanly via metadata heuristics."""
    rec_malware = [
        {
            "id": "TEST-META-01",
            "filename": "Quarterly_Bonus.pdf.exe",
            "file_type": "PE_EXECUTABLE",
            "label": "malware",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }
    ]
    rec_benign = [
        {
            "id": "TEST-META-02",
            "filename": "Standard_Document.pdf",
            "file_type": "PDF",
            "content_type": "application/pdf",
            "label": "benign",
            "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        }
    ]
    res_mal = evaluator.evaluate_attachment_dataset(rec_malware)
    assert res_mal["total_tested"] == 1
    exe_rec = res_mal["details"][0]
    assert exe_rec["has_raw_payload"] is False
    assert exe_rec["severity"] == "MALICIOUS"

    res_benign = evaluator.evaluate_attachment_dataset(rec_benign)
    assert res_benign["total_tested"] == 1
    pdf_rec = res_benign["details"][0]
    assert pdf_rec["has_raw_payload"] is False
    assert pdf_rec["severity"] == "SAFE"


def test_invalid_binary_representations_handled_safely(evaluator):
    """Verifies that non-binary, malformed base64, or unexpected types do not cause unhandled exceptions."""
    records = [
        {
            "id": "TEST-ERR-01",
            "filename": "corrupted_string.bin",
            "raw_bytes": "!!not_valid_base64_or_bytes!!",
            "label": "benign",
        },
        {
            "id": "TEST-ERR-02",
            "filename": "invalid_type.bin",
            "raw_bytes": 123456789,
            "label": "benign",
        },
    ]
    results = evaluator.evaluate_attachment_dataset(records)
    assert results["total_tested"] == 2
    for detail in results["details"]:
        assert detail["has_raw_payload"] is False
        assert "payload_warning" in detail


def test_oversized_attachments_respect_existing_limits(evaluator):
    """Verifies that files exceeding max_attachment_size_bytes trigger SKIPPED_OVERSIZED."""
    # 30 MB size_bytes declaration (limit is 25 MB)
    records = [
        {
            "id": "TEST-OVERSIZED-01",
            "filename": "enormous_dump.dat",
            "size_bytes": 30 * 1024 * 1024,
            "raw_bytes": b"A" * 1024,  # Small payload with declared large size
            "label": "malware",
        }
    ]
    results = evaluator.evaluate_attachment_dataset(records)
    assert results["total_tested"] == 1
    detail = results["details"][0]
    assert detail["severity"] == "SUSPICIOUS"
    assert "exceeds analysis limit" in detail["details"]


def test_binary_content_cannot_bypass_magic_validation(evaluator):
    """Verifies that an executable disguised as a benign PDF is caught via magic bytes."""
    pe_payload = b"MZ\x90\x00" + b"\x00" * 128
    records = [
        {
            "id": "TEST-BYPASS-01",
            "filename": "legitimate_statement.pdf",
            "content_type": "application/pdf",
            "raw_bytes": pe_payload,
            "label": "malware",
        }
    ]
    results = evaluator.evaluate_attachment_dataset(records)
    assert results["total_tested"] == 1
    detail = results["details"][0]
    assert detail["has_raw_payload"] is True
    assert "Binary" in detail["detected_format"] or "Executable" in detail["detected_format"]
    assert detail["severity"] == "MALICIOUS"
    assert "MIME mismatch" in detail["details"] or "Executable binary header" in detail["details"]


def test_existing_email_level_attachment_evaluation_unchanged(evaluator):
    """Verifies that evaluate_email_dataset continues to extract and evaluate attachments end-to-end."""
    msg = email.message.EmailMessage()
    msg["From"] = "finance@company.com"
    msg["To"] = "student@university.edu"
    msg["Subject"] = "Invoice Notification"
    msg.set_content("Please inspect the attached receipt.")
    msg.add_attachment(
        b"%PDF-1.7\n%Benign synthetic receipt PDF\n%%EOF",
        maintype="application",
        subtype="pdf",
        filename="receipt.pdf",
    )

    records = [
        {
            "record_id": "EML-ATT-01",
            "raw_bytes": msg.as_bytes(),
            "subject": "Invoice Notification",
            "canonical_label": CanonicalThreatLabel.BENIGN.value,
        }
    ]

    results = evaluator.evaluate_email_dataset(DatasetCategory.BENIGN_CONTROLS, records)
    assert results["total_tested"] == 1
    telem = results["module_telemetry"]
    assert telem["records_parsed"] == 1
    assert telem["records_attachment"] == 1
    assert telem["records_risk"] == 1
    detail = results["details"][0]
    assert detail["attachments_count"] == 1


# ============================================================================
# Mandatory Regression Suite: 12 Remediation Verification Scenarios
# ============================================================================

def test_scenario_01_declared_size_small_actual_payload_oversized(evaluator):
    """Scenario 1: Declared size 500 bytes with actual payload > 25 MB (effective_size 30MB -> SKIPPED_OVERSIZED)."""
    payload_30mb = b"X" * (30 * 1024 * 1024)
    records = [
        {
            "id": "SCENARIO-01",
            "filename": "payload_hidden_oversized.bin",
            "size_bytes": 500,  # Misleading declared size
            "raw_bytes": payload_30mb,
            "label": "malware",
        }
    ]
    results = evaluator.evaluate_attachment_dataset(records)
    assert results["total_tested"] == 1
    detail = results["details"][0]
    assert detail["effective_size"] >= 30 * 1024 * 1024
    assert detail["severity"] == "SUSPICIOUS"
    assert "exceeds analysis limit" in detail["details"]


def test_scenario_02_actual_payload_oversized_no_declared_size(evaluator):
    """Scenario 2: Actual payload > 25 MB with no declared size (SKIPPED_OVERSIZED)."""
    payload_26mb = b"Y" * (26 * 1024 * 1024)
    records = [
        {
            "id": "SCENARIO-02",
            "filename": "no_declared_size_oversized.bin",
            "raw_bytes": payload_26mb,
            "label": "malware",
        }
    ]
    results = evaluator.evaluate_attachment_dataset(records)
    assert results["total_tested"] == 1
    detail = results["details"][0]
    assert detail["effective_size"] >= 26 * 1024 * 1024
    assert detail["severity"] == "SUSPICIOUS"
    assert "exceeds analysis limit" in detail["details"]


def test_scenario_03_declared_size_larger_than_actual_payload(evaluator):
    """Scenario 3: Declared size larger than actual payload (30MB declared, 500B payload -> SKIPPED_OVERSIZED)."""
    payload_500b = b"Z" * 500
    records = [
        {
            "id": "SCENARIO-03",
            "filename": "declared_huge.dat",
            "size_bytes": 30 * 1024 * 1024,
            "raw_bytes": payload_500b,
            "label": "malware",
        }
    ]
    results = evaluator.evaluate_attachment_dataset(records)
    assert results["total_tested"] == 1
    detail = results["details"][0]
    assert detail["effective_size"] == 30 * 1024 * 1024
    assert detail["severity"] == "SUSPICIOUS"
    assert "exceeds analysis limit" in detail["details"]


def test_scenario_04_oversized_base64_rejected_before_decoding(evaluator):
    """Scenario 4: Oversized Base64 input rejected before decoding (check pre-decode bound, verify OVERSIZED_BASE64)."""
    max_limit = evaluator.attachment_analyzer.config.max_attachment_size_bytes
    max_b64_len = ((max_limit + 2) // 3) * 4 + 8192

    # String exceeding calculated pre-decode bound
    oversized_b64 = "QUJD" * (max_b64_len // 4 + 100)
    assert len(oversized_b64) > max_b64_len

    payload_bytes, warning = evaluator._extract_attachment_payload({"raw_base64": oversized_b64})
    assert payload_bytes is None
    assert warning is not None
    assert "OVERSIZED_BASE64" in warning


def test_scenario_05_malformed_base64_safely_handled(evaluator):
    """Scenario 5: Malformed Base64 safely handled (payload_warning set, zero crash)."""
    malformed_b64 = "Invalid===Base64!@#$%"
    payload_bytes, warning = evaluator._extract_attachment_payload({"raw_base64": malformed_b64})
    assert payload_bytes is None
    assert warning is not None
    assert "Invalid base64 payload" in warning

    records = [
        {
            "id": "SCENARIO-05",
            "filename": "malformed_b64.bin",
            "raw_base64": malformed_b64,
            "label": "benign",
        }
    ]
    results = evaluator.evaluate_attachment_dataset(records)
    assert results["total_tested"] == 1
    assert results["details"][0]["has_raw_payload"] is False
    assert "payload_warning" in results["details"][0]


def test_scenario_06_base64_valid_ordinary_text_handled_according_to_contract(evaluator):
    """Scenario 6: Base64-valid ordinary text handled according to explicit contract (bare string 'test' rejected as STRING_NOT_BINARY)."""
    # Plain text 'test' is valid base64 (decodes to b'\xb5\xeb-'), but passed as raw_bytes without prefix
    payload_bytes, warning = evaluator._extract_attachment_payload({"raw_bytes": "test"})
    assert payload_bytes is None
    assert warning is not None
    assert "STRING_NOT_BINARY" in warning

    # Explicit base64: prefix is accepted
    encoded_test = base64.b64encode(b"hello world").decode("ascii")
    payload_bytes_prefixed, warning_prefixed = evaluator._extract_attachment_payload({"raw_bytes": f"base64:{encoded_test}"})
    assert payload_bytes_prefixed == b"hello world"
    assert warning_prefixed is None


def test_scenario_07_oversized_adapter_input_does_not_duplicate_memory():
    """Scenario 7: Oversized adapter input does not duplicate payload in memory."""
    large_payload = b"M" * (5 * 1024 * 1024)
    raw_record = {
        "id": "ADAPTER-TEST-01",
        "filename": "memory_test.bin",
        "file_type": "UNKNOWN",
        "raw_bytes": large_payload,
        "label": "malware",
    }
    adapter = AttachmentDatasetAdapter("DS-TEST", DatasetCategory.MALWARE_ATTACHMENTS, "Module 6")
    normalized = adapter.normalize_record(raw_record)

    # Identical object reference in memory (no duplication into extra fields)
    assert normalized["raw_bytes"] is large_payload
    assert normalized.get("raw_payload") is None
    assert normalized["size_bytes"] == len(large_payload)


def test_scenario_08_original_payload_hash_distinguishable_from_truncated_hash(evaluator):
    """Scenario 8: Original payload hash remains distinguishable from truncated-buffer hash."""
    max_limit = evaluator.attachment_analyzer.config.max_attachment_size_bytes
    # Create payload larger than 25MB limit
    payload = b"H" * (max_limit + 4096)
    full_sha256 = hashlib.sha256(payload).hexdigest()
    truncated_sha256 = hashlib.sha256(payload[:max_limit]).hexdigest()

    assert full_sha256 != truncated_sha256

    records = [
        {
            "id": "SCENARIO-08",
            "filename": "hash_integrity_test.bin",
            "raw_bytes": payload,
            "label": "malware",
        }
    ]
    results = evaluator.evaluate_attachment_dataset(records)
    detail = results["details"][0]
    assert detail["is_truncated"] is True
    # The reported SHA-256 hash must be the authentic full payload hash
    assert detail["sha256_hash"] == full_sha256
    assert detail["sha256_hash"] != truncated_sha256


def test_scenario_09_truncated_zip_payload_not_treated_as_complete_archive():
    """Scenario 9: Truncated ZIP payload is not treated as a complete archive (Truncated archive buffer cannot be safely decompressed)."""
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test_file.txt", "Some content for zip archive testing.")
    full_zip = zip_buf.getvalue()

    # Slice archive in half to simulate truncated buffer
    truncated_zip = full_zip[:len(full_zip) // 2]

    analyzer = AttachmentAnalyzer()
    att_meta = AttachmentMetadata(
        filename="partial_archive.zip",
        original_filename="partial_archive.zip",
        content_type="application/zip",
        file_extension="zip",
        size_bytes=len(full_zip),
        sha256_hash=hashlib.sha256(full_zip).hexdigest(),
        raw_payload=truncated_zip,
        is_truncated=True,
    )
    finding = analyzer.analyze_single_attachment(att_meta)
    assert finding.is_archive is True
    assert finding.is_truncated is True
    assert finding.severity == "SUSPICIOUS"
    assert "Truncated archive buffer cannot be safely decompressed" in finding.details


def test_scenario_10_empty_benchmark_test_split_does_not_silently_evaluate(benchmark_evaluator):
    """Scenario 10: Empty benchmark test split does not silently evaluate training records (EMPTY_TEST_PARTITION)."""
    single_record = [
        {
            "id": "BENCHMARK-EMPTY-01",
            "filename": "benign.pdf",
            "raw_bytes": b"%PDF-1.7 ...",
            "label": "benign",
        }
    ]
    # Running under benchmark_evaluator (fixture_mode=False) with 1 record results in empty test split
    results = benchmark_evaluator.evaluate_attachment_dataset(single_record)
    assert results["status"] == "EMPTY_TEST_PARTITION"
    assert results["total_tested"] == 0
    assert results["partition_fallback_applied"] is False
    assert results["evaluation_mode"] == "BENCHMARK_STRICT"
    assert "Deterministic split yielded empty test partition" in results["error"]


def test_scenario_11_explicit_fixture_fallback_works_only_when_fixture_mode_enabled(benchmark_evaluator):
    """Scenario 11: Explicit fixture fallback works only when fixture_mode=True is enabled."""
    single_record = [
        {
            "id": "FIXTURE-FALLBACK-01",
            "filename": "benign.pdf",
            "raw_bytes": b"%PDF-1.7 ...",
            "label": "benign",
        }
    ]
    # Default benchmark_evaluator has fixture_mode=False
    res_strict = benchmark_evaluator.evaluate_attachment_dataset(single_record, fixture_mode=False)
    assert res_strict["status"] == "EMPTY_TEST_PARTITION"
    assert res_strict["total_tested"] == 0

    # Overriding with fixture_mode=True allows controlled fallback
    res_fixture = benchmark_evaluator.evaluate_attachment_dataset(single_record, fixture_mode=True)
    assert res_fixture["total_tested"] == 1
    assert res_fixture["partition_fallback_applied"] is True
    assert res_fixture["evaluation_mode"] == "FIXTURE_FALLBACK"


def test_scenario_12_evaluation_output_clearly_indicates_partition_fallback_telemetry(evaluator):
    """Scenario 12: Evaluation output clearly indicates whether fixture fallback was used (partition_fallback_applied)."""
    single_record = [
        {
            "id": "TELEMETRY-01",
            "filename": "invoice.pdf",
            "raw_bytes": b"%PDF-1.7 ...",
            "label": "benign",
        }
    ]
    results = evaluator.evaluate_attachment_dataset(single_record)
    assert "partition_fallback_applied" in results
    assert "evaluation_mode" in results
    assert results["partition_fallback_applied"] is True
    assert results["evaluation_mode"] == "FIXTURE_FALLBACK"
