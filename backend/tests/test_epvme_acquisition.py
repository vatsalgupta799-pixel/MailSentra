"""
Automated Verification Suite for MailSentra Category 3 (DS-SS-01 EPVME Protocol Spoofing Corpus).

Verifies:
1. Multi-archive acquisition integrity and SHA-256 hashes for all 8 ZIP files.
2. Safe extraction security guards (path traversal, absolute paths, compression limits, extension filtering).
3. Record normalization, canonical schema conformance, and PII masking.
4. Comprehensive scenario coverage across all 6 spoofing attack groups (1,496 total records).
5. Historical authentication untrusted status boundary enforcement.
6. Cross-corpus leakage controls and deduplication audit metrics against Nazario and SpamAssassin.
7. Dataset registry and sender_spoofing manifest lifecycle compliance (INTEGRATED, evaluated_record_count == 0).
8. Git exclusion protection for raw archives and processed corpora.
9. Ground-truth benchmark manifests invariance.
10. Production-path evaluation evidence for Modules 1, 2, and 3.
"""

import hashlib
import json
import os
import subprocess
import zipfile
import pytest

from app.datasets.contracts import (
    DatasetLifecycleStatus,
    ProvenanceNature,
    CanonicalThreatLabel,
    validate_lifecycle_state,
)
from app.datasets.epvme_adapter import EpvmeDatasetAdapter

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RAW_EPVME_DIR = os.path.join(PROJECT_ROOT, "backend", "data", "raw", "sender_spoofing", "epvme")
PROCESSED_JSONL = os.path.join(PROJECT_ROOT, "backend", "data", "processed", "sender_spoofing", "epvme_records.jsonl")
SUMMARY_JSON = os.path.join(PROJECT_ROOT, "backend", "data", "processed", "sender_spoofing", "epvme_summary.json")
EVAL_JSON = os.path.join(PROJECT_ROOT, "backend", "data", "processed", "sender_spoofing", "epvme_module_evaluation.json")
MANIFEST_JSON = os.path.join(PROJECT_ROOT, "backend", "data", "manifests", "sender_spoofing.json")
REGISTRY_JSON = os.path.join(PROJECT_ROOT, "backend", "data", "dataset_registry.json")
PROVENANCE_MANIFEST = os.path.join(RAW_EPVME_DIR, "provenance_manifest.json")

EXPECTED_ARCHIVES = {
    "EPVME_1.zip": (22669320, "3e4e18371f2dc08a9668b1c0309c91e19a612a5068021e245cb6005e92958b97"),
    "EPVME_2.zip": (22510355, "6e47779c7810aa02bac83e064abc6bef1ad5d599b9d32d0744d4595dc19caeac"),
    "EPVME_3.zip": (23222538, "6c3993b1624b42d9832ee4f4119b4dc05702f1d6ece4f644b69abf9b15973e95"),
    "EPVME_4.zip": (22760627, "c58075919e1b2e349515f78529b9099e727ea70aca4790523604e1b3f10e9fcc"),
    "EPVME_5.zip": (23365568, "e3ede08059236238c2c8815ea57c6afab6dd0af05834d93d97949f1dccb9b800"),
    "EPVME_6.zip": (20229117, "4d0bb77d6a21ec80a31f714e704dbfcb2c035bd5318527621409f11ffa0990a2"),
    "EPVME_7.zip": (19245502, "7ce8668590f66a86bcd79301ebaefce7101adfb469b4ad70b7e339b3d01ace8f"),
    "EPVME_8.zip": (17807890, "45204efa6841b43580860ae28c3d002e26fedb38098ff52cc0fa5ffd7afe41ca"),
}


def test_epvme_all_eight_archives_exist_and_hash():
    """Verifies that all 8 downloaded EPVME zip archives exist with correct byte sizes and SHA-256 hashes."""
    assert os.path.exists(RAW_EPVME_DIR), f"Raw EPVME directory {RAW_EPVME_DIR} does not exist"
    assert os.path.exists(PROVENANCE_MANIFEST), "provenance_manifest.json must exist"

    total_bytes = 0
    for arch_name, (expected_size, expected_sha) in EXPECTED_ARCHIVES.items():
        arch_path = os.path.join(RAW_EPVME_DIR, arch_name)
        assert os.path.exists(arch_path), f"Missing archive: {arch_name}"
        
        actual_size = os.path.getsize(arch_path)
        assert actual_size == expected_size, f"Size mismatch for {arch_name}: expected {expected_size}, got {actual_size}"
        total_bytes += actual_size

        with open(arch_path, "rb") as f:
            h = hashlib.sha256()
            while chunk := f.read(65536):
                h.update(chunk)
            actual_sha = h.hexdigest()
        assert actual_sha == expected_sha, f"SHA-256 mismatch for {arch_name}: expected {expected_sha}, got {actual_sha}"

    assert total_bytes == 171810917, f"Total archive size mismatch: expected 171810917, got {total_bytes}"


def test_safe_extraction_security_controls():
    """Verifies that EpvmeDatasetAdapter strictly blocks path traversal, absolute paths, and oversized members."""
    adapter = EpvmeDatasetAdapter(provenance_manifest_path=PROVENANCE_MANIFEST)

    # Test path traversal
    info_traversal = zipfile.ZipInfo(filename="../../evil.eml")
    info_traversal.file_size = 100
    valid, reason, action = adapter.validate_zip_member(info_traversal)
    assert not valid
    assert action == "REJECT"
    assert "Path traversal" in reason

    # Test absolute path
    info_abs = zipfile.ZipInfo(filename="/etc/evil.eml")
    info_abs.file_size = 100
    valid, reason, action = adapter.validate_zip_member(info_abs)
    assert not valid
    assert action == "REJECT"
    assert "Absolute path" in reason

    # Test non-EML extension
    info_non_eml = zipfile.ZipInfo(filename="payload.exe")
    info_non_eml.file_size = 100
    valid, reason, action = adapter.validate_zip_member(info_non_eml)
    assert not valid
    assert action == "REJECT"
    assert "Non-EML" in reason

    # Test size bomb protection (>10MB)
    info_oversized = zipfile.ZipInfo(filename="oversized.eml")
    info_oversized.file_size = 15 * 1024 * 1024
    valid, reason, action = adapter.validate_zip_member(info_oversized)
    assert not valid
    assert action == "REJECT"
    assert "exceeds maximum" in reason


def test_epvme_records_schema_and_normalization():
    """Verifies that all 1,496 normalized records conform to MailSentra's canonical schema."""
    assert os.path.exists(PROCESSED_JSONL), "Processed JSONL file missing"
    
    count = 0
    with open(PROCESSED_JSONL, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            count += 1
            rec = json.loads(line)

            assert "message_id" in rec
            assert rec["dataset_id"] == "DS-SS-01"
            assert rec["canonical_label"] == CanonicalThreatLabel.SPOOFING.value
            assert rec["provenance_nature"] == ProvenanceNature.TRANSFORMED_DERIVATIVE.value
            assert rec["auth_status"] == "UNKNOWN"
            assert "raw_message_sha256" in rec
            assert "content_sha256" in rec
            assert "attack_scenario" in rec

            # Dual-view PII redaction preview exists
            preview = rec["redacted_preview"]
            assert "subject" in preview
            assert "body_preview" in preview
            assert "from" in preview
            assert "to" in preview

    assert count == 1496, f"Expected 1496 normalized records, got {count}"


def test_epvme_scenario_coverage():
    """Verifies that all 6 spoofing attack scenarios are represented with exact documented distributions."""
    assert os.path.exists(SUMMARY_JSON), "epvme_summary.json missing"
    with open(SUMMARY_JSON, "r", encoding="utf-8") as f:
        summary = json.load(f)

    counts = summary["scenario_counts"]
    assert counts["MIME_SIGNATURE_TAMPERING"] == 528
    assert counts["EMPTY_MAIL_FROM"] == 365
    assert counts["FROM_HEADER_INJECTION"] == 323
    assert counts["MULTIPLE_FROM_HEADERS"] == 96
    assert counts["SUBDOMAIN_EVASION"] == 60
    assert counts["MAIL_FROM_MISMATCH"] == 28
    assert counts["OTHER_PROTOCOL_SPOOF"] == 96
    assert sum(counts.values()) == 1496


def test_historical_authentication_untrusted_status():
    """Verifies that historical authentication headers in EPVME are strictly marked UNKNOWN and untrusted."""
    with open(PROCESSED_JSONL, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            assert rec["auth_status"] == "UNKNOWN"
            assert "untrusted" in rec.get("auth_status_note", "").lower() or "boundary" in rec.get("auth_status_note", "").lower()


def test_cross_corpus_leakage_controls():
    """Verifies cross-corpus overlap metrics: 0 exact raw byte duplicates, with documented content overlaps."""
    nazario_path = os.path.join(PROJECT_ROOT, "backend", "data", "processed", "phishing_email", "nazario_phishing3_records.jsonl")
    spamassassin_path = os.path.join(PROJECT_ROOT, "backend", "data", "processed", "spam_email", "spamassassin_spam2_records.jsonl")

    assert os.path.exists(nazario_path)
    assert os.path.exists(spamassassin_path)

    epvme_raw_hashes = set()
    with open(PROCESSED_JSONL, "r", encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            epvme_raw_hashes.add(rec["raw_message_sha256"])

    # Check against Nazario
    naz_raw_match = 0
    with open(nazario_path, "r", encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            raw_h = rec.get("raw_payload_hash_sha256") or rec.get("raw_message_sha256")
            if raw_h in epvme_raw_hashes:
                naz_raw_match += 1

    # Check against SpamAssassin
    sa_raw_match = 0
    with open(spamassassin_path, "r", encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            raw_h = rec.get("raw_payload_hash_sha256") or rec.get("raw_message_sha256")
            if raw_h in epvme_raw_hashes:
                sa_raw_match += 1

    # Raw messages are distinct because EPVME modified headers/signatures
    assert naz_raw_match == 0, f"Expected 0 exact raw matches with Nazario, found {naz_raw_match}"
    assert sa_raw_match == 0, f"Expected 0 exact raw matches with SpamAssassin, found {sa_raw_match}"


def test_epvme_registry_and_manifest_lifecycle():
    """Verifies that DS-SS-01 is correctly integrated in manifests and dataset registry with honest metrics."""
    # Manifest verification
    with open(MANIFEST_JSON, "r", encoding="utf-8") as f:
        mf = json.load(f)
    ds_entry = next(d for d in mf["datasets"] if d["dataset_id"] == "DS-SS-01")
    assert ds_entry["lifecycle_status"] == DatasetLifecycleStatus.INTEGRATED.value
    assert ds_entry["is_synthetic_fixture"] is False
    assert ds_entry["provenance_nature"] == ProvenanceNature.TRANSFORMED_DERIVATIVE.value
    assert ds_entry["raw_record_count"] == 1496
    assert ds_entry["external_records_count"] == 1496
    assert ds_entry["evaluated_record_count"] == 0
    validate_lifecycle_state(ds_entry)

    # Registry verification
    with open(REGISTRY_JSON, "r", encoding="utf-8") as f:
        reg = json.load(f)
    reg_entry = next(d for d in reg["datasets"] if d["dataset_id"] == "DS-SS-01")
    assert reg_entry["lifecycle_status"] == DatasetLifecycleStatus.INTEGRATED.value
    assert reg_entry["is_synthetic_fixture"] is False
    assert reg_entry["provenance_nature"] == ProvenanceNature.TRANSFORMED_DERIVATIVE.value
    assert reg_entry["raw_record_count"] == 1496
    assert reg_entry["external_records_count"] == 1496
    assert reg_entry["evaluated_record_count"] == 0
    validate_lifecycle_state(reg_entry)

    assert reg["external_records_count"] == 5172
    assert reg["synthetic_fixture_datasets"] == 18
    assert reg["synthetic_fixture_records"] == 18


def test_git_exclusion_for_epvme():
    """Verifies that raw ZIP archives and processed JSONL records are completely ignored by git."""
    for rel_path in [
        "backend/data/raw/sender_spoofing/epvme/EPVME_1.zip",
        "backend/data/raw/sender_spoofing/epvme/EPVME_8.zip",
        "backend/data/processed/sender_spoofing/epvme_records.jsonl",
    ]:
        res = subprocess.run(
            ["git", "check-ignore", "-v", rel_path],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
        )
        assert res.returncode == 0, f"File {rel_path} is NOT ignored by git! Output: {res.stdout}"


def test_ground_truth_benchmarks_unmodified():
    """Verifies that historical ground-truth manifests are completely unmodified by DS-SS-01 acquisition."""
    rw25_path = os.path.join(PROJECT_ROOT, "backend", "tests", "fixtures", "ground_truth", "real_world_25_manifest.json")
    syn75_path = os.path.join(PROJECT_ROOT, "backend", "tests", "fixtures", "ground_truth", "synthetic_75_manifest.json")

    assert os.path.exists(rw25_path)
    assert os.path.exists(syn75_path)

    with open(rw25_path, "r", encoding="utf-8") as f:
        rw_data = json.load(f)
    assert rw_data["total_fixtures"] == 25
    assert len(rw_data["fixtures"]) == 25
    assert all(r.get("source_dataset") != "DS-SS-01" for r in rw_data["fixtures"])

    with open(syn75_path, "r", encoding="utf-8") as f:
        syn_data = json.load(f)
    assert syn_data["total_fixtures"] == 75
    assert len(syn_data["fixtures"]) == 75
    assert all(r.get("source_dataset") != "DS-SS-01" for r in syn_data["fixtures"])


def test_production_module_evaluation_evidence():
    """Verifies that the production-path evaluation evidence file exists with validated coverage across Modules 1-3."""
    assert os.path.exists(EVAL_JSON), "Evaluation evidence JSON missing"
    with open(EVAL_JSON, "r", encoding="utf-8") as f:
        ev = json.load(f)

    m1 = ev["module_1_mime_parser"]
    assert m1["records_tested"] == 1496
    assert m1["multiple_from_headers_detected"] == 96
    assert m1["empty_envelope_syntax_detected"] == 1402
    assert m1["header_injection_syntax_detected"] == 323
    assert m1["parser_coverage_rate"] == 1.0

    m2 = ev["module_2_sender_identity"]
    assert m2["records_tested"] == 1496
    assert m2["envelope_from_mismatch_flagged"] == 94
    assert m2["subdomain_evasion_flagged"] == 77
    assert m2["display_name_spoofing_flagged"] == 419
    assert m2["identity_coverage_rate"] == 1.0

    m3 = ev["module_3_auth_protocols"]
    assert m3["records_tested"] == 1496
    assert m3["dmarc_alignment_failures_identified"] == 1388
    assert m3["untrusted_historical_headers_enforced"] == 1496
    assert m3["auth_boundary_integrity_rate"] == 1.0
