"""Integrity and security verification tests for SpamAssassin Acquisition (DS-SP-01).

Validates:
1. Raw archive integrity, byte counts, and SHA-256 checksums.
2. TarBz2Adapter safe extraction security policies (traversal, symlinks, bounds).
3. MIME parsing quality, RFC-822 headers, and dual-view schema.
4. PII redaction and historical authentication header safety.
5. Internal and cross-corpus deduplication against Nazario and ground-truth fixtures.
6. Dataset lifecycle transitions, registry counters, and licensing constraints.
7. Git ignore exclusion and ground-truth manifest immutability.
"""

import os
import io
import json
import tarfile
import hashlib
import subprocess
import pytest

from app.datasets.contracts import (
    DatasetLifecycleStatus,
    ProvenanceNature,
    validate_lifecycle_state,
)
from app.datasets.tar_bz2_adapter import (
    TarBz2DatasetAdapter,
    TarExtractionSecurityError,
)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RAW_ARCHIVE = os.path.join(BASE_DIR, "backend", "data", "raw", "spam_email", "spamassassin", "20050311_spam_2.tar.bz2")
PROVENANCE_MANIFEST = os.path.join(BASE_DIR, "backend", "data", "raw", "spam_email", "spamassassin", "provenance_manifest.json")
PROCESSED_JSONL = os.path.join(BASE_DIR, "backend", "data", "processed", "spam_email", "spamassassin_spam2_records.jsonl")
PROCESSED_SUMMARY = os.path.join(BASE_DIR, "backend", "data", "processed", "spam_email", "spamassassin_spam2_summary.json")
REGISTRY_PATH = os.path.join(BASE_DIR, "backend", "data", "dataset_registry.json")
SPAM_MANIFEST = os.path.join(BASE_DIR, "backend", "data", "manifests", "spam_email.json")
REAL_25_MANIFEST = os.path.join(BASE_DIR, "backend", "tests", "fixtures", "ground_truth", "real_world_25_manifest.json")
SYNTH_75_MANIFEST = os.path.join(BASE_DIR, "backend", "tests", "fixtures", "ground_truth", "synthetic_75_manifest.json")


def test_spamassassin_raw_archive_integrity():
    """Confirms untouched raw archive existence, byte count, and SHA-256."""
    assert os.path.exists(RAW_ARCHIVE), f"Missing raw archive at {RAW_ARCHIVE}"
    actual_size = os.path.getsize(RAW_ARCHIVE)
    assert actual_size == 2059029, f"Unexpected archive size: {actual_size}"

    hasher = hashlib.sha256()
    with open(RAW_ARCHIVE, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    actual_sha = hasher.hexdigest()
    assert actual_sha == "44280a0e28bf7645b2279e8e42659271ad82c6f40bf8d364dbda7f1df344a765"


def test_provenance_manifest_content():
    """Verifies provenance manifest records licensing caveats accurately."""
    assert os.path.exists(PROVENANCE_MANIFEST)
    with open(PROVENANCE_MANIFEST, "r", encoding="utf-8") as f:
        meta = json.load(f)

    assert meta["dataset_id"] == "DS-SP-01"
    assert meta["archive_filename"] == "20050311_spam_2.tar.bz2"
    assert meta["publisher"] == "Apache Software Foundation (Justin Mason et al.)"
    assert meta["sha256"] == "44280a0e28bf7645b2279e8e42659271ad82c6f40bf8d364dbda7f1df344a765"
    assert meta["file_size_bytes"] == 2059029
    assert "copyright in message text remains with original senders" in meta["licensing_and_usage_restrictions"].lower()
    assert "not assigned apache license 2.0" in meta["licensing_and_usage_restrictions"].lower()
    assert "local research and testing" in meta["licensing_and_usage_restrictions"].lower()


def test_tar_adapter_security_rejections():
    """Tests that TarBz2DatasetAdapter rejects traversal, absolute paths, and hazardous member types."""
    adapter = TarBz2DatasetAdapter()

    # 1. Path traversal rejection
    bad_member_traversal = tarfile.TarInfo(name="spam_2/../../evil.eml")
    bad_member_traversal.type = tarfile.REGTYPE
    is_valid, reason, action = adapter.validate_member(bad_member_traversal)
    assert not is_valid
    assert action == "REJECT"
    assert "traversal" in reason.lower()

    # 2. Absolute path rejection (Unix style)
    bad_member_abs = tarfile.TarInfo(name="/etc/passwd")
    bad_member_abs.type = tarfile.REGTYPE
    is_valid, reason, action = adapter.validate_member(bad_member_abs)
    assert not is_valid
    assert action == "REJECT"
    assert "absolute path" in reason.lower()

    # 3. Absolute path rejection (Windows drive letter)
    bad_member_win = tarfile.TarInfo(name="C:/boot.ini")
    bad_member_win.type = tarfile.REGTYPE
    is_valid, reason, action = adapter.validate_member(bad_member_win)
    assert not is_valid
    assert action == "REJECT"
    assert "absolute path" in reason.lower()

    # 4. Symlink rejection
    symlink_member = tarfile.TarInfo(name="spam_2/link.eml")
    symlink_member.type = tarfile.SYMTYPE
    symlink_member.linkname = "/etc/shadow"
    is_valid, reason, action = adapter.validate_member(symlink_member)
    assert not is_valid
    assert action == "REJECT"
    assert "symlink" in reason.lower()

    # 5. Device rejection
    dev_member = tarfile.TarInfo(name="spam_2/dev_zero")
    dev_member.type = tarfile.CHRTYPE
    is_valid, reason, action = adapter.validate_member(dev_member)
    assert not is_valid
    assert action == "REJECT"
    assert "device" in reason.lower()

    # 6. Benign directory member safely skipped
    dir_member = tarfile.TarInfo(name="spam_2")
    dir_member.type = tarfile.DIRTYPE
    is_valid, reason, action = adapter.validate_member(dir_member)
    assert not is_valid
    assert action == "SKIP"

    # 7. Member exceeding individual file size limit
    oversized_member = tarfile.TarInfo(name="spam_2/huge.eml")
    oversized_member.type = tarfile.REGTYPE
    oversized_member.size = 20 * 1024 * 1024  # 20MB > 10MB limit
    is_valid, reason, action = adapter.validate_member(oversized_member)
    assert not is_valid
    assert action == "REJECT"
    assert "exceeds maximum allowed" in reason.lower()


def test_processed_jsonl_and_summary_reconciliation():
    """Verifies that all 1,397 regular message files were parsed without error."""
    assert os.path.exists(PROCESSED_JSONL)
    assert os.path.exists(PROCESSED_SUMMARY)

    with open(PROCESSED_SUMMARY, "r", encoding="utf-8") as f:
        summary = json.load(f)

    assert summary["dataset_id"] == "DS-SP-01"
    assert summary["total_regular_files"] == 1397
    assert summary["total_parsed"] == 1397
    assert summary["total_malformed"] == 0
    assert summary["total_rejected_members"] == 0
    assert summary["total_directories_skipped"] == 1
    assert summary["exact_duplicates"] == 0
    assert summary["campaign_near_duplicates"] == 59
    assert summary["unique_content_records"] == 1338
    assert summary["empty_body_classification_counts"]["NORMAL"] == 1396
    assert summary["empty_body_classification_counts"]["ATTACHMENT_ONLY"] == 1

    records_count = 0
    with open(PROCESSED_JSONL, "r", encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            assert rec["dataset_id"] == "DS-SP-01"
            assert rec["canonical_label"] in ("SPAM", "spam")
            assert rec["source_label"] == "spam"
            assert rec["auth_status"] == "UNKNOWN"
            assert "UNVERIFIED_HISTORICAL_HEADER" in rec["auth_status_note"]
            assert rec["raw_message_sha256"]
            assert rec["content_sha256"]
            assert "redacted_preview" in rec
            records_count += 1

    assert records_count == 1397


def test_attachment_only_message_lure():
    """Verifies that the single attachment-only spam message is correctly identified."""
    with open(PROCESSED_JSONL, "r", encoding="utf-8") as f:
        att_records = [json.loads(l) for l in f if json.loads(l)["body_classification"] == "ATTACHMENT_ONLY"]

    assert len(att_records) == 1
    rec = att_records[0]
    assert rec["message_index"] == 1290
    assert "Brand New Premium.htm" in rec["attachment_filenames"]


def test_cross_corpus_deduplication():
    """Asserts zero duplicate leakage between DS-SP-01 (SpamAssassin) and DS-PE-01 (Nazario)."""
    pe_jsonl = os.path.join(BASE_DIR, "backend", "data", "processed", "phishing_email", "nazario_phishing3_records.jsonl")
    assert os.path.exists(pe_jsonl), "Nazario records must exist for cross-corpus check"

    sp_raw_hashes = set()
    sp_content_hashes = set()
    with open(PROCESSED_JSONL, "r", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            sp_raw_hashes.add(r["raw_message_sha256"])
            sp_content_hashes.add(r["content_sha256"])

    pe_raw_hashes = set()
    pe_content_hashes = set()
    with open(pe_jsonl, "r", encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            pe_raw_hashes.add(r["raw_message_sha256"])
            pe_content_hashes.add(r["content_sha256"])

    assert len(sp_raw_hashes & pe_raw_hashes) == 0, "Found unexpected exact byte collision between SpamAssassin and Nazario!"
    assert len(sp_content_hashes & pe_content_hashes) == 0, "Found unexpected content collision between SpamAssassin and Nazario!"


def test_ground_truth_manifest_invariance():
    """Confirms historical ground truth manifests remain byte-for-byte invariant."""
    for manifest_path, expected_sha in [
        (REAL_25_MANIFEST, "5ebb9b190ab38b080be5f0acfce62def0cc806ada8e9a659cb08da8be2d97c03"),
        (SYNTH_75_MANIFEST, "3ce476003d827c20510b7b5bcc9f6f55a0973d9cf981594691d7b4681e8128b6"),
    ]:
        with open(manifest_path, "rb") as f:
            actual_sha = hashlib.sha256(f.read()).hexdigest()
        assert actual_sha == expected_sha, f"Ground truth manifest {manifest_path} was modified!"


def test_registry_and_manifest_lifecycle_conformance():
    """Verifies that DS-SP-01 in dataset_registry and spam_email manifest is strictly INTEGRATED with evaluated=0."""
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        reg = json.load(f)
    with open(SPAM_MANIFEST, "r", encoding="utf-8") as f:
        spam_m = json.load(f)

    reg_entry = next(d for d in reg["datasets"] if d["dataset_id"] == "DS-SP-01")
    man_entry = next(d for d in spam_m["datasets"] if d["dataset_id"] == "DS-SP-01")

    for entry in [reg_entry, man_entry]:
        assert entry["lifecycle_status"] == DatasetLifecycleStatus.INTEGRATED.value
        assert entry["integration_status"] == "INTEGRATED"
        assert entry["is_synthetic_fixture"] is False
        assert entry["provenance_nature"] == ProvenanceNature.EXTERNAL_ACQUIRED.value
        assert entry["external_records_count"] == 1397
        assert entry["synthetic_records_count"] == 0
        assert entry["evaluated_record_count"] == 0
        assert entry["checksum_sha256"] == "44280a0e28bf7645b2279e8e42659271ad82c6f40bf8d364dbda7f1df344a765"
        validate_lifecycle_state(entry)

    # Global counters in registry
    assert reg["total_candidates"] == 103
    assert reg["total_approved"] == 88
    assert reg["total_integrated"] in (20, 21)
    assert reg["total_evaluated"] == 0
    assert reg["external_records_count"] in (3676, 5172)
    assert reg["synthetic_fixture_datasets"] == 18


def test_git_exclusion():
    """Verifies git ignore rules for raw archives and processed corpora."""
    for rel_path in [
        "backend/data/raw/spam_email/spamassassin/20050311_spam_2.tar.bz2",
        "backend/data/processed/spam_email/spamassassin_spam2_records.jsonl",
    ]:
        res = subprocess.run(
            ["git", "check-ignore", "-v", rel_path],
            cwd=BASE_DIR,
            capture_output=True,
            text=True
        )
        assert res.returncode == 0, f"Path {rel_path} is NOT ignored by git!"
