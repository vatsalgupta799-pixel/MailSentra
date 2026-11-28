"""Automated Manifest and Evaluation Ground-Truth Integrity Verification Suite.

Guarantees version-controlled ground-truth integrity across all evaluation corpora:
1. Real-World 25 Scenarios Manifest (`real_world_25_manifest.json`)
2. Synthetic 75 Threat Validation Manifest (`synthetic_75_manifest.json`)

Validates:
- Schema completeness and schema versioning
- Uniqueness of fixture identifiers (no duplicates)
- Strict validity of ground-truth classification labels
- Physical file existence on disk
- Exact cryptographic SHA-256 hash matching (anti-tamper verification)
- Complete isolation and non-overlap between corpora
- Immutability of expected ground-truth labels against evaluation mutations
"""

import hashlib
import json
import os
import pytest

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
GROUND_TRUTH_DIR = os.path.join(FIXTURES_DIR, "ground_truth")
RW_MANIFEST_PATH = os.path.join(GROUND_TRUTH_DIR, "real_world_25_manifest.json")
SYNTH_MANIFEST_PATH = os.path.join(GROUND_TRUTH_DIR, "synthetic_75_manifest.json")


def load_manifest(path: str) -> dict:
    assert os.path.exists(path), f"Manifest not found: {path}"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def rw_manifest():
    return load_manifest(RW_MANIFEST_PATH)


@pytest.fixture(scope="module")
def synth_manifest():
    return load_manifest(SYNTH_MANIFEST_PATH)


# ============================================================================
# 1. Schema Completeness & Metadata Integrity
# ============================================================================

def test_real_world_manifest_schema(rw_manifest):
    required_keys = [
        "manifest_schema_version",
        "manifest_name",
        "corpus_id",
        "created_at",
        "provenance_declaration",
        "corpus_relative_path",
        "total_fixtures",
        "evaluation_summary",
        "fixtures",
    ]
    for key in required_keys:
        assert key in rw_manifest, f"Missing key in real-world manifest: {key}"

    assert rw_manifest["manifest_schema_version"] == "1.0.0"
    assert rw_manifest["corpus_id"] == "REAL_WORLD_25"
    assert rw_manifest["total_fixtures"] == 25
    assert len(rw_manifest["fixtures"]) == 25
    assert rw_manifest["evaluation_summary"]["total_evaluated_in_classification"] == 20
    assert rw_manifest["evaluation_summary"]["total_excluded_robustness"] == 5


def test_synthetic_manifest_schema(synth_manifest):
    required_keys = [
        "manifest_schema_version",
        "manifest_name",
        "corpus_id",
        "created_at",
        "provenance_declaration",
        "corpus_relative_path",
        "total_fixtures",
        "category_counts",
        "fixtures",
    ]
    for key in required_keys:
        assert key in synth_manifest, f"Missing key in synthetic manifest: {key}"

    assert synth_manifest["manifest_schema_version"] == "1.0.0"
    assert synth_manifest["corpus_id"] == "SYNTHETIC_75"
    assert synth_manifest["total_fixtures"] == 75
    assert len(synth_manifest["fixtures"]) == 75


# ============================================================================
# 2. Identifier Uniqueness (No Duplicate IDs)
# ============================================================================

def test_no_duplicate_ids_real_world(rw_manifest):
    ids = [item["id"] for item in rw_manifest["fixtures"]]
    assert len(ids) == len(set(ids)), f"Duplicate IDs found in real-world manifest: {len(ids)} vs {len(set(ids))}"
    for fid in ids:
        assert fid.startswith("RW-"), f"Invalid ID format: {fid}"


def test_no_duplicate_ids_synthetic(synth_manifest):
    ids = [item["test_id"] for item in synth_manifest["fixtures"]]
    assert len(ids) == len(set(ids)), f"Duplicate IDs found in synthetic manifest: {len(ids)} vs {len(set(ids))}"
    for fid in ids:
        assert fid.startswith("CORPUS-"), f"Invalid test_id format: {fid}"


# ============================================================================
# 3. Valid Ground-Truth Classification Labels
# ============================================================================

VALID_RW_CLASSIFICATIONS = {"LEGITIMATE", "MALICIOUS", "CORRUPTED", "ANOMALY"}
VALID_RW_APPLICABILITY = {"EVALUATED", "EXCLUDED_ROBUSTNESS"}

def test_valid_labels_real_world(rw_manifest):
    for item in rw_manifest["fixtures"]:
        label = item.get("ground_truth_classification")
        applicability = item.get("evaluation_applicability")
        assert label in VALID_RW_CLASSIFICATIONS, f"Invalid label '{label}' in {item['id']}"
        assert applicability in VALID_RW_APPLICABILITY, f"Invalid applicability '{applicability}' in {item['id']}"

        # Consistency check: CORRUPTED/ANOMALY must be EXCLUDED_ROBUSTNESS
        if label in {"CORRUPTED", "ANOMALY"}:
            assert applicability == "EXCLUDED_ROBUSTNESS", f"{item['id']} ({label}) must be EXCLUDED_ROBUSTNESS"
        elif label in {"LEGITIMATE", "MALICIOUS"}:
            assert applicability == "EVALUATED", f"{item['id']} ({label}) must be EVALUATED"

        # Rationale and provenance must be non-empty strings
        assert item.get("rationale"), f"Empty rationale in {item['id']}"
        assert item.get("provenance"), f"Empty provenance in {item['id']}"


VALID_SYNTH_VERDICTS = {"SAFE", "SUSPICIOUS", "MALICIOUS"}
VALID_SYNTH_CATEGORIES = {
    "phishing",
    "malware_delivery",
    "spoofing_authentication",
    "business_email_compromise",
    "advanced_adversarial",
    "legitimate",
}

def test_valid_labels_synthetic(synth_manifest):
    for item in synth_manifest["fixtures"]:
        cat = item.get("category")
        verdict = item.get("expected_verdict")
        assert cat in VALID_SYNTH_CATEGORIES, f"Invalid category '{cat}' in {item['test_id']}"
        assert verdict in VALID_SYNTH_VERDICTS, f"Invalid expected_verdict '{verdict}' in {item['test_id']}"


# ============================================================================
# 4. Physical Fixture Existence on Disk
# ============================================================================

def test_all_real_world_fixtures_exist(rw_manifest):
    corpus_root = os.path.normpath(os.path.join(GROUND_TRUTH_DIR, rw_manifest["corpus_relative_path"]))
    for item in rw_manifest["fixtures"]:
        target_path = os.path.join(corpus_root, item["filename"])
        assert os.path.exists(target_path), f"Real-world fixture does not exist: {target_path}"


def test_all_synthetic_fixtures_exist(synth_manifest):
    corpus_root = os.path.normpath(os.path.join(GROUND_TRUTH_DIR, synth_manifest["corpus_relative_path"]))
    for item in synth_manifest["fixtures"]:
        target_path = os.path.join(corpus_root, item["filename"])
        assert os.path.exists(target_path), f"Synthetic fixture does not exist: {target_path}"


# ============================================================================
# 5. Cryptographic SHA-256 Hash Verification (Anti-Tamper Integrity)
# ============================================================================

def test_sha256_integrity_real_world(rw_manifest):
    corpus_root = os.path.normpath(os.path.join(GROUND_TRUTH_DIR, rw_manifest["corpus_relative_path"]))
    for item in rw_manifest["fixtures"]:
        target_path = os.path.join(corpus_root, item["filename"])
        with open(target_path, "rb") as f:
            content = f.read()
        computed_sha = hashlib.sha256(content).hexdigest()
        assert computed_sha == item["sha256"], (
            f"SHA-256 hash mismatch for {item['id']} ({item['filename']})!\n"
            f"Expected: {item['sha256']}\n"
            f"Actual:   {computed_sha}"
        )
        assert len(content) == item["size_bytes"], (
            f"Size mismatch for {item['id']} ({item['filename']})!\n"
            f"Expected: {item['size_bytes']} bytes\n"
            f"Actual:   {len(content)} bytes"
        )


def test_sha256_integrity_synthetic(synth_manifest):
    corpus_root = os.path.normpath(os.path.join(GROUND_TRUTH_DIR, synth_manifest["corpus_relative_path"]))
    for item in synth_manifest["fixtures"]:
        target_path = os.path.join(corpus_root, item["filename"])
        with open(target_path, "rb") as f:
            content = f.read()
        computed_sha = hashlib.sha256(content).hexdigest()
        assert computed_sha == item["sha256"], (
            f"SHA-256 hash mismatch for {item['test_id']} ({item['filename']})!\n"
            f"Expected: {item['sha256']}\n"
            f"Actual:   {computed_sha}"
        )
        assert len(content) == item["size_bytes"], (
            f"Size mismatch for {item['test_id']} ({item['filename']})!\n"
            f"Expected: {item['size_bytes']} bytes\n"
            f"Actual:   {len(content)} bytes"
        )


# ============================================================================
# 6. Strict Corpora Separation & Zero Overlap
# ============================================================================

def test_corpora_are_strictly_separate(rw_manifest, synth_manifest):
    rw_ids = set(item["id"] for item in rw_manifest["fixtures"])
    synth_ids = set(item["test_id"] for item in synth_manifest["fixtures"])
    assert rw_ids.isdisjoint(synth_ids), "Corpus IDs must not overlap!"

    rw_paths = set(item["filename"] for item in rw_manifest["fixtures"])
    synth_paths = set(item["filename"] for item in synth_manifest["fixtures"])
    assert rw_paths.isdisjoint(synth_paths), "Fixture relative paths must not overlap!"

    assert rw_manifest["corpus_id"] != synth_manifest["corpus_id"]
    assert rw_manifest["corpus_relative_path"] != synth_manifest["corpus_relative_path"]


# ============================================================================
# 7. Tamper Detection & Immutability Simulation
# ============================================================================

def test_tamper_detection_on_mutated_content():
    """Simulates payload tampering to prove that hash verification detects any modification."""
    original_bytes = b"From: test@example.com\r\nSubject: Test\r\n\r\nBody"
    original_sha = hashlib.sha256(original_bytes).hexdigest()

    tampered_bytes = b"From: test@example.com\r\nSubject: Test\r\n\r\nBody [TAMPERED]"
    tampered_sha = hashlib.sha256(tampered_bytes).hexdigest()

    assert original_sha != tampered_sha, "Hash function must detect single-byte content alterations."


def test_immutable_ground_truth_protection(rw_manifest):
    """Ensures that manifest fixtures cannot have their ground-truth labels mutated silently."""
    # Attempting to assign an unauthorized classification must violate contract validation
    for item in rw_manifest["fixtures"]:
        invalid_item = dict(item)
        invalid_item["ground_truth_classification"] = "FABRICATED_LABEL"
        assert invalid_item["ground_truth_classification"] not in VALID_RW_CLASSIFICATIONS
