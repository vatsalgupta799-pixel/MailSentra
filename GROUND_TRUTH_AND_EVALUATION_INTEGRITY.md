# MailSentra — Ground-Truth and Evaluation Integrity Specification

**Specification Date:** November 27, 2026  
**Auditor / Architect:** Security Architecture & Evaluation Engineering  
**Version:** 1.0.0  
**Status:** IMPLEMENTED & CRYPTOGRAPHICALLY LOCKED  
**Test Suite:** `backend/tests/test_evaluation_integrity.py` (13 tests passed)  
**Full Regression Suite:** 643 / 643 tests passed  

---

## 1. Context & Purpose

The independent review of `HONEST_DETECTION_EVALUATION_REPORT.md` noted an evidence limitation: while the 25 real-world fixtures existed in repository commit history (`dab34b8`), the repository lacked a dedicated, version-controlled ground-truth manifest establishing immutable labels, cryptographic hashes, and provenance records prior to evaluation.

To eliminate ambiguity, prevent silent result tampering, and establish rigorous scientific standards for future evaluations, this specification introduces:
1. Version-controlled ground-truth manifests under `backend/tests/fixtures/ground_truth/`.
2. Cryptographic SHA-256 baseline hashing for all fixtures across both evaluation corpora.
3. Automated regression tests that detect missing fixtures, duplicate IDs, invalid labels, and hash mismatches.
4. Strict separation between expected ground-truth classifications and live evaluation outcomes.
5. Standard Operating Procedures (SOP) for recording future evaluation runs.

---

## 2. Historical Integrity & Transparent Provenance

To maintain absolute historical honesty:
- **No Retroactive Claims**: MailSentra makes **no claim** that the ground-truth classifications for the original 25 real-world fixtures were formally locked in a machine-readable manifest prior to November 27, 2026.
- **No Fabricated Timestamps**: Manifest metadata explicitly records the actual generation timestamp (`2026-11-27T16:50:00+05:30`).
- **Fixture Preservation**: Zero existing fixture files were modified, moved, or deleted.
- **Unmodified Detection Logic**: Production code in `backend/app/` remains strictly untouched.
- **Corpora Separation**: The 25-fixture real-world evaluation dataset and the 75-fixture synthetic threat dataset remain completely distinct.

---

## 3. Version-Controlled Ground-Truth Manifests

Two independent ground-truth manifests are maintained in `backend/tests/fixtures/ground_truth/`:

### 3.1 Real-World 25 Scenarios Manifest (`real_world_25_manifest.json`)
- **Corpus ID**: `REAL_WORLD_25`
- **Location**: `backend/tests/fixtures/ground_truth/real_world_25_manifest.json`
- **Fixture Root**: `backend/tests/fixtures/real_world_emails`
- **Total Fixtures**: 25
- **Classification Distribution**:
  - `LEGITIMATE`: 12 fixtures (Normal notices, multi-hop routing, international Unicode, multi-part attachments)
  - `MALICIOUS`: 8 fixtures (Phishing lures, display name BEC, Return-Path mismatch, double extensions, path traversal, IP URLs)
  - `CORRUPTED`: 4 fixtures (0-byte payload, truncated stream, broken MIME boundaries, unclosed HTML)
  - `ANOMALY`: 1 fixture (RFC 5322 syntax anomaly `From: <>`)
- **Evaluation Applicability**:
  - 20 fixtures marked `EVALUATED` (included in confusion matrix).
  - 5 fixtures marked `EXCLUDED_ROBUSTNESS` (parser crash-resilience tests excluded from 2×2 threat classification).

#### Complete Fixture Registry with Cryptographic SHA-256 Baselines
| ID | Relative Path | Bytes | SHA-256 Checksum | Ground Truth | Applicability |
|:---:|:---|:---:|:---|:---:|:---:|
| `RW-01` | `normal/01_university_announcement.eml` | 1,507 | `60900aafd39315184bc23c23784d163efee20b5c55a4dfd8f5c1ab9435e29788` | `LEGITIMATE` | `EVALUATED` |
| `RW-02` | `normal/02_genuine_password_reset.eml` | 1,521 | `e42b03359944fa735b567f5bec4c85c89f10447412a5286327fb66112acdc8db` | `LEGITIMATE` | `EVALUATED` |
| `RW-03` | `normal/11_plain_text.eml` | 421 | `680884c7915c834801427d2b05ff40dd985f819d14889fe5cf6a1d23ce6af6ea` | `LEGITIMATE` | `EVALUATED` |
| `RW-04` | `multipart/10_html_only.eml` | 653 | `ef7b25e496c5eca997d4d442f1767fff1f5d1e53ebbf4df0f9f6240c03bfa5ea` | `LEGITIMATE` | `EVALUATED` |
| `RW-05` | `multipart/12_multipart_mixed_alt.eml` | 1,043 | `47647bcdf33a3445215de18bfd77844c51345d0b2b0f076da739aa5f96695a2e` | `LEGITIMATE` | `EVALUATED` |
| `RW-06` | `attachments/15_multiple_attachments.eml` | 1,490 | `c6e7bd8c06497422b7928015f665687c783c54af0a989cc5018c3d109527009e` | `LEGITIMATE` | `EVALUATED` |
| `RW-07` | `edge_cases/06_multiple_received_hops.eml` | 885 | `fd2fe2f4f546299306f6fb2fa0d6d98d45bfd081e17d4869bfed3cbcc0ca0233` | `LEGITIMATE` | `EVALUATED` |
| `RW-08` | `edge_cases/07_missing_message_id.eml` | 269 | `da97d962d0924d6ae9c3637df57841d2e15aa7630421bf3b4fd411139e261a90` | `LEGITIMATE` | `EVALUATED` |
| `RW-09` | `edge_cases/08_missing_date_header.eml` | 255 | `b54e673f15a3c00f00e5cb65eb6a46f521f32ea574ccbf2091d4c23963138eee` | `LEGITIMATE` | `EVALUATED` |
| `RW-10` | `edge_cases/14_unicode_international.eml` | 611 | `8612c6ea25f761b98a3b22b2dfa6bc3c9805dfdb1b0db6660a2d986b80f0e85a` | `LEGITIMATE` | `EVALUATED` |
| `RW-11` | `edge_cases/17_unusually_long_headers.eml` | 832 | `beeeff34241e1723f03b679b30c1be79b76e5d8b76dfb6c68a410b050cfd1341` | `LEGITIMATE` | `EVALUATED` |
| `RW-12` | `edge_cases/19_encoded_subjects.eml` | 370 | `31343719b4cfb0bfa369528bc45b90f135b1c97a55ae56fc3d64c1aa5e4f4477` | `LEGITIMATE` | `EVALUATED` |
| `RW-13` | `malformed/b_empty_payload.eml` | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | `CORRUPTED` | `EXCLUDED` |
| `RW-14` | `malformed/b_truncated_email.eml` | 240 | `18ce1c9797072eaee46067b0b2e8ca92e4be54848074d284f3eb78479e00ce32` | `CORRUPTED` | `EXCLUDED` |
| `RW-15` | `malformed/18_malformed_mime_boundaries.eml`| 465 | `a8595984ba0a9f5d63f2719702220d91d0e51ee18779a5e8e8fb29beaafe7cf8` | `CORRUPTED` | `EXCLUDED` |
| `RW-16` | `malformed/c_malformed_html.eml` | 291 | `2d49c636f3c10a48d88e401ecaaeb6a33b00624838634e4f728fa538e1e7fca9` | `CORRUPTED` | `EXCLUDED` |
| `RW-17` | `edge_cases/09_invalid_sender_address.eml` | 299 | `24c050a8e27790bbd5e9853308da07b6f40ca358029b0cefe9e5983b8dea172b` | `ANOMALY` | `EXCLUDED` |
| `RW-18` | `suspicious/03_fake_admin.eml` | 818 | `e425144c75f3481bb23809d28ae856f9a208c2bc49f787eb218d8559a732f0b0` | `MALICIOUS` | `EVALUATED` |
| `RW-19` | `suspicious/04_display_name_spoofing.eml` | 538 | `ce67742a3515355f495c4a479231307036ccc41eab6b48bfb5e58bee73c662c3` | `MALICIOUS` | `EVALUATED` |
| `RW-20` | `suspicious/05_mismatched_from_replyto.eml` | 607 | `a1f7dec333328d95c0e41e5932a60760a0ca8d723c8b2e45627f1b786902398d` | `MALICIOUS` | `EVALUATED` |
| `RW-21` | `suspicious/16_suspicious_attachment_filename.eml`| 638 | `18f98f034df11b031d4d20706a8be3aad0bd77bc2834ba2862ee1e177c9d4a3d` | `MALICIOUS` | `EVALUATED` |
| `RW-22` | `edge_cases/13_several_urls.eml` | 832 | `409afa6f6f4ce423cf46e760be38f86086058f41be0c82c155de32c015d10726` | `MALICIOUS` | `EVALUATED` |
| `RW-23` | `attachments/d_double_extension.eml` | 603 | `cf97e9b1bff276970d9a6f6e5af26632f7dddb868ae10fe0f696848e1ee60d6b` | `MALICIOUS` | `EVALUATED` |
| `RW-24` | `attachments/d_traversal_filename.eml` | 570 | `612d349b959101a31681a782a6c2a570fba111ef4c23fcce7dbac21bc3b1c2e3` | `MALICIOUS` | `EVALUATED` |
| `RW-25` | `multipart/20_misleading_mime_metadata.eml` | 351 | `3e1b8da3dcfc8b9553c26ac1157b6f7b098528146b2b57a1da0d4cd41c642158` | `MALICIOUS` | `EVALUATED` |

---

### 3.2 Synthetic 75 Threat Validation Manifest (`synthetic_75_manifest.json`)
- **Corpus ID**: `SYNTHETIC_75`
- **Location**: `backend/tests/fixtures/ground_truth/synthetic_75_manifest.json`
- **Fixture Root**: `backend/tests/fixtures/email_corpus`
- **Total Fixtures**: 75
- **Category Counts**: Phishing (20), Malware (15), Spoofing (10), BEC (10), Adversarial (10), Legitimate (10)
- **Features**: Includes cryptographic SHA-256 hashes, byte sizes, expected threat indicators, and expected verdicts for all 75 fixtures.

---

## 4. Automated Manifest Integrity Test Suite

The test suite in `backend/tests/test_evaluation_integrity.py` executes 13 automated checks:

```python
# 1. Schema Completeness
test_real_world_manifest_schema()
test_synthetic_manifest_schema()

# 2. Identifier Uniqueness
test_no_duplicate_ids_real_world()
test_no_duplicate_ids_synthetic()

# 3. Label Validity
test_valid_labels_real_world()
test_valid_labels_synthetic()

# 4. Physical File Existence
test_all_real_world_fixtures_exist()
test_all_synthetic_fixtures_exist()

# 5. Cryptographic SHA-256 Integrity Verification
test_sha256_integrity_real_world()
test_sha256_integrity_synthetic()

# 6. Corpora Separation & Zero Overlap
test_corpora_are_strictly_separate()

# 7. Tamper Detection & Immutability Simulation
test_tamper_detection_on_mutated_content()
test_immutable_ground_truth_protection()
```

### Test Execution Telemetry
```
backend/tests/test_evaluation_integrity.py ............. [100%]
13 passed in 0.22s
```

---

## 5. Standard Operating Procedure (SOP) for Future Evaluations

Any future detection evaluation (e.g., following completion of Module 6 Attachment Forensics or Module 7 NLP Analysis) must follow this protocol:

### Step 1: Pre-Evaluation Hash Verification
Before running evaluation scripts, verify that zero fixtures have been altered:
```powershell
$env:PYTHONPATH="backend"
pytest backend/tests/test_evaluation_integrity.py -v
```

### Step 2: Immutable Evaluation Execution
Evaluations must load expected labels from the static manifest as **read-only references**. Evaluation scripts must write actual results to a separate timestamped report or output JSON:
- Prohibited: Modifying manifest files in place.
- Prohibited: Overriding expected verdicts based on model output.

### Step 3: Mandatory Evaluation Run Metadata
Every generated evaluation report must record:
1. **Timestamp**: ISO 8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
2. **Git Commit**: `git rev-parse HEAD` of the evaluated code state.
3. **Working Tree Cleanliness**: `git status --porcelain` confirming zero uncommitted production edits.
4. **Target Manifest Path & SHA-256**: Path and checksum of the ground-truth manifest used.
5. **Exact Command Line**: The reproducible terminal command.
6. **Output Telemetry Path**: Path to serialized per-fixture evaluation logs.

---

## 6. Summary of Hardening Deliverables

| Deliverable | Path | Status |
|:---|:---|:---:|
| Real-World 25 Ground-Truth Manifest | `backend/tests/fixtures/ground_truth/real_world_25_manifest.json` | **Created & Validated** |
| Synthetic 75 Ground-Truth Manifest | `backend/tests/fixtures/ground_truth/synthetic_75_manifest.json` | **Created & Validated** |
| Manifest Integrity Test Suite | `backend/tests/test_evaluation_integrity.py` | **13 / 13 Passed** |
| Full Regression Suite | `backend/tests/` | **643 / 643 Passed** |
| Integrity Specification Report | `GROUND_TRUTH_AND_EVALUATION_INTEGRITY.md` | **Completed** |

---

## 7. Remaining Limitations

1. **Historical Ground-Truth Baseline**: While future evaluations are now cryptographically locked and verifiable, historical evaluations conducted prior to November 27, 2026, rely on commit `dab34b8` and the retrospective documentation in `HONEST_DETECTION_EVALUATION_REPORT.md`. This limitation is documented and resolved for all future milestones.
2. **Sample Size Scope**: The real-world evaluation dataset ($N=25$) remains a focused sanity check. Production release gating should rely jointly on the 75-fixture synthetic corpus and expanded cyber threat intelligence test banks.
