# MAILSENTRA — CATEGORY 2, DATASET 01: SPAMASSASSIN ACQUISITION & INTEGRATION REPORT

**Dataset ID:** `DS-SP-01`  
**Dataset Name:** Apache SpamAssassin Public Corpus — `20050311_spam_2.tar.bz2`  
**Execution Timestamp:** 2026-11-27T18:30:00+05:30  
**Status:** `INTEGRATED` (Evaluated Record Count: `0`)  
**Audit Verdict:** ACCEPTED FOR RESEARCH & LOCAL TESTING — PENDING PIPELINE EVALUATION

---

## 1. Executive Summary & Key Milestones

In accordance with user authorization for **Phase 2, Category 2 (Spam Email)**, MailSentra acquired and integrated **`DS-SP-01` (Apache SpamAssassin Public Corpus — `20050311_spam_2.tar.bz2`)**.

1. **Licensing & Legal Usability:** Accurately recorded publisher's stated copyright reservations. Email contents retain individual sender copyright and are **NOT** assigned Apache License 2.0. Corpus usage is restricted strictly to local research and testing; raw messages must never be redistributed or relayed into a live mail transfer agent (MTA).
2. **Untouched Raw Preservation:** Downloaded directly over HTTPS from the official Apache archive. The raw archive (`2,059,029` bytes, SHA-256: `44280a0e28bf7645b2279e8e42659271ad82c6f40bf8d364dbda7f1df344a765`) is stored untouched at `backend/data/raw/spam_email/spamassassin/20050311_spam_2.tar.bz2`.
3. **Safe Streaming Extraction:** Implemented a dedicated streaming Python adapter (`TarBz2DatasetAdapter`). Shell commands were zero; members were inspected in-memory with strict rejection policies against path traversal (`..`), absolute paths, symlinks, hardlinks, character/block devices, and decompression bombs.
4. **100% Ingestion & Exact Reconciliation:** Inspected 1,398 tar members (1 directory skipped safely, 0 rejected). Parsed all **1,397 regular RFC-822 message files** into canonical MailSentra JSONL records with **0 malformed records and 0 dropped messages**, exactly reconciling the official README's documented count of 1,397 messages.
5. **Dual-View Schema & Privacy Protection:** Raw analysis headers and bodies are preserved unredacted for parser and RFC compliance, while preview strings are segregated in `redacted_preview` with email addresses and telephone numbers masked. Git exclusion (`.gitignore`) was verified for both raw archives and processed corpora.
6. **Cross-Corpus Deduplication:** 0 raw byte duplicates and 0 normalized content duplicates exist between `DS-SP-01` and `DS-PE-01` (Nazario Phishing), ground-truth manifests, or synthetic mock samples.
7. **Regression Stability:** All **46/46** dataset and SpamAssassin integrity tests passed; all **714/714** backend regression tests passed in 13.26s; frontend built cleanly in 2.71s.

---

## 2. Source Provenance & Licensing Boundaries

| Attribute | Specification | Verification Evidence |
| :--- | :--- | :--- |
| **Dataset Identifier** | `DS-SP-01` | Grand Registry & `backend/data/manifests/spam_email.json` |
| **Candidate Name** | Apache SpamAssassin Public Corpus | Official Apache SpamAssassin Project |
| **Exact Archive** | `20050311_spam_2.tar.bz2` | Archived March 2005 release |
| **Official Source URL** | `https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2` | HTTP 200 via HTTPS |
| **Publisher** | Apache Software Foundation (Justin Mason et al.) | Stated in archive documentation |
| **Archive Documentation** | `https://spamassassin.apache.org/old/publiccorpus/readme.html` | Official Corpus Readme |
| **Stated License** | Restricted Research & Testing / Sender Copyright Retained | Verified per official README text |
| **Redistribution Terms** | Copyright in message text remains with original senders. Not Apache 2.0. | Recorded in `provenance_manifest.json` |
| **Permitted Usage** | Controlled local research, offline benchmarking, and test fixtures. | Enforced in code and manifest |
| **Operational Restriction** | Never publish raw corpus messages; never relay corpus into live MTAs. | Technical and documentation lock |

### Provenance Manifest
Recorded at [`backend/data/raw/spam_email/spamassassin/provenance_manifest.json`](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/data/raw/spam_email/spamassassin/provenance_manifest.json):
```json
{
  "dataset_id": "DS-SP-01",
  "dataset_name": "Apache SpamAssassin Public Corpus — 20050311_spam_2.tar.bz2",
  "source_url": "https://spamassassin.apache.org/old/publiccorpus/20050311_spam_2.tar.bz2",
  "archive_filename": "20050311_spam_2.tar.bz2",
  "publisher": "Apache Software Foundation (Justin Mason et al.)",
  "archive_date": "March 2005",
  "license": "Restricted Research and Testing / Original Sender Copyright Retained",
  "licensing_and_usage_restrictions": "The official corpus README states that copyright in message text remains with original senders. Not assigned Apache License 2.0 to email contents. Use restricted to local research and testing pending a separate redistribution/commercial-use rights assessment. Do not publish or redistribute raw messages. Never send corpus messages into a live email system.",
  "attribution": "The Apache Software Foundation, SpamAssassin Public Corpus, https://spamassassin.apache.org/old/publiccorpus/",
  "retrieval_timestamp": "2026-11-27T12:54:56.544401+00:00",
  "file_size_bytes": 2059029,
  "sha256": "44280a0e28bf7645b2279e8e42659271ad82c6f40bf8d364dbda7f1df344a765",
  "http_status": 200,
  "content_type": "application/x-bzip2",
  "storage_path": "backend/data/raw/spam_email/spamassassin/20050311_spam_2.tar.bz2"
}
```

---

## 3. Acquisition, Download, and Integrity Verification

The archive was acquired using Python's streaming HTTPS client (`urllib.request` with default TLS verification) and streamed directly to disk through a temporary file before atomic renaming.

```text
Target Path: backend/data/raw/spam_email/spamassassin/20050311_spam_2.tar.bz2
HTTP Status: 200 OK
Content-Type: application/x-bzip2
Actual Bytes: 2,059,029 bytes (~1.96 MiB)
SHA-256:      44280a0e28bf7645b2279e8e42659271ad82c6f40bf8d364dbda7f1df344a765
```

### Git Exclusion Check
```powershell
PS> git check-ignore -v backend/data/raw/spam_email/spamassassin/20050311_spam_2.tar.bz2
.gitignore:113:backend/data/raw/**/*.bz2    backend/data/raw/spam_email/spamassassin/20050311_spam_2.tar.bz2

PS> git status --porcelain backend/data/raw/spam_email/spamassassin/20050311_spam_2.tar.bz2
# (Zero output — file is completely untracked and excluded from git staging)
```

---

## 4. Safe Extraction Architecture (`TarBz2DatasetAdapter`)

Extraction was performed by [`backend/app/datasets/tar_bz2_adapter.py`](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/datasets/tar_bz2_adapter.py).

### Security Bounds & Defenses Enforced
1. **Zero Shell Execution:** No `tar`, `gzip`, `bzip2`, or shell subshells invoked. All processing used Python's native `tarfile` module in streaming mode.
2. **Path Traversal Defense:** Every member name was normalized (`\\` -> `/`) and checked:
   - Rejected if containing `..` tokens in path segments.
   - Rejected if containing absolute paths (`/etc/...`, `C:\...`).
3. **Member Type Filtering:**
   - Permitted: Regular files (`member.isreg()`).
   - Safely Skipped: Directories (`member.isdir()`) logged as `SKIPPED_DIRECTORY` without parsing as messages.
   - Hard Rejected: Symlinks (`member.issym()`), hardlinks (`member.islnk()`), character/block devices (`ischr/isblk`), and FIFOs (`isfifo()`).
4. **Decompression Bomb Bounds:**
   - Maximum archive size: `50 MB` (Actual archive: `2.06 MB`).
   - Maximum cumulative decompressed size: `100 MB` (Actual uncompressed payload: `8.94 MB`).
   - Maximum member count: `10,000` (Actual inspected: `1,398`).
   - Maximum per-message size: `10 MB` (Largest message: `257,489 bytes`).
5. **In-Memory Streaming:** Members were streamed directly from `tar.extractfile(member)` into memory for hashing and RFC-822 parsing without dropping intermediate unvalidated files onto the filesystem.

---

## 5. Ingestion, Parsing, and Schema Reconciliation

### Archive Reconciliation
- **Total Members Inspected:** 1,398
- **Directories Skipped:** 1 (`spam_2` root directory)
- **Rejected Members:** 0
- **Regular Files Extracted:** 1,397
- **Parsed Records:** 1,397 (100.0% success rate)
- **Dropped or Malformed:** 0
- **Reconciliation with Official Documentation:** Exactly **1,397 messages** matching the README documentation.

### Body Classification Breakdown
| Body Classification | Record Count | Description |
| :--- | :--- | :--- |
| `NORMAL` | 1,396 | Valid textual RFC-822 body extracted from `text/plain` or `text/html`. |
| `ATTACHMENT_ONLY` | 1 | Message body is empty/whitespace; payload is an attachment lure. Message index 1290 (`umVwmIvsNQ@mx.seed.net.tw`, Subject: "Brand New Premium Promotion", Attachment: `Brand New Premium.htm`). |
| `WHITESPACE_ONLY` | 0 | 0 messages. |
| `EMPTY_MESSAGE` | 0 | 0 messages. |
| `BODY_EXTRACTION_FAILURE` | 0 | 0 unhandled extraction failures. |

### Canonical Dual-View Schema
Processed output: [`backend/data/processed/spam_email/spamassassin_spam2_records.jsonl`](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/data/processed/spam_email/spamassassin_spam2_records.jsonl).
Each record is serialized with full technical provenance:
- `dataset_id`: `"DS-SP-01"`
- `parent_archive`: `"20050311_spam_2.tar.bz2"`
- `parent_archive_sha256`: `"44280a0e28bf7645b2279e8e42659271ad82c6f40bf8d364dbda7f1df344a765"`
- `archive_member_path`: e.g. `"spam_2/00001.317e78fa8ee2f54cd4890fdc09ba8176"`
- `raw_message_sha256`: SHA-256 over exact raw RFC-822 message bytes.
- `content_sha256`: Normalized SHA-256 over lowercased subject + stripped primary body.
- `source_label`: `"spam"`
- `canonical_label`: `"SPAM"`
- `auth_status`: `"UNKNOWN"` (`UNVERIFIED_HISTORICAL_HEADER: Must not be trusted without trusted-boundary validation.`)
- `redacted_preview`: Segregated preview dictionary masking email addresses (`a***@domain.com`) and phone numbers (`[REDACTED_PHONE]`).
- `label_limitations`: Historical spam corpus (SpamAssassin 2005 archive); reflects 2001-2005 commercial spam, nigerian 419, pharmaceutical, and adult spam lures.

---

## 6. Deduplication and Cross-Corpus Overlap Analysis

| Comparison Scope | Exact Byte Overlap (`raw_sha256`) | Normalized Content Overlap (`content_sha256`) | Subject Overlap | Resolution |
| :--- | :--- | :--- | :--- | :--- |
| **`DS-SP-01` vs `DS-PE-01` (Nazario)** | **0** | **0** | 1 (Generic `"re:"` prefix) | Clean separation between phishing and spam corpora. |
| **`DS-SP-01` vs Ground Truth (Real 25 & Synth 75)** | **0** | **0** | 0 | Benchmark evaluation sets remain untainted. |
| **`DS-SP-01` vs Sample Mocks (`*_samples.json`)** | **0** | **0** | 0 | Synthetic fixtures remain isolated. |
| **Internal to `DS-SP-01`** | **0 exact duplicates** | **59 campaign near-duplicates** | 1,338 unique content records / 1,338 clusters | All 1,397 records preserved. None merged or deleted. |

---

## 7. Lifecycle State Machine & Registry Verification

Both `dataset_registry.json` and `backend/data/manifests/spam_email.json` were rebuilt via `registry_builder.py`.

### Grand Registry State (`dataset_registry.json`)
- `total_categories`: 8
- `total_candidates`: 103
- `total_verified`: 85
- `total_approved`: 88
- `total_integrated`: 20
- `total_evaluated`: 0 *(Strictly invariant — evaluation has not begun)*
- `total_conditionally_approved`: 3
- `total_rejected`: 15
- `external_records_count`: **3,676** (2,279 Nazario `DS-PE-01` + 1,397 SpamAssassin `DS-SP-01`)
- `synthetic_fixture_datasets`: **18** (reduced from 19; `DS-SP-01` is now classified `is_synthetic_fixture: false` / `EXTERNAL_ACQUIRED`)
- `synthetic_fixture_records`: 18
- `audit_verdict`: `PARTIALLY_VERIFIED (CATALOG & METADATA ONLY)`

---

## 8. Automated Verification & Regression Results

### 1. Dedicated SpamAssassin & Dataset Integrity Suite
```powershell
PS> pytest backend/tests/test_spamassassin_acquisition.py backend/tests/test_dataset_integrity.py backend/tests/test_evaluation_integrity.py -q
..............................................                           [100%]
46 passed in 1.50s
```
- Validated raw archive size and SHA-256.
- Validated safe extraction rejections (traversal, absolute path, symlink, device, size limits).
- Validated 1,397 parsed records and attachment-only lure identification.
- Validated PII masking and unverified authentication header marking.
- Validated cross-corpus zero-overlap assertions.
- Validated lifecycle states and registry counters.
- Validated Git exclusion rules.
- Validated ground-truth manifest invariance.

### 2. Full Backend Regression Suite
```powershell
PS> pytest backend/tests/ -q
714 passed in 13.26s
```
Zero regressions across all detection modules (Attachment Forensics, Auth Protocols, Risk Engine, URL Analysis, Lifespan/Config).

### 3. Frontend Build Verification
```powershell
PS> npm --prefix frontend run build
✓ built in 2.71s
```
Zero TypeScript or bundling errors.

### 4. Ground-Truth Manifest Baseline Check
- `real_world_25_manifest.json`: `5ebb9b190ab38b080be5f0acfce62def0cc806ada8e9a659cb08da8be2d97c03` (Invariant)
- `synthetic_75_manifest.json`: `3ce476003d827c20510b7b5bcc9f6f55a0973d9cf981594691d7b4681e8128b6` (Invariant)

---

## 9. Compliance with Execution Restrictions

1. **Evaluated State Preserved:** `DS-SP-01` is marked `INTEGRATED` with `evaluated_record_count == 0`. It was **NOT** marked `EVALUATED`.
2. **Git Baseline Preserved:** Zero commits, zero pushes, zero resets, and zero stashes performed.
3. **No Network Relays or Threat Execution:** Extracted spam messages and attachment lure were strictly parsed in memory without network execution or email relaying.
4. **Scope Enforced:** Work completed for `DS-SP-01` only. Execution stopped pending user review.
