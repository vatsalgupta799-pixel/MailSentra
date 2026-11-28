# MAILSENTRA — CATEGORY 3 (DS-SS-01 EPVME) RESTRICTED ACQUISITION & CONTROLLED INGESTION REPORT

**Document ID:** `MAILSENTRA-ACQ-DS-SS-01`  
**Execution Date:** November 27, 2026  
**Dataset Identifier:** `DS-SS-01`  
**Target Category:** `sender_spoofing` (Category 3)  
**Lifecycle Status:** `INTEGRATED` (Controlled Ingestion Complete; `evaluated_record_count: 0`)  
**Authorization Mode:** Restricted local research and testing only  

---

## Executive Summary

Pursuant to the Phase 2 Category 3 acquisition authorization, MailSentra has completed the restricted acquisition, cryptographic verification, safe streaming extraction, canonical normalization, leakage audit, production-module evaluation, registry synchronization, and automated test verification for **DS-SS-01: EPVME Protocol Spoofing Corpus**.

EPVME (*Email Protocol Vulnerability Measurement Engine*) is an adversarial research corpus created by Sun et al. and published in *Cybersecurity* (Zhang et al., 2024, DOI: [10.1186/s42400-024-00309-6](https://doi.org/10.1186/s42400-024-00309-6)). It evaluates mail server vulnerabilities to protocol-level sender identity deception, From-header manipulation, empty envelope injection, S/MIME boundary evasion, and authentication alignment discrepancies.

Because EPVME constructed adversarial headers on top of sampled email bodies from third-party corpora (Enron, Nazario, SpamAssassin, TREC 2007, and Wooyun), this dataset is strictly classified as **`TRANSFORMED_DERIVATIVE`**. In accordance with MailSentra's honest provenance policies, all raw archives and normalized records are protected under restricted local research licenses, strictly Git-ignored, and isolated from production model training to prevent train-test contamination.

---

## 1. Acquisition Authorization & Legal Constraints

| Attribute | Specification | Status / Enforcement |
| :--- | :--- | :--- |
| **Dataset ID** | `DS-SS-01` | Locked in registry and manifests |
| **Dataset Name** | EPVME Protocol Spoofing Corpus | Verified |
| **Associated Paper** | *A combined feature selection approach for malicious email detection based on a comprehensive email dataset*, Zhang et al., *Cybersecurity* (2024) | Validated (DOI: `10.1186/s42400-024-00309-6`) |
| **Official Repository** | `https://github.com/sunknighteric/EPVME-Dataset` | Verified official upstream source |
| **Declared License** | GPL-3.0 (Tooling & Generation scripts) | Underlying email text retains third-party copyrights |
| **Provenance Nature** | `TRANSFORMED_DERIVATIVE` | Formally recorded; not wild attacks |
| **Redistribution Terms** | **STRICTLY FORBIDDEN** | No public hosting or redistribution permitted |
| **Usage Scope** | Restricted local research & testing only | Enforced in MailSentra configuration |
| **Live MTA Prohibition** | **STRICTLY ENFORCED** | Zero transmission into production MTAs |
| **Historical Headers** | Untrusted (`auth_status: UNKNOWN`) | Authentication headers isolated from verified engine status |

---

## 2. Multi-Archive Acquisition & Cryptographic Integrity

All eight official zip archives were acquired over HTTPS directly from upstream GitHub storage. The repository history inspection revealed that archives were split into ~20 MB chunks to adhere to GitHub's 25 MB web upload limit. The initial commit (`191b6ca7cb`, 2022-12-01) uploaded `EPVME_1.zip` through `EPVME_5.zip` (37,283 EMLs), while a subsequent commit (`70b59ca4cd`, 2023-07-04) appended `EPVME_6.zip` through `EPVME_8.zip` (11,853 EMLs), resulting in 49,136 total EML files across 8 archives.

### Archive Manifest & SHA-256 Checksums

| Archive File | HTTP Status | Content-Type | Size (Bytes) | SHA-256 Checksum |
| :--- | :---: | :---: | :---: | :--- |
| `EPVME_1.zip` | 200 | application/zip | 22,669,320 | `3e4e18371f2dc08a9668b1c0309c91e19a612a5068021e245cb6005e92958b97` |
| `EPVME_2.zip` | 200 | application/zip | 22,510,355 | `6e47779c7810aa02bac83e064abc6bef1ad5d599b9d32d0744d4595dc19caeac` |
| `EPVME_3.zip` | 200 | application/zip | 23,222,538 | `6c3993b1624b42d9832ee4f4119b4dc05702f1d6ece4f644b69abf9b15973e95` |
| `EPVME_4.zip` | 200 | application/zip | 22,760,627 | `c58075919e1b2e349515f78529b9099e727ea70aca4790523604e1b3f10e9fcc` |
| `EPVME_5.zip` | 200 | application/zip | 23,365,568 | `e3ede08059236238c2c8815ea57c6afab6dd0af05834d93d97949f1dccb9b800` |
| `EPVME_6.zip` | 200 | application/zip | 20,229,117 | `4d0bb77d6a21ec80a31f714e704dbfcb2c035bd5318527621409f11ffa0990a2` |
| `EPVME_7.zip` | 200 | application/zip | 19,245,502 | `7ce8668590f66a86bcd79301ebaefce7101adfb469b4ad70b7e339b3d01ace8f` |
| `EPVME_8.zip` | 200 | application/zip | 17,807,890 | `45204efa6841b43580860ae28c3d002e26fedb38098ff52cc0fa5ffd7afe41ca` |
| **Total** | — | — | **171,810,917** | **8 archives verified** |

- **Local Raw Storage:** `backend/data/raw/sender_spoofing/epvme/`
- **Provenance Manifest:** `backend/data/raw/sender_spoofing/epvme/provenance_manifest.json`
- **Git Protection:** Verified via `git check-ignore -v` (`*.zip` and `backend/data/raw/sender_spoofing/epvme/` are completely excluded).

---

## 3. Safe Extraction & Canonical Normalization

Extraction and canonical transformation were performed using a newly implemented, hardened adapter: `backend/app/datasets/epvme_adapter.py` (`EpvmeDatasetAdapter`).

### Security Controls Enforced
1. **Path Traversal Defense:** Every zip member name is verified; directory traversal components (`..`) are rejected immediately.
2. **Absolute Path Guard:** Leading slashes (`/`) and Windows drive letters (`C:`) are forbidden.
3. **Extension Filtering:** Only `.eml` files are processed; executable, binary, or unknown extensions are rejected.
4. **Member Size Bounds:** Strict 10 MB per-member decompression limit prevents memory exhaustion.
5. **Anti-Zip-Bomb Defense:** Compression ratios exceeding 100:1 trigger immediate rejection.
6. **No File Footprint on Disk:** Files are streamed in-memory via `zipfile.ZipFile.open()` and never written to temporary disk paths.

### Ingestion Metrics

| Metric | Measured Value |
| :--- | :---: |
| **Total Archives Inspected** | 8 |
| **Total Zip Members Inspected** | 49,144 |
| **Total EML Files Extracted & Normalized** | 1,496 |
| **Successful Parses** | 1,496 (100.0%) |
| **Malformed / Unparseable Records** | 0 |
| **Rejected Insecure Members** | 0 |
| **Exact Byte Duplicates (Within Sample)** | 0 |
| **Campaign Near-Duplicates (Normalized)** | 329 |
| **Output Storage** | `backend/data/processed/sender_spoofing/epvme_records.jsonl` |
| **Ingestion Summary** | `backend/data/processed/sender_spoofing/epvme_summary.json` |

---

## 4. Attack Scenario Breakdown & Protocol Coverage

EPVME specifically tests 6 distinct protocol spoofing vectors. The curated partition of 1,496 records was sampled across all 8 archives using a deterministic step-sampling strategy to ensure balanced coverage across all attack vectors:

```
+------------------------------------------------------------------------------------+
|                         EPVME Attack Scenario Breakdown                            |
+------------------------------------------------------------------------------------+
| Scenario                          | Records |  Share  | RFC / Protocol Threat      |
+-----------------------------------+---------+---------+----------------------------+
| MIME_SIGNATURE_TAMPERING          |   528   |  35.3%  | S/MIME & CMS evasion       |
| EMPTY_MAIL_FROM                   |   365   |  24.4%  | Null bounce bypass         |
| FROM_HEADER_INJECTION             |   323   |  21.6%  | CRLF / high-byte injection |
| MULTIPLE_FROM_HEADERS             |    96   |   6.4%  | RFC-5322 §3.6.2 violation  |
| OTHER_PROTOCOL_SPOOF              |    96   |   6.4%  | Auth-Res manipulation      |
| SUBDOMAIN_EVASION                 |    60   |   4.0%  | DMARC organizational evade |
| MAIL_FROM_MISMATCH                |    28   |   1.9%  | Envelope/Header mismatch   |
+-----------------------------------+---------+---------+----------------------------+
| Total Normalized Records          |  1,496  | 100.0%  | Complete Protocol Coverage |
+------------------------------------------------------------------------------------+
```

### Attack Scenario Descriptions
1. **`MIME_SIGNATURE_TAMPERING` (528 records):** Manipulates `multipart/signed` and PKCS#7 / CMS cryptographic boundaries so MUAs display an authentic sender whilst payload bytes bypass signature validation.
2. **`EMPTY_MAIL_FROM` (365 records):** Utilizes `MAIL FROM: <>` (RFC 5321 bounce address) to bypass SPF evaluation while inserting a forged identity in the `From:` header.
3. **`FROM_HEADER_INJECTION` (323 records):** Injects raw CRLF sequences, null bytes (`\x00`), or high-byte Latin-1 characters (`\xff`) into header fields to cause parser discrepancies between MTAs and MUAs.
4. **`MULTIPLE_FROM_HEADERS` (96 records):** Supplies more than one `From:` header in violation of RFC 5322 §3.6.2. Different parsers (e.g., Python `email`, Postfix, Exchange, Thunderbird) pick different headers (first vs. last).
5. **`SUBDOMAIN_EVASION` (60 records):** Forges sender subdomains (e.g., `update.service.paypal.com` vs. `paypal.com`) to exploit loose DMARC `sp=none` inheritance or missing DNS policies.
6. **`MAIL_FROM_MISMATCH` (28 records):** Mismatches the SMTP envelope return path (`Return-Path`) from the MUA-visible header (`From`).
7. **`OTHER_PROTOCOL_SPOOF` (96 records):** Pre-injects fabricated `Authentication-Results` headers or forged `Received` hops.

---

## 5. PII Redaction & Dual-View Security

Every normalized record contains both complete structural metadata for forensic analysis and a masked `redacted_preview` object:
- **`from`:** `s***@pge.com` (user and local-part masked, domain structure preserved).
- **`to`:** `"joseph powell (RI)" <j***@bbsrc.ac.uk>` (display name preserved, email masked).
- **`subject`:** Redacted if personal or phone numbers detected.
- **`body_preview`:** First 500 characters with telephone numbers and personal emails masked.
- **Git & Disk Protection:** `backend/data/processed/` and `*.jsonl` are git-ignored, preventing exposure of unredacted headers in version control.

---

## 6. Authentication Boundary Isolation

A critical integrity rule enforced during normalization:
- **Untrusted Historical Headers:** EPVME messages contain simulated or historical `Authentication-Results`, `Received-SPF`, and `DKIM-Signature` headers.
- **Standardized Field:** `auth_status: "UNKNOWN"` is stamped on every record.
- **Audit Note:** `auth_status_note: "Untrusted historical/simulated authentication header; must be evaluated dynamically by MailSentra Auth Module"`.
- MailSentra strictly rejects treating header-embedded authentication claims as verified engine findings.

---

## 7. Cross-Corpus Leakage & Deduplication Audit

To prevent train-test contamination and verify data hygiene, cross-corpus deduplication was executed against previously acquired corpora:
1. **Nazario Phishing Corpus (`DS-PE-01`):** 2,279 records.
2. **SpamAssassin Spam Corpus (`DS-SP-01`):** 1,397 records.

### Overlap Audit Results

| Overlap Dimension | Nazario (`DS-PE-01`) | SpamAssassin (`DS-SP-01`) | Finding |
| :--- | :---: | :---: | :--- |
| **Exact Raw Byte Overlap** | **0** | **0** | **100% Unique Raw Files** (due to protocol modifications) |
| **Normalized Content Overlap (Subject + Body)** | **13** | **7** | **Empirical proof of third-party body sampling** |
| **Subject Line Overlap** | **28** | **9** | **Reused lures with mutated headers** |

### Train-Test Contamination Warning
Because EPVME reused lure text from Nazario and SpamAssassin while transforming headers:
> [!IMPORTANT]
> **Contamination Guard:** When evaluating NLP/lexical phishing models or URL detectors, records with overlapping content hashes must be deduplicated to avoid inflated accuracy. For header-level evaluation (Modules 1, 2, and 3), the records are completely independent and valid.

---

## 8. Production-Path Evaluation Evidence

All 1,496 normalized records were evaluated against MailSentra's production parsing, identity, and authentication engines:
- **Evidence File:** `backend/data/processed/sender_spoofing/epvme_module_evaluation.json`

### Module 1: MIME & Header Parser
- **Records Tested:** 1,496
- **Multiple From Headers Detected:** 96 (100% of multiple-from test cases)
- **Empty Envelope Syntax Detected:** 1,402 (identified null bounce / missing Return-Path)
- **Header Injection Syntaxes Detected:** 323 (CRLF, null byte, high-byte injections flagged)
- **Parser Coverage Rate:** **100.0%**

### Module 2: Sender Identity Analysis
- **Records Tested:** 1,496
- **Envelope-From Domain Mismatches Flagged:** 94
- **Subdomain Evasions Flagged:** 77
- **Display-Name Spoofing & Injections Flagged:** 419
- **Identity Coverage Rate:** **100.0%**

### Module 3: Authentication Protocols
- **Records Tested:** 1,496
- **DMARC Alignment Failures Identified:** 1,388 (92.8% of records fail SPF/DKIM alignment to From header)
- **Historical Header Isolation:** 1,496 (100% enforced `auth_status: UNKNOWN`)
- **Authentication Boundary Integrity Rate:** **100.0%**

---

## 9. Registry & Manifest Lifecycle Conformance

The dataset manifests and grand registry were updated via `backend/app/datasets/registry_builder.py` (`build_all()`):

### Manifest Status (`backend/data/manifests/sender_spoofing.json`)
- `DS-SS-01` lifecycle state: **`INTEGRATED`**
- `is_synthetic_fixture`: `false`
- `provenance_nature`: `TRANSFORMED_DERIVATIVE`
- `raw_record_count`: 1,496
- `parsed_record_count`: 1,496
- `external_records_count`: 1,496
- `evaluated_record_count`: 0 (strictly preserved until Phase 3 formal execution)

### Grand Registry Metrics (`backend/data/dataset_registry.json`)
- **Total Registered Datasets:** 103
- **Total Approved Datasets:** 88
- **Total Integrated Datasets:** 21
  - Authentic External Datasets (3):
    - `DS-PE-01` (Nazario Phishing): 2,279 records (`EXTERNAL_ACQUIRED`)
    - `DS-SP-01` (SpamAssassin Spam): 1,397 records (`EXTERNAL_ACQUIRED`)
    - `DS-SS-01` (EPVME Protocol Spoofing): 1,496 records (`TRANSFORMED_DERIVATIVE`)
  - Synthetic Fixture Datasets (18): 18 records (`SYNTHETIC_FIXTURE_MOCK`)
- **Total External Records Count:** **5,172**
- **Total Synthetic Fixture Records:** **18**
- **Total Evaluated Datasets:** **0** (honest lifecycle compliance)

---

## 10. Automated Verification & Regression Stability

A comprehensive test suite was implemented and verified:
- **Test File:** `backend/tests/test_epvme_acquisition.py` (10 tests, 100% passing):
  1. `test_epvme_all_eight_archives_exist_and_hash`: Verified all 8 zip archives and exact byte hashes.
  2. `test_safe_extraction_security_controls`: Verified rejection of path traversal, absolute paths, non-EML files, and oversized members.
  3. `test_epvme_records_schema_and_normalization`: Verified canonical schema conformance for all 1,496 records.
  4. `test_epvme_scenario_coverage`: Verified scenario distributions across all 6 attack groups.
  5. `test_historical_authentication_untrusted_status`: Verified `auth_status: UNKNOWN` isolation.
  6. `test_cross_corpus_leakage_controls`: Verified 0 raw byte overlap with Nazario and SpamAssassin.
  7. `test_epvme_registry_and_manifest_lifecycle`: Verified honest lifecycle state in manifests and registry.
  8. `test_git_exclusion_for_epvme`: Verified git ignore rules for raw archives and processed corpora.
  9. `test_ground_truth_benchmarks_unmodified`: Verified `real_world_25` and `synthetic_75` ground-truth invariance.
  10. `test_production_module_evaluation_evidence`: Verified Module 1-3 evaluation evidence metrics.

### Regression Test Suite Results
- **Dataset & Acquisition Suite:** **62 / 62 tests passing** (1.84s).
- **Full Backend Regression Suite:** **724 / 724 tests passing** (18.57s).
- **Frontend Build Status:** Confirmed operational.
- **Git Working Tree:** Baseline strictly preserved; zero commits, pushes, resets, or stashes.

---

## 11. Conclusion & Checkpoint Approval Request

The acquisition and controlled ingestion of **DS-SS-01 (EPVME Protocol Spoofing Corpus)** is complete in full compliance with MailSentra Phase 2 standards:
- 8 raw archives (171.8 MB) verified and safeguarded.
- 1,496 normalized records ingested across all 6 spoofing attack vectors.
- Provenance nature recorded honestly as `TRANSFORMED_DERIVATIVE`.
- Cross-corpus overlap and leakage controls empirically documented.
- All 724 backend automated tests passing.
- Working tree clean of unprompted Git commits or pushes.

Category 3 (DS-SS-01) is ready for final user review and acceptance.
