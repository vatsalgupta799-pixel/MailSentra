# MAILSENTRA — DATASET INTEGRATION RECONCILIATION & EVIDENCE AUDIT

**Audit Date:** November 27, 2026  
**Auditor:** Independent Cybersecurity Researcher, ML Engineer & Dataset Auditor  
**Audit Scope:** Read-Only Verification of Dataset Registry, Manifests, Raw Data Files, Pipeline Adapters, Evaluation Evidence, and Module Routing  
**Repository Baseline:** Branch `main` | Commit `a1ab60620b601737444fa39a1de329d4a5083a3f`  
**Execution Environment:** Windows Server / PowerShell | Python 3.13.7 (`pytest-9.2.0`)  
**Audit Directive:** Strict Evidence Verification (No Production Changes, Zero Inferred Claims)

---

## 1. Executive Summary & Audit Verdict

This audit performs an independent, read-only reconciliation of the MailSentra dataset integration portfolio documented in `dataset_registry.json`, the 8 category manifests in `backend/data/manifests/`, sample fixtures in `backend/data/raw/`, and the evaluation pipeline in `backend/app/datasets/`.

### Final Audit Verdict
```
================================================================================
FINAL AUDIT VERDICT: NOT VERIFIED (FOR ACTUAL LARGE-SCALE DATASET USAGE)
PORTFOLIO CATALOG CLASSIFICATION: PARTIALLY VERIFIED (CATALOG & METADATA ONLY)
================================================================================
```

### Critical Audit Findings:
1. **Count Reconciliation Resolved:** The apparent discrepancy between 85 "Verified" and 88 "Approved/Integrated" is fully resolved: 3 sources (`DS-PE-10`, `DS-SS-04`, `DS-MA-15`) are `CONDITIONALLY_APPROVED` (due to known record overlap, tabular-only format, or encrypted live malware binaries). $85 \text{ Verified} + 3 \text{ Conditional} = 88 \text{ Approved/Integrated}$.
2. **Actual Dataset Usage Deficit:** The previous integration report marked 85 datasets as `USED_IN_EVALUATION`. Direct disk inspection reveals that **65 of those 85 datasets have 0 records in `backend/data/raw/` or `backend/data/processed/`**. Only **20 sample fixture records total** exist on disk, representing at most 20 candidate datasets.
3. **Email Evaluation Engine Mock:** In `backend/app/datasets/evaluator.py`, `evaluate_email_dataset()` does not invoke MailSentra's production detection pipeline (`ScanService`, `ParserService`, `IdentityAnalyzer`, or `AuthService`). Instead, it executes an internal 8-keyword substring heuristic (`"verify" in body`, `"wire" in body`, etc.). Production email modules were **not genuinely evaluated** by this dataset pipeline.
4. **Split Partitioning Artifacts:** The deterministic MD5 hash-based modulo split (`hash_val < 70`) on small 2-to-3 record fixture sets causes severe partition distortions: in `bec_fraud` and `social_engineering`, 100% of records were hashed into the train split ($N=0$ test records), while in `malware_attachments`, 100% of malicious records fell into the train split, leaving only 1 benign record in the test split.
5. **False Negative on Static URL Detection:** The sample fixture `http://paypal-verification-account-sec.com/login.php` (Ground Truth: `MALICIOUS_URL`) was evaluated by `UrlAnalyzer` and returned `SAFE` (Severity: `SAFE`, Reason: *"No suspicious static indicators detected"*), yielding a False Negative and actual Recall of 50.0%, contradicting previous claims of 100% accuracy.

---

## 2. Eight-Category Portfolio Reconciliation

All figures recalculated directly from `backend/data/dataset_registry.json` and `backend/data/manifests/*.json`:

| Category | Candidate Entries | Independently Verified | Approved Sources | Integrated in Manifest | Actually Used in Pipeline | Conditional Sources | Rejected Sources | Unique Underlying Corpora |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Phishing Email** (`phishing_email`) | 16 | 9 | 10 | 10 | **3** (`DS-PE-01, 03, 04`) | 1 (`DS-PE-10`) | 6 | 9 |
| **Spam Email** (`spam_email`) | 15 | 15 | 15 | 15 | **2** (`DS-SP-01, 02`) | 0 | 0 | 15 |
| **Sender Spoofing** (`sender_spoofing`) | 9 | 5 | 6 | 6 | **2** (`DS-SS-03, 06`) | 1 (`DS-SS-04`) | 3 | 5 |
| **BEC & Email Fraud** (`bec_fraud`) | 8 | 5 | 5 | 5 | **0** (2 in train, 0 in test) | 0 | 3 | 5 |
| **Social Engineering** (`social_engineering`) | 9 | 7 | 7 | 7 | **0** (2 in train, 0 in test) | 0 | 2 | 7 |
| **Malicious URLs** (`malicious_urls`) | 16 | 15 | 15 | 15 | **3** (`DS-URL-04, 06, 07`) | 0 | 1 (`DS-URL-03`) | 15 |
| **Malware Attachments** (`malware_attachments`) | 15 | 14 | 15 | 15 | **3** (`DS-MA-01, 05, 06`) | 1 (`DS-MA-15`) | 0 | 14 |
| **Benign Controls** (`benign_controls`) | 15 | 15 | 15 | 15 | **1** (`DS-BC-02` in test; 2 in train)| 0 | 0 | 15 |
| **TOTALS** | **103** | **85** | **88** | **88** | **14** (65 unpopulated) | **3** | **15** | **85** |

### Discrepancy Resolution Table
| Reported Anomaly | Verified Count | Approved Count | Root Cause Analysis & Resolution |
| :--- | :---: | :---: | :--- |
| `phishing_email` (9 vs 10) | 9 | 10 | `DS-PE-10` (Zenodo 8339691) is `CONDITIONALLY_APPROVED` because it is an aggregate compilation of Nazario, SpamAssassin, and Enron. It is approved as a meta-dataset but cannot count as an independently verified primary corpus. |
| `sender_spoofing` (5 vs 6) | 5 | 6 | `DS-SS-04` (GregaVrbancic) is `CONDITIONALLY_APPROVED` because it consists of extracted tabular SPF feature records rather than raw RFC-5322 MIME messages. |
| `malware_attachments` (14 vs 15) | 14 | 15 | `DS-MA-15` (TheZoo) is `CONDITIONALLY_APPROVED` because it contains live encrypted malware binaries and is approved only under disarmed metadata inspection. |
| Portfolio Total (85 vs 88) | 85 | 88 | Across the 103 candidates, exactly 85 are `VERIFIED`, 3 are `CONDITIONALLY_APPROVED` ($85 + 3 = 88$), and 15 are `REJECTED`. |

---

## 3. Evidence of Actual Dataset Usage

The strict audit rule mandates: *"A dataset listed, downloaded, or normalized is not automatically evaluated. If actual records were not processed by the relevant production detector, change its status to NOT USED IN EVALUATION."*

### Breakdown of the 85 Claimed "Used" Datasets:
- **Datasets with records processed by Production Detectors during test runs:** **6 datasets**
  - `DS-URL-04` (PhishTank), `DS-URL-06` (URLhaus), `DS-URL-07` (Tranco): evaluated by `UrlAnalyzer`.
  - `DS-MA-01` (EMBER sample), `DS-MA-05` (Contagio PDF sample), `DS-MA-06` (Contagio Office sample): evaluated by `AttachmentAnalyzer`.
- **Datasets with records processed by Local Mock Heuristics:** **8 datasets**
  - `DS-PE-01`, `DS-PE-03`, `DS-PE-04`, `DS-SP-01`, `DS-SP-02`, `DS-SS-03`, `DS-SS-06`, `DS-BC-02`: processed by local string search in `evaluate_email_dataset()`.
- **Datasets with Sample Records that received 0 test executions (100% Train Partitioned):** **6 datasets**
  - `DS-BF-01`, `DS-BF-05`, `DS-SE-01`, `DS-SE-05`, `DS-BC-01`, `DS-BC-15`.
- **Datasets with ZERO records on disk (Metadata Catalog Only):** **65 datasets**
  - `DS-PE-02`, `DS-PE-05` to `DS-PE-10`, `DS-SP-03` to `DS-SP-15`, `DS-SS-01`, `DS-SS-02`, `DS-SS-04`, `DS-SS-05`, `DS-BF-02` to `DS-BF-04`, `DS-SE-02` to `DS-SE-04`, `DS-SE-06`, `DS-SE-07`, `DS-URL-01`, `DS-URL-02`, `DS-URL-05`, `DS-URL-08` to `DS-URL-16`, `DS-MA-02` to `DS-MA-04`, `DS-MA-07` to `DS-MA-15`, `DS-BC-03` to `DS-BC-14`.

**Audit Rectification:** All 65 unpopulated datasets must formally be designated `CATALOGED_ONLY (NOT USED IN EVALUATION)`.

---

## 4. Production Module Suitability Audit

| Evaluated Module | Appropriate Input | Actual Input Provided in Pipeline | Suitability Finding |
| :--- | :--- | :--- | :--- |
| **Module 4: URL Analysis** (`UrlAnalyzer`) | RFC-compliant URL string with scheme and authority. | URLs extracted from `malicious_urls_samples.json`. | **SUITABLE.** Directly invokes production lexical, IP literal, and domain rules. |
| **Module 6: Attachment Analysis** (`AttachmentAnalyzer`) | `AttachmentMetadata` with raw bytes or disarmed file stream. | `AttachmentMetadata` initialized with filename, content-type, and SHA-256 (payload bytes empty `b""`). | **PARTIALLY SUITABLE.** Tests static filename, double-extension, and extension-based rules. Does NOT test payload magic byte verification or ZIP bomb decompression. |
| **Module 1/2: RFC-5322 & Identity** | Raw MIME bytes or parsed header dictionary. | Not called. | **UNSUPPORTED / NOT EVALUATED.** Evaluator bypassed production MIME parser. |
| **Module 3: Authentication Protocols** | DNS records, `Authentication-Results` headers, SPF/DKIM/DMARC inputs. | Not called. | **UNSUPPORTED / NOT EVALUATED.** Dataset pipeline contains no SPF/DKIM verification execution. |
| **Module 5: Social Engineering** | Contextual email text with NLP/LLM classification. | Local 8-word substring match in `evaluator.py`. | **UNSUPPORTED / UNVERIFIED.** Evaluator used a placeholder mock rather than production contextual analysis. |

---

## 5. Leakage, Grouping & Independence Analysis

Inspection of `backend/app/datasets/pipeline.py`:
```python
def split_records(self, records: List[Dict[str, Any]], train_ratio: float = 0.7, test_ratio: float = 0.3):
    train_set, test_set = []
    for rec in records:
        if rec.get("is_duplicate"): continue
        identifier = rec.get("content_sha256") or rec.get("record_id")
        hash_val = int(hashlib.md5(identifier.encode("utf-8")).hexdigest(), 16) % 100
        if hash_val < int(train_ratio * 100):
            rec["split"] = "train"; train_set.append(rec)
        else:
            rec["split"] = "test"; test_set.append(rec)
    return train_set, test_set
```

### Audit Findings:
1. **Exact Duplicate Isolation:** Successful. Identical content SHA-256 digests are flagged and excluded from test splits ($|\text{Train} \cap \text{Test}| = 0$).
2. **Absence of Domain / Sender Grouping:** Records are partitioned purely by individual content hash. If an attacker domain appears across multiple samples, there is no domain-level or campaign-level cluster isolation.
3. **Absence of Near-Duplicate Detection:** No fuzzy hashing (ssdeep, TLSH) or MinHash/LSH is used; minor modifications to message bodies would cross partition boundaries undetected.
4. **Partition Collapse on Small Corpora:**
   - In `bec_fraud_samples.json` (2 records): MD5 hashes modulo 100 evaluated to 12 and 48 (both $<70$). Result: 2 train, 0 test.
   - In `social_engineering_samples.json` (2 records): MD5 hashes evaluated to 31 and 54 (both $<70$). Result: 2 train, 0 test.
   - In `malware_attachments_samples.json` (3 records): The 2 malware samples evaluated to 22 and 67 ($<70$). The benign sample evaluated to 84 ($\ge 70$). Result: 0 malware samples in the test split.

---

## 6. Actual Measured Evaluation Evidence

Executing `DatasetEvaluator` across all populated raw fixture sets yields the following verifiable metrics:

| Category | Loaded | Train Set | Test Set | TP | FP | TN | FN | Precision | Recall | Specificity | F1 Score | Notes / Failure Modes |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| `malicious_urls` | 3 | 1 | 2 | 1 | 0 | 0 | 1 | **1.0000** | **0.5000** | N/A | **0.6667** | **False Negative:** `http://paypal-verification-account-sec.com/login.php` was categorized as `SAFE` by `UrlAnalyzer`. |
| `malware_attachments` | 3 | 2 | 1 | 0 | 0 | 1 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | Test split contained ONLY 1 benign PDF. Malicious samples fell into train split. |
| `phishing_email` | 3 | 1 | 2 | 1 | 0 | 0 | 1 | **1.0000** | **0.5000** | N/A | **0.6667** | Evaluated via local mock. One sample lacked trigger keywords. |
| `spam_email` | 2 | 0 | 2 | 0 | 0 | 0 | 2 | **1.0000** | **0.0000** | N/A | **0.0000** | Evaluated via local mock. Neither sample triggered keyword list. |
| `sender_spoofing` | 2 | 0 | 2 | 2 | 0 | 0 | 0 | **1.0000** | **1.0000** | N/A | **1.0000** | Evaluated via local mock (matched `"confidential"` and `"unauthorized"`). |
| `bec_fraud` | 2 | 2 | 0 | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | **Zero test records.** Hash split assigned 100% to train. |
| `social_engineering`| 2 | 2 | 0 | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | **Zero test records.** Hash split assigned 100% to train. |
| `benign_controls` | 3 | 2 | 1 | 0 | 0 | 1 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 1 benign sample in test split correctly not flagged. |

---

## 7. Licensing and Provenance Audit

| Verification Tier | Criteria | Dataset Count | Representative Examples |
| :--- | :--- | :---: | :--- |
| **Tier 1: Open Permissive** | Verified OSI/Creative Commons license (CC0, CC-BY, MIT, Apache 2.0). | **42** | `SpamAssassin` (Apache 2.0), `Tranco` (MIT), `URLhaus` (CC0), `PhiUSIIL UCI` (CC-BY 4.0), `EMBER` (CC0). |
| **Tier 2: Research-Only** | Academic research license requiring non-commercial usage agreement. | **38** | `TREC 2005-2007` (NIST Agreement), `Ling-Spam` (AUEB), `ISCX-URL-2016` (UNB CIC), `BODMAS` (NJIT). |
| **Tier 3: Public Advisory / Unspecified** | Accessible on institutional web pages without formalized open-source license. | **5** | `Cornell PhishBowl`, `Berkeley ISO`, `Millersville Phishing`. |
| **Tier 4: Restricted / Confidential** | Inaccessible for open reproducible science. | **18** | `APWG eCX` (Commercial NDA), `FBI IC3` (Law enforcement only), synthetic mirrors. |

---

## 8. Audit Conclusion & Roadmap Rectification

1. **Portfolio Catalog Quality:** The cataloging of 103 candidates across 8 categories, the rejection of 15 duplicates/synthetics, and the formal registry/manifest structure represent rigorous research curation.
2. **Execution Reality:** Claiming that 85 datasets are "used in evaluation" when only 20 sample records exist and only 6 datasets were evaluated by production code is factually inaccurate.
3. **Required Next Steps for Phase 3:**
   - Ingest genuine, multi-thousand-record samples for verified datasets.
   - Refactor `DatasetEvaluator.evaluate_email_dataset()` to route full MIME messages through `ScanService.scan_email()`.
   - Implement domain-aware and campaign-aware group partitioning.
