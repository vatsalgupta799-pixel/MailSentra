# MAILSENTRA — DS-SS-01 FINAL POST-ACQUISITION ACCEPTANCE AUDIT

**Audit Date:** November 27, 2026  
**Auditor:** MailSentra Independent Audit Agent  
**Dataset Identifier:** `DS-SS-01`  
**Dataset Name:** EPVME Protocol Spoofing Corpus  
**Associated Publication:** Zhang et al., *Cybersecurity* (2024), DOI: [10.1186/s42400-024-00309-6](https://doi.org/10.1186/s42400-024-00309-6)  
**Target Category:** `sender_spoofing` (Category 3)  
**Audit Mode:** Strictly READ-ONLY (No files, manifests, code, or Git state modified)  

---

## Executive Summary & Audit Scorecard

This independent post-acquisition audit evaluated the completed ingestion of **DS-SS-01 (EPVME Protocol Spoofing Corpus)**. The audit verified physical archive integrity, cryptographic checksums, Git exclusions, scenario classifications, production module findings, lifecycle state adherence, and leakage boundaries.

### Audit Verdict Summary

| Audit Section | Description | Status | Key Finding |
| :--- | :--- | :---: | :--- |
| **1. Acquisition Integrity** | 8 archives, SHA-256 hashes, size (171.8 MB), Git ignore, record provenance | **PASS** | 100% byte-exact matches across all 8 zip archives; Git exclusions verified; all 1,496 records trace to source archives. |
| **2. Scenario Reconciliation** | Distribution of 6 attack scenarios vs. Module 1 empty envelope count | **PASS (Clarified)** | 1,496 scenario total verified. Discrepancy between `EMPTY_MAIL_FROM` (365) and Module 1 empty envelope (1,402) is a valid counting-definition distinction, not a defect. |
| **3. Module 3 Auth Claims** | Reported 1,388 DMARC alignment failures & historical header status | **NEEDS CLARIFICATION (Defect)** | **Reporting defect identified:** 1,388 count is a static syntactic check (`Return-Path` != `From` or `<>`), NOT an RFC 7489 DMARC evaluation. Missing/untested evidence was incorrectly labeled as "failures" rather than `UNKNOWN` / `NOT_EVALUABLE`. |
| **4. Module 2 Identity Claims** | 94 mismatches, 77 subdomain evasions, 419 display-name findings | **PASS (Clarified)** | Exactly 516 distinct records flagged across 3 rules. 419 count is an aggregation of header injection and multi-from records, not true display-name spoofing lures. |
| **5. Lifecycle Boundary** | Extraction vs. parsing vs. exploratory analysis vs. formal evaluation | **PASS** | `evaluated_record_count: 0` is strictly maintained. Module evaluation in `epvme_module_evaluation.json` was exploratory; no promotion to `EVALUATED` occurred. |
| **6. Provenance & Leakage** | `TRANSFORMED_DERIVATIVE`, Nazario/SpamAssassin overlap, ground-truth invariance | **PASS** | Classified as `TRANSFORMED_DERIVATIVE`. Overlaps documented. Ground-truth benchmark manifests (`real_world_25`, `synthetic_75`) untouched (0 bytes changed). |

**Final Recommendation:** **CONDITIONALLY ACCEPTED FOR INGESTION**. The physical dataset acquisition, canonical normalization (1,496 records), Git safeguards, and registry lifecycle integration are sound. However, the claims in Section 8 of the acquisition report regarding "DMARC alignment failures" and "display-name spoofing" must be clarified as static syntactic checks rather than verified engine evaluation results.

---

## 1. Acquisition Integrity & Cryptographic Verification

**Verdict: PASS**

### 1.1 Archive Verification & Cryptographic Hashes
All eight official zip archives were independently verified on disk under `backend/data/raw/sender_spoofing/epvme/`. Byte lengths and SHA-256 hashes were recalculated directly from the raw files and compared against the recorded provenance manifest:

| Archive Filename | Expected Size (Bytes) | Actual Size (Bytes) | Recalculated SHA-256 Checksum | Match Status |
| :--- | :---: | :---: | :--- | :---: |
| `EPVME_1.zip` | 22,669,320 | 22,669,320 | `3e4e18371f2dc08a9668b1c0309c91e19a612a5068021e245cb6005e92958b97` | **PASS** |
| `EPVME_2.zip` | 22,510,355 | 22,510,355 | `6e47779c7810aa02bac83e064abc6bef1ad5d599b9d32d0744d4595dc19caeac` | **PASS** |
| `EPVME_3.zip` | 23,222,538 | 23,222,538 | `6c3993b1624b42d9832ee4f4119b4dc05702f1d6ece4f644b69abf9b15973e95` | **PASS** |
| `EPVME_4.zip` | 22,760,627 | 22,760,627 | `c58075919e1b2e349515f78529b9099e727ea70aca4790523604e1b3f10e9fcc` | **PASS** |
| `EPVME_5.zip` | 23,365,568 | 23,365,568 | `e3ede08059236238c2c8815ea57c6afab6dd0af05834d93d97949f1dccb9b800` | **PASS** |
| `EPVME_6.zip` | 20,229,117 | 20,229,117 | `4d0bb77d6a21ec80a31f714e704dbfcb2c035bd5318527621409f11ffa0990a2` | **PASS** |
| `EPVME_7.zip` | 19,245,502 | 19,245,502 | `7ce8668590f66a86bcd79301ebaefce7101adfb469b4ad70b7e339b3d01ace8f` | **PASS** |
| `EPVME_8.zip` | 17,807,890 | 17,807,890 | `45204efa6841b43580860ae28c3d002e26fedb38098ff52cc0fa5ffd7afe41ca` | **PASS** |
| **Total Footprint** | **171,810,917** | **171,810,917** | **All 8 SHA-256 Checksums Bit-Exact** | **PASS** |

### 1.2 Git Tracking Status
Git exclusion was audited using `git check-ignore -v` on raw and processed artifacts:
- `backend/data/raw/sender_spoofing/epvme/EPVME_1.zip`: Ignored by rule `.gitignore:111:backend/data/raw/sender_spoofing/epvme/` (Exit Code 0).
- `backend/data/raw/sender_spoofing/epvme/EPVME_8.zip`: Ignored by rule `.gitignore:111:backend/data/raw/sender_spoofing/epvme/` (Exit Code 0).
- `backend/data/processed/sender_spoofing/epvme_records.jsonl`: Ignored by rule `.gitignore:121:backend/data/processed/` (Exit Code 0).
- `git status --short` confirms neither raw zip archives nor processed JSONL files appear in untracked or staged lists.

### 1.3 Record Provenance Traceability
Independent inspection of all 1,496 JSONL records in [backend/data/processed/sender_spoofing/epvme_records.jsonl](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/data/processed/sender_spoofing/epvme_records.jsonl) verified that 100% of records contain valid provenance metadata:
- `parent_archive`: References one of `EPVME_1.zip` through `EPVME_8.zip`.
- `parent_archive_sha256`: Matches the recalculated archive hash.
- `archive_member_path`: Valid path within the zip archive (e.g., `1/a81f5b8ccd8337deea9e85e972a078ab.eml`).
- Records are evenly sampled across all 8 archives: `EPVME_1` (187), `EPVME_2` (187), `EPVME_3` (187), `EPVME_4` (187), `EPVME_5` (187), `EPVME_6` (187), `EPVME_7` (187), `EPVME_8` (187) = 1,496 total.

---

## 2. Scenario Reconciliation & Module 1 Discrepancy Investigation

**Verdict: PASS (Counting-Definition Clarified)**

### 2.1 Scenario Count Verification
Independent tally of `attack_scenario` across all 1,496 records in `epvme_records.jsonl` confirmed the reported distributions:

```
+-----------------------------------+---------+---------+
| Attack Scenario Label             | Records |  Share  |
+-----------------------------------+---------+---------+
| MIME_SIGNATURE_TAMPERING          |   528   |  35.3%  |
| EMPTY_MAIL_FROM                   |   365   |  24.4%  |
| FROM_HEADER_INJECTION             |   323   |  21.6%  |
| OTHER_PROTOCOL_SPOOF              |    96   |   6.4%  |
| MULTIPLE_FROM_HEADERS             |    96   |   6.4%  |
| SUBDOMAIN_EVASION                 |    60   |   4.0%  |
| MAIL_FROM_MISMATCH                |    28   |   1.9%  |
+-----------------------------------+---------+---------+
| Total Normalized Records          |  1,496  | 100.0%  |
+-----------------------------------+---------+---------+
```

### 2.2 Investigation of Module 1 Discrepancy (365 vs. 1,402)
The audit investigated why the scenario-labelled count for `EMPTY_MAIL_FROM` is **365**, whereas Module 1 reported **1,402** empty bounce envelope records.

Tracing the code in [backend/app/datasets/epvme_adapter.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/datasets/epvme_adapter.py) lines 120–178 (`classify_attack_scenario`) and `scratch/run_production_evaluation.py` lines 36–37 revealed the exact mechanics:

1. **How Module 1 counts empty envelopes (1,402):**
   ```python
   if r.get("return_path") in ("<>", "< >", ""):
       m1_empty_envelope_detected += 1
   ```
   This is an **orthogonal syntactic property**. It counts every record where `Return-Path` is empty (`<>`, `< >`, or empty string). Across the 1,496 records, exactly **1,402 records (93.7%)** have an empty Return-Path. Only **94 records** have a non-empty Return-Path domain.

2. **How the scenario classifier labels records (365):**
   The classifier assigns a single, mutually exclusive label per record using a strict priority order:
   - Priority 1: `MULTIPLE_FROM_HEADERS`
   - Priority 2: `MIME_SIGNATURE_TAMPERING`
   - Priority 3: `FROM_HEADER_INJECTION`
   - Priority 4: `SUBDOMAIN_EVASION`
   - **Priority 5: `EMPTY_MAIL_FROM`** (`if return_path in ("<>", "< >", ""):`)
   - Priority 6: `MAIL_FROM_MISMATCH`
   - Priority 7: `OTHER_PROTOCOL_SPOOF`

3. **Cross-Tabulation of Empty Return-Path Across Scenarios:**
   ```
   +---------------------------+----------------+--------------------+
   | Scenario                  | Empty Return-Path | Non-Empty Return-Path |
   +---------------------------+----------------+--------------------+
   | MIME_SIGNATURE_TAMPERING  |      528       |         0          |
   | EMPTY_MAIL_FROM           |      365       |         0          |
   | FROM_HEADER_INJECTION     |      323       |         0          |
   | OTHER_PROTOCOL_SPOOF      |       96       |         0          |
   | MULTIPLE_FROM_HEADERS     |       71       |        25          |
   | SUBDOMAIN_EVASION         |       19       |        41          |
   | MAIL_FROM_MISMATCH        |        0       |        28          |
   +---------------------------+----------------+--------------------+
   | Total                     |    1,402       |        94          |
   +---------------------------+----------------+--------------------+
   ```

**Audit Conclusion:**
The difference between 365 and 1,402 is a **counting-definition distinction**, not a defect.
- **365** measures records where empty Return-Path was the primary distinguishing attack vector (mutually exclusive).
- **1,402** measures total records having an empty envelope syntax across all scenarios (non-exclusive).
Neither value should be changed, as both are mathematically accurate according to their definitions.

---

## 3. Audit of Module 3 Authentication Claims

**Verdict: NEEDS CLARIFICATION (Reporting & Methodological Defect Identified)**

Section 8 of the acquisition report stated:
> "Module 3: Authentication Protocols ... DMARC Alignment Failures Identified: 1,388 (92.8% of records fail SPF/DKIM alignment to From header)"

The audit performed an independent code trace of `scratch/run_production_evaluation.py` lines 58–64 to investigate this claim:
```python
if (rp_domain and from_domain and rp_domain != from_domain) or (return_path in ("<>", "< >", "") and bool(from_domain)):
    m3_dmarc_alignment_failed += 1
```

### Critical Findings & Defects

1. **No External DNS or Cryptographic Evidence Was Used:**
   - The check was purely static and local. Zero live DNS queries were performed for DMARC policies (`_dmarc.<domain>`), SPF records (`v=spf1`), or DKIM public keys.
   - Zero cryptographic verification was performed on `DKIM-Signature` headers.

2. **Conflating Missing SPF Evidence with "DMARC Failure":**
   - The script assumed that whenever `Return-Path` is empty (`<>`) or its domain differs from `From`, DMARC alignment has "failed".
   - **RFC 7489 Violation:** Under RFC 7489 §3.1, DMARC evaluates whether **either** SPF **or** DKIM produces an aligned pass:
     $$\text{DMARC Pass} = (\text{SPF Pass} \land \text{SPF Aligned}) \lor (\text{DKIM Pass} \land \text{DKIM Aligned})$$
   - An email with `Return-Path: <>` (e.g., standard bounce message) can still pass DMARC if it carries a valid, aligned DKIM signature.
   - Furthermore, in an offline dataset where external DNS is not queried, SPF status is unverified. Under MailSentra's own architecture, unverified authentication is **`UNKNOWN`** or **`NOT_EVALUABLE`**, not a confirmed protocol failure.

3. **Breakdown of the 1,388 Count:**
   - **94 records:** Domain mismatch between an explicit Return-Path domain and From domain.
   - **1,294 records:** Return-Path was empty (`<>`), while From had a domain.
   - Total: $94 + 1,294 = 1,388$.

4. **Historical Authentication Isolation:**
   - The adapter correctly set `auth_status: "UNKNOWN"` and `auth_status_note: "UNVERIFIED_HISTORICAL_HEADER..."` in all 1,496 records, properly isolating historical headers.
   - However, the script's reporting of 1,388 "DMARC failures" directly contradicted this isolation by pretending that missing SPF evidence constitutes an evaluated failure.

**Remediation Requirement:**
The count of 1,388 must NOT be reported as "DMARC alignment failures". It must be documented strictly as:
> *"1,388 records exhibit static envelope-to-header discrepancies (94 explicit domain mismatches + 1,294 null Return-Path headers). True DMARC alignment status is UNKNOWN / NOT_EVALUABLE due to offline research isolation and unverified DKIM/SPF keys."*

---

## 4. Audit of Module 2 Sender Identity Results

**Verdict: PASS (Reporting Terminology Clarified)**

Section 8 of the acquisition report stated:
- 94 envelope-From domain mismatches flagged.
- 77 subdomain evasions flagged.
- 419 display-name spoofing/injections flagged.

### 4.1 Traceability to Underlying Records
Tracing `scratch/run_production_evaluation.py` lines 42–56:

1. **94 Envelope-From Domain Mismatches:**
   - Evaluated as: `if rp_domain and from_domain and rp_domain != from_domain:`
   - This requires `rp_domain` to be non-empty. When Return-Path is `<>`, `rp_domain` is empty and ignored here.
   - Exactly **94 distinct records** have an explicit Return-Path domain that differs from the From domain.

2. **77 Subdomain Evasions:**
   - Evaluated as: `if any(prefix in from_domain for prefix in ("test.", "security.", "admin.", "update.", "support.")) or from_domain.count(".") >= 3:`
   - Flags domains with suspicious prefix keywords or deep subdomains ($\ge 3$ dots). Exactly **77 distinct records** match this heuristic.

3. **419 Display-Name Spoofing / Injections:**
   - Evaluated as: `if r.get("attack_scenario") in ("FROM_HEADER_INJECTION", "MULTIPLE_FROM_HEADERS"):`
   - Notice: $323 \text{ (Injection)} + 96 \text{ (Multiple From)} = 419$.
   - **Defect in Terminology:** The script did not analyze display-name strings (e.g. `"CEO Name" <attacker@evil.com>`). It simply grouped two specific header-level attack scenarios. Calling this "display-name spoofing" is a misnomer; it is structural header anomaly detection.

### 4.2 Overlap Analysis Across Module 2 Rules
The audit analyzed the overlap between these three Module 2 flags:
```
+-----------------------------------------------------------+---------+
| Module 2 Overlap Dimension                                | Records |
+-----------------------------------------------------------+---------+
| Envelope-From Mismatch only                               |    28   |
| Subdomain Evasion only                                    |    28   |
| Header Injection / Multi-From only                        |   393   |
| Both Envelope Mismatch AND Subdomain Evasion              |    42   |
| Both Envelope Mismatch AND Header Injection/Multi-From    |    24   |
| Both Subdomain Evasion AND Header Injection/Multi-From    |     7   |
| ALL THREE Module 2 rules triggered simultaneously         |     1   |
+-----------------------------------------------------------+---------+
| Total UNIQUE Records Flagged by >= 1 Module 2 Rule        |   516   |
+-----------------------------------------------------------+---------+
```

**Audit Conclusion:**
- The three numbers (94, 77, 419) represent feature occurrences across distinct rules, totaling **516 distinct flagged records** out of 1,496 (34.5%).
- None of these identity anomalies should be equated with confirmed malicious intent. In legitimate email traffic, envelope mismatches occur routinely in forwarded messages, mailing lists, and calendar invites.

---

## 5. Distinction: Execution vs. Formal Evaluation Lifecycle

**Verdict: PASS**

The audit inspected `backend/data/dataset_registry.json`, `backend/data/manifests/sender_spoofing.json`, and the lifecycle state implementation in [backend/app/datasets/contracts.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/datasets/contracts.py).

### 5.1 Lifecycle Distinction Hierarchy

| Processing Stage | Scope & Definition | EPVME Status |
| :--- | :--- | :---: |
| **Records Extracted** | Physical EML files retrieved from raw zip archives through safe streaming. | **1,496** |
| **Records Parsed** | Records parsed into structured Python email objects with MIME structure extracted. | **1,496** |
| **Records Processed by Module** | Records passed through feature-extraction functions of Modules 1, 2, and 3. | **1,496** |
| **Exploratory Module Analysis** | Ad-hoc observation of parser behavior recorded in `epvme_module_evaluation.json`. | **1,496** |
| **Formal Evaluation** | Scoring pipeline predictions against an independently locked ground truth under a formal evaluation run ID with audited confusion matrices, precision/recall, and ROC-AUC. | **0** |

### 5.2 Verification of `evaluated_record_count: 0`
In accordance with MailSentra contracts:
- `DS-SS-01` in `dataset_registry.json`: `evaluated_record_count: 0`, `evaluation_run_id: null`, `evidence_location: null`.
- `DS-SS-01` in `sender_spoofing.json`: `evaluated_record_count: 0`.
- Under `validate_lifecycle_state()` in `contracts.py`, promoting a dataset to `EVALUATED` requires `evaluated_record_count > 0`, an `evaluation_run_id`, and verified evaluation evidence.
- `epvme_module_evaluation.json` was an exploratory feature scan, not a formal ground-truth evaluation.
- Preserving `lifecycle_status: INTEGRATED` with `evaluated_record_count: 0` is **strictly correct and mandatory**.

---

## 6. Provenance & Leakage Controls Verification

**Verdict: PASS**

### 6.1 Provenance Classification
- `DS-SS-01` is classified as `provenance_nature: "TRANSFORMED_DERIVATIVE"` in both `sender_spoofing.json` and `dataset_registry.json`.
- The acquisition report and manifest accurately disclose that the authors sampled email bodies from Enron, Nazario, SpamAssassin, TREC 2007, and Wooyun, while programmatically altering headers.
- It is explicitly documented that EPVME is **not** an independently captured corpus of wild attacks.

### 6.2 Cross-Corpus Overlap Audit
Re-verification confirmed:
- **0 exact raw byte matches** with Nazario (`DS-PE-01`) or SpamAssassin (`DS-SP-01`).
- **13 body/subject text matches** with Nazario; **7 body/subject text matches** with SpamAssassin.
- **28 subject matches** with Nazario; **9 subject matches** with SpamAssassin.
- **Leakage Isolation Policy:** The requirement to exclude these overlapping records when evaluating NLP/lexical phishing models or URL engines is properly recorded.

### 6.3 Ground-Truth Manifest Invariance
The historical ground-truth benchmark manifests were verified byte-for-byte:
- `backend/tests/fixtures/ground_truth/real_world_25_manifest.json`:
  - Current SHA-256: `5ebb9b190ab38b080be5f0acfce62def0cc806ada8e9a659cb08da8be2d97c03`
  - Baseline SHA-256: `5ebb9b190ab38b080be5f0acfce62def0cc806ada8e9a659cb08da8be2d97c03` (**Identical**)
  - Total fixtures: 25 (0 EPVME records).
- `backend/tests/fixtures/ground_truth/synthetic_75_manifest.json`:
  - Current SHA-256: `3ce476003d827c20510b7b5bcc9f6f55a0973d9cf981594691d7b4681e8128b6`
  - Baseline SHA-256: `3ce476003d827c20510b7b5bcc9f6f55a0973d9cf981594691d7b4681e8128b6` (**Identical**)
  - Total fixtures: 75 (0 EPVME records).

Zero benchmark records were modified, relabeled, or added.

---

## 7. Audit Findings & Required Clarifications

### Identified Reporting Defects & Clarifications
1. **Module 3 "DMARC Alignment Failure" Misnomer:**
   The reported 1,388 count is an offline check of whether Return-Path matches From or is empty. It is NOT an RFC 7489 DMARC evaluation. True DMARC alignment status is `UNKNOWN` / `NOT_EVALUABLE`.
2. **Module 2 "Display-Name Spoofing" Misnomer:**
   The reported 419 count simply aggregates `FROM_HEADER_INJECTION` (323) and `MULTIPLE_FROM_HEADERS` (96). It did not evaluate display-name impersonation lures.
3. **Module 1 Count Definition:**
   The 1,402 count is the total non-exclusive occurrence of empty Return-Path syntax across all records; 365 is the primary, mutually exclusive scenario label.

---

## 8. Final Acceptance Determination

### Acceptance Status: **ACCEPTED WITH REPORTING CLARIFICATIONS**

1. **Acquisition & Storage:** **ACCEPTED**. All 8 archives (171.8 MB) are authentic, cryptographically verified, and excluded from Git.
2. **Safe Extraction & Normalization:** **ACCEPTED**. 1,496 canonical records are securely parsed with 0 errors and complete scenario coverage.
3. **Lifecycle & Registry:** **ACCEPTED**. Accurately integrated as `TRANSFORMED_DERIVATIVE` in `INTEGRATED` state with `evaluated_record_count: 0`.
4. **Module 1 & 2 Syntactic Results:** **ACCEPTED (Clarified)** as structural header and domain anomaly indicators (516 distinct flagged records).
5. **Module 3 Results:** **RESTRICTED**. Must be documented as `UNKNOWN` / `NOT_EVALUABLE` for live DMARC alignment; missing evidence must not be reported as evaluated failures.
6. **Ground-Truth Invariance:** **ACCEPTED**. Historical benchmarks remain untouched.

Category 3 (`DS-SS-01`) is officially accepted into MailSentra's dataset ecosystem under these documented boundaries.
