# MailSentra — Controlled Detection Test Documentation

**Document ID:** `MAILSENTRA-CDT-01`  
**Execution Date:** November 28, 2026  
**Evaluation Scope:** Five Controlled Synthetic Fixture Test Runs  
**Execution Interface:** MailSentra Threat Defense Console (`http://localhost:5173`) via `POST /api/v1/scans/upload`  
**Backend Application:** FastAPI Core (`http://127.0.0.1:8000`) backed by SQLite  

---

## 1. Executive Summary & Testing Scope

This document details the execution and observed results of **five controlled detection tests** performed against the running MailSentra application using curated synthetic fixtures from `backend/tests/fixtures/real_world_emails/`.

Each test was ingested end-to-end through the native web upload workflow, evaluated by MailSentra's multi-vector detection pipeline (MIME Parser, Sender Identity Analyzer, Auth Protocols Evaluator, URL Security Analyzer, Attachment Forensics Analyzer, and RiskEngine), and recorded in the application database (`scan_incidents`).

```
+-----------------------------------------------------------------------------------------------------------------------+
|                                    CONTROLLED DETECTION TEST EXECUTION MATRIX                                         |
+------+-------------------------------------------+---------+--------------------------------------+------------+-------+
| Test | Fixture Filename                          | Scan ID | Scan UUID                            | Verdict    | Score |
+------+-------------------------------------------+---------+--------------------------------------+------------+-------+
| 1    | normal/01_university_announcement.eml     | #9      | 157c8877-50d4-4d55-a677-749f71bf57d6 | CLEAN      | 0.0   |
| 2    | suspicious/03_fake_admin.eml              | #10     | 2bd46dd8-6a5d-4d3f-a8c8-edb9217aa4f1 | SUSPICIOUS | 47.0  |
| 3    | suspicious/05_mismatched_from_replyto.eml | #11     | b93737e0-69f4-41a1-a294-7f1b9a44466c | SUSPICIOUS | 59.0  |
| 4    | edge_cases/09_invalid_sender_address.eml  | #12     | 442d943b-7f59-408a-a547-efd96cab9501 | SUSPICIOUS | 57.0  |
| 5    | suspicious/16_suspicious_attachment_filename.eml | #13 | ed2a0066-1e74-47f7-ac91-5a6613ea4ab5 | MALICIOUS | 87.0  |
+------+-------------------------------------------+---------+--------------------------------------+------------+-------+
```

---

## 2. Important Methodological Disclaimers & Accuracy Constraints

> [!IMPORTANT]
> **Controlled Regression Runs, NOT a Universal Benchmark**:  
> These five tests evaluate specific synthetic regression fixtures designed to verify deterministic rule execution across foundational threat archetypes. They **do not** constitute a statistically representative real-world benchmark, and no claim of 100% detection accuracy across open-world email flows is made. Open-world benchmarks evaluated separately against external corpora (1,195 records across Nazario, SpamAssassin, and EPVME) achieve an overall detection rate of 54.64%, reflecting the real-world performance of offline heuristics without commercial threat reputation subscriptions.

> [!WARNING]
> **Authentication Semantics in Direct File Upload**:  
> In direct EML upload scenarios without live MTA relay telemetry or authenticated SMTP session metadata, SPF evaluation is classified as `NOT_EVALUATED` and DMARC evaluates under a fail-safe incomplete state. These offline results **must not** be construed as successful cryptographic authentication.

> [!NOTE]
> **Heuristic Limitations**:  
> - **URLs Marked SAFE**: A URL evaluated as `SAFE` indicates that no local pattern-based heuristic (e.g. suspicious TLD, IP-literal host, subdomain brand impersonation) fired. It is **not** proof that the destination domain is benign on the live internet.  
> - **Attachment Header Inspection**: The identification of leading `b"MZ"` magic bytes verifies executable file structure signatures. It is **not** proof of a complete, compilable, or functionally weaponized malware payload.

---

## 3. Individual Test Execution Reports

### Test 1: Legitimate Email (Normal Clean Baseline)

* **Fixture:** `backend/tests/fixtures/real_world_emails/normal/01_university_announcement.eml`
* **Objective:** Verify that a standard, well-formed announcement email containing no deceptive links, clean headers, and no attachments evaluates to a clean baseline without false-positive signal inflation.
* **Scan Identifiers:** Scan ID `#9`, UUID `157c8877-50d4-4d55-a677-749f71bf57d6`
* **Subject:** `Campus Facilities Update: Library Extended Hours`
* **From:** `University Communications <announcements@university.edu>`
* **To:** `campus-all@university.edu`
* **Observed Telemetry & Indicators:**
  - Extracted URLs: `0`
  - Attachments: `0`
  - Contributing Threat Signals: `[]`
  - Identity Analysis: `display_name_spoofed: false`, `envelope_header_match: true`
  - Parsing Warnings: `[]`
* **Expected vs. Observed Outcome:**
  - Expected Verdict: `CLEAN` (Risk Score: `0.0`)
  - Observed Verdict: `CLEAN` (Risk Score: `0.0`)
  - Concordance: **MATCH (PASS)**
* **Caveats & Limitations:**
  - *Duplicate-Scan Caveat:* Fixture `01_university_announcement.eml` contains a deterministic `Message-ID` header (`<announcement-2026-11-20@university.edu>`). In the local testing database, previous validation runs had indexed this Message-ID; MailSentra's duplicate-detection logic tracked the reference scan while correctly completing the independent analysis with a score of `0.0`. A clean score on a controlled synthetic announcement does not guarantee that every benign corporate email will score 0.0 in production.

---

### Test 2: Phishing Email (Suspicious TLD & Urgency Theme)

* **Fixture:** `backend/tests/fixtures/real_world_emails/suspicious/03_fake_admin.eml`
* **Objective:** Evaluate detection of a synthetic credential-harvesting lure impersonating IT administration with urgent verification calls-to-action and a suspicious `.xyz` top-level domain.
* **Scan Identifiers:** Scan ID `#10`, UUID `2bd46dd8-6a5d-4d3f-a8c8-edb9217aa4f1`
* **Subject:** `Urgent: Account Verification Required`
* **From:** `IT Helpdesk <support@university-portal.com>`
* **To:** `student@university.edu`
* **Observed Telemetry & Indicators:**
  - Extracted URL: `hxxp://university-secure-login[.]xyz/portal/verify` (defanged)
  - Contributing Threat Signal: `[URL-SUSPICIOUS] hxxp://university-secure-login[.]xyz/portal/verify: Suspicious TLD '.xyz' identified`
  - URL Severity: `SUSPICIOUS`
  - Attachments: `0`
* **Score Derivation:**
  - Base Severity Tier: `RiskTier.SUSPICIOUS` base = `45.0`
  - Contributing Signal Increment: 1 signal × `2.0` = `+2.0`
  - Computed Risk Score: `45.0 + 2.0 = 47.0`
* **Expected vs. Observed Outcome:**
  - Expected Verdict: `SUSPICIOUS` (Risk Score: `47.0`)
  - Observed Verdict: `SUSPICIOUS` (Risk Score: `47.0`)
  - Concordance: **MATCH (PASS)**
* **Caveats & Limitations:**
  - Detection fired exclusively on the static URL TLD rule (`.xyz`). No live DNS queries, WHOIS age checks, or threat reputation API lookups were made.

---

### Test 3: Brand Impersonation & Header Mismatch

* **Fixture:** `backend/tests/fixtures/real_world_emails/suspicious/05_mismatched_from_replyto.eml`
* **Objective:** Detect routing deception where the visible sender displays a financial brand identity while technical response headers route to an external, unrelated infrastructure domain.
* **Scan Identifiers:** Scan ID `#11`, UUID `b93737e0-69f4-41a1-a294-7f1b9a44466c`
* **Subject:** `Notice of Account Restriction`
* **From:** `"JPMorgan Chase Support" <no-reply@chase.com>`
* **Reply-To:** `<chase-fraud-prevention@secure-resolve-tickets.net>`
* **Return-Path:** `<bounce-9911@secure-resolve-tickets.net>`
* **Observed Telemetry & Indicators:**
  - Contributing Signal 1: `[IDENTITY-MISMATCH] FROM_REPLYTO_MISMATCH: Reply-To domain 'secure-resolve-tickets.net' does not match From domain 'chase.com'.`
  - Contributing Signal 2: `[IDENTITY-MISMATCH] FROM_RETURN_PATH_MISMATCH: Observed Return-Path domain 'secure-resolve-tickets.net' does not match From domain 'chase.com'.`
  - Extracted URL: `hxxp[://]secure-resolve-tickets[.]net/chase/auth` (severity: `SAFE` under local pattern heuristics; visible text: `resolve online`)
  - Attachments: `0`
* **Score Derivation:**
  - Base Severity Tier: `RiskTier.SUSPICIOUS` base = `55.0`
  - Contributing Signals Increment: 2 signals × `2.0` = `+4.0`
  - Computed Risk Score: `55.0 + 4.0 = 59.0`
* **Expected vs. Observed Outcome:**
  - Expected Verdict: `SUSPICIOUS` (Risk Score: `59.0`)
  - Observed Verdict: `SUSPICIOUS` (Risk Score: `59.0`)
  - Concordance: **MATCH (PASS)**
* **Caveats & Limitations:**
  - The extracted link (`secure-resolve-tickets.net`) was graded `SAFE` by the offline URL analyzer because it did not trigger suspicious TLD or IP heuristics. This illustrates that local heuristics alone cannot establish domain reputation.
  - In direct EML upload mode without live MTA envelope telemetry, SPF is classified as `NOT_EVALUATED` and DKIM as `NONE` (no signatures present in fixture), leading to an `INDETERMINATE` DMARC safety status.

---

### Test 4: Malformed or Duplicated Headers (RFC 5322 Integrity)

* **Fixture:** `backend/tests/fixtures/real_world_emails/edge_cases/09_invalid_sender_address.eml`
* **Objective:** Verify parser resilience and threat scoring when encountering structural header corruption, specifically an invalid sender mailbox syntax violating RFC 5322.
* **Scan Identifiers:** Scan ID `#12`, UUID `442d943b-7f59-408a-a547-efd96cab9501`
* **Subject:** `Malformed Sender Address Header Test`
* **From Header:** `From: <<<Invalid Sender Box Without Domain>>>`
* **To:** `target@domain.com`
* **Observed Telemetry & Indicators:**
  - Extracted Sender Address: Sanitized to safe empty string `""` (address) / `""` (domain) without crashing the pipeline.
  - Contributing Threat Signal: `[IDENTITY-HEADER-INTEGRITY] MALFORMED_SENDER_ADDRESS: Sender address '<>' does not conform to RFC 5322 mailbox syntax.`
  - Extracted URLs: `0`
  - Attachments: `0`
  - Parsing Warnings: `[]` (handled gracefully by header normalization)
* **Score Derivation:**
  - Base Severity Tier: `RiskTier.SUSPICIOUS` base = `55.0`
  - Contributing Signal Increment: 1 signal × `2.0` = `+2.0`
  - Computed Risk Score: `55.0 + 2.0 = 57.0`
* **Expected vs. Observed Outcome:**
  - Expected Verdict: `SUSPICIOUS` (Risk Score: `57.0`)
  - Observed Verdict: `SUSPICIOUS` (Risk Score: `57.0`)
  - Concordance: **MATCH (PASS)**
* **Caveats & Limitations:**
  - The test verifies that structural RFC syntax violations trigger actionable risk without throwing unhandled exceptions.

---

### Test 5: Disguised Executable Attachment (Double Extension & Magic Bytes)

* **Fixture:** `backend/tests/fixtures/real_world_emails/suspicious/16_suspicious_attachment_filename.eml`
* **Objective:** Evaluate static attachment forensics when inspecting a disguised executable payload utilizing a deceptive double extension (`.xlsx.exe`) and leading DOS/MZ header bytes.
* **Scan Identifiers:** Scan ID `#13`, UUID `ed2a0066-1e74-47f7-ac91-5a6613ea4ab5`
* **Subject:** `Updated Employee Benefit Schedule`
* **From:** `Payroll Department <payroll@internal-services.com>`
* **To:** `accounting@company.com`
* **Observed Telemetry & Indicators:**
  - Attachment Filename: `Q4_Salary_Adjustments.xlsx.exe`
  - Declared MIME Type: `application/octet-stream`
  - Detected Format: `DOS/MZ Binary` (leading header: `b"MZ"`)
  - Detected MIME: `application/x-dosexec`
  - Double Extension: `is_double_extension: true` (apparent `xlsx` masked as `exe`)
  - Payload Size: `15` bytes
  - Cryptographic Hash (SHA-256): `0d05caaf4a3df5d5219d62088048b28572a060c082789d494cd16c89e3d85887`
  - Attachment Severity: `MALICIOUS`
  - Contributing Signal: `[ATTACHMENT-MALICIOUS] Q4_Salary_Adjustments.xlsx.exe: Suspicious double extension: apparent 'xlsx' masked as 'exe'; High-risk executable file extension '.exe' detected; Executable binary header identified: DOS/MZ Binary`
  - Parsing Warning: `["Suspicious double extension detected in attachment 'Q4_Salary_Adjustments.xlsx.exe' (apparent 'xlsx' masked as 'exe')"]`
* **Score Derivation:**
  - Base Severity Tier: `RiskTier.MALICIOUS` base = `85.0`
  - Contributing Signal Increment: 1 signal × `2.0` = `+2.0`
  - Computed Risk Score: `85.0 + 2.0 = 87.0`
* **Expected vs. Observed Outcome:**
  - Expected Verdict: `MALICIOUS` (Risk Score: `87.0`)
  - Observed Verdict: `MALICIOUS` (Risk Score: `87.0`)
  - Concordance: **MATCH (PASS)**
* **Caveats & Limitations:**
  - *Synthetic Payload Caveat:* The payload is 15 bytes long, consisting of truncated MZ header bytes. It is **not** a working PE executable or functional malware.
  - *Static Inspection Boundary:* The analysis was conducted purely in-memory using pure-Python header byte comparisons. No dynamic sandbox detonation or external cloud antivirus scanning was performed.

---

## 4. Summary of Verification Findings

1. **Deterministic Scoring:** Across all five distinct categories (Clean, Phishing, Identity Mismatch, Structural RFC Defect, and Disguised Executable), the observed verdicts and numerical risk scores matched the expected values with 100% concordance.
2. **Failure Isolation:** Parser and identity components handled missing or corrupted fields (such as malformed mailbox syntax) safely without pipeline crashes.
3. **Execution Safety:** All attachments and URLs were evaluated strictly in-memory and via defanged representations without dynamic execution, network resolution, or external data leakage.
