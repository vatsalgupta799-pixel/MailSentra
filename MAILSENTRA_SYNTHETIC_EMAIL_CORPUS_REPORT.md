# MailSentra — Synthetic Email Threat Validation Corpus Report
## Milestone: Synthetic Email Threat Validation (75 Test Cases)

**Date**: November 27, 2026  
**Status**: COMPLETE WITH DOCUMENTED DETECTION GAPS  
**Total Fixtures**: Exactly 75 `.eml` files  
**Corpus Test Suite**: `backend/tests/test_email_corpus.py` (82 tests passed)  
**Full Backend Regression**: 630 / 630 tests passed  

---

## 1. Executive Summary

As part of the MailSentra detection evaluation program, a comprehensive synthetic email threat validation corpus comprising **exactly 75 realistic `.eml` fixtures** across six threat and control categories was designed, generated, and integrated into the automated test suite.

The purpose of this corpus is an **honest, empirical baseline evaluation** of MailSentra's current detection capabilities across implemented modules (Module 3/4 Sender Identity & Authentication Protocols, Module 5 Static URL Security Analysis) and an objective characterization of detection gaps corresponding to upcoming modules (Module 6 Attachment Forensics, Module 7/8 Semantic & Business Email Compromise Analysis).

### Ground Rules Compliance
- **Zero Production Modifications**: No production detection logic in `backend/app/` was altered during corpus creation.
- **Strictly Harmless Payloads**: Zero real malware, live exploit shellcodes, or active attack scripts were included; all simulated malicious attachments contain inert ASCII/header placeholders (`MZ\x90...`, dummy PK headers, text markers).
- **Safe Network Artifacts**: All simulated malicious domains and links use standard reserved/safe domains (`.invalid`, `.example.com`, RFC 2606 / RFC 6761).
- **Honest Metrics**: Clear distinction between **MIME/Header Parsing Success**, **Feature/Indicator Extraction**, and **Active Threat Detection**. Unbuilt capabilities are explicitly reported as detection gaps rather than artificially passed tests.

---

## 2. Corpus Taxonomy & Distribution

The corpus resides under `backend/tests/fixtures/email_corpus/` organized into six functional subdirectories:

| Category | Folder | Count | Description & Attack Vectors |
| :--- | :--- | :---: | :--- |
| **Category A: Phishing** | `phishing/` | 20 | Credential harvesting, university account reset, Microsoft 365, Google security alerts, banking suspensions, shipping delivery, tax refunds, HR/payroll portals, document signing, multi-stage lure. |
| **Category B: Malware Delivery** | `malware_delivery/` | 15 | Inert malicious attachment formats: `.exe`, `.zip`, double extension (`.pdf.exe`), macro-enabled `.docm`, `.js`, `.ps1`, `.html` smuggling, `.iso`, `.img`, `.lnk` shortcut, `.tar.gz`, `.vbs`, `.scr`, `.bat`, `.rtf` exploit lure. |
| **Category C: Spoofing & Auth** | `spoofing_authentication/` | 10 | Display name spoofing, cousin domain lookalikes, envelope vs. header `From` mismatch, `Reply-To` redirection, missing/invalid DKIM signatures, SPF softfail/fail, DMARC alignment failure, duplicate headers. |
| **Category D: BEC** | `business_email_compromise/` | 10 | CEO gift card requests, urgent vendor wire transfer redirection, executive payroll direct deposit changes, urgent legal settlement wire, confidential acquisition NDA lure, supplier bank detail update. |
| **Category E: Advanced / Adversarial** | `advanced_adversarial/` | 10 | Zero-width whitespace evasion, Cyrillic/homoglyph mixed script URLs, base64 `data:` URI phishing, anchor tag text vs. target mismatch, scheme obfuscation (`hxxp`, `@` userinfo), excessive subdomain chaining, punycode spoofing. |
| **Category F: Legitimate Controls** | `legitimate/` | 10 | Benign negative controls: normal text emails, team meeting invites, clean corporate newsletters, system maintenance notifications, benign PDF attachments, genuine Google Drive sharing, order receipts. |
| **Total** | | **75** | **100% Compliant Fixture Distribution** |

---

## 3. Fixture Inventory & Manifest Structure

The corpus is accompanied by a machine-readable manifest at `backend/tests/fixtures/email_corpus/manifest.json`.

Each entry conforms to the schema:
```json
{
  "test_id": "CORPUS-PHISH-01",
  "filename": "phishing/phish_01.eml",
  "category": "phishing",
  "expected_verdict": "SUSPICIOUS",
  "expected_severity": "SUSPICIOUS",
  "expected_indicators": ["IP_HOSTED_URL", "CREDENTIAL_HARVESTING"],
  "expected_sender_anomalies": [],
  "expected_url_findings": ["IP_BASED_URL"],
  "attachment_metadata": [],
  "rationale": "University credentials verification alert pointing to bare raw IPv4 address."
}
```

### MIME & Structure Coverage:
- **`text/plain`**: Simple text-only lures, plain-text BEC requests, administrative notifications.
- **`multipart/alternative`**: Rich HTML emails paired with plain-text fallback representations (essential for inspecting anchor text mismatches and hidden zero-width evasion).
- **`multipart/mixed`**: Multi-part email containers carrying base64-encoded attachment payloads across 15 file types.

---

## 4. Detection Evaluation & Baseline Results

MailSentra's parsing engine (`EmailParser`), sender anomaly detector (`SenderAnomalyDetector`), and static URL security engine (`UrlAnalyzer`) were executed against all 75 fixtures in `backend/tests/test_email_corpus.py`.

### 4.1 Evaluation Summary Matrix

| Category | Total Fixtures | Parsing Success | Indicator Extraction | Target Module | Current Detection Status |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Category A: Phishing** | 20 | 20/20 (100%) | 20/20 (100%) | Module 5 (URLs) | **100% DETECTED** (All 20 flagged by URL analyzer findings: IP URLs, punycode, open redirects, typosquats, userinfo, suspicious TLDs, hex/octal encodings). |
| **Category B: Malware Delivery** | 15 | 15/15 (100%) | 15/15 (100%) | Module 6 (Attachments) | **PARSED & EXTRACTED** (Attachments extracted into `EmailAttachment`; detection flagged as gap pending Module 6 attachment scanning). |
| **Category C: Spoofing & Auth** | 10 | 10/10 (100%) | 10/10 (100%) | Module 3 & 4 (Sender/Auth) | **100% DETECTED** (All 10 flagged by `SenderAnomalyDetector` / Auth Analyzer: display name spoofing, cousin domains, Return-Path mismatch, Reply-To redirect). |
| **Category D: BEC** | 10 | 10/10 (100%) | 10/10 (100%) | Module 7 & 8 (Semantic/BEC) | **PARSED & EXTRACTED** (Headers, display names, and text extracted; financial/semantic intent flagged as gap pending Module 7/8 NLP heuristics). |
| **Category E: Advanced Adversarial** | 10 | 10/10 (100%) | 10/10 (100%) | Module 5 (URLs) | **100% DETECTED** (All 10 flagged by static URL analyzer: homoglyphs, zero-width spaces, anchor mismatches, `data:` URIs, excessive subdomains). |
| **Category F: Legitimate Controls** | 10 | 10/10 (100%) | 10/10 (100%) | System Baseline | **0% FALSE POSITIVE** (All 10 classified cleanly with 0 URL findings and 0 sender anomalies). |

### 4.2 Honesty Assessment & Documented Detection Gaps

In accordance with strict honest evaluation principles:
1. **Module 6 (Attachment Forensics Gap)**:
   - *Observation*: MailSentra's `EmailParser` successfully extracts attachment filenames, MIME types, raw payloads, and computes MD5/SHA256 hashes into `EmailAttachment`.
   - *Gap*: Because Module 6 (Attachment Analysis) is not yet implemented, MailSentra does not yet execute static file extension blocking (e.g., blocking `.exe`, `.scr`, `.bat`), VBA macro extraction (`.docm`), archive recursion (`.zip`, `.iso`), or hash reputation lookups.
   - *Action*: These 15 fixtures establish the exact validation benchmark for Module 6.

2. **Module 7 & 8 (Natural Language Processing & BEC Gap)**:
   - *Observation*: Clean BEC emails containing pure text (e.g., CEO asking for gift cards or CFO requesting wire account change without links or spoofed headers) pass email parsing and sender syntax checks cleanly.
   - *Gap*: Semantic intent classification, urgent financial pressure detection, and VIP impersonation heuristics require Module 7 (NLP Analysis) and Module 8 (BEC Heuristic Engine).
   - *Action*: These 10 fixtures establish the exact evaluation benchmark for Modules 7 and 8.

3. **Modules 4 & 5 (Sender Security & URL Engine Strengths)**:
   - 100% of tested phishing and adversarial URLs are flagged with appropriate risk findings (`CRITICAL`, `SUSPICIOUS`, `INFORMATIONAL`).
   - 100% of header spoofing and domain impersonation attacks are detected.
   - Zero legitimate negative controls were misclassified (0% False Positive rate).

---

## 5. Test Suite Integration & Verification

A dedicated test suite was authored in `backend/tests/test_email_corpus.py`:
- `test_corpus_manifest_integrity`: Verifies manifest consistency, schema adherence, and that all 75 fixtures exist on disk.
- `test_fixture_parsing_and_subsystem_execution`: Parameterized across all 75 fixtures, ensuring each fixture parses cleanly through `EmailParser`, runs through `SenderAnomalyDetector`, and executes `UrlAnalyzer`.
- `test_phishing_category_detection`: Verifies active threat detection on all 20 phishing fixtures.
- `test_malware_category_extraction`: Verifies attachment extraction and metadata indexing on all 15 malware delivery fixtures.
- `test_spoofing_category_detection`: Verifies sender anomaly detection on all 10 spoofing fixtures.
- `test_bec_category_extraction`: Verifies extraction of plain text and header fields on all 10 BEC fixtures.
- `test_advanced_adversarial_detection`: Verifies evasion detection on all 10 adversarial fixtures.
- `test_legitimate_controls_zero_false_positives`: Verifies zero false positives across all 10 negative control fixtures.

### Test Run Telemetry
```
backend/tests/test_email_corpus.py .................................................................................. [100%]
82 passed in 1.47s
```

### Full Regression Suite
```
pytest backend/tests/ -q
630 passed in 12.69s
```
- Previous baseline: 548 passing tests.
- New corpus tests: 82 passing tests.
- Total passing tests: **630 passing tests (100% pass rate, 0 failures, 0 regressions)**.

---

## 6. Milestone Conclusion & Deliverables

| Deliverable | Location | Status |
| :--- | :--- | :---: |
| 75 Synthetic `.eml` Fixtures | `backend/tests/fixtures/email_corpus/` | **Complete (75/75)** |
| Corpus Manifest JSON | `backend/tests/fixtures/email_corpus/manifest.json` | **Complete** |
| Automated Corpus Test Suite | `backend/tests/test_email_corpus.py` | **Complete (82/82 passed)** |
| Full Regression Suite | `backend/tests/` | **Complete (630/630 passed)** |
| Milestone Report | `MAILSENTRA_SYNTHETIC_EMAIL_CORPUS_REPORT.md` | **Complete** |

**Final Milestone Verdict**: **COMPLETE WITH DOCUMENTED DETECTION GAPS**  
The synthetic threat validation corpus is fully operational, safely constructed, completely integrated into CI/testing, and ready to guide the implementation of Module 6 (Attachment Analysis) and Module 7/8 (BEC & Semantic Analysis).
