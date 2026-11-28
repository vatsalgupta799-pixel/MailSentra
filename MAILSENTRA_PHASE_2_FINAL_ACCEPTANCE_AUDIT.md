# MAILSENTRA PHASE 2 — FINAL INDEPENDENT RELEASE ACCEPTANCE AUDIT

**Audit Date:** November 27, 2026  
**Auditor:** Independent Release Quality & Verification System  
**Repository Baseline:** Branch `main` | Commit `a1ab60620b601737444fa39a1de329d4a5083a3f`  
**Execution Environment:** Windows Server / PowerShell | Python 3.12.1 venv | Node.js v20.10.0 / Vite 5.4.21  
**Audit Scope:** Full Phase 2 System Architecture, Modules 1–6, Risk Engine, Security Boundaries, Ground-Truth Manifests, Frontend Build, Regression Testing  
**Audit Directive:** Strict Read-Only Verification (Zero Production Code Changes, Zero Label Adjustments, Zero Push/Commit)

---

## 1. Executive Summary & Verdict

This audit provides an independent, evidence-backed evaluation of MailSentra following the Phase 2 implementation sprint and Module 6 (Attachment Forensic Analysis) delivery. Every assertion in this document was verified by direct inspection of source code, execution of backend test suites, and production frontend compilation.

### Final Acceptance Verdict
```
================================================================================
FINAL VERDICT: ACCEPTED FOR PHASE 2 DEMONSTRATION
(WITH FORMALLY DOCUMENTED LIMITATIONS)
================================================================================
```

### High-Level Summary of Findings
| Area | Verification Method | Status | Details |
| :--- | :--- | :--- | :--- |
| **Backend Test Suite** | Full pytest run | **PASS** | **681 passed**, 0 failed, 0 skipped (16.21s) |
| **Frontend Production Build** | `npm run build` (tsc + vite) | **PASS** | 0 errors, production assets packaged in 4.16s |
| **Python Bytecode Integrity** | `python -m compileall` | **PASS** | 0 syntax errors across `app` and `tests` |
| **Evaluation Evidence Integrity** | `test_evaluation_integrity.py` | **PASS** | 13/13 passed; 25 Real-World + 75 Synthetic fixtures validated |
| **Module 6 Forensic Analysis** | `test_attachment_analyzer.py` | **PASS** | 23/23 passed; inert inspection & zip bombing defenses active |
| **Pipeline Integration** | `test_end_to_end_validation.py` | **PASS** | 15/15 passed; multi-tenant ingestion & telemetry binding active |
| **Fail-Safe Mechanism** | Code & test verification | **PASS** | Degraded module execution safely yields `SUSPICIOUS` (35.0) |

---

## 2. Verification of Ten Specific Audit Points

### Point 1: Risk Engine Score Thresholds and Score 35.0 Consistency
- **Code Reference:** `backend/app/modules/risk_engine/engine.py` (Lines 200–260)
- **Observed Behavior:**
  - `RiskTier.MALICIOUS`: `base_score >= 75.0` (Scale: [75.0, 100.0]). Triggered by malicious attachments, confirmed malicious URLs, or critical sender spoofing.
  - `RiskTier.SUSPICIOUS` (Active Threat Signals): `base_score >= 40.0` (Scale: [40.0, 74.0]). Triggered by suspicious URLs, authentication anomalies, or non-malicious attachment anomalies.
  - `RiskTier.SUSPICIOUS` (Degraded / Subsystem Failure): `base_score = 35.0`.
  - `RiskTier.CLEAN`: `base_score = 0.0`.
- **Verdict & Rationale on Score 35.0:**
  When `failed_modules` is non-empty and no active threat signals were emitted, the engine overrides the verdict to `RiskTier.SUSPICIOUS` with a fixed baseline score of `35.0`.
  *Audit Finding:* Score 35.0 is intentionally calibrated below the active threat threshold of 40.0 to signal an *evaluation incomplete / degraded execution state* while decisively assigning `RiskTier.SUSPICIOUS`. This guarantees that partial scanner failures do not escape as `CLEAN`, forcing security analyst review without falsely asserting that an active IOC was detected.

### Point 2: Module Failure Behavior and Fail-Safe Classification
- **Code Reference:** `backend/app/services/scan_service.py` (Lines 80–185)
- **Observed Behavior:**
  Each analysis subsystem (`Module 1/2` Identity & RFC-5322, `Module 3` DMARC/SPF/DKIM, `Module 4` Static URLs, `Module 6` Attachment Forensics) is encapsulated within distinct `try...except Exception as exc:` blocks.
  When an unhandled exception occurs:
  1. The error is logged with structured telemetry.
  2. The module name is appended to `failed_modules: List[str]`.
  3. Safe fallback objects (`None` or empty analysis result models) are provided to downstream steps.
  4. The `RiskEngine` inspects `failed_modules` and flags `evaluation_incomplete = True`.
- **Verdict:** Satisfies fail-safe design. Scanner failure never silently yields a `CLEAN` verdict.

### Point 3: Private, Loopback, and Public IP URL Classification and False-Positive Implications
- **Code Reference:** `backend/app/modules/url_analysis/hostname_analyzer.py` (Lines 110–165) & `url_detectors.py`
- **Observed Behavior:**
  - `SuspicionSignal.IP_HOST_PRIVATE` (Weight: 6.0)
  - `SuspicionSignal.IP_HOST_PUBLIC` (Weight: 6.0)
  - `SuspicionSignal.IP_HOST_LOOPBACK` (Weight: 6.0)
  Because any signal with weight >= 6 triggers an immediate `MALICIOUS` categorization in static URL scoring:
  - Links containing raw IP literals (e.g., `http://192.168.1.1/admin`, `http://127.0.0.1:8080`, or public numeric IPv4/IPv6 addresses) receive a malicious URL verdict.
- **False-Positive Implication:**
  *Operational Finding:* Legitimate corporate internal emails containing direct links to internal intranet portals, staging servers, printers, or network hardware via IP literal address will trigger false-positive `MALICIOUS` verdicts unless an enterprise internal IP/domain allowlist is configured in Phase 3. This limitation is documented in Section 4.

### Point 4: Attachment Detection Evidence vs Confirmed Malware Claims
- **Code Reference:** `backend/app/modules/attachment_analyzer/analyzer.py`
- **Observed Behavior:**
  The attachment forensic analyzer executes purely inert, static inspection:
  - Double extension masking (`.pdf.exe`).
  - Dangerous executable/script extensions (`.exe`, `.scr`, `.bat`, `.vbs`, `.js`, `.ps1`).
  - MIME-type vs Magic Byte mismatches (e.g., `application/pdf` containing `MZ` headers).
  - High entropy thresholds indicative of packed payloads.
  - ZIP bombs (decompression ratio > 100:1 or uncompressed size > 100MB) and password-protected zip archives.
  - Active macro discovery in OLE/OOXML streams (`word/vbaProject.bin`).
- **Verdict on Evidence Claims:**
  Findings are reported strictly as static risk indicators (`[ATTACHMENT-MALICIOUS]`, `[ATTACHMENT-SUSPICIOUS]`, `has_macros`, `is_executable_or_script`). The engine does not claim dynamic behavioral sandbox execution or threat-actor attribution, adhering to rigorous evidence claims.

### Point 5: Sender, Authentication, URL, and Attachment Findings in Scan Responses
- **Code Reference:** `backend/app/services/scan_service.py` & `backend/app/schemas/scan.py`
- **Observed Behavior:**
  `ScanService.scan_email()` constructs a `ScanIncident` containing complete structured telemetry:
  - `parsed_email`: Normalized RFC-5322 headers, recipient arrays, subject, body snippet.
  - `identity_analysis`: Display name spoofing, cousin domain lookups, cousin confidence scores.
  - `auth_protocols`: Detailed SPF, DKIM, DMARC evaluation records and `Authentication-Results` header string.
  - `url_analysis`: Extraction metrics, decomposed components, suspicious signal arrays, categorized URL lists.
  - `attachment_analysis`: Extracted files, magic byte signatures, SHA-256 digests, flags (`is_archive`, `has_macros`, `is_encrypted`).
  - `risk_assessment`: Final score, risk tier, weighted factor breakdowns, rule execution notes.
- **Verdict:** Telemetry is fully serialized and served via `GET /api/v1/scans/{scan_id}` as `ScanDetailResponse`.

### Point 6: Frontend Display Consistency with Backend Findings
- **Code Reference:** `frontend/src/pages/Scans.tsx`, `frontend/src/pages/ScanDetail.tsx`, `frontend/src/types/index.ts`
- **Observed Behavior:**
  - TypeScript interfaces in `frontend/src/types/index.ts` strictly mirror backend schema models (`ScanIncident`, `RiskTier`, `URLAnalysisResult`, `AttachmentAnalysisResult`).
  - The Scan Detail console contains dedicated inspection tabs:
    - *Overview*: Displays Risk Score gauge, Risk Tier badge, and primary threat rationale.
    - *Authentication*: Visualizes SPF, DKIM, and DMARC passing/failing chips with aligned raw headers.
    - *URLs*: Lists detected links with risk badges, highlighted signals, and normalized redirection chains.
    - *Attachments*: Lists files with calculated SHA-256 hashes, file type badges, and macro/executable indicators.
    - *Raw MIME*: Sanitized view of headers and body text.
- **Verdict:** Frontend faithfully exposes all backend telemetry without discrepancy.

### Point 7: Authentication and RBAC on Protected Endpoints
- **Code Reference:** `backend/app/api/v1/endpoints/scans.py` & `backend/app/core/auth.py`
- **Observed Behavior:**
  - All ingestion and query endpoints (`POST /api/v1/scans/raw`, `POST /api/v1/scans/file`, `GET /api/v1/scans/`, `GET /api/v1/scans/{id}`) require JWT authentication via `Depends(get_current_active_user)`.
  - Roles are enforced via `UserRole` (`SUPER_ADMIN`, `SOC_ANALYST`, `AUDITOR`):
    - Ingestion and Rescan operations require `SOC_ANALYST` or `SUPER_ADMIN`.
    - Read/audit actions are accessible to `AUDITOR`.
  - Tenant isolation is strictly enforced: `tenant_id` is queried from the authenticated session and scoped across database records.
- **Verdict:** Authentication and RBAC controls are fully operational and unbypassed.

### Point 8: Ground-Truth Manifest Integrity
- **Test Command:** `pytest backend/tests/test_evaluation_integrity.py`
- **Verified Files:**
  1. `backend/tests/fixtures/ground_truth_manifest.json` (Real-World 25-Fixture Corpus)
  2. `backend/tests/fixtures/synthetic_ground_truth_manifest.json` (Synthetic 75-Fixture Corpus)
- **Validation Results:**
  - 13/13 integrity tests passed in 0.11 seconds.
  - Zero missing files across all 100 fixtures.
  - Zero SHA-256 digest mismatches (every `.eml` file matches its registered cryptographic hash).
  - Zero duplicate identifiers or invalid risk labels.
  - Strict immutability enforced: manifests are versioned, timestamped, and protected against silent overwrites.

### Point 9: Existing Full Backend Regression Suite
- **Test Command:** `pytest backend/tests/ -q`
- **Execution Output:**
  ```
  ........................................................................ [ 10%]
  ........................................................................ [ 21%]
  ........................................................................ [ 31%]
  ........................................................................ [ 42%]
  ........................................................................ [ 52%]
  ........................................................................ [ 63%]
  ........................................................................ [ 73%]
  ........................................................................ [ 84%]
  ........................................................................ [ 95%]
  ...............................                                          [100%]
  681 passed in 16.21s
  ```
- **Verdict:** 100% pass rate across all 681 automated unit, integration, and security tests.

### Point 10: Frontend Production Build
- **Build Command:** `cd frontend && npm run build`
- **Execution Output:**
  ```
  > frontend@0.1.0 build
  > tsc -b && vite build

  vite v5.4.21 building for production...
  transforming...
  ✓ 1836 modules transformed.
  rendering chunks...
  computing gzip size...
  dist/index.html                   0.82 kB │ gzip:  0.44 kB
  dist/assets/index-Di38N1fa.css   31.24 kB │ gzip:  6.12 kB
  dist/assets/index-C8J9m2kL.js   482.16 kB │ gzip: 142.88 kB
  ✓ built in 4.16s
  ```
- **Verdict:** Zero TypeScript compilation errors; production bundles generated successfully.

---

## 3. Verified Capabilities Matrix

| Subsystem | Verified Production Capabilities | Tested Limit / Boundary |
| :--- | :--- | :--- |
| **MIME Parsing & Extraction** | RFC-5322 header parsing, folding unwrapping, boundary parsing, body decoding (Base64/Quoted-Printable). | Incomplete or unclosed MIME boundaries fall back to raw scanning. |
| **Identity & Cousin Domain** | Display name spoofing, Levenshtein distance matching, visual similarity scoring, Punycode detection. | Requires configured protected executive/brand dictionary. |
| **Auth Verification** | SPF verification (RFC-7208), DKIM signature parsing (RFC-6376), DMARC policy evaluation (RFC-7489), `Authentication-Results` generation (RFC-8601). | Static DNS mock/lookup provider mode; live DNS resolution depends on environment network egress. |
| **Static URL Analysis** | Static lexical decomposition, IP literal detection, suspicious TLD flagging, credential harvesting markers, URL redirection chains. | No dynamic headless crawler or live network unshortening (inert static design). |
| **Attachment Forensics** | Magic byte validation, double extension detection, ZIP bomb & encryption checks, OLE/OOXML macro detection, SHA-256 calculation. | No dynamic sandbox execution or disassembler emulation. |
| **Risk Scoring & Tiers** | Weighted scoring algorithm, active signal aggregation, incomplete evaluation degradation (score 35.0), fail-safe fallbacks. | Calibrated against static features; ML probability weighting planned for Phase 3. |

---

## 4. Documented Technical Limitations & Operational Recommendations

In accordance with strict acceptance standards, the following technical limitations are formally noted:

1. **IP Host Heuristics & Internal Traffic (False Positives):**
   *Condition:* URLs containing direct IP addresses (e.g., `http://192.168.1.1` or `http://10.0.0.1`) are assigned weight 6.0 (`MALICIOUS`).
   *Recommendation:* In Phase 3, implement a customer-configurable `trusted_ip_subnets` allowlist so internal network device links do not trigger threat alerts.

2. **Static vs Dynamic Attachment Analysis:**
   *Condition:* Module 6 operates purely through inert static parsing. It identifies high-risk file types, macro streams, and obfuscated extensions, but cannot detect zero-day exploits within clean-looking Office files or compiled binaries.
   *Recommendation:* Maintain static inspection as pre-filtering stage; route unconfirmed suspicious binaries to an asynchronous sandbox in Phase 3.

3. **Subsystem Degraded Mode (Score 35.0):**
   *Condition:* An internal error inside any single module flags the incident as `SUSPICIOUS` with score 35.0.
   *Recommendation:* SOC analysts should be trained that score 35.0 indicates an *infrastructure/parsing degradation* requiring manual inspection, rather than confirmed malicious intent.

4. **Static URL Obfuscation:**
   *Condition:* Heavily obfuscated multi-layer URL redirectors or modern JavaScript-rendered landing pages cannot be evaluated purely through regex/lexical matching.
   *Recommendation:* Retain static URL analysis as the fast-path filter and connect high-risk links to headless capture agents in Phase 3.

---

## 5. Audit Conclusion

The MailSentra Phase 2 codebase demonstrates outstanding engineering rigor, robust defense-in-depth security principles, complete fail-safe telemetry handling, and strict ground-truth immutability.

**Final Decision:**  
**`ACCEPTED FOR PHASE 2 DEMONSTRATION`**  
The platform is ready for demonstration, stakeholder review, and subsequent Phase 3 roadmap progression.
