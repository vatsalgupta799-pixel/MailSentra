# MailSentra — Next Milestone Discovery Report

**Date:** November 27, 2026  
**Auditor/Engineer:** Senior Email Security Architect & Backend Engineer  
**Baseline Git Commit:** `a1ab60620b601737444fa39a1de329d4a5083a3f` (origin/main)  
**Inspection Mode:** Strictly READ-ONLY (No source modifications, no commits/pushes, no state alteration)  
**Authoritative Sources:** `DEVELOPMENT_ROADMAP.md`, `ARCHITECTURE.md`, `STEP_3_7_3A_ARCHITECTURE_INSPECTION.md`, `STEP_3_7_2D_FINAL_COMPLIANCE_AUDIT.md`, `contracts.py`, and actual repository code.

---

## 1. Executive Summary

Following the completion and independent security verification of **Step 3.7.3C** (incorporating Stage 1 Contracts & Serializer, Stage 2 `AuthProtocolsAnalyzer` Orchestrator, and Stage 3 `ScanService` Delivery Integration with 443/443 backend tests passing), this discovery audit inspects the engineering roadmap, architecture specifications, and codebase to establish the exact next milestone sequence.

The audit identifies two distinct horizons:
1. **Immediate Operational Closure (Step 3.7.4):** Subsystem Operationalization & Application Lifespan Wiring (closing the minor operational items originally specified in Section 9 of `STEP_3_7_3A_ARCHITECTURE_INSPECTION.md`: FastAPI lifespan two-phase shutdown in `backend/main.py` and application-level environment settings in `backend/app/core/config.py`).
2. **Next Major Threat Module (Phase 3 / Step 4.1):** **Module 5 — URL Security Analysis Module (`backend/app/modules/url_analysis`)**, as formally sequenced in `DEVELOPMENT_ROADMAP.md` and `ARCHITECTURE.md`.

---

## 2. DMARC 3.7.x Status Matrix: Completed, Partially Completed, and Pending

| Milestone / Sub-Step | Component Description | Current Status | Implemented Artifacts & Tests |
| :--- | :--- | :---: | :--- |
| **Step 3.7.1** | DMARC Record Discovery & Alignment Check | **COMPLETED** | `evaluators/dmarc.py`, `test_dmarc_discovery.py` |
| **Step 3.7.2 (A–D)** | Tree-walk, PSD, Subdomain (`sp=`, `np=`), Tag Metadata Parsing | **COMPLETED** | `evaluators/dmarc.py`, `test_dmarc_evaluator.py` |
| **Step 3.7.3A** | Architecture Review Corrections & 6-Stage Decision Pipeline Gate | **COMPLETED** | `STEP_3_7_3A_ARCHITECTURE_INSPECTION.md` |
| **Step 3.7.3B** | Published-Policy Interpretation & Pure Policy Enforcer (`DMARCPolicyEnforcer`), plus Remediations (H1–H3, M1–M5) & Final Hardening (L3, H2, H3, M1, L1, L2) | **COMPLETED** | `policy_enforcer.py`, `test_dmarc_policy_enforcement.py` |
| **Step 3.7.3C Stage 1** | Contracts, `AuthResultsGenerator`, `AuthResultsTrustEvaluator`, and `local_authserv_id` | **COMPLETED** | `evaluators/auth_results.py`, `test_auth_results.py` (23 tests) |
| **Step 3.7.3C Stage 2** | `AuthProtocolsAnalyzer` Orchestrator (concurrent SPF, DKIM, DMARC, Policy Enforcement) | **COMPLETED** | `analyzer.py`, `test_auth_analyzer.py` (7 tests) |
| **Step 3.7.3C Stage 3** | `ScanService` Delivery Integration & Telemetry Injection (`ScanIncident.telemetry["auth_protocols"]`) | **COMPLETED** | `scan_service.py`, `test_auth_pipeline.py` (4 tests) |
| **Step 3.7.4** | Application Lifespan Wiring & Root Environment Configuration | **PARTIALLY COMPLETED** *(Code operational in ScanService, but FastAPI lifespan shutdown and core `.env` settings remain unwired)* | `backend/main.py`, `backend/app/core/config.py` |
| **Step 3.7.5** | DMARC Feedback Reporting (Aggregate RUA XML & Forensic RUF Reports per RFC 7489 / RFC 9990) | **PENDING** *(Deferred per Step 3.7.2D audit)* | None |
| **Step 3.7.6** | Authenticated Received Chain (ARC, RFC 8617) Chain Validation | **PENDING** *(Deferred per Step 3.7.2D audit)* | None |
| **Step 3.7.7** | Dynamic Policy Override Database Persistence & Admin REST APIs (`/api/v1/policies`) | **PENDING** *(Deferred per Step 3.7.3A §3.5)* | Schema & routers pending |

---

## 3. Dependencies & Existing Implementations (Do Not Duplicate)

The following components are fully implemented, verified, and operational; any future work must consume them directly without duplication:
1. **`AuthProtocolsAnalyzer` (`backend/app/modules/auth_protocols/analyzer.py`):**
   - Coordinates `SPFEvaluator`, `DKIMVerifier`, `DMARCEvaluator`, `DMARCPolicyEnforcer`, and `AuthResultsGenerator`.
   - Already instantiates bounded resources and implements `async def analyze()` and `async def shutdown()`.
2. **`ScanService.ingest_and_parse()` (`backend/app/services/scan_service.py`):**
   - Already instantiates `self.auth_analyzer` and executes Module 4 authentication analysis on line 107.
   - Injects output into `incident.telemetry["auth_protocols"]` and passes summary records to `AuditLogger` and database `AuditRecord`.
   - Guarantees byte immutability for `raw_payload.raw_bytes`.
3. **`AuthResultsGenerator` and `AuthResultsTrustEvaluator` (`backend/app/modules/auth_protocols/evaluators/auth_results.py`):**
   - Implements full RFC 8601, RFC 7601, RFC 6008, and RFC 5322 serialization, line folding, CRLF neutralization, and upstream trust gating.
4. **Data Contracts (`backend/app/modules/contracts.py`):**
   - Module 4 contracts (`AuthProtocolsResult`, `DKIMSignatureResult.signature_b_prefix`, `DMARCEnforcementDecision`, `LocalPolicyOverrideRule`) are complete.
   - Module 5 contracts (`UrlRiskSeverity`, `UrlFinding`, `UrlAnalysisResult`) are already defined and ready for consumption on lines 588–614.

---

## 4. Integrity of Step 3.7.3B and 3.7.3C Security Remediations

The audit confirms that all security remediations from Step 3.7.3B and Step 3.7.3C remain 100% active and covered by regression tests:
- **Finding L3 (Channel Isolation & Transport Authority):** Direct uploads strictly reject caller-supplied transport metadata; SPF remains `NOT_EVALUATED` on non-SMTP channels (`test_analyzer_direct_upload_ignores_untrusted_transport_meta`).
- **Finding H2 (Server-Rule HMAC Attestation):** `DMARCPolicyEnforcer` verifies 256-bit HMAC signatures and `SUPER_ADMIN` actor authorization; unattested rules fail with `UNAUTHENTICATED_OR_FORGED_RULE_PROVENANCE` (`test_h2_rule_provenance_actor_auth_and_tenant_isolation`).
- **Finding H3 (DNS Resolver Error Taxonomy):** `AsyncDNSResolver` safely handles OS/socket/timeout exceptions as `RESOLVER_ERROR`/`TIMEOUT`/`INTERNAL_ERROR` without silent failures (`test_dns_resolver.py`).
- **Finding M1 (Audit Persistence & Privacy):** Complete SHA-256 decision fingerprinting and PII local-part redaction in telemetry and audit logs (`test_redact_local_part`).
- **Finding L1 (PSD Candidate Selection):** DMARC tree-walk accurately isolates `psd=y` candidate domains from intermediate non-PSD nodes (`test_dmarc_discovery.py`).
- **Finding L2 (Typed DKIM State & Alignment Authority):** Verifier uses typed `DKIMEvaluationState` and overrides signature alignment when DNS tree-walk is authoritative (`test_dkim_verifier.py`).

**Empirical Verification:** The full backend suite executes with **443 passed** in 17.24s (0 failures, 0 skipped), and the authentication subsystem suite executes with **286 passed** in 3.12s.

---

## 5. Next Milestone Options and Recommendation

### Option 1: Step 3.7.4 — Subsystem Operationalization & Application Lifespan Wiring (Smallest Scope)
- **Objective:** Finalize operational integration of the completed Module 4 authentication subsystem at the FastAPI application level.
- **Scope:**
  1. **FastAPI Lifespan Integration (`backend/main.py`):** Register `AuthProtocolsAnalyzer` and `DKIMExecutor` shutdown hooks into FastAPI's `lifespan` manager to ensure clean worker thread termination and resolver cache disposal during server reload/shutdown.
  2. **Application Settings Wiring (`backend/app/core/config.py`):** Add `LOCAL_AUTHSERV_ID: Optional[str] = "mailsentra.local"` and `DMARC_POLICY_ENFORCEMENT_ENABLED: bool = True` to the global `Settings` class so administrators can configure them via environment variables.
- **Implementation Effort:** Minimal (~30 lines of code, 2 targeted test cases).

### Option 2: Phase 3 / Step 4.1 — Module 5: URL Security Analysis Module (`backend/app/modules/url_analysis`) (Next Major Feature)
- **Objective:** Implement Module 5 of the MailSentra detection pipeline, assessing threat posture for all URLs extracted by Module 2.
- **Scope:**
  1. Implement `UrlSecurityAnalyzer` in `backend/app/modules/url_analysis/analyzer.py` implementing `BaseDetectionModule`.
  2. Implement detection rules: URL canonicalization, defanging, IP-host detection, suspicious TLD matching, open redirect identification, and zero-width character inspection (strictly zero outbound network requests per security policy).
  3. Wire `UrlSecurityAnalyzer` into `ScanService.ingest_and_parse()` following Module 4.
  4. Unit test suite `backend/tests/test_url_analysis.py`.
- **Implementation Effort:** Moderate (~350 lines of code, ~15 test cases).

---

## 6. Authoritative Conclusion & Next Milestone Definition

### **Exact Next Milestone ID:**
**STEP 3.7.4 — Subsystem Operationalization & Application Lifespan Integration**

### **Objective:**
Operationalize the completed Module 4 authentication subsystem by connecting its resource lifecycle (`DKIMExecutor` and `AsyncDNSResolver`) to the FastAPI ASGI `lifespan` in `backend/main.py`, and exposing `LOCAL_AUTHSERV_ID` and DMARC operational settings in `backend/app/core/config.py`.

### **Dependencies:**
- Step 3.7.3C `AuthProtocolsAnalyzer.shutdown()` (already implemented).
- `ScanService.auth_analyzer` (already implemented).
- `backend/main.py` lifespan context manager.
- `backend/app/core/config.py` Pydantic `Settings`.

### **Recommended Implementation Scope:**
1. In `backend/app/core/config.py`: Add `LOCAL_AUTHSERV_ID: Optional[str] = None` and `DMARC_POLICY_ENFORCEMENT_ENABLED: bool = True`.
2. In `backend/main.py`: Update `lifespan` to invoke `scan_service.auth_analyzer.shutdown()` on server shutdown.
3. Add lifespan test in `backend/tests/test_health.py` or `backend/tests/test_auth_pipeline.py` verifying clean shutdown without leaked threads or hanging event loops.
4. Verify full backend suite passes with 444+ tests.
