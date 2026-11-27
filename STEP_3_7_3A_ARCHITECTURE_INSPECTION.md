# MailSentra — Step 3.7.3A: Architecture Review Corrections, Standards Specification, and Implementation Gate

**Project:** MailSentra  
**Repository:** `C:\Users\vatsa\OneDrive\Desktop\MailSantra`  
**Branch / Baseline Commit:** `main` @ `113132f66b37dc71cf681e15db1925d6b9f68069`  
**Architecture Reference:** `MS-ARCH-SEC-2026-AUTH-PROTOCOLS-REV13` *(see Section 4.2 for provenance details)*  
**Standards Audited:** RFC 9989, RFC 8601, RFC 6008, RFC 7208, RFC 6376 (with RFC 8301 / 8463), RFC 5322, RFC 7960  
**Mode:** STRICTLY READ-ONLY — Design & Implementation Gate (Zero production code, test, dependency, DB schema, or Git changes)

---

## 1. Review Corrections & Contradictions Discovered

This revision updates the initial Step 3.7.3A inspection against all ten architecture review directives and audits the actual codebase, tests, and normative RFC texts.

### 1.1 Architectural Corrections Made Since Initial Draft
1. **Six-Stage Decision Pipeline Replaces Flat Precedence List:** Policy evaluation, test-mode (`t=y`) transformation, RFC 9989 §7.4 interoperability handling, receiver-local security policy, and channel-specific action mapping are now separated into **six strict sequential stages** (Section 2). Conflicts are governed by an explicit security policy matrix (Section 3.4) instead of a single flattened priority list.
2. **Resolved Incomplete-Evaluation Audit & RFC vs. MailSentra Boundary:** Inspected [dmarc.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/evaluators/dmarc.py#L1267-L1344) and [test_dmarc_evaluator.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_dmarc_evaluator.py#L209-L234) to establish *why* `SPF NOT_EVALUATED` + absent/failed DKIM currently returns `FAIL`, documented the internal codebase contradiction, explicitly confirmed RFC 9989 does **not** standardize `INDETERMINATE`, and specified the complete 9-scenario decision matrix (Section 3.1).
3. **Strict `t=y` Pre-Local-Policy Policy Transformation:** Formalized `reject -> quarantine`, `quarantine -> none`, `none -> none` strictly on the published policy stage *before* receiver-local disposition, preventing `t=y` from being modeled as an allowlist or authentication override (Sections 2.3 & 3.2).
4. **RFC 9989 §7.4 & RFC 7960 Interoperability Separation:** Explicitly defined what qualifies as `"other knowledge and analysis"`, mandated verifiable sending-path evidence for trusted forwarders/mediators, prohibited trusting domain-name or display-name similarity, and isolated interoperability rules from admin blocklists/allowlists (Sections 2.4 & 3.3).
5. **Channel-Specific Semantics (Direct HTTP `.eml` Upload vs. Future SMTP):** Prohibited claiming SMTP `5xx`/`4xx` or mutating uploaded `.eml` bytes on HTTP ingestion; restricted `Authentication-Results` generation on HTTP uploads to telemetry/preview; defined synchronous pre-`DATA`-reply semantics for future SMTP integration to prevent backscatter (Section 2.6).
6. **Conflict-Aware Override Security Matrix & Scope Decision:** Added the complete 11-condition policy matrix, analyzed cross-signal conflicts (e.g., allowlist vs. confirmed malware), and resolved that persistence/admin override UI/API endpoints belong in a later administrative-control phase while Step 3.7.3 keeps DB schema unchanged (`ScanIncident.telemetry` JSON + `AuditRecord` + server config rules) (Section 3.4 & 3.5).
7. **Complete RFC 8601 / 6008 / 5322 Serialization Spec:** Clarified dedicated `local_authserv_id` vs. `trusted_authserv_ids`, strict omission of `NOT_EVALUATED` and internal `INDETERMINATE`, RFC 8601 §2.2 `; none` form, no in-place modification of existing `Authentication-Results` headers (RFC 8601 §4), CRLF sanitization, folding (`78`/`998`), and top placement (Section 6).

### 1.2 Contradictions Discovered in Existing Code, Tests, and Design History

| # | Contradiction Observed | Exact Locations | Resolution / Gate Impact |
| :--- | :--- | :--- | :--- |
| **C1** | **Incomplete Evaluation (`SPF NOT_EVALUATED`) vs. `FAIL`:** `REV2` §3.2, `REV3` §4, and Step 3.3 contracts specify `SPF=NOT_EVALUATED` + `DKIM=NONE/FAIL` $\to$ `DMARC=INDETERMINATE`. However, `DMARCEvaluator.evaluate()` checks only `status == PASS` and unconditionally falls through to `FAIL`, and two unit tests explicitly assert `FAIL` when `spf_result` is `NOT_EVALUATED`, `INDETERMINATE`, `TEMPERROR`, or `None`. | [test_contracts.py:139-174](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_contracts.py#L139-L174) vs. [dmarc.py:1267-1344](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/evaluators/dmarc.py#L1267-L1344), [test_dmarc_evaluator.py:209-234](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_dmarc_evaluator.py#L209-L234), [lines 1196-1205](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_dmarc_evaluator.py#L1196-L1205) | Root cause identified. Step 3.7.3B must restore incomplete-evaluation safety in `DMARCEvaluator` (`INDETERMINATE`, `rfc_status=None`, no policy enforcement) and update those conflicting test assertions once approved. |
| **C2** | **Input `SPF TEMPERROR` / All-`DKIM TEMPERROR` Converted to `FAIL`:** `dmarc.py` propagates DNS `TEMPERROR` during *alignment tree-walk* lookups (`lines 1282, 1315`), but ignores `spf_result.status == TEMPERROR` and `dkim.status == TEMPERROR` when no aligned `PASS` exists; `test_dmarc_dkim_all_signatures_fail` mixes `[PERMERROR, FAIL, TEMPERROR]` and asserts `FAIL`. | [dmarc.py:1267-1344](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/evaluators/dmarc.py#L1267-L1344) vs. [test_dmarc_evaluator.py:221-230](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_dmarc_evaluator.py#L221-L230), [lines 342-357](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_dmarc_evaluator.py#L342-L357) | Under RFC 9989 §5.3.6 & §9.2, transient DNS error preventing validation yields `TEMPERROR` (never actionable `FAIL`) when no aligned `PASS` rescues the message. Reconcile in Step 3.7.3B (confirming whether both `SPF TEMPERROR` and `DKIM TEMPERROR` escalate when no aligned pass exists). |
| **C3** | **`parse_dmarc_tags()` Parses `t=`, `DMARCEvaluator` Ignores It:** `parse_dmarc_tags()` validates and defaults `t="n"`, while `evaluate()` reads only `p`, `sp`, `np`, `aspf`, `adkim`, dropping `t`. | [dmarc.py:347-356](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/evaluators/dmarc.py#L347-L356) vs. [dmarc.py:1196-1228](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/evaluators/dmarc.py#L1196-L1228) | Propagate `t` (`test_mode: bool`) into `DMARCResult` and apply `t=y` policy transformation in Stage 3 before local policy. |
| **C4** | **DKIM Unexpected Worker Exception Maps to Cryptographic `FAIL` & Omits `b=` Prefix:** `DKIMVerifier._verify_single_signature()` converts generic `Exception` at worker runtime into `ProtocolStatus.FAIL` (`REV13` requires `INDETERMINATE`/incomplete error) and omits the signature `b=` prefix needed for RFC 6008 `header.b`. | [dkim.py:327-333](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/evaluators/dkim.py#L327-L333), [contracts.py:212-224](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/contracts.py#L212-L224) | Capture `signature_b_prefix` (`b=` tag) in `DKIMVerifier` and separate unexpected worker failure from cryptographic `FAIL`. |
| **C5** | **Multi-`From` Support & Incomplete Implementation:** `EmailParser` extracts `all_from_senders`, while `DMARCEvaluator.evaluate()` takes only a single string `from_domain`; `AuthProtocolsConfig` lacks `local_authserv_id`; `raw_auth_results_header` on `AuthProtocolsResult` is ambiguous; `ScanService` stops at Module 3. | [parser.py:97-104](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/parser/parser.py#L97-L104), [config.py:34](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/config.py#L34), [contracts.py:369](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/contracts.py#L369), [scan_service.py:82-100](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/services/scan_service.py#L82-L100) | Inspect `len(all_from_senders) != 1` (RFC 9989 §§5.3.1, 11.5), introduce dedicated `local_authserv_id` + `generated_auth_results_header`, and wire `AuthProtocolsAnalyzer` into `ScanService`. |

---

## 2. Final Six-Stage Decision Architecture

### Strict Three-Tier Data Model Invariant
* **Tier 1 — Published Domain Owner Assessment Policy (`PublishedPolicy`):** `p`, `sp`, `np`, `t`, `psd`, `discovered_domain`, `applicable_policy_tag`. Immutable record of what DNS declared.
* **Tier 2 — Protocol Authentication Result (`SPFResult`, `List[DKIMSignatureResult]`, `DMARCResult`):** Objective technical outcome (`PASS`, `FAIL`, `NONE`, `PERMERROR`, `TEMPERROR`, `INDETERMINATE`, `NOT_EVALUATED`) + `@computed_field rfc_status` (`'pass'|'fail'|'none'|'permerror'|'temperror'|None`). **Never rewritten by any disposition, override, `t=y`, or channel rule.**
* **Tier 3 — Receiver-Local Disposition (`DMARCEnforcementDecision`):** Actionable policy output for downstream triage, `RiskEngine`, or MTA edge delivery.

```
[RawEmailPayload.raw_bytes] + [ParsedEmail] + [IngestionSource] + [Server TrustedSMTPMetadata (optional)]
        │
        ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ STAGE 1: Evidence Provenance & Trust Validation (Sync + Auth Boundary Check)                    │
│ • Ingress channel check: HTTP /upload & /parse-raw MUST supply trusted_smtp_metadata = None.    │
│ • Inbound Authentication-Results check: UNTRUSTED_SENDER unless ALL 3 invariants pass.          │
│ • Detect boundary spoofing (local_authserv_id / trusted_authserv_ids without proof -> CRITICAL).│
│ • Check RFC5322.From cardinality via parsed_email.all_from_senders (must be exactly 1 domain).  │
└───────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ STAGE 2: Protocol Authentication Evaluation (Async, Bounded 5.0s / 15-Query Shared DNS Budget) │
│ • SPFEvaluator: NOT_EVALUATED if missing trusted SMTP metadata; else PASS/FAIL/TEMP/PERM/etc.  │
│ • DKIMVerifier: Offloaded to DKIMExecutor on pristine raw_bytes; captures b= prefix per sig.    │
│ • DMARCEvaluator: Discovery + RFC 9989 §4.10.2 alignment + Incomplete-Eval & TEMPERROR gates.   │
│   Outputs immutable Tier 1 (Published Tags) + Tier 2 (SPFResult, DKIMResults, DMARCResult).     │
└───────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                │ (Tier 2 DMARCResult frozen; NEVER mutated below)
                                                ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ STAGE 3: Published Policy Selection & Test-Mode Transformation (Sync, Pure)                    │
│ • Eligibility Gate (RFC 9989 §5.3.6): Only DMARC PASS / FAIL has valid policy-eval completion;   │
│   only FAIL activates Domain Owner Assessment Policy (TEMPERROR/PERMERROR/INDET/NONE do not).   │
│ • Tag Selection (RFC 9989 §4.10.1): Author domain -> 'p'; existing sub -> 'sp' or 'p';          │
│   non-existent sub -> 'np' or 'sp' or 'p'; invalid policy tag + valid 'rua' -> 'p=none'.        │
│ • Testing Mode t=y Transform (RFC 9989 §4.7 — applied BEFORE any receiver-local decision):      │
│   reject -> quarantine | quarantine -> none | none -> none (records reason: policy_test_mode).  │
└───────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ STAGE 4: RFC 9989 §7.4 Interoperability & Indirect-Flow Handling (Sync, Pure)                   │
│ • Safeguard A (RFC 9989 §7.4 Missing Other Knowledge): If policy == reject and no qualifying     │
│   corroborating knowledge/analysis confirms rejection, downgrade effective policy -> quarantine. │
│ • Safeguard B (Verified Indirect Flows — RFC 7960 / §7.4): Requires server-verified sending-path│
│   evidence (authenticated forwarder connector/IP/ARC-capable trusted relay list, never domain or │
│   display name alone!). May exempt DMARC FAIL from DMARC-triggered quarantine/reject.           │
└───────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ STAGE 5: Receiver-Local Security Policy Arbitration (Sync, Conflict-Explicit Matrix)            │
│ • Evaluates orthogonal signals alongside Stage 4 output using explicit conflict rules (§3.4):   │
│   - Content/threat signals (confirmed malware attachment, malicious URL, high-conf impersonation)│
│   - SUPER_ADMIN security blocklists vs. scoped allowlists                                       │
│   - TEMPERROR policy (fail-open vs defer) & INDETERMINATE safety freeze                         │
│ • Hard security blocks & confirmed malicious payloads CANNOT be bypassed by ordinary allowlists.│
└───────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│ STAGE 6: Channel-Specific Action Mapping & Authentication-Results Generation                    │
│ • AuthResultsGenerator produces RFC 8601/9989/6008 string using dedicated local_authserv_id.    │
│ • Channel = DIRECT_UPLOAD / RAW_PAYLOAD (HTTP API):                                             │
│   - Telemetry & header preview ONLY; archival raw_bytes NEVER modified or prepended.            │
│   - Never claims SMTP 550/451; outputs inspection disposition (ACCEPT / QUARANTINE / FLAG /     │
│     REVIEW_INCOMPLETE / RETRY_RECOMMENDED).                                                     │
│ • Channel = Future Authenticated SMTP MTA Integration (pre-DATA-reply synchronous boundary):    │
│   - Maps to SMTP 250 / quarantine store / 451 4.7.x / 550 5.7.1 BEFORE closing DATA (no DSN!). │
│   - Prepending freshly generated header in outbound MTA copy (after stripping forged locals).     │
└─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Execution Model (Synchronous vs. Asynchronous)
* **Asynchronous (`async`):** `AuthProtocolsAnalyzer.analyze()`, `AsyncDNSResolver`, `SPFEvaluator.evaluate()`, `DKIMVerifier.verify()` (async TXT key pre-fetch + offloaded `DKIMExecutor` worker pool), `DMARCRecordDiscovery`, `DMARCEvaluator.evaluate()`, DB reads/writes (`AsyncSession`) — bounded by a single `5.0s` `asyncio.wait_for` timeout and 15-query DNS cap.
* **Synchronous (Pure Functions):** Stage 1 inbound `Authentication-Results` parser (`AuthResultsTrustEvaluator`), Stage 3–5 policy transformation/arbitration (`DMARCPolicyEnforcer`), and Stage 6 serialization (`AuthResultsGenerator`). Config/DB override rules are pre-loaded asynchronously before entering the pure enforcer.

### 2.2 Channel-Specific Semantics (Direct HTTP Upload vs. Future SMTP)
1. **Direct HTTP `.eml` Uploads (`DIRECT_UPLOAD`, `RAW_PAYLOAD`):**
   * Not an SMTP transaction (`connecting_ip`, `MAIL FROM`, `HELO` are unavailable; `TrustedSMTPMetadata` is strictly `None`).
   * **Never claim to execute SMTP reject or defer.** Instead emit `channel_mode = "http_inspection"` and a recommended inspection disposition (`ACCEPT`, `QUARANTINE`, `RECOMMEND_REJECT` / `FLAG_HIGH_RISK`, `MANUAL_REVIEW_INCOMPLETE`, or `RETRY_RECOMMENDED`).
   * **Preserve uploaded message unmodified.** Do **not** prepend or edit `raw_payload.raw_bytes`. Store `generated_auth_results_header` strictly inside `ScanIncident.telemetry["auth_protocols"]` as a preview/audit record.
   * Keep incomplete evaluation (`INDETERMINATE` due to missing SMTP context) and transient failure (`TEMPERROR`) explicitly distinguishable from completed `FAIL` so analysts can retry transient DNS errors or review unsigned direct uploads manually.
2. **Future SMTP Integration (`SMTP_RELAY` / MTA Milter — Interface Contract Only, Not Implemented in Step 3.7.3):**
   * All protocol checks and Stage 1–6 enforcement MUST execute synchronously **prior to sending the final SMTP reply to `DATA`** (RFC 9989 §§5.3, 7.2; RFC 7208 §2.5; RFC 8601 §4.2, §7.5) so rejections return `550 5.7.1` (or silent discard per policy) in-band rather than generating forged-sender DSN **backscatter**.
   * `ACCEPT` $\to$ SMTP `250` with newly prepended `Authentication-Results` at top of headers (never mutating existing `Authentication-Results` fields).
   * `QUARANTINE` $\to$ accept (`250`) into quarantined mailbox/hold queue with `Authentication-Results`.
   * `REJECT` $\to$ synchronous SMTP `550 5.7.1 Email rejected per DMARC policy for <domain>` (only when Stage 4 & 5 allow rejection).
   * `TEMPERROR` $\to$ configurable: `FAIL_CLOSED_DEFER` issues SMTP `451 4.7.x` retryable error (RFC 9989 §4.10.1, §7.2); `FAIL_OPEN_ACCEPT` issues `250` with `temperror` telemetry & `Authentication-Results`.

---

## 3. Complete Evaluation and Disposition Matrices

### 3.1 Incomplete-Evaluation & Protocol Error Decision Matrix (Reconciling RFC 9989 & MailSentra Safety Model)

**Why existing `dmarc.py` currently returns `FAIL`:** In [dmarc.py:1267-1344](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/evaluators/dmarc.py#L1267-L1344), `DMARCEvaluator.evaluate()` sets `dmarc_pass = spf_aligned or dkim_aligned`, checking only `status == PASS` for SPF/DKIM and tracking `identifier_transient_error` / `identifier_limit_exceeded` solely for *alignment tree walks*. Consequently, `SPF=NOT_EVALUATED`, `SPF=TEMPERROR`, and `DKIM=TEMPERROR` (when unrescued by an aligned `PASS`) all fall through `else:` to `FAIL`. Both [test_dmarc_evaluator.py:209-234](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_dmarc_evaluator.py#L209-L234) (`test_dmarc_spf_non_pass_statuses_never_align`) and `test_dmarc_dkim_all_signatures_fail` ([lines 342-357](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_dmarc_evaluator.py#L342-L357)) encode this defect, contradicting `REV2`/`REV3` and [test_contracts.py:139-174](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_contracts.py#L139-L174).

**Normative Distinction:** RFC 9989 §9.2 standardizes **only** `pass`, `fail`, `none`, `permerror`, `temperror`. **RFC 9989 does NOT standardize `INDETERMINATE` or `NOT_EVALUATED`.** Under MailSentra's safety model for offline/incomplete channels, incomplete evaluation uses internal `ProtocolStatus.INDETERMINATE` with `standard_status = None` (`rfc_status = None`) and **never enforces published DMARC `quarantine`/`reject`**.

*(Assumes DMARC Policy Record is discovered at Domain/Org/PSD except rows 8–9.)*

| # | Scenario | Current `dmarc.py` Behavior | Direct RFC 9989 Normative Semantics | Target MailSentra Internal Status | Target `rfc_status` (JSON / RFC 8601) | Policy Applied? | Channel Disposition (HTTP / Future SMTP) | Classification Rule Origin |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **SPF `NOT_EVALUATED` + DKIM absent** *(no sigs / HTTP upload)* | Returns **`FAIL`** *(defect)* | Assumes MTA evaluated both (§5.3.3); absent identifiers $\to$ `fail` (§5.3.5). Does **not** standardize `INDETERMINATE`. | **`INDETERMINATE`** | `None` *(omit `dmarc=` from Auth-Results)* | **No** *(DMARC policy frozen)* | HTTP: `MANUAL_REVIEW_INCOMPLETE` / `ACCEPT` *(flag `DMARC_EVALUATION_INCOMPLETE`)*<br>SMTP: N/A (SMTP always evaluates SPF) | **MailSentra Channel-Safety Rule** (`REV2`/`REV3`/`Step 3.3`) |
| **2** | **SPF `NOT_EVALUATED` + DKIM `FAIL`** *(HTTP upload, bad/tampered sig)* | Returns **`FAIL`** *(defect)* | Assumes SPF was evaluated too; if SPF wasn't pass $\to$ `fail` (§5.3.5). | **`INDETERMINATE`** | `None` *(omit `dmarc=` from Auth-Results; still emit `dkim=fail`)* | **No** *(DMARC policy frozen; risk engine scores broken DKIM)* | HTTP: `MANUAL_REVIEW_INCOMPLETE` / RiskEngine review | **MailSentra Channel-Safety Rule** (`test_contracts.py:152-173`) |
| **3** | **SPF `NOT_EVALUATED` + DKIM aligned `PASS`** | Returns **`PASS`** *(correct)* | **Direct `pass`** (§5.3.5): single aligned Authenticated Identifier suffices. | **`PASS`** | `"pass"` | Evaluated as Pass *(no enforcement restriction)* | HTTP: `ACCEPT` (RiskEngine still inspects content/URLs)<br>SMTP: `250` | **Direct RFC 9989 §5.3.5** |
| **4** | **SPF `TEMPERROR` + DKIM aligned `PASS`** | Returns **`PASS`** *(when DKIM passes; note tree-walk error tested at `line 801`)* | **Direct `pass`** (§5.3.5): aligned DKIM `PASS` satisfies DMARC regardless of SPF transient error. | **`PASS`** | `"pass"` | Evaluated as Pass | HTTP: `ACCEPT`<br>SMTP: `250` | **Direct RFC 9989 §5.3.5** |
| **5** | **SPF `PASS` aligned + DKIM `FAIL`** | Returns **`PASS`** *(correct)* | **Direct `pass`** (§5.3.5): aligned SPF `PASS` satisfies DMARC (even though §7.4 warns senders against SPF-only reliance). | **`PASS`** | `"pass"` | Evaluated as Pass | HTTP: `ACCEPT` (dkim=fail logged & inspected by RiskEngine)<br>SMTP: `250` | **Direct RFC 9989 §5.3.5** |
| **6** | **SPF `PASS` unaligned + DKIM absent** *(completed SPF check, unsigned mail)* | Returns **`FAIL`** *(correct)* | **Direct `fail`** (§5.3.5): SPF ran (no aligned ID); zero DKIM sigs (`DKIM=NONE`). Both mechanisms checked; neither aligned. | **`FAIL`** | `"fail"` | **Yes** *(Stage 3 `p`/`sp`/`np` + `t=y` $\to$ Stage 4/5)* | HTTP: Recommended disposition per policy (`ACCEPT` / `QUARANTINE` / `RECOMMEND_REJECT` capped by §7.4)<br>SMTP: `250` / Quarantine / `550 5.7.1` | **Direct RFC 9989 §5.3.5** |
| **7** | **Both methods unavailable** *(SPF `NOT_EVALUATED` AND DKIM unevaluated/unavailable, e.g. missing raw bytes or DKIM crashed/`TEMPERROR`)* | Missing bytes in `DKIMVerifier` yields `PERMERROR` $\to$ `dmarc.py` returns **`FAIL`** *(defect)* | Outside §5.3.5 assumption (§5.3.6 forbids pass/fail if required queries failed to complete). | **`INDETERMINATE`** *(or `TEMPERROR` if DKIM failure was DNS/executor timeout)* | `None` *(or `"temperror"` if transient)* | **No** *(policy frozen)* | HTTP: `RETRY_RECOMMENDED` (if `TEMPERROR`) or `MANUAL_REVIEW_INCOMPLETE` | **RFC 9989 §5.3.6** (if DNS timeout) + **MailSentra Safety Rule** |
| **8** | **DMARC DNS `TEMPERROR`** *(discovery `TEMPERROR`, alignment tree-walk `TEMPERROR`, or underlying SPF/DKIM `TEMPERROR` w/o aligned pass)* | Discovery & alignment walk $\to$ **`TEMPERROR`**; input `SPF/DKIM TEMPERROR` $\to$ **`FAIL`** *(defect C2)* | **Direct `temperror`** (§§4.10.1, 5.3.6, 9.2): transient DNS error prevents determining pass/fail; DO policy **MUST NOT** be applied. | **`TEMPERROR`** | `"temperror"` | **No** *(policy frozen)* | HTTP: `RETRY_RECOMMENDED` / `ACCEPT` *(telemetry records `TEMPERROR`)*<br>SMTP: Configurable `451 4.7.x` (`FAIL_CLOSED`) or `250` (`FAIL_OPEN`) | **Direct RFC 9989 §§4.10.1, 5.3.6, 9.2** |
| **9** | **DMARC discovery `PERMERROR`** *(malformed record w/o `rua`, empty/malformed/`From` != 1 domain)* *(Note: multiple records at one node discarded per §4.10 $\to$ walk continues/`NONE`)* | Malformed w/o `rua` / invalid `From` $\to$ **`PERMERROR`**; invalid `p`/`sp`/`np` + valid `rua` $\to$ `FOUND` as `p=none` | **Direct `permerror`** (§9.2 Table 4) / no DMARC processing (§4.10.1); malformed/multi-`From` out-of-scope anomaly (§5.3.1, §11.5). | **`PERMERROR`** *(or `NONE` if multi-record discard finds no record)* | `"permerror"` *(or `"none"`)* | **No** *(invalid tag + `rua` is `p=none` monitoring only)* | HTTP: `ACCEPT` (escalate multi-`From` to RiskEngine as high risk per §11.5)<br>SMTP: `250` (unless local anti-abuse blocks multi-`From`) | **Direct RFC 9989 §§4.10, 4.10.1, 5.3.1, 9.2, 11.5** |

### 3.2 `t=y` Testing-Mode Transformation Matrix (Stage 3 — RFC 9989 §4.7)
Applies **exclusively** after `DMARC = FAIL` and policy tag selection (`np` $\to$ `sp` $\to$ `p`), strictly **before** Stages 4–5 (never acts as an allowlist or alters `dmarc_status`):

| Condition | Raw Published Tag | `t=` Tag | Stage 3 Transformed Policy | Recorded Rationale / Override Reason | Stage 4 Interop Impact |
| :--- | :---: | :---: | :---: | :--- | :--- |
| `DMARC PASS` or non-`FAIL` | Any | `y` or `n` | *(Policy not enforced)* | N/A | N/A |
| `DMARC FAIL` | `none` | `y` or `n` | **`none`** | `t=y` has no effect on `none` (RFC 9989 §4.7) | None (`ACCEPT`) |
| `DMARC FAIL` | `quarantine` | `n` | **`quarantine`** | Published policy intact | Subject to Stage 4/5 local rules |
| `DMARC FAIL` | `quarantine` | `y` | **`none`** | `policy_test_mode` (stepped down 1 level) | Treated as `none` downward (`ACCEPT`) |
| `DMARC FAIL` | `reject` | `n` | **`reject`** | Published policy intact | Enters Stage 4 §7.4 check |
| `DMARC FAIL` | `reject` | `y` | **`quarantine`** | `policy_test_mode` (stepped down 1 level) | Already `quarantine`; §7.4 reject cap unnecessary |

### 3.3 RFC 9989 §7.4 Interoperability & Other Knowledge Specification (Stage 4)
Normative restriction in RFC 9989 §7.4 (and §5.4 / §8):
> *"Mail Receivers **MUST NOT** reject incoming messages solely on the basis of a `'p=reject'` policy by the sending domain... In the absence of other knowledge and analysis, Mail Receivers **MUST** treat such failing mail as if the policy were `'p=quarantine'` rather than `'p=reject'`."*

* **What Qualifies as `"Other Knowledge and Analysis"` (for allowing `reject` on future SMTP connectors when Stage 3 `post_test_mode_policy == reject`):**
  1. Corroborating negative risk/content analysis (`RiskDecisionReport` / confirmed threat signals such as malicious URL, malicious attachment, or impersonation detection), **OR**
  2. Verified non-indirect sending-pattern / bilateral domain enforcement policy explicitly configured on the tenant/gateway *confirming* the domain does not rely on unprotected indirect flows and is opted into strict SMTP rejection (`allow_strict_p_reject = True` + connector capability).
  * *In the absence of qualifying corroborating evidence (and ALWAYS on direct HTTP `.eml` uploads)*: downgrade Stage 3 `reject` $\to$ Stage 4 `quarantine` (preserving `published_policy = reject` in Tier 1 telemetry).
* **Trusted-Forwarder / Mailing-List Indirect-Flow Evidence (RFC 9989 §5.4, RFC 7960 §§2.2, 4.1.2.2):**
  * **Valid Evidence Required:** Server-verified sending-path identity from `TrustedSMTPMetadata`: e.g., authenticated connector session (`authenticated_connector_id`) matched against a server-configured `trusted_forwarder` IP/CIDR or authorized relay list (or future RFC 8617 ARC validation chain anchored to trusted intermediaries), optionally paired with verified MLM/list headers (`List-Id` / `List-Post`) **when coming through an authenticated connector / trusted relay path**.
  * **Strictly Prohibited as Forwarder Proof:** Domain name match in `From:` or `Return-Path:`, display name strings (e.g., `"via Alumni Group"`), unauthenticated `Received:` hops, `X-Original-From`, or untrusted sender `Authentication-Results:` headers.
  * **Separation Rule:** Stage 4 interoperability records `PolicyOverrideType.TRUSTED_FORWARDER` or `PolicyOverrideType.MAILING_LIST` (excusing DMARC `FAIL` on verified indirect hops) independently of administrator-configured security blocklists/allowlists in Stage 5.

### 3.4 Receiver-Local Policy Conflict Resolution Matrix (Stage 5)

Each row shows how orthogonal authentication states, interoperability signals, threat findings, and administrative controls arbitrate into Tier 3 `DMARCEnforcementDecision` **without altering Tier 2 `dmarc_status`**.

| Input Condition / Signal | Combined Context / Conflict Case | Resulting Tier 3 Disposition | Tier 2 Status Rewritten? | Conflict Resolution Principle |
| :--- | :--- | :--- | :--- | :--- |
| **Administrative Blocklist** | + `DMARC PASS` (or `DMARC FAIL` + `t=y`) | **HARD BLOCK** (`QUARANTINE` or `REJECT` per block rule) | **No** *(remains `PASS` / `FAIL`)* | RFC 9989 §5.4: local anti-abuse control overrides passing auth. |
| **Administrative Blocklist** | + **Administrative Allowlist** (both match same message) | **HARD BLOCK** (`QUARANTINE` / `REJECT`) + emit `ADMIN_POLICY_CONFLICT_DETECTED` | **No** | **Security Block Cannot Be Bypassed by Ordinary Allowlist.** |
| **Confirmed Malicious Attachment** *(future Module 6 signal)* | + `DMARC PASS`, `p=none`, `t=y`, **Trusted Forwarder**, or **Administrative Allowlist** | **HARD BLOCK** (`QUARANTINE` / `REJECT` per tenant threat posture) | **No** | Confirmed payload exploit overrides auth pass, allowlists, & indirect-flow exemptions. |
| **Confirmed Malicious URL** *(future Module 5 / 8 signal)* | + `DMARC PASS`, **Trusted Forwarder**, or **Administrative Allowlist** | **HARD BLOCK** (`QUARANTINE` / `REJECT`) | **No** | Confirmed credential-harvesting/malware URL cannot be allowlisted away by ordinary domain allowlist. |
| **High-Confidence Impersonation** *(Module 3 / BEC signal, e.g. lookalike/VIP spoof)* | + `DMARC PASS` *(e.g. attacker registered `paypa1.com` and validly signed it! RFC 8601 §4.1)* or **Allowlist** *(unless explicit SOP break-glass exception)* | **QUARANTINE / ESCALATE** | **No** *(attacker's domain passed DKIM/SPF for `paypa1.com`)* | RFC 9989 §4.1 & RFC 8601 §7.2: DMARC `PASS` proves domain alignment, not trustworthiness; threat engine takes precedence over DMARC `PASS` & ordinary allowlists. |
| **Administrative Allowlist** *(ordinary domain/sender exception)* | + `DMARC FAIL` (`p=quarantine`/`reject`), **Zero hard blocks & zero confirmed threat signals** | **ACCEPT** (`local_override_applied=True`, reason `local_policy`) | **No** *(remains `FAIL`)* | Scoped exemption prevents false-positive DMARC disruption ONLY when payload/reputation are clean. |
| **Trusted Forwarder** *(verifiable path proof)* | + `DMARC FAIL` (`p=quarantine`/`reject`), **Zero hard blocks & zero confirmed threat signals** | **ACCEPT** (`local_override_applied=True`, reason `trusted_forwarder`) | **No** *(remains `FAIL`)* | Excuses SPF/DKIM breakage caused by benign forwarding unless payload is malicious or blocklisted. |
| **Trusted Forwarder Spoofed** *(domain/display name claim w/o verified path)* | + `DMARC FAIL` (`p=reject`) | Ignore forwarder claim $\to$ proceed as normal Stage 4 `FAIL` (`QUARANTINE` / `REJECT`) + flag warning | **No** | Spoofed indirect-flow indicators never grant exemptions. |
| **Mailing-List / Indirect-Flow Evidence** *(verified relay/MLM heuristics)* | + `DMARC FAIL` (`p=reject`/`quarantine`), **Zero hard blocks & zero confirmed threat signals** | **ACCEPT** or **TAG/QUARANTINE** per policy (`mailing_list`) | **No** *(remains `FAIL`)* | Prevents mailing list breakage per RFC 9989 §7.4 & RFC 7960 §4.1.2.2 without ignoring malware. |
| **`DMARC PASS`** | + No threat signals, no blocklist | **ACCEPT** | **No** | Normal verified delivery / ingestion pass. |
| **`DMARC FAIL`** | + No overrides, no threat signals | Stage 3 (`t=y`) $\to$ Stage 4 (§7.4 `reject -> quarantine` unless other signals) | **No** *(remains `FAIL`)* | Standard DMARC enforcement subject to §7.4 safeguard. |
| **`DMARC TEMPERROR`** | + No hard blocks/malware | HTTP: `RETRY_RECOMMENDED` / `ACCEPT`; SMTP: `DEFER` (`451`) or `ACCEPT` | **No** | RFC 9989 §5.3.6 forbids applying Domain Owner policy on `TEMPERROR`; **hard malware/blocklist still blocks.** |
| **Internal `INDETERMINATE`** | + No hard blocks/malware *(e.g. HTTP direct upload lacking SMTP)* | HTTP: `MANUAL_REVIEW_INCOMPLETE` / `ACCEPT`; SMTP: N/A unless budget limit | **No** | Incomplete evaluation cannot trigger DMARC enforcement; **hard malware/blocklist still blocks.** |

**Explicit Precedence Conflict Explanation:**  
Rather than pretending "Rule 1 > Rule 2 > Rule 3" in one list, arbitration cleanly separates **two independent planes**:
1. **Authentication Plane (DMARC `p`/`sp`/`np` $\to$ `t=y` $\to$ §7.4 / Forwarder / Allowlist):** Governs *whether failure to align with the From domain warrants blocking*. It can only relax itself (`FAIL` $\to$ `ACCEPT`) via `t=y`, §7.4, trusted forwarders, mailing lists, or scoped admin allowlists.
2. **Threat / Hard-Security Plane (Admin Blocklists, Confirmed Malware, Confirmed Malicious URLs, High-Confidence Impersonation):** Operates orthogonally on *payload, impersonation, and operator deny decisions*. Even if Plane 1 yields `ACCEPT` (because DMARC `PASS`, `p=none`, `t=y`, allowlist, or trusted forwarder passed DMARC), **Plane 2 always wins (`QUARANTINE`/`REJECT`)** unless no threat/block exists! And if both an Admin Blocklist and an Admin Allowlist match the same artifact, Blocklist takes precedence and logs an `ADMIN_POLICY_CONFLICT_DETECTED` audit alert.

### 3.5 Decision: Override Persistence & Administration APIs Belong in a Later Phase
* **Decision for Step 3.7.3:** Override definitions are modeled cleanly via server-side `AuthProtocolsConfig.local_override_rules` (injected/configured by `SUPER_ADMIN` deployment configuration), while per-scan enforcement outcomes, overrides applied, and reasons persist inside existing `ScanIncident.telemetry["auth_protocols"]` JSON alongside immutable `AuditLogger` + `AuditRecord` rows — **requiring zero database schema migrations or new admin REST endpoints in Step 3.7.3**.
* **Deferral Rationale:**
  1. [router.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/api/v1/router.py) has no `/admin` or `/policies` router yet, and threat modules 5–9 (`url_analysis`, `attachment`, `social_engineering`, `threat_intel`, `risk_engine`) are still roadmap Phase 3–4 stubs (`DEVELOPMENT_ROADMAP.md`, [risk_engine/__init__.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/risk_engine/__init__.py)).
  2. Preserves the zero-schema-migration constraint across Day 3 Module 4 delivery while keeping `LocalPolicyOverrideRule` and `DMARCEnforcementDecision` Pydantic-ready for future SQLAlchemy policy tables and `SUPER_ADMIN` / `SOC_ANALYST` override endpoints (`SECURITY_DESIGN.md:35-39`).

---

## 4. RFC Compliance Mapping & REV13 Provenance

### 4.1 Exact Normative Standards Mapping

| Standard & Exact Section | Normative Requirement Used in Step 3.7.3 Design |
| :--- | :--- |
| **RFC 9989 §3.2.1–3.2.14, §4.4, §4.7** | Definitions of Authenticated Identifier, Author Domain, SPF/DKIM alignment, Domain Owner Assessment Policy (`none`/`quarantine`/`reject`), `np`, `sp`, `psd`, and testing mode `t` (`y`/`n`, default `n`). `t=y` transforms failing policy 1 level (`reject -> quarantine`, `quarantine -> none`, `none -> none`) without altering reporting/auth result. |
| **RFC 9989 §4.8, §4.10.1–4.10.2** | Unknown tags ignored (`pct` removed); invalid optional tags fallback to defaults; `np -> sp -> p` hierarchy; invalid `p`/`sp`/`np` + valid `rua` $\to$ `p=none`; no DMARC record $\to$ mechanism does not apply; transient DNS error policy discretion (fail-open vs 4xx). |
| **RFC 9989 §5.3.1, §5.3.5–5.3.7, §11.5** | Must have exactly 1 `RFC5322.From` domain (0 or $>1$ out-of-scope / high-risk DoS/bypass attack §11.5); binary §5.3.5 pass/fail; §5.3.6 forbids pass/fail or Domain Owner policy enforcement when required DNS queries fail; preserve results (§5.3.7). |
| **RFC 9989 §5.4, §7.2, §7.4, §8** | Final handling always local policy; receivers MAY block `PASS` or accept `FAIL` (§5.4); `p=none` MUST NOT alter handling (§5.4); synchronous pre-`DATA` SMTP rejection (`550 5.7.1`) vs silent discard / `4xx` defer avoids backscatter (§7.2); **MUST NOT reject solely on `p=reject`** — treat as `quarantine` without other knowledge/analysis (§7.4, §8); SHOULD add `Authentication-Results` (§5.4). |
| **RFC 9989 §9.1 (Table 3), §9.2 (Table 4)** | IANA `Authentication-Results` `dmarc` method properties: `header.from` and `policy.dmarc` (`"none"`, `"quarantine"`, `"reject"` evaluated after policy options); registered `dmarc` codes strictly `{none, pass, fail, temperror, permerror}`. |
| **RFC 8601 §§2.1–2.7.2, §4, §4.1, §4.2, §5, §6.3, §7.1–7.10** | Trace header format & ABNF (`authserv-id`, `method=result`, `reasonspec`, `propspec`), special `authserv-id; none` (§2.2), `policy` ptype (§2.4), `authserv-id` uniqueness (§2.5), DKIM `header.d/i/s/a` (§2.7.1, §6.3.1–6.3.2), SPF `smtp.mailfrom` / `smtp.helo` only (§2.7.2, §4), **MUST NOT modify existing `Authentication-Results` fields** (§4), prepend at top (§4.1), delete forged internal `authserv-id` headers across untrusted boundaries (§5), ignore nested `message/rfc822` headers (§4.1, §7.10), reject before generating DSN backscatter (§4.2, §7.5), malformed header DoS (§7.8). |
| **RFC 6008 §§4, 5, 6.1–6.2** | `dkim` `header.b`: MUST include $\ge$ first 8 chars of signature `b=` tag (entire value if $<8$ chars), long enough to be unique among signatures; case-sensitive matching (§4); ignore conflicting results on identical `header.b` from same trusted `authserv-id` (§4, §6.2). |
| **RFC 7208 §§2.3–2.6, §4.6.4, §7, §§8.1–8.7, §9** | HELO vs MAIL FROM (`<>` synthesizes `postmaster@<helo>` per §2.4), check during SMTP transaction to prevent forged headers & backscatter (§2.5), 7 SPF outcomes (`none`, `neutral`, `pass`, `fail`, `softfail`, `temperror`, `permerror`), `550 5.7.1` / `451 4.4.3` SMTP semantics (§8), record via `Authentication-Results` (§9). |
| **RFC 6376 §§3.5, 3.6.2.2, §§6.1–6.3** | Multi-signature processing, multiple DNS key records invalid (§3.6.2.2), prepend auth header before existing `DKIM-Signature` / auth headers and delete bogus headers before adding new ones (§6.2), do not reject solely on missing/unverifiable sig and restrict `451` to transient key-lookup errors (§6.3); SHA-1 rejected per RFC 8301, Ed25519 supported per RFC 8463. |
| **RFC 5322 §§2.1.1, 2.2, 2.2.3, 3.6, 3.6.2, 3.6.7** | Line length limits (SHOULD $\le 78$, MUST $\le 998$ excluding CRLF, §2.1.1), no raw CR/LF in header body except folding (§2.2), folding `CRLF + WSP` at syntactic breaks (§2.2.3), single `From:` field (§3.6, §3.6.2), trace fields prepended without reordering (§3.6.7). |
| **RFC 7960 §§2.1.1–2.3, §4.1.2.1–4.1.2.2** | Multi-DKIM signature alignment (§2.1.1, §4.1.2.1), hybrid SPF null-bounce behavior (§2.1.2), multi-`From` spoofing risk (§2.1.3), forwarding/mailing-list breakage of SPF/DKIM (§2.2, §2.3), and receiver forwarder-list policy overrides (§4.1.2.2). |
| *(Informative)* **RFC 9990 §3.1.6** | Provides standard override vocabulary (`local_policy`, `mailing_list`, `policy_test_mode`, `trusted_forwarder`, `other`) for internal telemetry consistency only; aggregate XML report generation/dispatch remains out of scope. |

### 4.2 `MS-ARCH-SEC-2026-AUTH-PROTOCOLS-REV13` Provenance Disclosure
* **Standalone Document Not Present:** No standalone `MS-ARCH-SEC-2026-AUTH-PROTOCOLS-REV13` file exists anywhere in the repository or local workspace.
* **What Available Design Transcript & Docs Support:**
  * Earlier session design steps (`Steps 363–573`, `REV0`–`REV13`, Step 3.3 / Step 3.3A reports) and repo docs ([ARCHITECTURE.md](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/ARCHITECTURE.md), [SECURITY_DESIGN.md](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/SECURITY_DESIGN.md), [DEVELOPMENT_ROADMAP.md](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/DEVELOPMENT_ROADMAP.md)) establish: the Three-Tier DMARC Model (`REV5` §5 / `REV6` §6), RFC 8601 tripartite trust boundary & `FORGED_AUTHENTICATION_RESULTS_DETECTED` (`REV0–REV3`, Step 3.3A), `AuthProtocolsAnalyzer` 5.0s deadline / 15-query budget (`REV0–REV2`), incomplete-evaluation safety (`REV2` §3.2 / `REV3` §4 / Step 3.3), pristine `raw_bytes` handling (`REV0` §2), `BoundedDKIMExecutor` two-phase lifespan shutdown (`REV10–REV13`), and RBAC roles (`SECURITY_DESIGN.md` §2.3).
* **What Was Resolved / Added Here Beyond Available `REV13` Text:** Six-stage decoupling, specific conflict-resolution rules across malware/blocklists/allowlists/forwarders, HTTP upload vs. future SMTP channel semantics, omission/`; none` serialization rules, dedicated `local_authserv_id`, and deferral of DB override tables & admin APIs. Open items remain isolated in **Section 10**.

---

## 5. Trust-Boundary Design

1. **Ingress & Transport Metadata Separation:** Client requests to `/upload` and `/parse-raw` **cannot** specify `TrustedSMTPMetadata`, `is_trusted_mta`, `authenticated_connector_id`, or `mta_sanitization_guaranteed` (always `None` from HTTP client upload endpoints). Only authenticated server-side MTA connectors (future `SMTP_RELAY` ingestion route with connector credentials) may supply verified `TrustedSMTPMetadata`.
2. **`local_authserv_id` vs. `trusted_authserv_ids` Isolation:** `AuthProtocolsConfig.local_authserv_id` identifies MailSentra itself and **must never be placed into `trusted_authserv_ids` as an inbound-trusted peer**. Any inbound email containing `Authentication-Results: <local_authserv_id>; ...` across direct uploads or unauthenticated connectors is treated as an active impersonation attack (`UNTRUSTED_SENDER` + critical finding `FORGED_AUTHENTICATION_RESULTS_DETECTED`).
3. **Tripartite `TRUSTED_UPSTREAM` Rule (RFC 8601 §5 & Step 3.3A):** Enforced via `ParsedAuthResultsHeader.validate_trust_boundary()`: accepted **only** when (a) `authserv_id_matched_config == True` (case-insensitive normalized match against `trusted_authserv_ids`, after A-label/U-label canonicalization if EAI), (b) `authenticated_connector_id` is present on server-side `TrustedSMTPMetadata`, AND (c) `mta_sanitization_guaranteed == True` (and positioned above untrusted `Received` trace hops — headers buried below untrusted `Received` or inside `message/rfc822` MIME parts per RFC 8601 §4.1/§7.10 remain `UNTRUSTED_SENDER`).
4. **Local Verification & Policy Supremacy:** Inbound upstream headers can **never** elevate, downgrade, or overwrite MailSentra's locally computed `SPF`, `DKIM`, or `DMARC` status (nor unlock `LocalPolicyOverrideRule` allowlists).
5. **Override Governance & RBAC Boundary:** Automated rules (`LocalPolicyOverrideRule`) live strictly in server config (`SUPER_ADMIN` managed); post-ingestion triage overrides require authenticated JWT (`UserRole.SUPER_ADMIN` or `UserRole.SOC_ANALYST` — API keys/`SYSTEM_AGENT` blocked at `403`, cross-tenant blocked via `authorize_scan_incident_access`), with mandatory immutable `AuditLogger` + `AuditRecord` logging.

---

## 6. `Authentication-Results` Serialization Specification

### 6.1 Identity & Placement Rules
* **Dedicated `local_authserv_id`:** Configured via `AuthProtocolsConfig.local_authserv_id` / `Settings.LOCAL_AUTHSERV_ID` (strictly validated RFC 8601 §2.5 host/domain token; separate from `trusted_authserv_ids`). If unset (`None`), header generation is skipped (telemetry records `authserv_id_unconfigured`) unless dev default is explicitly approved.
* **No Mutation of Existing Fields (RFC 8601 §4):** An MTA/agent MUST NEVER append `; dmarc=...` or alter any existing `Authentication-Results:` header field. Local results always emit a **new standalone `Authentication-Results` field**.
* **Channel Placement:**
  * **HTTP Direct Uploads (`/upload`, `/parse-raw`):** Archival `raw_payload.raw_bytes` is **never modified or prepended**. The serialized header is stored solely as telemetry preview (`generated_auth_results_header` / `LOCALLY_VERIFIED` `ParsedAuthResultsHeader`) inside `ScanIncident.telemetry["auth_protocols"]`.
  * **Future MTA / Export Path:** Before emitting a relayed copy (after DKIM verification ran on untouched inbound bytes), strip any pre-existing inbound `Authentication-Results` headers claiming `local_authserv_id` or untrusted forged `trusted_authserv_ids` (RFC 8601 §5), then prepend the single newly generated header at the **very top** above existing trace and `DKIM-Signature` headers (RFC 8601 §4, §4.1; RFC 6376 §6.2; RFC 5322 §3.6.7).

### 6.2 Grammar, Method Serialization, and Fallback Semantics
Following RFC 8601 §2.2 ABNF:
```abnf
Authentication-Results: <authserv-id>; <resinfo> *(; <resinfo>)
```
* **No Authentication Performed (RFC 8601 §2.2 `no-result`):** If **all** authentication checks produced no reportable RFC result (e.g., `SPF=NOT_EVALUATED`, `DKIM` unrun/unavailable, and `DMARC=INDETERMINATE`/`NOT_EVALUATED`), serialize strictly:
  ```text
  Authentication-Results: <local_authserv_id>; none
  ```
* **DMARC (`dmarc` — RFC 9989 §§9.1–9.2):**
  * **Emit ONLY when `dmarc_result.rfc_status` is in `{"pass", "fail", "none", "permerror", "temperror"}`.**
  * **Strictly OMIT `dmarc=...` when internal status is `INDETERMINATE` or `NOT_EVALUATED`** (never invent `dmarc=indeterminate` or falsify `dmarc=fail` / `dmarc=none`).
  * Properties emitted:
    * `header.from=<normalized_from_domain>` (RFC 9989 §9.1 Table 3).
    * `policy.dmarc=<effective_policy_value>` (`"none"`, `"quarantine"`, or `"reject"` — the evaluated DMARC policy after `sp`/`np`/`t=y` policy options per RFC 9989 §9.1 Table 3; omit `policy.dmarc` when no policy record applied / `NOT_CONFIGURED`). If a Stage 4/5 local override altered the disposition of a passing/failing check, record diagnostic `reason="..."` safely (and optionally `policy.override=...` if ADMD internal downstream filtering uses RFC 8601 §2.4 `policy.<prop>` tokens).
* **SPF (`spf` — RFC 8601 §2.7.2 & §4):**
  * Emit ONLY when evaluated to standardized RFC 7208 §2.6 result `{pass, fail, softfail, neutral, none, temperror, permerror}`.
  * **Strictly OMIT `spf=...` when `SPFResult.status` is `NOT_EVALUATED` or internal `INDETERMINATE`** (e.g. direct `.eml` uploads or unsupported `%{p}`).
  * Identity property (§4: emit **only** the evaluated parameter; §2.7.2: omit local-part since SPF does not authenticate it, or domain of HELO):
    * Normal MailFrom scope: `smtp.mailfrom=<spf_domain>`
    * Null reverse-path synthesized / HELO scope: `smtp.helo=<helo_domain>` *(or `smtp.mailfrom=<spf_domain>` with `smtp.helo` if HELO evaluated — follow §4 strictly: emit whichever parameter determined the result, avoiding unverified local-parts)*.
* **DKIM (`dkim` — RFC 8601 §2.7.1, §6.3.1–6.3.2 & RFC 6008 §4):**
  * If message contained **zero** signatures and DKIM verifier ran normally: emit `dkim=none` (RFC 8601 §2.7.1). If DKIM verifier could not run (`NOT_EVALUATED`/unavailable), omit `dkim=...`.
  * For **each verified signature**, emit an independent `; dkim=<result>` clause (`pass`, `fail`, `temperror`, `permerror`, `neutral`, `policy`):
    * Include `header.d=<d>` (when present), `header.i=<i_sanitized>` (if non-empty and safe), `header.s=<s>`, `header.a=<a>`, and **`header.b=<prefix>`** (at least first 8 base64 chars of `b=`, extended if collisions exist among signatures on the message, case-sensitive per RFC 6008 §4).
    * Cap serialized signature clauses defensively (e.g., max 10 signatures) if an attacker floods synthetic signatures.

### 6.3 Sanitization, Injection Defense, Folding & Line Bounds
1. **Strict Character & ABNF Validation:** Reject/strip `\r`, `\n`, `\x00`, and ASCII control characters (`0x00–0x1F`, `0x7F`) on *every* interpolated value (`local_authserv_id`, domains, selectors, algorithms, `b=` prefix, `reason`). Domains pass UTS #46 A-label normalization; `b=` prefixes match `^[A-Za-z0-9+/=]{1,64}$`. Any unencoded/invalid token fails safe (replaced by safe sanitized placeholder or omitted `reason`) — **never** emit raw CR/LF or unescaped quotes.
2. **Quoted-String Safety for `reason="..."`:** Escape `\` $\to$ `\\` and `"` $\to$ `\"` per RFC 5322/8601, strip CR/LF/CTL, truncate to max `128` ASCII characters.
3. **Header Folding & Size Caps (RFC 5322 §§2.1.1, 2.2.3):** Fold cleanly at syntactic `CFWS` boundaries (after `;` clauses, or between `propspec` tokens) with `\r\n ` so each physical line stays **`<= 78` characters** (excluding CRLF). Enforce hard assertion that **zero physical lines exceed `998` characters** (truncating optional `reason`/excess properties or failing closed if needed) and bound total serialized header size (e.g., `<= 8,192` bytes).

---

## 7. Security Threat Analysis

| Threat | Exploit Scenario | Concrete Defense in Architecture |
| :--- | :--- | :--- |
| **Forged Local/Trusted `Authentication-Results`** | Upload contains `Authentication-Results: auth.mailsentra.corp; dmarc=pass` or spoofs configured upstream gateway ID to hide DMARC `FAIL`. | Stage 1 forces `UNTRUSTED_SENDER` unless all 3 connector invariants hold; `local_authserv_id` never admitted on inbound mail; raises critical `FORGED_AUTHENTICATION_RESULTS_DETECTED`; future MTA outbound builder deletes forged local/trusted headers per RFC 8601 §5. |
| **Header / CRLF Injection in Generated Header** | Attacker crafts `s=bad\r\nBcc:evil@x`, malformed `From:`, or poisoned DNS record so MailSentra emits forged headers inside generated `Authentication-Results`. | Strict character allowlist + A-label validation + `\r\n\x00`/CTL rejection prior to `AuthResultsGenerator` formatting; quoted-string escaping + bounding on `reason=`. |
| **ReDoS & Oversized Inbound Header DoS** | Attacker sends 500 `Authentication-Results` headers or 50 KB nested `(comment)` `CFWS` payload to stall parser. | Enforce header count cap (e.g. `16`), per-header byte cap (`4096`), linear non-backtracking tokenizer (no nested backtracking regexes), per-header error isolation. |
| **DMARC Denial via Multi-`From` Headers (RFC 9989 §11.5)** | Message contains `From: attacker@evil.com, ceo@bank.com`; victim MUA displays `bank.com` while first-domain check passes DMARC for `evil.com`. | Stage 1 checks `ParsedEmail.all_from_senders`; `len != 1` blocks DMARC `PASS`, sets `PERMERROR` / `DMARC_MULTIPLE_FROM_DOMAINS`, and escalates to Stage 5 security triage. |
| **False `p=reject` on Direct `.eml` Upload** | Analyst uploads unsigned `.eml` for a `p=reject` domain; `SPF=NOT_EVALUATED` triggers false `DMARC FAIL` $\to$ `REJECT`. | Reconcile Stage 2 incomplete-evaluation rule (`SPF=NOT_EVALUATED` + `DKIM=NONE/FAIL` $\to$ `INDETERMINATE`, no policy applied) + Stage 6 HTTP upload channel cannot execute SMTP `reject`/`defer`. |
| **Allowlist Bypass via Compromised/Phishing Payloads** | Domain is on local allowlist or verified forwarder, and attacker sends malicious macro attachment or phishing URL spoofing/abusing it. | Stage 5 orthogonal Threat Plane mandates hard security blocks (malware attachment, malicious URL, high-conf impersonation, admin blocklist) **override** ordinary allowlists and forwarder exemptions. |
| **Spoofed Trusted-Forwarder / Mailing-List Claim** | Attacker puts `From: news@fwd.partner.org` or `List-Id: ...` and fake `Received:` header to claim indirect-flow DMARC exemption. | Stage 4 forwarder/MLM exceptions require server-side verified sending path (`TrustedSMTPMetadata` / authenticated connector / relay IP), never message headers or domain similarity. |
| **Duplicate Self-Header Stacking & Backscatter** | Re-scanning exported `.eml` appends a second local `Authentication-Results`; rejecting failed mail post-`DATA` floods innocent victims with DSNs. | HTTP scan never mutates `raw_bytes`; outbound MTA builder strips prior `local_authserv_id` before prepending once; future SMTP rejection occurs **pre-DATA-reply** (`550 5.7.1`) only. |

---

## 8. Comprehensive Test Plan & Expected Outcomes (Step 3.7.3 Gate)

All tests execute deterministically offline (`MockDNSResolver`, synthetic keys, isolated unit/integration fixtures):

| # | Test Suite & Case | Setup / Inputs | Expected Assertions / Outcomes |
| :--- | :--- | :--- | :--- |
| **1** | **Incomplete-Evaluation Matrix (all 9 rows)** (`test_dmarc_evaluator.py` + `test_dmarc_policy_enforcement.py`) | Cover all 9 cases from §3.1: `(NOT_EVAL, None)`, `(NOT_EVAL, FAIL)`, `(NOT_EVAL, aligned PASS)`, `(SPF TEMP, aligned PASS)`, `(aligned PASS, DKIM FAIL)`, `(unaligned PASS, DKIM None)`, `(both unavail)`, `(DMARC DNS TEMP)`, `(DMARC PERM / multi-From / rua rescue)`. | Rows 1, 2, 7 $\to$ `INDETERMINATE`, `rfc_status is None`, policy frozen (`ACCEPT`/`MANUAL_REVIEW_INCOMPLETE`); Rows 3, 4, 5 $\to$ `PASS`, `"pass"`, `ACCEPT`; Row 6 $\to$ `FAIL`, `"fail"`, Stage 3–5 policy applied; Row 8 $\to$ `TEMPERROR`, `"temperror"`, no `REJECT`; Row 9 $\to$ `PERMERROR` (or `p=none` with `rua`), no `REJECT`/`QUARANTINE`. |
| **2** | **Every `t=y` Transformation** (`test_dmarc_policy_enforcement.py`) | `DMARC FAIL` across `p`/`sp`/`np` in `{reject, quarantine, none}` with `t=y` vs `t=n`; also `DMARC PASS` with `t=y`. | `FAIL`+`reject`+`t=y` $\to$ Stage 3 `quarantine` (`policy_test_mode`); `FAIL`+`quarantine`+`t=y` $\to$ `none`; `FAIL`+`none`+`t=y` $\to$ `none`; `published_policy` & `dmarc_status=FAIL` remain unmutated; `PASS` unaffected. |
| **3** | **`p=reject` With & Without Corroborating Risk Evidence (RFC 9989 §7.4)** | `DMARC FAIL`, `p=reject`, `t=n`: (a) HTTP upload no signals, (b) SMTP connector no corroborating signals + conservative fallback, (c) SMTP connector + malicious URL / `allow_strict_p_reject`. | (a) `QUARANTINE` (never HTTP SMTP reject claim); (b) downgraded to `QUARANTINE` per §7.4; (c) `REJECT` (`550 5.7.1`). |
| **4** | **Forwarder Trust Validation & Spoofed Forwarder** | (a) Verified connector IP/forwarder ID + `DMARC FAIL`; (b) Unauthenticated upload / non-forwarder IP claiming forwarder domain or display name `"via Partner Forwarder"`. | (a) Exempted (`ACCEPT`, `trusted_forwarder`, `dmarc_status=FAIL`); (b) Spoof claim ignored, Stage 3–4 policy (`QUARANTINE`/`REJECT`) enforced + spoof warning. |
| **5** | **Allowlist vs. Confirmed Malware / URL Conflict** | Sender matches `LocalPolicyOverrideRule(EXEMPT_ACCEPT)` AND confirmed malicious attachment (or malicious URL / impersonation / blocklist rule). | Malware / hard blocklist **wins** (`QUARANTINE`/`REJECT`); `dmarc_status` stays unchanged; conflict/block audit recorded. |
| **6** | **Admin Blocklist vs. `DMARC PASS`** | Aligned `DKIM PASS` + `SPF PASS` + `DMARC PASS`, matching `FORCE_QUARANTINE`/`FORCE_REJECT` admin blocklist rule. | Blocklist enforces `QUARANTINE`/`REJECT`; `dmarc_status` strictly remains `PASS` (`rfc_status == "pass"`). |
| **7** | **`TEMPERROR` Across HTTP & SMTP Channels** | `DMARCDiscoveryStatus.TEMPERROR` (or `SPF=TEMPERROR` + `DKIM=NONE`) evaluated on (a) `DIRECT_UPLOAD` and (b) `SMTP_RELAY` (`FAIL_CLOSED_DEFER` vs `FAIL_OPEN_ACCEPT`). | (a) HTTP returns `RETRY_RECOMMENDED`/`ACCEPT`, `rfc_status="temperror"`, never claims SMTP 4xx/5xx; (b) SMTP returns `DEFER` (`451 4.7.x`) or `ACCEPT` (`250`), never `550`. |
| **8** | **Direct Upload Without SMTP Context** | `/api/v1/scans/upload` (and `/parse-raw`) `.eml` for `p=reject` unsigned email and DKIM-signed aligned email; verify `raw_bytes` untouched. | Unsigned $\to$ `SPF=NOT_EVALUATED`, `DMARC=INDETERMINATE`, `rfc_status=None`, archival bytes unmutated, `generated_auth_results_header` preview only; DKIM-signed aligned $\to$ `DMARC=PASS`, `ACCEPT`. |
| **9** | **Forged `Authentication-Results` Using `local_authserv_id`** | Uploaded `.eml` containing `Authentication-Results: <local_authserv_id>; spf=pass; dkim=pass; dmarc=pass`. | Classified `UNTRUSTED_SENDER` (`is_trusted=False`), critical finding `FORGED_AUTHENTICATION_RESULTS_DETECTED`, does not affect Stage 2 results; outbound helper strips forged header. |
| **10** | **Trusted vs. Untrusted Upstream `authserv-id`** | Permute `(matched_config, authenticated_connector_id, mta_sanitization_guaranteed)` + below-untrusted-`Received` / `message/rfc822` attachment header. | `TRUSTED_UPSTREAM` (`is_trusted=True`) **only** when all 3 true at top boundary; partial proof or attached `.eml` demoted to `UNTRUSTED_SENDER`; fails locally remain authoritative. |
| **11** | **Multiple DKIM Signatures (`header.b`, `header.a`, `header.s`)** | Email with 3 DKIM signatures (`rsa-sha256` PASS aligned, `ed25519-sha256` FAIL, `rsa-sha1` PERMERROR), sharing same `d=` and close `b=` values. | Emits 3 separate `; dkim=...` clauses with unique `header.b` ($\ge 8$ chars, extended if needed), `header.d`, `header.s`, `header.a=rsa-sha1`; DMARC passes via aligned sig 0. |
| **12** | **Injection, Malformed Values, Oversize Headers & Folding** | Malicious `\r\nBcc: x`, `\x00`, unbalanced `"`, 10 KB inbound header, ReDoS comment storm, long multi-sig output. | Zero CR/LF injection in serialized output; parser safely isolates & caps oversize/malformed headers; physical folded lines strictly `<= 78` chars (always `< 998`). |
| **13** | **Duplicate Local Result Headers (Idempotency & Non-Mutation)** | Re-scan same `.eml` / exported `.eml` containing prior `local_authserv_id` header; verify no existing `Authentication-Results` field mutated. | Inbound self-header untrusted; outbound copy strips duplicate prior `local_authserv_id` and prepends 1 fresh header at index 0; HTTP `.eml` bytes never modified; existing upstream header never altered. |
| **14** | **Auditable Administrative Override Decisions** | Execute automated `LocalPolicyOverrideRule` match + RBAC-checked triage simulation (`SUPER_ADMIN` vs `SOC_ANALYST` vs `AUDITOR` vs `API_KEY`). | Unauthorized roles fail (`403`); valid overrides write immutable `AuditLogger` + `AuditRecord` entries (`DMARC_POLICY_ENFORCED`, `DMARC_POLICY_OVERRIDE_APPLIED`, `FORGED_AUTHENTICATION_RESULTS_DETECTED`) without PII/secrets leakage. |

---

## 9. Step 3.7.3B+ Implementation Sequence & Expected Files

Proceed **only after explicit review approval** of this inspection & Section 10 decisions:

1. **Step 3.7.3B — Evaluator Reconciliation, Contracts & Pure Policy Enforcer:**
   * Reconcile [contracts.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/contracts.py) (additive enums/models: `DMARCDisposition`, `PolicyOverrideType`, `LocalPolicyOverrideRule`, `DMARCEnforcementDecision`, `DKIMSignatureResult.signature_b_prefix`, `DMARCResult` policy/test-mode fields, `ParsedAuthResultItem.properties`, `AuthProtocolsResult.generated_auth_results_header`).
   * Reconcile `DMARCEvaluator.evaluate()` (`t` retention, multi-`From` check, incomplete-evaluation `INDETERMINATE`, `SPF/DKIM TEMPERROR` propagation) and update the conflicting `NOT_EVALUATED`/`TEMPERROR` $\to$ `FAIL` assertions in [test_dmarc_evaluator.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_dmarc_evaluator.py#L209-L234).
   * Implement pure `DMARCPolicyEnforcer` (`backend/app/modules/auth_protocols/policy_enforcer.py`) implementing Stages 3–5 + unit tests (`backend/tests/test_dmarc_policy_enforcement.py`).
2. **Step 3.7.3C — `Authentication-Results` Trust Evaluator & Generator:**
   * Capture `b=` prefix & fix generic exception $\to$ `INDETERMINATE` in [dkim.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/evaluators/dkim.py).
   * Implement `AuthResultsTrustEvaluator` + `AuthResultsGenerator` in `backend/app/modules/auth_protocols/evaluators/auth_results.py` + unit tests (`backend/tests/test_auth_results.py`).
3. **Step 3.7.3D — Analyzer, Lifespan, Config & `ScanService` Integration:**
   * Add `local_authserv_id` & enforcement settings to [auth_protocols/config.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/config.py) and [core/config.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/core/config.py); wire `DKIMExecutor` two-phase shutdown in [main.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/main.py).
   * Implement `AuthProtocolsAnalyzer` (`backend/app/modules/auth_protocols/analyzer.py`) and wire into [scan_service.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/services/scan_service.py) with audit events & `ScanIncident.telemetry["auth_protocols"]`, plus end-to-end pipeline/regression tests (`backend/tests/test_auth_pipeline.py`).

### Expected Modified / Created Files (Future Implementation Only)
* **New:** `backend/app/modules/auth_protocols/analyzer.py`, `policy_enforcer.py`, `evaluators/auth_results.py`, `backend/tests/test_dmarc_policy_enforcement.py`, `test_auth_results.py`, `test_auth_pipeline.py`.
* **Modified:** `backend/app/modules/contracts.py`, `backend/app/modules/auth_protocols/config.py`, `__init__.py`, `evaluators/__init__.py`, `evaluators/dmarc.py`, `evaluators/dkim.py`, `backend/app/core/config.py`, `backend/app/services/scan_service.py`, `backend/main.py`, `backend/tests/test_contracts.py`, `backend/tests/test_dmarc_evaluator.py`, `backend/tests/test_dkim_verifier.py`.

---

## 10. Explicit Unresolved Decisions (Requiring Sign-Off Before Step 3.7.3B)

While Stages 1–6, `t=y` ordering, RFC 9989 §7.4 fallback rules, conflict-plane precedence, HTTP vs. SMTP channel rules, `Authentication-Results` constraints, and deferral of admin DB/API endpoints are designed cleanly above, the following **specific parameter choices** require explicit confirmation before editing code in Step 3.7.3B:

1. **Approval to Reconcile Existing Conflicting Tests (`C1` & `C2`):**
   * Confirm updating [test_dmarc_evaluator.py:221-230, 342-357, 1196-1205](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_dmarc_evaluator.py#L221-L230) where tests currently assert `DMARC FAIL` on `SPF=NOT_EVALUATED`, `SPF=INDETERMINATE`, `spf_result=None`, and `SPF/DKIM TEMPERROR`, so `DMARCEvaluator` enforces incomplete-evaluation (`INDETERMINATE`) and transient DNS (`TEMPERROR`) safety rules consistently with `REV2`/`REV3`/`test_contracts.py`.
2. **Policy Default for Future SMTP `TEMPERROR` Disposition:**
   * Confirm default `dmarc_temperror_disposition`: **fail-open (`ACCEPT` / SMTP `250`)** vs. **fail-closed (`DEFER` / SMTP `451 4.7.x`)** per RFC 9989 §4.10.1. *(Proposed default: `ACCEPT` for telemetry stability with configurable toggle to `DEFER` for strict MTAs.)*
3. **Production Default When `LOCAL_AUTHSERV_ID` Is Unset:**
   * Confirm whether `local_authserv_id = None` (unconfigured) **skips** generating `generated_auth_results_header` in production (preventing spoofable/non-unique defaults per RFC 8601 §2.5), or uses a development fallback such as `"mailsentra.local"` only when `ENVIRONMENT == "development"`.
4. **Corroborating Threat Integration Toggle Before Modules 5–9 Exist:**
   * Since Modules 5–9 (`RiskEngine`, URL, Attachment, BEC) are not yet implemented, Stage 5 conflict hooks (`confirmed_malicious_attachment`, `confirmed_malicious_url`, `high_confidence_impersonation`) must accept injected optional booleans/findings on `DMARCPolicyEnforcer`. Confirm whether `IdentityAnalysisResult` (Module 3 — already wired in `ScanService`) should count immediately as corroborating Stage 4/5 evidence when `display_name_spoofed`, `typosquatting_detected`, or `homoglyph_detected` triggers alongside `DMARC FAIL + p=reject`.
5. **Transient `TEMPERROR` / Executor-Error Mapping vs. Omission in `Authentication-Results` Header:**
   * Confirm whether *permanent/missing-channel* `DMARC=INDETERMINATE` (e.g. `SPF=NOT_EVALUATED`, 8-query tree-walk exhaustion) is **always omitted** from generated `Authentication-Results` (`; none` if nothing else verified), while genuine transient DNS timeouts emit `dmarc=temperror` directly via Stage 2.
6. **`raw_auth_results_header` Field Deprecation vs. Syncing (`AuthProtocolsResult`):**
   * Confirm keeping existing `AuthProtocolsResult.raw_auth_results_header` synced with `generated_auth_results_header` for backward compatibility vs. keeping `raw_auth_results_header` for legacy callers only while documenting `generated_auth_results_header` as canonical.

---

**Gate Status:** Step 3.7.3A Review Corrections complete. Read-only state preserved (`HEAD = 113132f66b37dc71cf681e15db1925d6b9f68069`). Awaiting explicit approval of this design and Section 10 decisions before beginning Step 3.7.3B.
