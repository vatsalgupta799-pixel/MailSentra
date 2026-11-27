# MailSentra — Step 3.7.2D: Final RFC 9989 Compliance Audit and Remediation

**Repository:** `C:\Users\vatsa\OneDrive\Desktop\MailSantra`  
**Current Baseline Commit:** `113132f66b37dc71cf681e15db1925d6b9f68069`  
**Primary Standards:** RFC 9989 (DMARCbis), RFC 7208 (SPF), RFC 8601 (Authentication-Results)  
**Execution Timestamp:** 2026-11-26T10:16:00+05:30  
**Final Audit Verdict:** **PASS**

---

## 1. Executive Summary & Verdict

This compliance audit was conducted to rigorously verify the three areas of standards-compliance identified in the Step 3.7.2D specification:
1. **The Same-Domain Alignment Shortcut vs. Organizational Domain Determination:** Resolving the distinction between identifier equality and Organizational Domain tree-walk discovery under RFC 9989 §4.4 and §4.10.2.
2. **Synthesized MAIL FROM SPF Evaluation Context:** Verifying that null reverse-path bounces (`MAIL FROM:<>`) evaluate with effective context `postmaster@<helo>`, with verified macro expansion (`%{s}`, `%{l}`, `%{d}`, `%{h}`, `%{o}`) and DNS-query generation.
3. **API Serialization and RFC 9989 Result Representation:** Ensuring that internal diagnostic states (`INDETERMINATE`, `NOT_EVALUATED`) serialize as `null` in standardized result fields and are never falsely converted into public `fail` or `none`.

### Final Verdict: **PASS**
All three areas have been normatively validated against RFC 9989 and RFC 7208, corrected where defective, and verified through 10 new regression tests. All 371 backend tests pass deterministically in 7.76s with zero regressions.

---

## 2. Files Inspected & Modified

### Inspected Files:
- `backend/app/modules/contracts.py`
- `backend/app/modules/auth_protocols/evaluators/dmarc.py`
- `backend/app/modules/auth_protocols/evaluators/spf.py`
- `backend/app/modules/auth_protocols/dns_resolver.py`
- `backend/app/schemas/scan.py`
- `backend/app/api/v1/endpoints/scans.py`
- `backend/tests/test_dmarc_evaluator.py`
- `backend/tests/test_spf_evaluator.py`
- `backend/tests/test_contracts.py`

### Modified Files:
- [backend/app/modules/contracts.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/contracts.py): Added `computed_field` to `rfc_status` property in `DMARCResult` so that Pydantic `model_dump()` and `model_dump_json()` reliably serialize the standardized IANA result string.
- [backend/app/modules/auth_protocols/evaluators/dmarc.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/evaluators/dmarc.py): Relocated and corrected the `aligned_strict` same-domain evaluation in `check_domain_alignment()` to occur after `from_org` has been authoritatively determined per RFC 9989 §4.10.2.
- [backend/tests/test_dmarc_evaluator.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_dmarc_evaluator.py): Added regression tests for author subdomain same-domain alignment and organizational domain inheritance.
- [backend/tests/test_spf_evaluator.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_spf_evaluator.py): Added regression tests verifying DNS query generation and macro expansion for synthesized bounce identities.
- [backend/tests/test_contracts.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_contracts.py): Added unit and serialization tests for `DMARCResult` and `AuthProtocolsResult` across all protocol statuses.

---

## 3. Detailed Audit Findings by Task

### Task 1 — Audit of the Same-Domain Alignment Shortcut

#### Investigated Scenario:
- RFC 5322 From domain: `mail.example.com`
- Authenticated SPF / DKIM identifier: `mail.example.com`
- DMARC policy exists only at `_dmarc.example.com`
- No DMARC policy exists at `_dmarc.mail.example.com`

#### Code-Level Defect Identified:
In `backend/app/modules/auth_protocols/evaluators/dmarc.py` (lines 891–905 prior to correction):
```python
aligned_strict = (a_norm == f_norm)
if aligned_strict:
    effective_from = org_domain_from or org_domain_hint or f_norm
    return AlignmentOutcome(
        is_aligned=True,
        aligned_strict=True,
        aligned_relaxed=True,
        discovery_status=DMARCDiscoveryStatus.FOUND,
        auth_org_domain=effective_from,
        from_org_domain=effective_from,
    )
```
When `org_domain_from` and `org_domain_hint` were omitted, `effective_from` defaulted to `f_norm` (`"mail.example.com"`). When `DMARCEvaluator.evaluate()` consumed this outcome, it overwrote `effective_org_domain` with `outcome.from_org_domain` (`"mail.example.com"`), causing `DMARCResult.org_domain` to be reported as `"mail.example.com"` rather than the true Organizational Domain `"example.com"`.

#### Normative Standards Analysis:
1. **Identifier Equality vs. Organizational Domain:**
   - RFC 9989 §4.4 states:
     - Strict mode: The authenticated domain and Author Domain must match exactly.
     - Relaxed mode: The authenticated domain and Author Domain must share the same Organizational Domain.
   - If `a_norm == f_norm`:
     - Strict alignment is satisfied (`mail.example.com == mail.example.com`).
     - Relaxed alignment is satisfied because by mathematical identity, identical domains share the identical Organizational Domain.
   - **However**, string equality of identifiers does not define what that Organizational Domain actually is. The Organizational Domain must be determined using the RFC 9989 §4.10.2 tree walk (or retrieved from policy discovery §4.10.1 cache), where `mail.example.com` discovers `_dmarc.example.com`, giving `org_domain = "example.com"`.
2. **Policy Discovery Preservation:**
   - DMARC policy discovery (RFC 9989 §4.10.1) is always performed first on `norm_from`. If no DMARC record exists in the DNS tree, `evaluate()` terminates with `ProtocolStatus.NONE`. Identifier alignment is never evaluated if policy discovery fails.
3. **Query Limit Budget:**
   - Policy discovery traverses `mail.example.com` -> `example.com` (2 queries).
   - In `check_domain_alignment()`, `mail.example.com` is already cached in `org_domain_cache`.
   - Because `a_norm == f_norm`, `auth_org` is identically `from_org`, completely eliminating a redundant second DNS tree walk. Total queries for the entire DMARC evaluation remain at 2 (well below the 8-query limit).

#### Correction Implemented:
`check_domain_alignment()` was updated so that `from_org` is authoritatively resolved from `org_domain_cache` or `disc_runner.determine_org_domain(f_norm)` first. If `aligned_strict` is True, it returns `auth_org_domain=from_org` and `from_org_domain=from_org`, preserving `"example.com"` as the Organizational Domain.

---

### Task 2 — Verification of Synthesized MAIL FROM Evaluation

#### Normative Standards Analysis:
- **RFC 7208 §2.4:** *"If the reverse-path was null, the 'MAIL FROM' identity is synthesized from the EHLO/HELO domain: the local-part is 'postmaster', and the domain is the EHLO/HELO domain."*
- **RFC 9989 §3.2.4 & §4.4.2:** DMARC relies on the RFC 5321.MailFrom identity as defined by RFC 7208 §2.4.
- **RFC 7208 §7.1:** For a null reverse path, macro `%s` is `postmaster@<helo>`, `%l` is `postmaster`, `%o` is `<helo>`, and `%d` is the current evaluation domain.

#### Findings & Behavioral Verification:
1. When `SPFEvaluator.evaluate(smtp_metadata, scope="mfrom")` processes a null reverse-path message (`mail_from_envelope="<>"` or `""` with `is_trusted_mta=True`):
   - `effective_scope` is set to `"helo"` (for RFC 7208 mechanism compatibility).
   - `is_synthesized_mfrom` is set to `True`.
   - `is_null_reverse_path` is set to `True`.
   - `is_standalone_helo` is set to `False`.
   - `identity` is set to `f"postmaster@{helo}"`.
   - `ctx.mail_from` is initialized with `f"postmaster@{helo}"`.
2. **Actual Macro Expansion and DNS Query Generation:**
   - In `test_step372d_null_reverse_path_macro_expansion_and_dns_queries`:
     - SPF record: `v=spf1 exists:%{l}._spf.%{d} exists:%{s}._spf.%{h} -all`
     - Connecting HELO: `outbound.mailrelay.com`
     - Evaluator expanded `%{l}._spf.%{d}` to `postmaster._spf.outbound.mailrelay.com`.
     - `MockDNSResolver.recorded_queries` verified an actual A-record DNS query for `("postmaster._spf.outbound.mailrelay.com", DNSQueryType.A)`.
3. **DMARC Consumption and Standalone HELO Rejection:**
   - If an SPF check was run with explicit `scope="helo"`, `is_standalone_helo` is `True` and `is_synthesized_mfrom` is `False`.
   - `DMARCEvaluator.evaluate()` checks:
     ```python
     is_synthesized_bounce = (
         spf_result.is_null_reverse_path
         and spf_result.is_synthesized_mfrom
         and not spf_result.is_standalone_helo
     )
     ```
   - Standalone HELO checks on a message are rejected for DMARC alignment (`SPF standalone HELO check ignored for DMARC (RFC 9989 §4.4.2)`).
   - Only genuine synthesized MAIL FROM bounces are accepted for DMARC alignment.
4. **Transport Metadata Integrity:**
   - When `is_trusted_mta=False`, `SPFEvaluator` immediately aborts with `ProtocolStatus.NOT_EVALUATED`, preventing untrusted message headers from injecting forged envelope metadata.

---

### Task 3 — Audit of API Serialization and Public DMARC Results

#### Normative Standards Analysis:
- **RFC 9989 §9.2:** IANA DMARC Result Codes Registry specifies valid values: `pass`, `fail`, `none`, `permerror`, `temperror`.
- Incomplete evaluations (e.g. query-limit exhaustion or `INDETERMINATE`) and unevaluated states (`NOT_EVALUATED`) have no RFC 9989 result code. They must never be converted into `fail`, `none`, or an invented string in standardized fields.

#### Findings & Serialization Correction:
1. `DMARCResult` in `backend/app/modules/contracts.py` defines:
   - `status: ProtocolStatus` (internal engine status enum).
   - `standard_status: Optional[str]` (standardized string or `None`).
   - `rfc_status` property.
2. Previously, `rfc_status` was a standard Python `@property`. In Pydantic v2, standard properties are omitted during `.model_dump()` and `.model_dump_json()`.
3. **Correction:** Annotated `@computed_field` on `rfc_status`:
   ```python
   @computed_field
   @property
   def rfc_status(self) -> Optional[str]:
   ```
4. **Resulting JSON Serialization Matrix:**

| Internal Status | `standard_status` (dict) | `rfc_status` (JSON/dict) | Public RFC Result Representation |
|---|---|---|---|
| `ProtocolStatus.PASS` | `"pass"` | `"pass"` | Standard DMARC `pass` |
| `ProtocolStatus.FAIL` | `"fail"` | `"fail"` | Standard DMARC `fail` |
| `ProtocolStatus.NONE` | `"none"` | `"none"` | Standard DMARC `none` (no policy published) |
| `ProtocolStatus.TEMPERROR` | `"temperror"` | `"temperror"` | Standard DMARC `temperror` |
| `ProtocolStatus.PERMERROR` | `"permerror"` | `"permerror"` | Standard DMARC `permerror` |
| `ProtocolStatus.INDETERMINATE` | `None` (`null`) | `None` (`null`) | Incomplete evaluation; internal diagnostic state |
| `ProtocolStatus.NOT_EVALUATED` | `None` (`null`) | `None` (`null`) | Unevaluated; not a completed evaluation |

API clients deserializing the JSON payload can unambiguously distinguish between an RFC-defined result and an incomplete or internal diagnostic state.

---

## 4. Normative RFC Evidence and Quotes

### RFC 9989 §4.4 (Identifier Alignment):
> *"In relaxed mode, the DKIM d= domain and the RFC5322.From domain MUST have the same Organizational Domain."*  
> *"In strict mode, the DKIM d= domain and the RFC5322.From domain MUST match exactly."*  
> *"In relaxed mode, the RFC5321.MailFrom domain and the RFC5322.From domain MUST have the same Organizational Domain."*  
> *"In strict mode, the RFC5321.MailFrom domain and the RFC5322.From domain MUST match exactly."*

### RFC 9989 §4.10.1 (Policy Discovery):
> *"To discover a DMARC policy record for an Author Domain, the Mail Receiver MUST query the DNS for a DMARC TXT record at the Author Domain name prefixed with '_dmarc.'... If no DMARC policy record is found, the Mail Receiver MUST apply the tree walk procedure described in Section 4.10.2."*

### RFC 9989 §4.10.2 (Tree Walk for Organizational Domain Determination):
> *"Rule 1: If a retrieved DMARC policy record contains 'psd=n', the domain where the record was found is the Organizational Domain."*  
> *"Rule 2: If the record contains 'psd=y' and the record was found other than at the starting domain of the walk, the domain one label below is the Organizational Domain."*  
> *"Rule 3: If candidate records were retrieved with 'psd=u' (or omitted), select the candidate record found at the name with the fewest number of labels. This is the Organizational Domain."*

### RFC 9989 §9.2 (DMARC Result Codes Registry):
> *"The IANA registry 'DMARC Result Codes' has been created... The registry contains the following initial entries: none, pass, fail, temperror, permerror."*

### RFC 7208 §2.4 (The "MAIL FROM" Identity):
> *"If the reverse-path was null, the 'MAIL FROM' identity is synthesized from the EHLO/HELO domain: the local-part is 'postmaster', and the domain is the EHLO/HELO domain."*

### RFC 7208 §7.1 (Macro Definitions):
> *"'s' represents the sender... 'l' represents the local-part of the sender... 'o' represents the domain of the sender... 'd' represents the current domain... 'h' represents the HELO/EHLO domain."*

---

## 5. Test Execution & Regression Telemetry

### 5.1 Focused Authentication Protocol Suites
**Command:**
```powershell
$env:PYTHONPATH="backend"; backend\.venv\Scripts\python.exe -m pytest backend\tests\test_dmarc_evaluator.py backend\tests\test_spf_evaluator.py backend\tests\test_contracts.py backend\tests\test_dmarc_discovery.py backend\tests\test_dkim_verifier.py backend\tests\test_dkim_executor.py -v
```
**Outcome:** **211 passed in 3.21s (Exit Code: 0)**

### 5.2 Full Backend Test Suite
**Command:**
```powershell
$env:PYTHONPATH="backend"; backend\.venv\Scripts\python.exe -m pytest backend\tests -v
```
**Outcome:** **371 passed in 7.76s (Exit Code: 0)**

### 5.3 Test Suite Progression Baseline:
- Step 3.6 Baseline: 253 tests
- Step 3.7.1 Baseline: 270 tests
- Step 3.7.2 Baseline: 345 tests
- Step 3.7.2C Baseline: 361 tests
- **Step 3.7.2D Baseline: 371 tests (All Passing, 0 Failures, 0 Warnings)**

---

## 6. Remaining Limitations & Non-Implemented Scope

The following areas are intentionally outside the boundary of Step 3.7.2 and remain strictly unstarted:
1. **DMARC Policy Enforcement / Disposition:** Rejecting, quarantining, or routing messages based on `p=` or `sp=` policies (belongs to policy enforcement stage).
2. **`Authentication-Results` Header Emission:** Formatting and prepending RFC 8601 auth headers (Step 3.7.3).
3. **Aggregate (RUA) and Forensic (RUF) Reporting:** Parsing or sending XML feedback reports.
4. **Authenticated Received Chain (ARC):** RFC 8617 evaluation.

---

## 7. Git Safeguards Confirmation

- **Branch:** `main`
- **Baseline HEAD:** `113132f66b37dc71cf681e15db1925d6b9f68069`
- **Staging (`git add`):** None (0 files staged).
- **Commits:** None (0 commits made).
- **Pushes:** None (0 pushes made).
- **Working Tree Integrity:** All uncommitted Day 3 work and untracked files are strictly preserved.
