# MailSentra — Focused RiskEngine Header-Integrity Signal Remediation Report

**Date:** 2026-11-28  
**Scope:** Remediation of the signal-integration gap between `SenderIdentityAnalyzer` and `RiskEngine` (`engine.py`)  
**Auditor/Engineer:** Senior ML Security Engineer & Python Security Auditor  
**Status:** COMPLETE & VERIFIED (776/776 tests passing)

---

## 1. Executive Summary

During the second external benchmark evaluation (`RUN-20261128-090528`), an acute detection gap was identified where 100% of the 542 false negatives received a risk score of `0.0` (tier `CLEAN`). In the EPVME protocol spoofing corpus (`DS-SS-01`), 140 of the 153 false negatives (91.5%) featured RFC 5322 From-header injection (XSS payloads, control characters, unclosed angle brackets).

Source-code inspection revealed that while `SenderIdentityAnalyzer` (Module 3) **successfully detected and flagged** these structural header violations (emitting `MALFORMED_SENDER_ADDRESS` and `EMPTY_RETURN_PATH`), `RiskEngine.evaluate()` only evaluated identity findings matching `"IMPERSONATION"`, `"MISMATCH"`, or `"LOOKALIKE"`. All structural header integrity findings were silently discarded, collapsing risk scores to zero and defaulting threat tiers to `CLEAN`.

This remediation bridges that signal gap safely, deterministically, and with zero impact on existing detection vectors:
1. Established an explicit set of actionable RFC 5322 structural header integrity indicators in `RiskEngine`.
2. Avoided broad substring matching (no wildcard matching of `EMPTY`, `MALFORMED`, or `DUPLICATE`).
3. Explicitly preserved benign handling of absent `Return-Path` headers (`EMPTY_RETURN_PATH` is never penalized alone).
4. Implemented finding-key deduplication to guarantee that duplicate findings for the same underlying header defect do not inflate risk scores or signals.
5. Added 11 focused regression tests covering benign, adversarial, deduplication, and mixed-severity scenarios.
6. Validated the full backend test suite: **776 passed in 17.51s (exit code 0)**.

---

## 2. Confirmed Root Cause from Source Code

### 2.1 Upstream Detection vs Downstream Aggregation Disconnect

In [backend/app/modules/identity/rules/header_integrity.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/identity/rules/header_integrity.py), the rule `check_header_integrity()` evaluates RFC 5322 header constraints:
- Missing mandatory From header $\rightarrow$ `MISSING_FROM_HEADER`
- Multiple separate From header lines $\rightarrow$ `DUPLICATE_FROM_HEADER`
- Multiple Reply-To header lines $\rightarrow$ `DUPLICATE_REPLY_TO_HEADER`
- Mailbox syntax violation or illegal characters $\rightarrow$ `MALFORMED_SENDER_ADDRESS`
- Multiple From mailboxes missing Sender header $\rightarrow$ `MISSING_SENDER_HEADER`
- Multiple Sender header lines $\rightarrow$ `DUPLICATE_SENDER_HEADER`

In [backend/app/modules/risk_engine/engine.py:82-90](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/risk_engine/engine.py#L82-L90) prior to remediation, the identity signal evaluation loop read:
```python
# PRIOR DEFECTIVE IMPLEMENTATION:
if identity_result:
    if identity_result.analysis_status == "FAILED":
        failed_modules.append("SenderIdentityAnalyzer")
    for f in identity_result.findings:
        if f.is_vip or "IMPERSONATION" in f.indicator:
            is_malicious = True
            base_score = max(base_score, 80.0)
            contributing_signals.append(f"[IDENTITY-IMPERSONATION] {f.indicator}: {f.description}")
        elif "MISMATCH" in f.indicator or "LOOKALIKE" in f.indicator:
            is_suspicious = True
            base_score = max(base_score, 55.0)
            contributing_signals.append(f"[IDENTITY-MISMATCH] {f.indicator}: {f.description}")
```

### 2.2 Why Findings Were Discarded
When an adversarial email contained a malformed sender address (e.g. `<"test<marquee onstart=alert(/xss/)></marquee>@attack.com">`):
1. `f.is_vip` was `False`.
2. `"IMPERSONATION" in "MALFORMED_SENDER_ADDRESS"` evaluated to `False`.
3. `"MISMATCH" in "MALFORMED_SENDER_ADDRESS"` evaluated to `False`.
4. `"LOOKALIKE" in "MALFORMED_SENDER_ADDRESS"` evaluated to `False`.

Consequently, the loop completed without matching any branch. Neither `is_malicious` nor `is_suspicious` was set to `True`. `base_score` remained `0.0`. No signals were appended to `contributing_signals`. The email fell through to the default branch:
```python
else:
    tier = RiskTier.CLEAN
    score = 0.0
    summary = "CLEAN EMAIL. All active detection modules (Identity, Auth, URLs, Attachments) passed cleanly."
```

---

## 3. Exact Files Changed

1. **[backend/app/modules/risk_engine/engine.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/risk_engine/engine.py)**:
   - Added class constant `HEADER_INTEGRITY_INDICATORS` containing explicit actionable RFC 5322 header defect indicators.
   - Added explicit handling branch for `f.indicator in self.HEADER_INTEGRITY_INDICATORS` setting `is_suspicious = True`, `base_score = max(base_score, 55.0)`, and prefix `[IDENTITY-HEADER-INTEGRITY]`.
   - Introduced `seen_identity_keys` tracking to deduplicate redundant signals for the same underlying finding and prevent score inflation.
2. **[backend/tests/test_risk_engine_header_remediation.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_risk_engine_header_remediation.py)**:
   - New dedicated regression test suite containing 11 tests verifying all functional requirements and edge cases.

---

## 4. Explicit Indicator-to-Risk Mapping

To strictly satisfy the requirement prohibiting broad substring matching (e.g. matching wildcard `EMPTY`, `MALFORMED`, or `DUPLICATE`), `RiskEngine` now maintains an explicit whitelist of verified structural header defect indicators:

```python
HEADER_INTEGRITY_INDICATORS = {
    "MALFORMED_SENDER_ADDRESS",
    "DUPLICATE_FROM_HEADER",
    "MISSING_FROM_HEADER",
    "DUPLICATE_REPLY_TO_HEADER",
    "DUPLICATE_SENDER_HEADER",
    "MISSING_SENDER_HEADER",
}
```

### 4.1 Detailed Mapping Table

| Indicator | Source Rule | Actionable Defect? | Target Tier | Base Score | Signal Category & Prefix | Rationale |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `MALFORMED_SENDER_ADDRESS` | `header_integrity.py` | **Yes** | `SUSPICIOUS` | 55.0 | `[IDENTITY-HEADER-INTEGRITY]` | Violates RFC 5322 §3.4.1 mailbox syntax; primary vector for parser confusion and XSS injection. |
| `DUPLICATE_FROM_HEADER` | `header_integrity.py` | **Yes** | `SUSPICIOUS` | 55.0 | `[IDENTITY-HEADER-INTEGRITY]` | RFC 5322 §3.6 strictly permits exactly one From header; classic header injection vector. |
| `MISSING_FROM_HEADER` | `header_integrity.py` | **Yes** | `SUSPICIOUS` | 55.0 | `[IDENTITY-HEADER-INTEGRITY]` | RFC 5322 §3.6 mandates From header; email without sender identity is severely structurally invalid. |
| `DUPLICATE_REPLY_TO_HEADER` | `header_integrity.py` | **Yes** | `SUSPICIOUS` | 55.0 | `[IDENTITY-HEADER-INTEGRITY]` | RFC 5322 §3.6.2 permits at most one Reply-To header. |
| `DUPLICATE_SENDER_HEADER` | `header_integrity.py` | **Yes** | `SUSPICIOUS` | 55.0 | `[IDENTITY-HEADER-INTEGRITY]` | RFC 5322 §3.6.2 permits at most one Sender header. |
| `MISSING_SENDER_HEADER` | `header_integrity.py` | **Yes** | `SUSPICIOUS` | 55.0 | `[IDENTITY-HEADER-INTEGRITY]` | RFC 5322 §3.6.2 requires Sender header when From contains multiple mailboxes. |
| `EMPTY_RETURN_PATH` | `address_alignment.py` | **No** (Informational) | *Ignored* | 0.0 | *None* | RFC 5321 permits null return-path (bounces, DSNs, initial client submissions). Must NOT penalize. |
| `RECOGNIZED_ESP_RETURN_PATH` | `address_alignment.py` | **No** (Benign) | *Ignored* | 0.0 | *None* | Valid third-party ESP routing alignment. |
| `MULTIPLE_FROM_MAILBOXES` | `header_integrity.py` | **No** (Compliant) | *Ignored* | 0.0 | *None* | Informational finding noting compliant multi-sender message when Sender is present. |
| `PUNYCODE_DOMAIN_LABEL` | `lookalike_domain.py` | **No** (Informational) | *Ignored* | 0.0 | *None* | Standard internationalized domain encoding; requires corroborating typosquatting. |

---

## 5. Scoring Behavior Before and After

### 5.1 Established Scoring Conventions
- **Suspicious Baseline:** In `RiskEngine`, all existing suspicious identity signals (`"MISMATCH"` and `"LOOKALIKE"`) assign `base_score = max(base_score, 55.0)`. Structural header integrity findings reuse this exact Module 3 baseline (55.0).
- **Signal Multiplier:** Under `RiskTier.SUSPICIOUS`, final score is calculated as:
  $$\text{score} = \min(74.0, \text{base\_score} + \min(10.0, \text{len}(\text{contributing\_signals}) \times 2.0))$$
  - 1 signal $\rightarrow 55.0 + 2.0 = 57.0$ (`SUSPICIOUS`)
  - 2 distinct signals $\rightarrow 55.0 + 4.0 = 59.0$ (`SUSPICIOUS`)
  - Max suspicious cap: 74.0 (MALICIOUS tier begins at 75.0+).
- **Corroboration Precedence:** If an email contains both a malicious indicator (e.g. Malicious URL, base 85.0) and a header integrity finding, `is_malicious` remains `True`, tier remains `RiskTier.MALICIOUS` (score $\ge 85.0$), and the header integrity signal appears as corroborating evidence without downgrading the tier.

### 5.2 Deduplication Mechanics (Avoiding Double-Counting)
In `header_integrity.py`, both `from_sender` and `all_from_senders` are inspected. An email with a malformed From address previously generated two separate `ImpersonationFinding` objects with slightly differing representations (e.g. `raw='"test<marquee...>@attack.com"'` vs `address='test<marquee...>@attack.com'`).

To prevent double-counting:
- In `RiskEngine`, `seen_identity_keys` tracks `("HEADER_INTEGRITY", f.indicator)`.
- The first `MALFORMED_SENDER_ADDRESS` finding sets `is_suspicious = True`, records `sig_key = ("HEADER_INTEGRITY", "MALFORMED_SENDER_ADDRESS")`, and appends the signal.
- Any subsequent `MALFORMED_SENDER_ADDRESS` finding matches the seen key and is skipped.
- `len(contributing_signals)` remains 1, ensuring the score is precisely 57.0, NOT 59.0.

### 5.3 Behavior Comparison

| Scenario | Raw Findings | Score Before | Tier Before | Score After | Tier After | Contributing Signals After |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Malformed Sender (`<marquee>` XSS in From)** | `[EMPTY_RETURN_PATH, MALFORMED_SENDER_ADDRESS (x2)]` | 0.0 | `CLEAN` | **57.0** | `SUSPICIOUS` | `[IDENTITY-HEADER-INTEGRITY] MALFORMED_SENDER_ADDRESS: ...` (exactly 1 signal) |
| **Duplicate From Header** | `[DUPLICATE_FROM_HEADER]` | 0.0 | `CLEAN` | **57.0** | `SUSPICIOUS` | `[IDENTITY-HEADER-INTEGRITY] DUPLICATE_FROM_HEADER: ...` |
| **Missing From Header** | `[MISSING_FROM_HEADER]` | 0.0 | `CLEAN` | **57.0** | `SUSPICIOUS` | `[IDENTITY-HEADER-INTEGRITY] MISSING_FROM_HEADER: ...` |
| **Duplicate From + Malformed Address** | `[MALFORMED_SENDER_ADDRESS, DUPLICATE_FROM_HEADER]` | 0.0 | `CLEAN` | **59.0** | `SUSPICIOUS` | Both distinct signals present (len=2, +4.0 pts) |
| **Absent Return-Path Alone** | `[EMPTY_RETURN_PATH]` | 0.0 | `CLEAN` | **0.0** | `CLEAN` | `[]` (Clean email unaffected) |
| **Normal Benign Email** | `[]` | 0.0 | `CLEAN` | **0.0** | `CLEAN` | `[]` (Clean email unaffected) |
| **VIP Impersonation** | `[VIP_IMPERSONATION]` | 80.0+ | `MALICIOUS` | **80.0+** | `MALICIOUS` | Unchanged |
| **Malformed Sender + Malicious URL** | `[MALFORMED_SENDER_ADDRESS, URL-MALICIOUS]` | 85.0+ | `MALICIOUS` | **89.0** | `MALICIOUS` | Both signals present; tier stays MALICIOUS |

---

## 6. Tests Added & Validation Results

### 6.1 Focused Regression Test Suite
Created [backend/tests/test_risk_engine_header_remediation.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_risk_engine_header_remediation.py) containing 11 tests:
1. `test_malformed_sender_address_contributes_risk_signal`: Validates adversarial XSS `<marquee>` payload in From address produces `RiskTier.SUSPICIOUS` and score in $[55.0, 74.0]$.
2. `test_duplicate_from_header_contributes_risk_signal`: Validates multi-From injection produces `RiskTier.SUSPICIOUS` and score in $[55.0, 74.0]$.
3. `test_missing_from_header_contributes_risk_signal`: Validates email missing From header produces `RiskTier.SUSPICIOUS` and score in $[55.0, 74.0]$.
4. `test_absent_return_path_alone_remains_clean`: Validates email missing Return-Path (emitting `EMPTY_RETURN_PATH`) produces `RiskTier.CLEAN`, score 0.0, and empty signals.
5. `test_normal_email_with_valid_headers_remains_clean`: Validates clean email evaluates as `RiskTier.CLEAN` with score 0.0.
6. `test_existing_vip_impersonation_scoring_unchanged`: Validates VIP impersonation continues to score `RiskTier.MALICIOUS` with score $\ge 80.0$.
7. `test_existing_from_replyto_mismatch_scoring_unchanged`: Validates From vs Reply-To domain mismatch continues to score `RiskTier.SUSPICIOUS` with score in $[55.0, 74.0]$.
8. `test_existing_url_risk_behavior_unchanged`: Validates standalone URL analyzer results continue to yield `MALICIOUS` ($\ge 85.0$) and `SUSPICIOUS` ($\ge 45.0$).
9. `test_findings_are_not_counted_twice`: Validates that passing redundant `MALFORMED_SENDER_ADDRESS` findings generates exactly 1 contributing signal and score 57.0 (not 59.0).
10. `test_multiple_distinct_header_anomalies_contribute_distinct_signals`: Validates that distinct anomalies (`MALFORMED_SENDER_ADDRESS` and `DUPLICATE_FROM_HEADER`) each add their own signal and increment score to 59.0.
11. `test_header_integrity_does_not_override_malicious_tier`: Validates that combining a header integrity finding with a malicious URL retains `RiskTier.MALICIOUS` with score $\ge 85.0$.

### 6.2 Test Execution Commands and Results

| Test Suite Scope | Execution Command | Tests Passed | Failures | Execution Time | Exit Code |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **New Regression Suite** | `$env:PYTHONPATH=".;backend"; & backend\.venv\Scripts\pytest.exe -v backend\tests\test_risk_engine_header_remediation.py` | **11** | 0 | 0.27s | **0** |
| **Identity & E2E Suites** | `$env:PYTHONPATH=".;backend"; & backend\.venv\Scripts\pytest.exe -v backend\tests\test_identity_analyzer.py backend\tests\test_end_to_end_validation.py` | **50** | 0 | 3.70s | **0** |
| **Full Backend Test Suite** | `$env:PYTHONPATH=".;backend"; & backend\.venv\Scripts\pytest.exe backend\tests -q` | **776** | 0 | 17.51s | **0** |

---

## 7. Remaining Risks & Unresolved Questions

1. **Controlled Evaluation Requirement:** While unit tests confirm that `MALFORMED_SENDER_ADDRESS` and `DUPLICATE_FROM_HEADER` now correctly yield `RiskTier.SUSPICIOUS` (score 57.0), no claim is made that the 140 EPVME false negatives are fixed until a future controlled benchmark evaluation is executed.
2. **False-Positive Risk on Real-World Benign Mail:** Although standard email clients and compliant MTAs strictly generate valid RFC 5322 From headers, zero false-positive risk cannot be claimed without evaluating a large, clean benign control corpus. Certain legacy automated mailing scripts or internally forwarded mail fragments could theoretically emit malformed sender headers.
3. **Subsequent Detection Priorities (Priorities 2–5):**
   - **Priority 2 (Nazario Subdomain Squatting):** 120+ Nazario false negatives remain unaddressed because brand tokens embedded in subdomains (e.g. `*.chase.com.evilhost.jp`) are not yet inspected by `UrlAnalyzer`.
   - **Priority 3 (Display Name Brand Spoofing):** 40+ Nazario false negatives using brand display names on unaligned non-free domains remain unaddressed.
   - **Priority 4 (Lexical / Spam Content):** 228 SpamAssassin commercial spam samples remain undetected due to the absence of statistical/Bayesian text classifiers.
   - **Priority 5 (Offline Auth Inspection):** Structural `Received-SPF: fail` inspection remains unaddressed.

---

## 8. Final Verdict

The signal-integration defect between `SenderIdentityAnalyzer` and `RiskEngine` is **fully remediated**. All verified structural header integrity findings are now deterministically aggregated into appropriate risk scores and tiers, redundant signals are deduplicated, absent Return-Path headers remain non-penalized, and all 776 backend tests pass.
