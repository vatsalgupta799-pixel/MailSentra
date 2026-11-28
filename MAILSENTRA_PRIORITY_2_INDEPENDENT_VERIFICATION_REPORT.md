# MailSentra — Priority 2: Independent Detection and Evaluation Verification Report

**Date:** 2026-11-28  
**Scope:** Independent verification of Subdomain Brand Impersonation Detection (`config.py`, `hostname_analyzer.py`, `url_detectors.py`, `risk_scorer.py`, `RiskEngine`, and the Priority 2 micro-evaluation artifacts)  
**Verdict:** **CONDITIONALLY ACCEPTED**

---

## 1. Executive Summary

An independent code, pipeline, and evaluation audit was conducted on MailSentra's Priority 2 Subdomain Brand Impersonation Detection feature.

- **Detection implementation & RiskEngine integration:** **Verified.** All 10 technical verification criteria pass. The detector uses exact hostname-label matching, production offline PSL resolution (`tldextract.TLDExtract(suffix_list_urls=None)`), proper canonical brand exclusions, IDN/punycode decoding, trailing-dot normalization, safe malformed-URL handling, and single-signal emission per URL. A standalone `SUBDOMAIN_BRAND_IMPERSONATION` signal (weight `6`) deterministically yields `UrlRiskSeverity.SUSPICIOUS` in `RiskScorer` and `RiskTier.SUSPICIOUS` (`score = 47.0`) in `RiskEngine`.
- **Evaluation methodology:** **Partially independent (selection bias identified).** While metric calculations are exact and dataset-derived vs. synthetic categories are cleanly separated, Category A positive examples (133 records) were selected using a heuristic (`brand_in_subdomain`) that mirrors the detector's own multi-label matching rule and 17-brand list. Additionally, the 292-record corpus contains 6 duplicate URLs (8 duplicate hostnames), and the 91 Tranco benign controls all use a uniform `www.<domain>` pattern.
- **Documentation fix applied:** Corrected the count inconsistency in `MAILSENTRA_PRIORITY_2_SUBDOMAIN_BRAND_DETECTION_REPORT.md` (Section 2.3 previously stated `6 protected brands` while listing `7` brands in the table and `7` in Section 3.1).

---

## 2. Detection Implementation Findings

Inspected [`config.py`](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/url_analysis/config.py), [`hostname_analyzer.py`](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/url_analysis/hostname_analyzer.py), [`url_detectors.py`](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/url_analysis/url_detectors.py), [`normalizer.py`](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/url_analysis/normalizer.py), [`analyzer.py`](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/url_analysis/analyzer.py), and [`domain_utils.py`](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/identity/domain_utils.py).

| # | Verification Criterion | Result | Evidence / Mechanism |
|---|------------------------|--------|----------------------|
| 1 | Complete hostname-label matching | ✅ Verified | Rule 1 (`hostname_analyzer.py:240-249`) checks exact label-slice equality `subdomain_labels[i : i + k] == brand_labels`. Rule 2 (`hostname_analyzer.py:262-272`) checks exact label membership `brand_stem in subdomain_labels`. Substrings like `paypalsupport.example.com` and `example-paypal.com` are not flagged. |
| 2 | Production PSL registered-domain identification | ✅ Verified | `get_registered_domain_offline()` (`domain_utils.py:66-76`) uses `_OFFLINE_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)` with zero network calls. Verified on `www.paypal.com.au` → `paypal.com.au` and `ebay.com.attacker.co.uk` → `attacker.co.uk`. |
| 3 | Canonical brand-domain exclusions | ✅ Verified | `hostname_analyzer.py:204` skips `norm_host == reg_domain`; lines `225-232` skip when `reg_domain == brand_reg`, `reg_domain == norm_brand`, `is_subdomain_of(reg_domain, norm_brand)`, or `is_subdomain_of(norm_brand, reg_domain)`. |
| 4 | Multi-label brand-domain matching | ✅ Verified | Rule 1 (`k >= 2`) slides a window of length `k` across `subdomain_labels` and `decoded_sub_labels`, detecting `nationalcity.com`, `ebay.com`, `bankofamerica.com`, etc. |
| 5 | Standalone brand-stem matching | ✅ Verified | Rule 2 checks `brand_stem = brand_labels[0]` when `len(brand_stem) >= 4` (e.g., `paypal.example.org` → matches `paypal` for `paypal.com`). |
| 6 | IDN and punycode handling | ✅ Verified | `decode_idna_safely()` (`domain_utils.py:148-165`) decodes `xn--` labels; `hostname_analyzer.py:210-217` extracts `decoded_sub_labels` and evaluates both ASCII and decoded labels. Tested `https://paypal.com.xn--bcher-kva.de/login` (detected) and `https://xn--pypal-4ve.com.evil.org/login` (caught by `HOMOGRAPH_HOSTNAME` + `PUNYCODE_DETECTED`). |
| 7 | Trailing-dot handling | ✅ Verified | `normalize_domain()` (`domain_utils.py:47`) strips trailing dots (`.rstrip(".")`). Verified `https://paypal.com.example.org./login` and `https://paypal.com.example.org../login` are detected, while `https://www.paypal.com./login` remains `SAFE`. |
| 8 | Malformed URL handling | ✅ Verified | `UrlNormalizer.parse()` (`normalizer.py:28-138`) handles empty/whitespace strings, unclosed IPv6 brackets, invalid ports, and userinfo-only authorities without raising exceptions. `HostnameAnalyzer.analyze()` returns early on empty `host_stripped` or IP literals. |
| 9 | Duplicate signal prevention | ✅ Verified | Once Rule 1 or Rule 2 matches in `HostnameAnalyzer.analyze()`, `res.subdomain_brand_target` is set and the loop `break`s (`hostname_analyzer.py:257, 272`). Confirmed `http://paypal.com.paypal.example.org/login` emits `SUBDOMAIN_BRAND_IMPERSONATION` exactly once. |
| 10 | RiskEngine scoring & thresholds | ✅ Verified | Weight `6` → `UrlRiskSeverity.SUSPICIOUS` → `RiskTier.SUSPICIOUS` (`score = 47.0`). Detailed trace in Section 3. |

---

## 3. Actual RiskEngine Scoring Path & End-to-End Traces

### Scoring & Threshold Logic
1. `UrlDetectors` (`url_detectors.py:64, 231-238`): `SuspicionSignal.SUBDOMAIN_BRAND_IMPERSONATION` has weight **`6`**.
2. `RiskScorer.score()` (`risk_scorer.py:24-38`):
   - `critical_signals`: `weight >= 10`
   - `high_signals`: `6 <= weight < 10` (includes `SUBDOMAIN_BRAND_IMPERSONATION`)
   - `medium_signals`: `4 <= weight < 6`
   - `MALICIOUS` requires `critical_signals`, or `len(high_signals) >= 2`, or `len(high_signals) >= 1 and (len(medium_signals) >= 2 or total_weight >= 10)`.
   - A standalone weight-`6` signal satisfies none of these, so it falls through to `else: severity = UrlRiskSeverity.SUSPICIOUS`.
3. `UrlAnalyzer.analyze_sync()` (`analyzer.py:70-75`): Non-`SAFE` findings are appended to `UrlAnalysisResult.findings`, and `highest_severity` becomes `UrlRiskSeverity.SUSPICIOUS`.
4. `RiskEngine.evaluate()` (`engine.py:80-85, 139-142`):
   - `url_result.highest_severity == UrlRiskSeverity.SUSPICIOUS` sets `is_suspicious = True` and `base_score = max(base_score, 45.0)`.
   - Appends `"[URL-SUSPICIOUS] <url>: <reason>"` to `contributing_signals`.
   - Final score calculation: `score = min(74.0, base_score + min(10.0, len(contributing_signals) * 2.0))`. For 1 signal: `45.0 + 2.0 = 47.0`, `tier = RiskTier.SUSPICIOUS`.

### Live Pipeline Traces

**Positive Example:** `https://signin.ebay.com.evil-example.org/login`
- `UrlNormalizer.parse`: `scheme='https'`, `host_stripped='signin.ebay.com.evil-example.org'`, `is_valid=True`
- `HostnameAnalyzer.analyze`: `registered_domain='evil-example.org'`, `subdomain_labels=3`, `subdomain_brand_target='ebay.com'`
- `SuspicionEngine.evaluate`: `[DetectedSignal(SUBDOMAIN_BRAND_IMPERSONATION, weight=6)]`
- `RiskScorer.score`: `UrlRiskSeverity.SUSPICIOUS`
- `RiskEngine.evaluate`: `score=47.0`, `tier=RiskTier.SUSPICIOUS`, `summary="SUSPICIOUS EMAIL. Anomaly indicators: [URL-SUSPICIOUS] https://signin.ebay.com.evil-example.org/login: [SUBDOMAIN_BRAND_IMPERSONATION] ..."`

**Benign Example:** `https://www.paypal.com/signin`
- `UrlNormalizer.parse`: `scheme='https'`, `host_stripped='www.paypal.com'`, `is_valid=True`
- `HostnameAnalyzer.analyze`: `registered_domain='paypal.com'`, `subdomain_labels=1`, canonical exclusion triggered (`reg_domain == norm_brand`) → `subdomain_brand_target=None`
- `SuspicionEngine.evaluate`: `[]` (0 signals)
- `RiskScorer.score`: `UrlRiskSeverity.SAFE`
- `UrlAnalyzer.analyze_sync`: `highest_severity=UrlRiskSeverity.SAFE`, `findings=[]`
- `RiskEngine.evaluate`: `score=0.0`, `tier=RiskTier.CLEAN`

---

## 4. Evaluation Methodology & Independence Assessment

Inspected `scratch/analyze_nazario_brands.py`, `scratch/nazario_brand_hits.jsonl`, `scratch/build_corpus.py`, `scratch/subdomain_brand_corpus.jsonl`, `scratch/micro_eval.py`, and `scratch/micro_eval_results.jsonl`.

### 4.1 Selection Bias in Positive Examples (Key Finding)
- `analyze_nazario_brands.py` (lines 37–49) and `build_corpus.py` (lines 47–57) selected Category A positive URLs using `brand_in_subdomain()`, a `labels[:-2]` sliding-window matcher against the exact same 17 `PROTECTED_BRANDS` list used by the detector.
- **Impact:** Category A only contains phishing URLs that match the detector's multi-label rule for those 17 brands. Therefore, Category A recall (`0.9925`) measures **consistency with the selection heuristic**, not unbiased recall over all subdomain-impersonation phishing in Nazario or PhishTank (e.g., standalone-stem-only cases or unconfigured brands are excluded from Category A).

### 4.2 Dataset Labeling Assessment
- **Category A (133 records):** Phishing provenance is independent (Nazario Phishing Corpus 3 and PhishTank `online-valid.json.bz2`), but the specific `is_brand_subdomain_impersonation=True` label was assigned by the selection script.
- **Category B (139 records):** Benign labels (`False`) are independently justified via canonical brand domains (27), synthetic boundary/non-brand controls (21), and Tranco Top-1M entries (91).
- **Category C (20 records):** Hand-crafted adversarial examples with `True` labels, cleanly separated from Category A.

### 4.3 Duplicates & Corpus Hygiene
- **6 duplicate URLs** (7 extra rows) exist in the 292-record corpus:
  - 5 Nazario URLs repeated 2–3× because `analyze_nazario_brands.py` did not deduplicate across email records (`www.amazon.com.encrypted-inquiry.cn?/exec/obidos` ×2, `www.ebay.com...miclau.com/566734666.htm` ×2, `www.bankofamerica.com...officials2you.info/session.cgi` ×2, `member.ebay.com.issl.info/.../Signin.html` ×3, `www.paypal.com.cableadtv.com/cgi-bin/` ×2).
  - `https://www.cloudflare.com/` appears in both B2 (Synthetic Benign) and B3 (Tranco).
- **8 duplicate hostnames** total (adding `www.wikipedia.org` across B2/B3 and `paypal.com.example.org` with/without trailing dot in C).

### 4.4 Benign Control Representativeness
- The 139 benign controls effectively test canonical subdomains (`www.paypal.com`, `www.paypal.com.au`), substring boundaries (`paypalsupport.example.com`, `example-paypal.com`), adjacent domains (`fonts.googleapis.com`), and IP literals.
- **Limitation:** All 91 Tranco controls were generated as `https://www.<domain>/`. They do not exercise diverse multi-label benign subdomains (e.g., third-party SaaS subdomains or deep legitimate subdomains).

### 4.5 Metric Calculation Assessment
- `micro_eval.py` (`compute_metrics`, lines 45–61) computes Precision, Recall, Specificity, FPR, and F1 from unrounded counts, uses `None` (`null` in JSON) for 0/0 divisions, and rounds only at output.
- Recomputing metrics after deduplication confirms minimal impact:
  - **Raw (292 records):** `TP=152, FP=0, TN=139, FN=1` → `P=1.0000, R=0.9935, F1=0.9967`
  - **Deduplicated by URL (285 records):** `TP=146, FP=0, TN=138, FN=1` → `P=1.0000, R=0.9932, F1=0.9966`
  - **Deduplicated by hostname (283 records):** `TP=145, FP=0, TN=137, FN=1` → `P=1.0000, R=0.9932, F1=0.9966`
- Minor script discrepancy noted: `micro_eval.py:34` passes `parsed.host` instead of `parsed.host_stripped` to `host_analyzer.analyze()` (unlike `UrlAnalyzer.analyze_url()`). For all corpus URLs except `https://[::1]/api` (which remains TN either way), `parsed.host == parsed.host_stripped`.

---

## 5. Confirmed Defects & Documentation Corrections

- **Code defects:** **None** requiring remediation. (Cosmetic note only: `url_detectors.py` has two consecutive rule comments numbered `# 16.` at lines 231 and 240, with zero functional impact.)
- **Documentation inconsistency fixed:**
  - `MAILSENTRA_PRIORITY_2_SUBDOMAIN_BRAND_DETECTION_REPORT.md` (Section 2.3, line 50) stated `across 6 protected brands` while the table listed `7` brands (`nationalcity.com`, `bankofamerica.com`, `ebay.com`, `paypal.com`, `amazon.com`, `citi.com`, `chase.com`).
  - **Files updated:**
    - [`MAILSENTRA_PRIORITY_2_SUBDOMAIN_BRAND_DETECTION_REPORT.md`](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/MAILSENTRA_PRIORITY_2_SUBDOMAIN_BRAND_DETECTION_REPORT.md) (workspace root) — changed `6 protected brands` to `7 protected brands`.
    - [Artifact copy of `MAILSENTRA_PRIORITY_2_SUBDOMAIN_BRAND_DETECTION_REPORT.md`](file:///C:/Users/vatsa/.gemini/antigravity/brain/5e32ca87-7254-4e62-9e94-32692f735b3d/MAILSENTRA_PRIORITY_2_SUBDOMAIN_BRAND_DETECTION_REPORT.md) — same fix applied.

---

## 6. Validation Summary

Ran targeted existing tests after documentation edits:
- Command: `pytest -q backend/tests/test_url_subdomain_brand_detection.py backend/tests/test_url_analyzer.py`
- Result: **105 passed in 0.43s** (exit code `0`).

---

## 7. Final Verdict

**CONDITIONALLY ACCEPTED**

The Priority 2 detection logic and `RiskEngine` integration are sound, deterministic, and verified without code defects. Acceptance is conditional on recognizing that the micro-evaluation's Category A recall reflects consistency with a heuristic mirroring the detector rather than unbiased benchmark recall, and that end-to-end detection impact remains to be measured in a controlled external benchmark.
