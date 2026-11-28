# MailSentra — Priority 2: Subdomain Brand Impersonation Detection Report

**Date:** 2026-11-28  
**Scope:** Priority 2 Implementation — Subdomain Brand-Impersonation Detection in URL Security Analysis Engine (`Module 5`)  
**Auditor/Engineer:** Senior ML Security Engineer & Python Security Auditor  
**Status:** COMPLETE & VERIFIED (815/815 tests passing)

---

## 1. Executive Summary

During the benchmark evaluation and false-negative deep dive on the Nazario Phishing Corpus (`DS-PE-01`), 161 false negatives were identified. Of these, **155 (96.3%) contained URLs**. A recurring attack pattern was the embedding of trusted brand domains and financial institution names directly into subdomains of unrelated registered domains (e.g. `http://session-424368524.nationalcity.com.trenkst.jp/...`, `https://signin.ebay.com.evil-example.org/login`). 

The existing `UrlAnalyzer` evaluated typosquatting exclusively on the Public Suffix List (PSL) `registered_domain`. Because the registered domain in these attacks was an unrelated third-party domain (e.g. `trenkst.jp`), the Damerau-Levenshtein distance to the brand target (`nationalcity.com`) was large, causing the typosquatting detector to skip it completely. Meanwhile, the subdomains (`nationalcity.com`) were left completely uninspected, classifying the URL as `SAFE` with a risk score of `0.0`.

To eliminate this detection blind spot, we have designed, implemented, and verified a deterministic **Subdomain Brand Impersonation Detector** within MailSentra's static URL analysis pipeline:
1. Reused the existing PSL registered domain resolution mechanism, hostname normalization, and `SuspicionEngine` signal pipeline without adding any third-party dependencies or parallel frameworks.
2. Implemented label-boundary-aware sliding window matching for multi-label brand domain sequences (e.g. `['nationalcity', 'com']`, `['ebay', 'com']`, `['paypal', 'com']`).
3. Implemented exact-label matching for standalone brand name tokens (e.g. `paypal.example.org`) while strictly rejecting arbitrary substring matches (e.g. `example-paypal.com`).
4. Guarded canonical brand URLs (e.g. `www.paypal.com`) so legitimate domains are never flagged.
5. Integrated with the existing `RiskScorer` and `RiskEngine`, producing `UrlRiskSeverity.SUSPICIOUS` (base score 45.0) which corroborates with other indicators up to `MALICIOUS` (base score 85.0).
6. Added 13 focused regression test scenarios (39 test cases) covering canonical guards, multi-label brands, substring rejections, case/dot normalization, IP/malformed safety, and RiskEngine integration.
7. Validated the entire backend test suite: **815 tests passed in 13.11s (exit code 0)**.

---

## 2. Confirmed Root Cause from Source Code

### 2.1 The Subdomain Blind Spot in `HostnameAnalyzer`
In [backend/app/modules/url_analysis/hostname_analyzer.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/url_analysis/hostname_analyzer.py), the `HostnameAnalyzer.analyze()` method resolved the registered domain using `get_registered_domain_offline(norm_host)`. It then evaluated typosquatting as follows:

```python
# PRE-REMEDIATION IMPLEMENTATION (hostname_analyzer.py:169-194):
if config.protected_domains and reg_domain:
    for prot in config.protected_domains:
        norm_prot = normalize_domain(prot)
        if not norm_prot or norm_prot == reg_domain or norm_host == norm_prot:
            continue
        reg_prot = get_registered_domain_offline(norm_prot)
        if reg_prot == reg_domain:
            continue

        comp_host = reg_domain
        comp_prot = reg_prot if reg_prot else norm_prot

        if (
            len(comp_host) >= config.typosquatting_min_domain_length
            and len(comp_prot) >= config.typosquatting_min_domain_length
        ):
            dist = damerau_levenshtein_distance(comp_host, comp_prot)
            sim = calculate_domain_similarity(comp_host, comp_prot)
            if dist <= config.typosquatting_max_distance and sim >= config.typosquatting_min_similarity:
                res.typosquat_target = norm_prot
                res.typosquat_similarity = sim
                break
```

### 2.2 Why Attacks Evaded Detection
When presented with an attack URL like `http://session-424368524.nationalcity.com.trenkst.jp/`:
1. `norm_host` was `session-424368524.nationalcity.com.trenkst.jp`.
2. `reg_domain` was correctly extracted as `trenkst.jp`.
3. `comp_host` was `trenkst.jp`.
4. Comparing `comp_host` (`trenkst.jp`) against protected brand `nationalcity.com` yielded:
   - Damerau-Levenshtein distance: 13 (limit: 2).
   - Similarity: < 0.20 (limit: 0.75).
5. The comparison failed, and no typosquatting finding was emitted.
6. The subdomains (`session-424368524.nationalcity.com`) were never compared against known brand names or protected domains.
7. Consequently, `HostAnalysisResult` emitted no suspicious findings, `RiskScorer` returned `UrlRiskSeverity.SAFE`, and the email fell to a `0.0` score (`CLEAN`).

---

## 3. Existing Architecture Reused

Rather than creating a parallel framework, the detection capability was integrated directly into the established Module 5 pipeline:
- **`UrlNormalizer` ([normalizer.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/url_analysis/normalizer.py)):** Reused for safe URL decomposition, scheme validation, IPv6/port parsing, and defanging.
- **`domain_utils` ([domain_utils.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/identity/domain_utils.py)):** Reused `get_registered_domain_offline()` (PSL extraction), `normalize_domain()`, `is_subdomain_of()`, and `decode_idna_safely()`.
- **`HostnameAnalyzer` ([hostname_analyzer.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/url_analysis/hostname_analyzer.py)):** Extended `HostAnalysisResult` to store `subdomain_brand_target` and `subdomain_brand_evidence`.
- **`SuspicionEngine` ([url_detectors.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/url_analysis/url_detectors.py)):** Extended `SuspicionSignal` enum with `SUBDOMAIN_BRAND_IMPERSONATION` and added weight 6 (High severity, matching `TYPOSQUATTING_HOSTNAME`).
- **`RiskScorer` ([risk_scorer.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/url_analysis/risk_scorer.py)):** Reused existing multi-signal aggregation logic without alteration.
- **`RiskEngine` ([engine.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/risk_engine/engine.py)):** Reused existing URL severity ingestion (`url_result.highest_severity`).

---

## 4. Exact Files Changed

| File | Change Description |
| :--- | :--- |
| **[backend/app/modules/url_analysis/config.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/url_analysis/config.py)** | Added `default_protected_brands` containing high-profile targets (`paypal.com`, `ebay.com`, `chase.com`, `nationalcity.com`, `microsoft.com`, etc.) and `get_effective_protected_domains()` helper. |
| **[backend/app/modules/url_analysis/hostname_analyzer.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/url_analysis/hostname_analyzer.py)** | Extended `HostAnalysisResult` with `subdomain_brand_target` and `subdomain_brand_evidence`. Implemented label-aware subdomain brand matching. |
| **[backend/app/modules/url_analysis/url_detectors.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/url_analysis/url_detectors.py)** | Added `SuspicionSignal.SUBDOMAIN_BRAND_IMPERSONATION`, assigned weight 6 in `SIGNAL_WEIGHTS`, and added Rule 16 in `SuspicionEngine.evaluate()`. |
| **[backend/tests/test_url_subdomain_brand_detection.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_url_subdomain_brand_detection.py)** | Created comprehensive test suite covering all 12 functional scenarios and RiskEngine integration (13 tests, 39 test cases). |

---

## 5. Detection Logic & Hostname Comparison Approach

### 5.1 Hostname Preprocessing and Boundary Extraction
1. **Safety Preconditions:** If the URL host is an IP literal (`is_ip_host == True`), or if parsing fails, subdomain brand analysis is safely skipped.
2. **Normalization:** The host string is stripped, lowercased, and trailing dots are removed via `normalize_domain()`.
3. **PSL Registered Domain Extraction:** The registered domain `reg_domain` is extracted via the offline bundled PSL snapshot (`get_registered_domain_offline()`).
4. **Subdomain Label Extraction:** If `norm_host != reg_domain`, labels are split on `.`:
   $$\text{labels} = [\text{lbl} \text{ for } \text{lbl} \in \text{norm\_host.split}('.')]$$
   $$\text{reg\_labels} = [\text{lbl} \text{ for } \text{lbl} \in \text{reg\_domain.split}('.')]$$
   $$\text{subdomain\_labels} = \text{labels}[:\text{len}(\text{labels}) - \text{len}(\text{reg\_labels})]$$
5. **IDN / Punycode Support:** If `decoded_hostname` contains non-ASCII representations, `decoded_sub_labels` is extracted in parallel to inspect both ASCII and decoded forms.

### 5.2 Explicit Brand-Domain Matching Rules
For each protected brand domain `brand` in `get_effective_protected_domains()`:

#### Guard 1: Canonical Brand Domain Protection
If the registered domain of the URL matches the brand's registered domain, or if either is a subdomain of the other:
$$\text{reg\_domain} == \text{brand\_reg} \quad\lor\quad \text{is\_subdomain\_of}(\text{reg\_domain}, \text{norm\_brand}) \quad\lor\quad \text{is\_subdomain\_of}(\text{norm\_brand}, \text{reg\_domain})$$
The URL is canonical (e.g. `https://www.paypal.com/login` or `https://checkout.paypal.com/pay`). It is **never flagged**.

#### Rule 1: Contiguous Multi-Label Brand Domain Sequence Matching
Attackers commonly embed the full brand domain into subdomains (e.g. `signin.ebay.com.evil.org` has subdomain labels `['signin', 'ebay', 'com']`).
- Brand labels: `brand_labels = norm_brand.split('.')` (e.g. `['ebay', 'com']`, $k=2$).
- The detector slides a window of length $k$ across `subdomain_labels`:
  $$\exists i \text{ such that } \text{subdomain\_labels}[i : i+k] == \text{brand\_labels}$$
- If matched, flags:
  `Subdomain contains embedded brand domain '{norm_brand}' under unrelated registered domain '{reg_domain}'`.

#### Rule 2: Standalone Exact Brand-Name Label Matching
Attackers also deploy single-label brand subdomains (e.g. `https://paypal.example.org/login`).
- Primary brand stem: `brand_stem = brand_labels[0]` (e.g. `'paypal'`).
- Bounded minimum length: $\text{len}(\text{brand\_stem}) \ge 4$ (prevents matching short generic tokens).
- Complete label equality:
  $$\text{brand\_stem} \in \text{subdomain\_labels} \quad\lor\quad \text{brand\_stem} \in \text{decoded\_sub\_labels}$$
- If matched, flags:
  `Subdomain label matches protected brand name '{brand_stem}' (brand: '{norm_brand}') under unrelated registered domain '{reg_domain}'`.

#### Rule 3: Rejection of Arbitrary Substring Matches
By requiring complete label equality and sliding window comparisons over structured `List[str]` labels, compound and hyphenated hostnames such as `example-paypal.com`, `paypalsupport.com`, `pineapples.com`, or `chasebankersassociation.org` do not match either rule and are **safely passed**.

---

## 6. Required Detection Examples Verification

| URL | Expected Behavior | MailSentra Evaluated Result | Finding Reason Emitted |
| :--- | :--- | :--- | :--- |
| `https://www.paypal.com/login` | No finding | **`SAFE`** | *No suspicious static indicators detected* |
| `https://paypal.com.example.org/login` | Flag brand-subdomain impersonation | **`SUSPICIOUS`** | `[SUBDOMAIN_BRAND_IMPERSONATION] Subdomain contains embedded brand domain 'paypal.com' under unrelated registered domain 'example.org'` |
| `https://signin.ebay.com.evil-example.org/login` | Flag brand-subdomain impersonation | **`SUSPICIOUS`** | `[SUBDOMAIN_BRAND_IMPERSONATION] Subdomain contains embedded brand domain 'ebay.com' under unrelated registered domain 'evil-example.org'` |
| `https://secure.chase.com.attacker.net/login` | Flag brand-subdomain impersonation | **`SUSPICIOUS`** | `[SUBDOMAIN_BRAND_IMPERSONATION] Subdomain contains embedded brand domain 'chase.com' under unrelated registered domain 'attacker.net'` |
| `https://example-paypal.com/login` | Do not flag solely because string contains paypal | **`SAFE`** | *No suspicious static indicators detected* |
| `https://paypal.example.org/login` | Evaluate according to explicit brand matching rules | **`SUSPICIOUS`** | `[SUBDOMAIN_BRAND_IMPERSONATION] Subdomain label matches protected brand name 'paypal' (brand: 'paypal.com') under unrelated registered domain 'example.org'` |
| `https://example.org/login` | No brand impersonation finding | **`SAFE`** | *No suspicious static indicators detected* |

---

## 7. Severity and Scoring Rationale

### 7.1 Existing Scoring Architecture Alignment
In MailSentra's static URL analysis architecture:
- `SIGNAL_WEIGHTS` maps indicators into four tiers: Critical (10), High (6–7), Medium (4), and Low (2–3).
- `TYPOSQUATTING_HOSTNAME` is assigned weight 6 (High).
- `SUBDOMAIN_BRAND_IMPERSONATION` is assigned **weight 6 (High)**.

### 7.2 Verdict Resolution in `RiskScorer`
Under [risk_scorer.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/url_analysis/risk_scorer.py):
1. **Standalone Finding:** A URL containing only `SUBDOMAIN_BRAND_IMPERSONATION` (weight 6) satisfies `total_weight = 6`, which evaluates to **`UrlRiskSeverity.SUSPICIOUS`**.
2. **Corroborated Finding:** If the URL features an additional High signal (e.g. homoglyph hostname, public IP) or multiple Medium signals (e.g. suspicious `.xyz` TLD with weight 4, bringing total weight to $6 + 4 = 10$), `RiskScorer` automatically escalates the severity to **`UrlRiskSeverity.MALICIOUS`**.

### 7.3 RiskEngine Integration
When `UrlAnalysisResult` is passed to [RiskEngine.evaluate()](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/risk_engine/engine.py):
- `highest_severity == UrlRiskSeverity.SUSPICIOUS`:
  - `is_suspicious = True`
  - `base_score = max(base_score, 45.0)`
  - Signals: `[URL-SUSPICIOUS] {url}: [SUBDOMAIN_BRAND_IMPERSONATION] ...`
  - In `evaluator.py`: `is_detected = (tier in (RiskTier.MALICIOUS, RiskTier.SUSPICIOUS)) or (score >= 35.0)` $\rightarrow$ **True Positive!**
- `highest_severity == UrlRiskSeverity.MALICIOUS`:
  - `is_malicious = True`
  - `base_score = max(base_score, 85.0)`
  - `tier = RiskTier.MALICIOUS`

---

## 8. Regression Tests and Validation Results

### 8.1 Focused Test Suite Details
Created [backend/tests/test_url_subdomain_brand_detection.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_url_subdomain_brand_detection.py) with 13 test scenarios:
1. `test_01_canonical_brand_domains_not_flagged` (8 cases): Validates `paypal.com`, `google.com`, `apple.com`, and `microsoft.com` subdomains remain `SAFE`.
2. `test_02_brand_domains_embedded_in_subdomains_detected` (5 cases): Validates full embedded brand sequences (`paypal.com`, `ebay.com`, `chase.com`, `microsoft.com`, `google.com`).
3. `test_03_multiple_brands_handled_correctly`: Validates distinct target attribution.
4. `test_04_arbitrary_substring_matches_not_flagged` (5 cases): Validates `example-paypal.com`, `pineapples.com`, etc., remain unflagged.
5. `test_05_registered_domain_boundaries_respected`: Validates `example.org` is safe while `paypal.example.org` flags.
6. `test_06_multi_label_brand_domains_handled_correctly`: Validates authentic Nazario pattern (`session-424368524.nationalcity.com.trenkst.jp`).
7. `test_07_case_normalization_works` (3 cases): Validates uppercase and mixed-case URL variants.
8. `test_08_trailing_dot_hostnames_handled_safely`: Validates trailing-dot FQDN handling.
9. `test_09_ip_addresses_do_not_cause_crashes_or_false_brand_matches` (4 cases): Validates IPv4, IPv6, hex, and path containment.
10. `test_10_malformed_urls_fail_safely` (5 cases): Validates unclosed brackets, missing hosts, whitespace, and empty strings.
11. `test_11_existing_typosquatting_detection_unchanged` (3 cases): Validates `paypa1.com`, `micros0ft.com`, `go0gle.com`.
12. `test_12_existing_url_risk_scoring_unchanged_for_unrelated_urls`: Validates suspicious TLDs and dangerous extensions.
13. `test_13_risk_engine_integration_with_subdomain_impersonation`: Validates end-to-end RiskEngine scoring.

### 8.2 Execution Results Across Test Suites

| Suite | Command | Tests | Failures | Duration | Exit Code |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Subdomain Brand Suite** | `$env:PYTHONPATH=".;backend"; pytest -v backend\tests\test_url_subdomain_brand_detection.py` | **39** | 0 | 0.22s | **0** |
| **Existing URL Analyzer Suite** | `$env:PYTHONPATH=".;backend"; pytest -v backend\tests\test_url_analyzer.py` | **66** | 0 | 0.19s | **0** |
| **RiskEngine Integration Suite** | `$env:PYTHONPATH=".;backend"; pytest -v backend\tests\test_risk_engine_header_remediation.py backend\tests\test_end_to_end_validation.py` | **26** | 0 | 1.25s | **0** |
| **Full Backend Test Suite** | `$env:PYTHONPATH=".;backend"; pytest backend\tests -q` | **815** | 0 | 13.11s | **0** |

---

## 9. False-Positive Considerations & Limitations

1. **Third-Party Partnerships & Delegated Portals:** In legitimate enterprise IT, organizations occasionally delegate subdomains to software vendors or partners (e.g. `partner.vendor.com` configuring `client.vendor.com`). Because MailSentra operates in strict offline evaluation mode without live DNS CNAME resolution, such cross-domain arrangements can produce a `SUSPICIOUS` finding if an organization’s own brand is embedded in an external vendor's subdomain. This can be tuned via `UrlAnalysisConfig.protected_domains`.
2. **Empirical Benchmark Verification:** While unit tests confirm that `nationalcity.com.trenkst.jp` and other benchmark patterns are detected and produce `RiskTier.SUSPICIOUS`, no claim is made that all 120 Nazario false negatives are fixed until an authorized controlled external benchmark is executed.
3. **Remaining Detection Gaps (Priorities 3–5):**
   - **Priority 3 (Display-Name Brand Spoofing):** 40+ Nazario false negatives using brand display names on unaligned non-free domains remain unaddressed.
   - **Priority 4 (Commercial Spam):** 228 SpamAssassin commercial text samples remain undetected due to the absence of statistical/Bayesian text classifiers.
   - **Priority 5 (Offline Auth):** Static `Received-SPF: fail` inspection remains unaddressed.

---

## 10. Final Verdict

Priority 2 (Subdomain Brand Impersonation Detection) is **fully implemented, verified, and integrated**. It accurately detects embedded brand domain sequences and standalone brand labels without regex wildcards, respects canonical domains and registered domain boundaries, and passes all 815 backend tests.
