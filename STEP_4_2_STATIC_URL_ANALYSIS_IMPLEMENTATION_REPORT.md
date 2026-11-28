# MailSentra — Step 4.2: Static URL Security Analysis Engine
## Implementation Completion Report

**Date:** November 27, 2026  
**Engineer:** Senior Email Security Architect, Python Backend Engineer, Independent Application Security Reviewer  
**Baseline Git Commit:** `a1ab60620b601737444fa39a1de329d4a5083a3f` (branch: `main`)  
**Status:** **COMPLETE — ALL TESTS PASSED**

---

## 1. Executive Summary

Milestone **Step 4.2** implements the offline, deterministic **Static URL Security Analysis Engine (Module 5)** in MailSentra alongside the assessment and structured integration of 15 cybersecurity intelligence datasets. 

The engine strictly operates **offline with zero outbound network operations** (no HTTP/HTTPS probing, no DNS queries, no socket connections, no redirect crawling). All threat determinations are derived through RFC-compliant component parsing, IP categorization, IDN/homoglyph inspection, brand typosquatting distance metrics, and multi-signal corroboration.

---

## 2. Architecture Implemented

The static URL analysis engine conforms to the approved Step 4.1 architecture specification, structured into 7 decoupled components under `backend/app/modules/url_analysis/`:

```
backend/app/modules/url_analysis/
├── __init__.py             # Public module interface exports
├── config.py               # UrlAnalysisConfig (Pydantic BaseModel with operational thresholds)
├── normalizer.py           # UrlNormalizer & UrlParseResult (safe parsing via urlsplit & defanging)
├── hostname_analyzer.py    # HostnameAnalyzer & HostAnalysisResult (IP parsing & IDN/Punycode/PSL)
├── url_detectors.py        # SuspicionEngine & SuspicionSignal (18 deterministic static heuristic rules)
├── risk_scorer.py          # RiskScorer (multi-signal evidence aggregation & severity categorization)
└── analyzer.py             # UrlAnalyzer (BaseDetectionModule implementation & email batch evaluator)
```

---

## 3. Files Created & Modified

### New Engine Files:
1. `backend/app/modules/url_analysis/__init__.py` — Module exports
2. `backend/app/modules/url_analysis/config.py` — Config schema with default operational lists
3. `backend/app/modules/url_analysis/normalizer.py` — Safe URI scheme separation, bracket IPv6 extraction, defanging
4. `backend/app/modules/url_analysis/hostname_analyzer.py` — Static IP parsing (standard, hex, octal, integer), IDNA, mixed scripts, Levenshtein
5. `backend/app/modules/url_analysis/url_detectors.py` — 18 static heuristic rules with defined signal weights
6. `backend/app/modules/url_analysis/risk_scorer.py` — Evidence aggregation logic with multi-signal escalation
7. `backend/app/modules/url_analysis/analyzer.py` — Subsystem orchestrator implementing `BaseDetectionModule`

### New Dataset & Test Artifacts:
8. `datasets/README.md` — Security governance, no-live-crawl mandates, portfolio overview
9. `datasets/dataset_registry.csv` — Full 15-source registry across 15 standard schema columns
10. `datasets/dataset_manifest.json` — Machine-readable portfolio manifest with record counts & licenses
11. `datasets/samples/benign_tranco_sample.json` — Sanitized benign top-domain test fixtures
12. `datasets/samples/malware_urlhaus_sample.json` — Sanitized malware distribution URL fixtures
13. `datasets/samples/phishing_phishtank_sample.json` — Sanitized verified phishing URL fixtures
14. `backend/tests/test_url_analyzer.py` — 66 deterministic unit tests covering 32 threat categories
15. `backend/tests/test_dataset_validation.py` — 6 integration tests verifying registry, manifest, and dataset fixtures

---

## 4. Existing Contracts Reused (Zero Duplication)

The implementation strictly consumes existing immutable data models from `backend/app/modules/contracts.py`:
- `UrlRiskSeverity` (`SAFE`, `SUSPICIOUS`, `MALICIOUS`)
- `UrlFinding` (`url`, `defanged_url`, `resolved_ip`, `is_ip_host`, `is_suspicious_tld`, `is_open_redirect`, `redirect_chain`, `severity`, `reason`)
- `UrlAnalysisResult` (`total_urls_scanned`, `highest_severity`, `findings`)
- `ExtractedUrl` (`original_url`, `normalized_url`, `defanged_url`, `source_location`, `is_duplicate`, `occurrence_count`)
- `ParsedEmail` (`urls: List[ExtractedUrl]`)
- Reused domain utilities from `backend/app/modules/identity/domain_utils.py`:
  - `decode_idna_safely()`
  - `detect_mixed_scripts()`
  - `detect_suspicious_unicode()`
  - `get_registered_domain_offline()`
  - `damerau_levenshtein_distance()`
  - `calculate_domain_similarity()`
  - `normalize_domain()`

---

## 5. Detection Capabilities & Signal Weights

| Signal ID | Category | Weight | Target Threat / Condition |
|---|---|---|---|
| `UNSUPPORTED_SCHEME` | Critical | 10 | Non-HTTP/HTTPS schemes (`javascript:`, `data:`, `file:`, `ftp:`) |
| `IP_HOST_PRIVATE` | Critical | 10 | RFC 1918 private IPv4/IPv6 address as host |
| `IP_HOST_LOOPBACK` | Critical | 10 | `127.0.0.0/8`, `::1` loopback addresses |
| `IP_HOST_LINK_LOCAL` | Critical | 10 | `169.254.0.0/16`, `fe80::/10` cloud metadata / APIPA addresses |
| `IP_HOST_RESERVED` | Critical | 10 | Reserved, broadcast, or multicast addresses |
| `IP_HOST_UNSPECIFIED` | Critical | 10 | `0.0.0.0` unspecified address |
| `IP_HOST_ENCODED` | High | 7 | Hexadecimal (`0x7f000001`), octal (`0177.0.0.1`), or integer (`2130706433`) encoded IP |
| `IP_HOST_PUBLIC` | High | 6 | Raw public IP address used as hostname |
| `HOMOGRAPH_HOSTNAME` | High | 6 | Mixed Unicode script labels (e.g. Cyrillic 'а' in Latin domain) |
| `ZERO_WIDTH_UNICODE` | High | 6 | Zero-width spaces (`\u200B`), non-joiners, or directional overrides |
| `TYPOSQUATTING_HOSTNAME`| High | 6 | Damerau-Levenshtein distance <= 2 against protected brand list |
| `EMBEDDED_CREDENTIALS` | High | 6 | Embedded username/password in URL authority (`user:pass@host`) |
| `SUSPICIOUS_TLD` | Medium | 4 | High-abuse TLDs (`.xyz`, `.top`, `.tk`, `.zip`, `.mov`, `.pw`, etc.) |
| `OPEN_REDIRECT_PARAM` | Medium | 4 | Known redirection query parameter (`url=`, `redirect=`, `next=`, etc.) |
| `SUSPICIOUS_FILE_EXT` | Medium | 4 | Dangerous download extensions (`.exe`, `.bat`, `.ps1`, `.vbs`, `.scr`, etc.) |
| `USERINFO_PRESENT` | Medium | 4 | Authority userinfo field populated |
| `URL_ENCODING_OBFUSCATION`| Low | 3 | Double percentage encoding (`%25`) or null-byte injection (`%00`) |
| `SUSPICIOUS_QUERY_PARAM`| Low | 3 | Command execution tokens in query string (`cmd=`, `exec=`, `shell=`) |
| `KNOWN_SHORTENER` | Low | 2 | Registered domain matches shortener list (`bit.ly`, `t.co`, `tinyurl.com`) |
| `PUNYCODE_DETECTED` | Low | 2 | `xn--` internationalized domain label present |
| `EXCESSIVE_URL_LENGTH`| Low | 2 | URL string length exceeds 2,000 characters |
| `HIGH_ENTROPY_PATH` | Low | 2 | Path segment length >= 40 with Shannon entropy >= 4.2 |
| `EXCESSIVE_SUBDOMAINS` | Low | 2 | Subdomain depth exceeds 4 labels |
| `NON_STANDARD_PORT` | Low | 2 | Port specified and not in `{80, 443, 8080, 8443}` |
| `MALFORMED_URL` | Low | 2 | Unparseable or empty URI syntax |

---

## 6. Risk Scoring & Escalation Rules

- **Deterministic & Explainable**: Every finding produces a semicolon-delimited list of detected signals and human-readable evidence.
- **Critical Severity Trigger**: Any single signal with weight >= 10 immediately results in `MALICIOUS` (private/loopback IPs, cloud metadata endpoints, unsupported schemes).
- **Corroboration Requirement**: High, medium, and low signals require corroboration:
  - 2+ High signals -> `MALICIOUS`
  - 1 High signal + 2+ Medium signals (or total weight >= 10) -> `MALICIOUS`
- **Weak-Signal Guard**: A single weak or medium indicator (e.g. `.xyz` TLD alone, or `bit.ly` alone, or Punycode alone) **never** triggers `MALICIOUS`, safely categorizing as `SUSPICIOUS`.
- **Benign Baseline**: Zero triggered indicators results in `UrlRiskSeverity.SAFE`. Safe URLs are recorded in `total_urls_scanned` but omitted from the `findings` list to maintain bounded incident telemetry.

---

## 7. Security Controls & Offline Verification

1. **Zero Outbound Sockets**: Static analysis is strictly offline. No `socket.connect`, `httpx.request`, `urllib.request`, or DNS resolver calls are invoked.
2. **SSRF Neutralization**: Private, loopback, link-local, and cloud metadata addresses (`169.254.169.254`, `[::1]`, `127.0.0.1`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`) are identified and assigned `MALICIOUS` severity directly from static integer/string decoding without touching network stacks.
3. **Regex ReDoS Guard**: Bounded length checks (<2,000 chars) are applied before evaluating regular expressions. Linear-time character passes are prioritized.
4. **Failure Isolation**: An unparseable or corrupted URL inside a multi-URL email is caught via try/except, logging a warning and adding a `MALFORMED_URL` finding without aborting analysis of remaining URLs.
5. **Bytecode Compilation**: Verified clean across all 7 module files via `compileall`.

---

## 8. Test Execution Results

```powershell
backend\.venv\Scripts\python.exe -m pytest backend/tests/test_url_analyzer.py backend/tests/test_dataset_validation.py -v -p no:cacheprovider
```

- **Module 5 Static URL Analyzer Suite**: 66 passed (0 failures)
- **Dataset Portfolio Validation Suite**: 6 passed (0 failures)
- **Total New Milestone Tests**: 72 passed
- **Full Backend Regression Suite**: 548 passed (476 baseline + 72 new tests, 0 failures, 0 regressions)

---

## 9. Git Working-Tree State

- **Branch**: `main`
- **Commit HEAD**: `a1ab60620b601737444fa39a1de329d4a5083a3f`
- **Strict Compliance**: Zero git commits, pushes, stashes, or resets were performed.

---

## 10. Conclusion & Final Verdict

**FINAL VERDICT: `COMPLETE — ALL TESTS PASSED`**

The Static URL Security Analysis Engine (Module 5) and the 15-dataset portfolio validation are fully implemented, verified offline, and passing 100% of tests without regressions.
