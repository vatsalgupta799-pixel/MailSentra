# MailSentra — Step 4.1: Module 5 URL Security Analysis
## Architecture & Security Plan

**Date:** November 27, 2026
**Author:** Senior Email Security Architect / Python Backend Engineer / RFC Compliance Specialist / Independent Application Security Reviewer
**Baseline Commit:** `a1ab60620b601737444fa39a1de329d4a5083a3f` (branch: `main`)
**Inspection Mode:** READ-ONLY — No source modifications, no commits, no dependency installs
**Full Backend Baseline:** 476/476 tests passed (Step 3.7.4 completion)

---

## 1. Existing Implementation Inventory

### 1.1 Module 5 Stub

| File | Status | Contents |
|---|---|---|
| `backend/app/modules/url_analysis/__init__.py` | **STUB** | Single docstring comment, no implementation |
| `backend/app/modules/url_analysis/analyzer.py` | **ABSENT** | File does not exist |
| `backend/app/modules/url_analysis/config.py` | **ABSENT** | File does not exist |

### 1.2 Verified Contracts (Do Not Duplicate)

All Module 5 contracts are **fully defined** in `backend/app/modules/contracts.py` and must be consumed as-is:

| Contract | Lines | Fields (verified) |
|---|---|---|
| `UrlRiskSeverity` | ≈588 | Enum: `SAFE`, `SUSPICIOUS`, `MALICIOUS` |
| `UrlFinding` | ≈593 | `url`, `defanged_url`, `resolved_ip`, `is_ip_host`, `is_suspicious_tld`, `is_open_redirect`, `redirect_chain: List[str]`, `severity: UrlRiskSeverity`, `reason: str` |
| `UrlAnalysisResult` | ≈607 | `total_urls_scanned: int`, `highest_severity: UrlRiskSeverity`, `findings: List[UrlFinding]` |
| `ExtractedUrl` | ≈450 | `original_url`, `normalized_url`, `defanged_url`, `visible_text`, `source_location`, `is_duplicate`, `occurrence_count` |
| `ParsedEmail.urls` | ≈480 | `List[ExtractedUrl]` — populated by Module 2, available as pipeline input to Module 5 |

Additional contracts already in `contracts.py` relevant to future phases:
- `ObservableReputation`, `ThreatIntelResult` — for future threat intelligence integration
- `RiskDecisionReport`, `ScoredFactor`, `DecisionTier` — for risk engine integration

### 1.3 Verified Reusable Utilities

**URL Extractor** (`backend/app/modules/parser/url_extractor.py` — 160 lines):
- Regex extraction from plain-text bodies and HTML `<a href>` attributes
- Scheme filtering: blocks `javascript:`, `mailto:`, `tel:`, `data:`, `file:`, `vbscript:`, `blob:`
- `defang_url()`: replaces `http://` → `hxxp://`, `.` → `[.]`
- `normalize_url()`: scheme/host lowercasing, trailing punctuation stripping, `urllib.parse.urlsplit`
- Deduplication with occurrence counting
- Max URL limit enforced (`settings.MAX_EXTRACTED_URLS = 500`)

**Domain Utils** (`backend/app/modules/identity/domain_utils.py` — 219 lines — FULLY REUSABLE for hostname analysis):
- `normalize_domain()` — lowercasing, strip brackets
- `damerau_levenshtein_distance()` / `calculate_domain_similarity()` — typosquatting on URL hostnames
- `decode_idna_safely()` — Punycode detection and IDNA decoding via `idna` library
- `detect_mixed_scripts()` — homograph/Unicode script mixing detection on hostname
- `detect_suspicious_unicode()` — zero-width characters, directional overrides in hostname
- `get_registered_domain_offline()` — PSL via `tldextract` with `suffix_list_urls=None` (zero network)
- `is_subdomain_of()` — subdomain relationship checks

**Body Parser** (`backend/app/modules/parser/body_parser.py` — 51 lines):
- `extract_clean_text_from_html()`: BeautifulSoup-based stripping of `<script>`, `<iframe>`, `<style>`, SVG, forms, comments; bounded at 2MB HTML input

**Lookalike Rule** (`backend/app/modules/identity/rules/lookalike_domain.py` — 140 lines):
- Complete reference implementation of Punycode, mixed-script, suspicious Unicode, and Levenshtein typosquatting checks on a domain — logic can be adapted for URL hostname analysis

### 1.4 Verified Configuration (`backend/app/core/config.py`)

| Setting | Value | Relevance to Module 5 |
|---|---|---|
| `MAX_EXTRACTED_URLS` | 500 | Upper bound on URLs sent to Module 5 |
| `MAX_EMAIL_SIZE_BYTES` | 15 MB | Upstream cap |
| `DEFAULT_RISK_THRESHOLD_SUSPICIOUS` | 30 | Risk engine integration reference |
| `DEFAULT_RISK_THRESHOLD_MALICIOUS` | 70 | Risk engine integration reference |

No URL-analysis-specific settings exist yet (e.g., redirect hop limit, probe timeout, network probe enable flag).

### 1.5 Verified Available Dependencies

| Package | Version | Use in Module 5 |
|---|---|---|
| `httpx` | 0.28.1 | ✅ Available — async HTTP for redirect chain resolution |
| `idna` | 3.20 | ✅ Available (via domain_utils) — Punycode decode |
| `tldextract` | 5.4.0 | ✅ Available (via domain_utils) — PSL registered domain |
| `beautifulsoup4` | 4.15.0 | ✅ Available (via body_parser) — HTML parsing |
| `dnspython` | 2.9.2 | ✅ Available — optional async DNS resolution for IP validation |
| `certifi` | 2026.11.20 | ✅ Available — TLS trust store for httpx |
| `urllib3` | 2.8.0 | ✅ Available |
| `requests` | 2.34.2 | ✅ Available (not preferred; httpx is async) |
| `aiohttp` | — | ❌ **Not installed** — do not use |
| `validators` | — | ❌ **Not installed** — do not use |
| Standard library: `ipaddress`, `urllib.parse`, `re`, `unicodedata` | stdlib | ✅ Always available |

### 1.6 Verified Module Architecture Pattern

| Pattern Element | Reference | Notes |
|---|---|---|
| `BaseDetectionModule` ABC | `backend/app/modules/base.py` | Properties: `module_name`, `version`; async method: `analyze()` |
| Config model | `IdentityAnalysisConfig`, `AuthProtocolsConfig` | Pydantic `BaseModel` with defaults |
| Error isolation | `ScanService.ingest_and_parse()` | Each module wrapped in try/except; error dict stored in telemetry |
| Telemetry injection | `scan_service.py` lines 107–165 | Key: `incident.telemetry["module_name"]` = `result.model_dump(mode="json")` |
| Singleton pattern | `scan_service = ScanService()` module level | Shared instance; `shutdown()` called on lifespan exit |

### 1.7 Existing URL Test Coverage

**Verified tests in `backend/tests/test_email_parser.py`:**
- `test_scenario_04_multiple_urls` — extracts 3 URLs from HTML, verifies defanging
- `test_scenario_09_duplicate_urls` — deduplication with occurrence counts
- `test_ip_address_url_extraction` — extracts `http://192.168.1.1:8080/admin/settings`

No existing tests cover URL *analysis* (threat scoring, redirect chains, TLD suspicion, homograph hostnames, SSRF safety). This is the gap Module 5 must fill.

---

## 2. Missing Functionality

The following capabilities are entirely absent and must be implemented:

### 2.1 URL Canonicalization & Parsing (Static, No Network)
- Percent-encoding normalization (decode double-encoded sequences, re-encode correctly)
- Case folding of scheme and host (already in url_extractor; must extend to path handling)
- Fragment stripping (`#anchor` is not sent to server)
- IPv4 literal host detection (`http://192.168.1.1/admin`)
- IPv6 bracket notation parsing (`http://[::1]/admin`)
- Hex-encoded IP host detection (`http://0xC0A80101/admin`)
- Octal-encoded IP host detection (`http://0300.0250.01.01/admin`)
- Decimal-encoded IP (`http://3232235777/admin`)
- Port extraction and non-standard port flagging
- Punycode/IDN hostname decoding for analysis (reuse `decode_idna_safely`)

### 2.2 Static Heuristic Detection Engine
- Suspicious TLD classification (`.xyz`, `.top`, `.tk`, `.zip`, `.mov`, `.ru`, `.cn`, `.pw`, `.gq`, `.cf`, `.ga`, `.ml`)
- Known URL shortener domain detection (`bit.ly`, `t.co`, `tinyurl.com`, `goo.gl`, `ow.ly`, etc.) — static list, no network fetch
- Open redirect parameter detection (`redirect_to=`, `url=`, `next=`, `goto=`, `return=`, `forward=`, `dest=`, `location=`, `redir=`)
- Subdomain abuse patterns (excessive subdomain depth, long numeric subdomains)
- High-entropy path inspection (base64-looking paths, random hex strings)
- Excessively long URL detection (>2000 characters)
- Zero-width character detection in URL path/query (reuse `detect_suspicious_unicode`)
- Mixed-script hostname detection (reuse `detect_mixed_scripts`)
- Typosquatting of configured protected domains in URL hostname (reuse `damerau_levenshtein_distance`)
- Homograph detection on URL hostname (reuse `decode_idna_safely` + `detect_mixed_scripts`)

### 2.3 Network Probe Module (Optional, Disabled by Default)
- Async HTTP HEAD/GET with SSRF safety filter applied **before** any network connection
- Redirect chain tracking with configurable hop limit (default 5)
- Per-request timeout (default 5 seconds)
- Maximum response byte read (64 KB headers only for HEAD, avoid GET body)
- Final destination URL extraction after redirect chain
- Final IP validation against SSRF blocklist after DNS resolution
- Circular redirect detection (visited URL set)

### 2.4 `UrlAnalysisConfig` Pydantic Model
- `max_urls_to_analyze: int` — cap (default 200; well below `MAX_EXTRACTED_URLS=500`)
- `enable_network_probe: bool` — default `False`
- `max_redirect_hops: int` — default 5
- `probe_timeout_seconds: float` — default 5.0
- `max_response_bytes: int` — default 65536
- `suspicious_tld_list: List[str]` — configurable, with sensible defaults
- `shortener_domains: List[str]` — configurable, with sensible defaults
- `open_redirect_params: List[str]` — configurable, with sensible defaults

### 2.5 `UrlAnalyzer` Class
- Implements `BaseDetectionModule`
- `analyze(parsed_email, config)` → `UrlAnalysisResult`
- Internal component orchestration (see Architecture section)

### 2.6 Pipeline Integration
- `ScanService` does not currently invoke Module 5
- `incident.telemetry["url_analysis"]` is not populated
- `UrlAnalyzer` is not instantiated or shut down in `ScanService`

### 2.7 Test Suite
- No `backend/tests/test_url_analyzer.py` exists
- Existing 3 URL tests cover extraction only, not analysis

---

## 3. Threat Model & Attack Surface

### 3.1 Adversarial Inputs to Module 5

| Threat | Attack Vector | Detection Method | FP Risk |
|---|---|---|---|
| **IP-host URL** | Direct IP in URL (`http://1.2.3.4/evil`) to bypass domain reputation | Parse host, detect IPv4/IPv6/encoded-IP literal | Low — legitimate rare |
| **Obfuscated IP encoding** | Hex (`0xC0A80101`), octal (`0300.0250.01.01`), decimal (`3232235777`) | Normalize to dotted-decimal before analysis | Low |
| **Suspicious TLD** | Domains on high-risk TLDs (`.zip`, `.top`, `.tk`) | Static TLD allowlist/blocklist lookup | Medium — `.zip` is now legitimate GTLD |
| **URL shortener abuse** | `bit.ly/evil` to hide destination | Static shortener domain list; flag for unshortening | Medium — legitimate shorteners exist |
| **Open redirect** | `https://trusted.com/redirect?url=https://evil.com` | Query parameter name matching | Medium — many apps use redirect params |
| **Homograph / IDN** | `аpple.com` with Cyrillic α, `xn--pple-43d.com` | IDNA decode + mixed-script detection | Low — exotic domains are genuinely suspicious |
| **Typosquatting in URL host** | `g00gle.com`, `micosoft.com` | Damerau-Levenshtein against protected domain list | Medium — short domains collide |
| **SSRF via URL analysis** | Email contains `http://169.254.169.254/latest/meta-data/` to trigger platform SSRF | SSRF pre-filter blocks private IPs before any probe | Zero — defense is in the prober |
| **Redirect chain to internal** | Chain: `http://legit.com` → `http://10.0.0.1/secret` | SSRF filter applied after each redirect hop | Zero — each hop validated |
| **Zero-width character injection** | `paypal\u200b.com` in URL | `detect_suspicious_unicode()` on hostname | Low |
| **Redirect loop DoS** | Circular chain: A→B→A | Visited URL set + hop counter | Zero |
| **Excessively long URL** | 10,000-character URL to cause regex catastrophic backtracking | URL length cap before regex; use `re.match` not `re.search` | Zero |
| **Mixed-scheme confusion** | `hTtP://evil.com` bypassing scheme check | Scheme normalized to lowercase before comparison | Zero |
| **Data URI in body** | `data:text/html;base64,...` bypasses scheme filter | Already blocked in url_extractor.py scheme filter | Zero |
| **Credential exfiltration URL** | `https://user:password@evil.com` | `userinfo` in URL authority is a suspicion signal | Low |

### 3.2 Module 5 Internal Attack Surface

| Risk | Scenario | Mitigation |
|---|---|---|
| SSRF via network probe | Module probes attacker-supplied URL | SSRF pre-filter mandatory; probe disabled by default |
| CPU exhaustion | Malformed URL causes catastrophic regex | URL length cap (max 2000 chars) before analysis; linear-time regex patterns only |
| Memory exhaustion | 500 URLs × expensive analysis | `max_urls_to_analyze` cap (default 200); per-URL timeout |
| FP causing MALICIOUS verdict on legitimate URL | Single weak signal → MALICIOUS | Multi-signal corroboration required; conservative verdict logic |
| Logging PII in URLs (email addresses in query params) | `?email=victim@corp.com` logged in telemetry | Redact query parameter values in logged representations; defanged form used |

---

## 4. Proposed Architecture

```
UrlAnalyzer (BaseDetectionModule)
├── UrlAnalysisConfig            Pydantic BaseModel with all tunable parameters
├── UrlNormalizer                Canonicalize: scheme, host, percent-encoding, fragment strip
├── UrlComponentParser           urllib.parse.urlsplit → scheme, netloc, path, query, fragment
├── HostAnalyzer                 IP literal detection (v4/v6/encoded), port, Punycode, PSL
│    └── uses domain_utils:      decode_idna_safely, detect_mixed_scripts,
│                                detect_suspicious_unicode, get_registered_domain_offline,
│                                damerau_levenshtein_distance
├── SuspicionEngine              Static heuristic signals → Set[SuspicionSignal]
│    Rules:                      SuspiciousTld, KnownShortener, OpenRedirectParam,
│                                LongUrl, HighEntropyPath, UserInfoPresent,
│                                ExcessiveSubdomains, ZeroWidthInPath
├── NetworkProbe (optional)      SSRF-safe async httpx redirect chain resolver
│    └── SsrfBlocker             Validates IP against RFC 1918/5735/4193 before any connect
└── RiskAggregator               Combines signals → UrlFinding (severity, reason, evidence)
```

### 4.1 Data Flow (per URL)

```
ExtractedUrl (from ParsedEmail.urls)
    │
    ▼
UrlNormalizer.normalize()
    │  → canonical_url (str)
    ▼
UrlComponentParser.parse()
    │  → scheme, host, path, query, port
    ▼
HostAnalyzer.analyze(host)
    │  → is_ip_host, ip_version, is_encoded_ip, resolved_host,
    │    is_punycode, homoglyph_detected, registered_domain,
    │    is_suspicious_unicode, typosquat_signal
    ▼
SuspicionEngine.evaluate(url_components, host_analysis)
    │  → Set[SuspicionSignal] with confidence weights
    ▼
[Optional] NetworkProbe.resolve(canonical_url)  if enable_network_probe=True
    │  → redirect_chain: List[str], final_url: str
    ▼
RiskAggregator.score(signals, host_analysis, probe_result)
    │  → UrlFinding(severity, reason, redirect_chain, resolved_ip, ...)
    ▼
UrlAnalysisResult(total_urls_scanned, highest_severity, findings)
```

### 4.2 Module File Structure

```
backend/app/modules/url_analysis/
    __init__.py          (existing stub — update docstring only)
    analyzer.py          (UrlAnalyzer: BaseDetectionModule)
    config.py            (UrlAnalysisConfig: BaseModel)
    normalizer.py        (UrlNormalizer, UrlComponentParser)
    host_analyzer.py     (HostAnalyzer, IP detection, Punycode, PSL)
    suspicion_engine.py  (SuspicionEngine, SuspicionSignal enum, heuristic rules)
    network_probe.py     (NetworkProbe, SsrfBlocker — optional, disabled by default)
    risk_aggregator.py   (RiskAggregator, signal-to-severity mapping)
```

---

## 5. Detection Methodology

### 5.1 Static Signals and Severity Mapping

| Signal | Weight | Standalone Verdict | Notes |
|---|---|---|---|
| IP-host URL (IPv4/IPv6 literal) | HIGH | `SUSPICIOUS` | MALICIOUS only if private/loopback IP |
| Encoded IP host (hex/octal/decimal) | HIGH | `SUSPICIOUS` | Strongly correlates with evasion intent |
| Private IP as URL host (10.x, 192.168.x, 172.16-31.x) | CRITICAL | `MALICIOUS` | Direct SSRF/phishing risk |
| Loopback IP (127.x.x.x, ::1) | CRITICAL | `MALICIOUS` | Direct SSRF risk |
| Link-local IP (169.254.x.x) | CRITICAL | `MALICIOUS` | Cloud metadata endpoint abuse |
| Suspicious TLD | MEDIUM | `SUSPICIOUS` | Needs corroboration for MALICIOUS |
| Known URL shortener | LOW | `SUSPICIOUS` | Destination unknown; flag for probe |
| Open redirect parameter present | MEDIUM | `SUSPICIOUS` | Destination unknown |
| Homograph/mixed-script hostname | HIGH | `SUSPICIOUS` | Needs corroboration for MALICIOUS |
| Punycode label detected | LOW | `SUSPICIOUS` | Context-dependent |
| Zero-width Unicode in URL | HIGH | `SUSPICIOUS` | Strongly correlates with evasion |
| Excessive URL length (>2000 chars) | LOW | `SUSPICIOUS` | Tracking pixel / obfuscation |
| UserInfo in URL authority (`user:pass@`) | MEDIUM | `SUSPICIOUS` | Phishing credential harvesting |
| Typosquatting of protected domain | HIGH | `SUSPICIOUS` | MALICIOUS if combined with other signals |
| High-entropy path (>40 chars, random-looking) | LOW | `SUSPICIOUS` | Needs corroboration |
| Excessive subdomain depth (>4 labels) | LOW | `SUSPICIOUS` | CDN bypass pattern |
| Non-standard port (not 80/443/8080/8443) | LOW | `SUSPICIOUS` | Needs corroboration |
| Redirect chain destination = private IP | CRITICAL | `MALICIOUS` | SSRF confirmed post-probe |
| Redirect chain length > 3 | MEDIUM | `SUSPICIOUS` | Evasion chain |

### 5.2 Verdict Logic

```
MALICIOUS:
  - Any CRITICAL signal
  - OR: 2+ HIGH signals on same URL
  - OR: 1 HIGH + 2+ MEDIUM signals

SUSPICIOUS:
  - 1+ HIGH signal without corroboration
  - OR: 2+ MEDIUM signals
  - OR: 1 MEDIUM + 2+ LOW signals
  - OR: redirect chain destination is a suspicious TLD

SAFE:
  - No signals above LOW threshold, or no signals at all
  - Single LOW signal without corroboration → SAFE with note
```

**Key principle:** No single weak signal shall produce a `MALICIOUS` verdict. Unknown/inconclusive results default to `SAFE` with an informational note.

### 5.3 URL Cap and Budget

- Up to `config.max_urls_to_analyze` URLs analyzed (default: 200)
- Excess URLs beyond cap: reported as `total_urls_scanned` count without individual findings
- Per-URL analysis target: <5ms for static-only, <config.probe_timeout_seconds for network probe
- Total module budget: 1 second for 200 URLs (static), configurable for network mode

---

## 6. SSRF and Network Security Controls

> [!CAUTION]
> The network probe component (Step 4.3) MUST implement every control listed here. Failure to enforce all controls would make MailSentra itself a SSRF attack vector when processing attacker-crafted emails.

### 6.1 Pre-Connection IP Blocklist

Applied **before** any TCP connection is opened, and **again after each redirect hop** (because the redirect target may resolve to a different IP):

| Block Category | Range | RFC |
|---|---|---|
| IPv4 Private Class A | `10.0.0.0/8` | RFC 1918 |
| IPv4 Private Class B | `172.16.0.0/12` | RFC 1918 |
| IPv4 Private Class C | `192.168.0.0/16` | RFC 1918 |
| IPv4 Loopback | `127.0.0.0/8` | RFC 5735 |
| IPv4 Link-local (APIPA/Cloud Metadata) | `169.254.0.0/16` | RFC 3927 |
| IPv4 Multicast | `224.0.0.0/4` | RFC 1112 |
| IPv4 Broadcast / Reserved | `240.0.0.0/4` | RFC 1112 |
| IPv6 Loopback | `::1/128` | RFC 4291 |
| IPv6 Link-local | `fe80::/10` | RFC 4291 |
| IPv6 Unique Local (ULA) | `fc00::/7` | RFC 4193 |
| IPv6 Multicast | `ff00::/8` | RFC 4291 |
| IPv4-mapped IPv6 | `::ffff:0:0/96` | RFC 4291 |

**Additional block rules:**
- Block DNS names resolving to any of the above (e.g., `metadata.google.internal`, `169.254.169.254`)
- Block non-HTTP(S) schemes in probe (`ftp://`, `file://`, `gopher://` are forbidden)
- Reject URLs where host is `localhost` (case-insensitive)

### 6.2 Network Probe Configuration Defaults

| Parameter | Default | Notes |
|---|---|---|
| `enable_network_probe` | `False` | Explicitly opt-in; never probes by default |
| `max_redirect_hops` | 5 | Prevents infinite redirect chains |
| `probe_timeout_seconds` | 5.0 | Total timeout per URL (connect + response) |
| `max_response_bytes` | 65536 | HEAD preferred; body size capped for GET fallback |
| `follow_redirects` | True | But with per-hop SSRF validation |

### 6.3 httpx Configuration (Verified Package: 0.28.1)

```python
# Reference configuration only — not implementation
httpx.AsyncClient(
    follow_redirects=False,   # Manual redirect control for per-hop SSRF validation
    timeout=httpx.Timeout(5.0),
    max_redirects=0,          # We handle redirects manually
    verify=True,              # TLS verification always enabled (certifi installed)
    headers={"User-Agent": "MailSentra-URLProbe/1.0 (security-scanner; not-for-crawling)"}
)
```

### 6.4 Static IP-Host Detection (No Network, Always Active)

Even when `enable_network_probe=False`, URLs containing:
- Literal private/loopback IPv4 addresses as host
- IPv6 loopback/link-local in bracket notation
- Encoded IP addresses (hex/octal/decimal)

...shall receive a `MALICIOUS` verdict from static analysis alone, with no network request made.

---

## 7. Risk Scoring Design

### 7.1 Signal Table (Full)

```
SuspicionSignal (enum)
├── IP_HOST_PUBLIC            weight=6  → SUSPICIOUS alone
├── IP_HOST_PRIVATE           weight=10 → MALICIOUS alone
├── IP_HOST_LOOPBACK          weight=10 → MALICIOUS alone
├── IP_HOST_LINK_LOCAL        weight=10 → MALICIOUS alone
├── IP_HOST_ENCODED           weight=7  → SUSPICIOUS alone
├── SUSPICIOUS_TLD            weight=4  → needs corroboration
├── KNOWN_SHORTENER           weight=2  → SUSPICIOUS alone
├── OPEN_REDIRECT_PARAM       weight=4  → needs corroboration
├── HOMOGRAPH_HOSTNAME        weight=6  → SUSPICIOUS alone
├── PUNYCODE_DETECTED         weight=2  → needs corroboration
├── ZERO_WIDTH_UNICODE        weight=6  → SUSPICIOUS alone
├── USERINFO_IN_URL           weight=4  → SUSPICIOUS alone
├── TYPOSQUATTING_HOSTNAME    weight=6  → SUSPICIOUS alone
├── EXCESSIVE_URL_LENGTH      weight=2  → needs corroboration
├── HIGH_ENTROPY_PATH         weight=2  → needs corroboration
├── EXCESSIVE_SUBDOMAINS      weight=2  → needs corroboration
├── NON_STANDARD_PORT         weight=2  → needs corroboration
├── REDIRECT_TO_PRIVATE_IP    weight=10 → MALICIOUS alone (network probe result)
└── REDIRECT_CHAIN_LONG       weight=4  → SUSPICIOUS alone (network probe result)
```

### 7.2 Aggregation Algorithm

```
total_weight = sum(signal.weight for signal in detected_signals)
max_weight = max(signal.weight for signal in detected_signals, default=0)

if max_weight >= 10:
    severity = MALICIOUS
elif total_weight >= 10 or (max_weight >= 6 and total_weight >= 8):
    severity = MALICIOUS
elif total_weight >= 4 or max_weight >= 4:
    severity = SUSPICIOUS
else:
    severity = SAFE
```

### 7.3 Confidence Classification

| Confidence | Condition |
|---|---|
| `HIGH` | Network probe confirmed destination + 1+ static signal |
| `MEDIUM` | 2+ static signals corroborating, or 1 HIGH-weight signal |
| `LOW` | Single weak static signal |
| `INFORMATIONAL` | Zero signals; URL is `SAFE` |

### 7.4 `UrlFinding` Population

For each URL producing `SUSPICIOUS` or `MALICIOUS` verdict:
- `url`: original URL (not normalized — preserve what was in the email)
- `defanged_url`: defanged form (already computed by url_extractor)
- `resolved_ip`: IP address of host (if available from static parse or probe)
- `is_ip_host`: True if host was an IP literal
- `is_suspicious_tld`: True if TLD in suspicious list
- `is_open_redirect`: True if open redirect parameter detected
- `redirect_chain`: List of intermediate URLs (from network probe, else `[]`)
- `severity`: `UrlRiskSeverity` enum
- `reason`: Human-readable string listing all triggered signals

**Result cap:** At most `config.max_urls_to_analyze` findings reported. URLs with `SAFE` verdict are not included in `findings` list (to bound telemetry size).

---

## 8. Pipeline Integration Design

### 8.1 `ScanService` Changes

**`__init__`:** Add after `self.auth_analyzer`:
```python
# Module 5: URL Security Analyzer
self.url_analyzer = UrlAnalyzer()
```

**`ingest_and_parse()`:** Add after Module 4 (Auth Protocols) block:
```python
# Module 5: URL Security Analysis
url_result: Optional[UrlAnalysisResult] = None
try:
    url_result = await self.url_analyzer.analyze(parsed_email)
    incident_telemetry["url_analysis"] = url_result.model_dump(mode="json")
except Exception as e_url:
    logger.error("Module 5 URL analysis failed", exc_info=True)
    incident_telemetry["url_analysis"] = {"error": str(e_url), "status": "FAILED"}
```

**`shutdown()`:** Add:
```python
await self.url_analyzer.shutdown()
```

### 8.2 Input Contract

Module 5 receives `parsed_email.urls: List[ExtractedUrl]` — this list is fully populated by Module 2 (`EmailParser`) before any analysis modules run. No additional extraction is required.

### 8.3 Output Contract

`UrlAnalysisResult` stored as `incident.telemetry["url_analysis"]` JSON. Existing `ScanIncident.telemetry` column is a JSON dict — no schema migration required.

### 8.4 Ordering in Pipeline

```
Module 1: Ingestion (EmailIngestionService)
Module 2: Parsing   (EmailParser)             ← produces ParsedEmail.urls
Module 3: Identity  (SenderIdentityAnalyzer)
Module 4: Auth      (AuthProtocolsAnalyzer)
Module 5: URL       (UrlAnalyzer)             ← NEW, consumes ParsedEmail.urls
```

Module 5 is independent of Modules 3 and 4 (no data dependency). It could theoretically run concurrently with them, but sequential execution matches the existing pattern and keeps telemetry assembly simple.

### 8.5 Error Isolation Guarantee

- Module 5 failure (exception) MUST NOT abort the scan or affect Modules 3/4 results
- Error is recorded in telemetry with `{"error": ..., "status": "FAILED"}`
- `highest_severity` defaults to `UrlRiskSeverity.SAFE` on failure
- Existing test baseline (476 tests) must remain fully green after integration

---

## 9. Technology and Dependency Recommendations

### 9.1 Use (Already Installed — Zero New Dependencies for Static Analysis)

| Library | Usage |
|---|---|
| `urllib.parse` (stdlib) | `urlsplit`, `urlunparse`, `unquote`, `parse_qs` |
| `ipaddress` (stdlib) | `ip_address()`, `ip_network()`, SSRF IP validation |
| `re` (stdlib) | Scheme/shortener/redirect-param matching |
| `unicodedata` (stdlib) | Category checks for zero-width characters |
| `tldextract` (installed) | Registered domain extraction via offline PSL |
| `idna` (installed) | Punycode decode via `decode_idna_safely()` |
| `domain_utils` (project) | Full suite of hostname analysis functions |

### 9.2 Use for Network Probe (Step 4.3 Only — Already Installed)

| Library | Usage |
|---|---|
| `httpx` 0.28.1 | Async HTTP client with timeout, manual redirect control |
| `certifi` | TLS trust store (httpx uses it automatically) |

### 9.3 Do NOT Add

- `aiohttp` — not installed; `httpx` already covers async HTTP needs
- `validators` — not installed; stdlib `urllib.parse` + custom logic is sufficient
- `publicsuffix2` — not installed; `tldextract` already installed and used in `domain_utils`
- Any reputation API client — out of scope for Step 4.1/4.2 (Phase 4 work)

### 9.4 No External API Calls in Step 4.1 / 4.2

Static-only analysis produces zero network requests. External reputation lookups (VirusTotal, AbuseIPDB) are deferred to Phase 4 (`ThreatIntelResult` contract is already defined for future use).

---

## 10. Testing and Validation Strategy

### 10.1 Test File

**Primary:** `backend/tests/test_url_analyzer.py` (new file)
**Extend:** `backend/tests/test_email_parser.py` (optional integration assertions)

### 10.2 Test Categories

| Category | Coverage | Count Target |
|---|---|---|
| URL normalization | Scheme case, host lowercasing, trailing punctuation, fragment strip | 8 |
| IP host detection | IPv4 literal, IPv6 bracket, hex-IP, octal-IP, decimal-IP | 10 |
| Suspicious TLD | `.zip`, `.top`, `.tk`, `.xyz`, `.cf`, legitimate `.com` (no FP) | 8 |
| URL shortener detection | `bit.ly`, `t.co`, `tinyurl.com`, unknown domain (no FP) | 5 |
| Open redirect detection | `redirect_to=`, `url=`, `next=`, `goto=`, path without params (no FP) | 8 |
| Homograph/Unicode | Mixed-script hostname, zero-width in path, Punycode label | 6 |
| Typosquatting | Near-match to protected domain, exact match (no FP) | 5 |
| SSRF static detection | Private IP URL → MALICIOUS, public IP → SUSPICIOUS | 6 |
| Verdict logic | Single weak signal → SAFE, corroborated signals → escalation | 8 |
| URL cap enforcement | 200+ URL list → only max_urls_to_analyze analyzed | 2 |
| Pipeline integration | `ScanService` populates `telemetry["url_analysis"]` correctly | 4 |
| Error isolation | Module 5 exception → scan completes, telemetry has error key | 2 |
| Regression | All 476 existing tests still pass | (run full suite) |

**Total target:** ≥ 50 new tests for Module 5

### 10.3 SSRF Test Cases (Critical)

```python
# These URLs must produce MALICIOUS verdict from STATIC analysis alone
# (no network probe required):
SSRF_STATIC_MALICIOUS = [
    "http://10.0.0.1/secret",
    "http://192.168.1.1:8080/admin",
    "http://172.16.0.1/internal",
    "http://127.0.0.1/localhost",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/admin",
    "http://[fe80::1]/admin",
    "http://0x7f000001/loopback",        # hex-encoded 127.0.0.1
    "http://0177.0.0.01/loopback",       # octal-encoded
    "http://2130706433/",                # decimal-encoded 127.0.0.1
]
```

### 10.4 Mock Strategy for Network Probe Tests

```python
# Use httpx's built-in test transport for deterministic redirect simulation:
# httpx.MockTransport / respx (if installed) OR unittest.mock.patch
# No live network calls in any test
```

### 10.5 False-Positive Guard Tests

```python
# These legitimate URLs must NOT produce SUSPICIOUS or MALICIOUS:
FP_GUARD_SAFE = [
    "https://www.google.com/search?q=python",
    "https://github.com/user/repo",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://en.wikipedia.org/wiki/Email",
    "https://portal.enterprise.com/benefits",   # multi-label subdomain but benign
]
```

---

## 11. Phased Implementation Plan

### Phase 1 — Step 4.1 (Current): Architecture Assessment ✅ COMPLETE
- READ-ONLY inspection, threat modeling, dependency verification
- This document is the deliverable

### Phase 2 — Step 4.2: Static Analysis Engine
**Scope (zero new dependencies):**
1. `url_analysis/config.py` — `UrlAnalysisConfig`
2. `url_analysis/normalizer.py` — `UrlNormalizer`, `UrlComponentParser`
3. `url_analysis/host_analyzer.py` — `HostAnalyzer` (IP detection, Punycode, PSL via domain_utils)
4. `url_analysis/suspicion_engine.py` — `SuspicionEngine`, `SuspicionSignal` enum, all static heuristics
5. `url_analysis/risk_aggregator.py` — `RiskAggregator` (signal weighting, verdict logic)
6. `url_analysis/analyzer.py` — `UrlAnalyzer` (BaseDetectionModule implementation)
7. Update `url_analysis/__init__.py` docstring
8. `backend/tests/test_url_analyzer.py` — ≥ 45 static analysis tests
9. Pipeline integration: add `UrlAnalyzer` to `ScanService`
10. Regression verification: 476 + new tests all pass

### Phase 3 — Step 4.3: Network Probe (Optional, Disabled by Default)
**Scope:**
1. `url_analysis/network_probe.py` — `SsrfBlocker`, `NetworkProbe`
2. Configure `httpx.AsyncClient` with strict SSRF controls
3. Integrate probe result into `RiskAggregator`
4. Test: SSRF blocking, redirect chain tracking, timeout, circular redirect, response size cap
5. Enable via `UrlAnalysisConfig(enable_network_probe=True)` in tests only

### Phase 4 — Step 4.4: Threat Intelligence Integration
**Scope:**
1. `UrlAnalyzer` optionally queries `ThreatIntelResult` for domain/IP reputation
2. Integration with Phase 4 roadmap: AbuseIPDB, VirusTotal connectors
3. `ObservableReputation` and `ThreatIntelResult` contracts already defined in `contracts.py`

### Phase 5 — Step 4.5: Risk Engine Contribution
**Scope:**
1. `UrlAnalysisResult.highest_severity` contributes to `RiskDecisionReport`
2. URL findings included in explainable rationale matrix
3. `RiskDecisionReport`, `ScoredFactor`, `DecisionTier` contracts already defined

---

## 12. Acceptance Criteria

### Non-Negotiable (Must Pass for Step 4.2 Approval)

- [ ] All 476 existing backend tests continue to pass (zero regressions)
- [ ] `UrlAnalyzer` implements `BaseDetectionModule` interface (`module_name`, `version`, `analyze()`)
- [ ] `UrlAnalysisResult` is populated with correct contract fields (no extra fields, no missing fields)
- [ ] `incident.telemetry["url_analysis"]` is populated after scan completes
- [ ] Module 5 failure (simulated exception) does not abort the scan or affect other modules' telemetry
- [ ] No duplicate contracts created (must import `UrlRiskSeverity`, `UrlFinding`, `UrlAnalysisResult` from `contracts.py`)
- [ ] Static SSRF detection: all 10 private/loopback/link-local IP URLs produce `MALICIOUS` verdict WITHOUT network probe
- [ ] `UrlAnalysisConfig(enable_network_probe=False)` is the default (no outbound connections in production)

### Quality Targets

- [ ] ≥ 50 new URL analyzer tests pass
- [ ] FP guard tests: 5+ legitimate URLs produce `SAFE` verdict
- [ ] Single weak signal (e.g., `.xyz` TLD alone) produces at most `SUSPICIOUS`, never `MALICIOUS`
- [ ] URL analysis completes for 200 URLs in < 1 second (static-only mode)
- [ ] Bytecode compilation passes: `python -m compileall backend/app/modules/url_analysis/`

### Security Controls Verification

- [ ] All Step 3.7.3B remediations (L3, H2, H3, M1, L1, L2) remain intact
- [ ] All Step 3.7.3C authentication protections unaffected
- [ ] No user-controllable input reaches a network connection without SSRF pre-filter
- [ ] Query parameter values are not logged in plain form (defanged form used in findings)

---

## Dependency Map

```mermaid
flowchart TD
    P2[ParsedEmail.urls\nModule 2 output] --> U5[UrlAnalyzer\nModule 5 INPUT]
    DC[contracts.py\nUrlRiskSeverity\nUrlFinding\nUrlAnalysisResult\nExtractedUrl] --> U5
    DU[domain_utils.py\ndecode_idna_safely\ndetect_mixed_scripts\ndetect_suspicious_unicode\nget_registered_domain_offline\ndamerau_levenshtein_distance] --> U5
    SS[Settings\nMAX_EXTRACTED_URLS=500] --> U5
    HX[httpx 0.28.1\ninstalled] --> NP[NetworkProbe\nStep 4.3 only]
    IP[ipaddress stdlib] --> SSRF[SsrfBlocker]
    NP --> U5
    SSRF --> NP
    U5 --> TEL[incident.telemetry\nurl_analysis]
```

---

**Assessment Verdict:**

> **READY FOR IMPLEMENTATION**
>
> All contracts are defined, all required dependencies are installed, all reusable utilities are verified, and the pipeline integration point is clearly identified. Step 4.2 (Static Analysis Engine) can begin immediately with zero new dependency installations.
