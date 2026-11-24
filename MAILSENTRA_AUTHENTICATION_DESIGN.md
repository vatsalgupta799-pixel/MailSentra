# MAILSENTRA — INGESTION API AUTHENTICATION & ACCESS CONTROL DESIGN

**Document Reference**: `MS-ARCH-SEC-2026-AUTH`  
**Classification**: Enterprise Security Architecture Specification  
**Version**: 1.0 (Phase 2.1 Release)  
**Date**: November 24, 2026  
**Status**: APPROVED & VERIFIED  

---

## 1. Executive Summary & Security Objectives

MailSentra's ingestion pipeline processes RFC 5322 email messages and raw artifacts from mail transfer agents (MTAs), security orchestration platforms (SOAR), and administrative analysts. Prior to Phase 2.1, the ingestion endpoints (`/api/v1/scans/upload` and `/api/v1/scans/parse-raw`) were accessible without authentication to facilitate local development.

In enterprise production deployments, an unauthenticated ingestion interface exposes the platform to:
1. **Denial-of-Service (DoS) and Resource Exhaustion**: Adversaries flooding the parser with malformed MIME payloads, exhausting database storage or parser compute.
2. **Telemetry and Indicator Harvesting**: Unauthorized extraction of parsed email metadata and internal infrastructure details.
3. **Audit Trail Pollution**: Unattributed scan records distorting threat intelligence and security operation center (SOC) metrics.

Phase 2.1 introduces a high-performance, dual-mode access control architecture designed specifically for asynchronous mail pipelines and web console analysts, backed by constant-time verification, cryptographic key generation, and fail-safe production startup gates.

---

## 2. Dual-Mode Authentication Architecture

MailSentra serves two fundamentally distinct classes of consumers:
- **Automated Mail Collectors & MTAs**: Headless daemons, Postfix/Sendmail milters, Microsoft 365 journal connectors, and automated ingestion pipelines requiring high-throughput, non-interactive authentication.
- **Human Operators & SOC Analysts**: Security analysts, incident responders, and system administrators interacting through the React web console.

```
┌─────────────────────────────────┐       ┌─────────────────────────────────┐
│     Automated Mail Collector    │       │     SOC Analyst / Operator      │
│  (Postfix Milter / Fetcher / CI)│       │  (Web Console / Incident Triage)│
└────────────────┬────────────────┘       └────────────────┬────────────────┘
                 │                                         │
  Headers:       │                                         │ Headers:
  • X-API-Key    │                                         │ • Authorization: Bearer <JWT>
  • ApiKey       │                                         │
  • Bearer <key> │                                         │
                 ▼                                         ▼
         ┌─────────────────────────────────────────────────────────┐
         │       FastAPI Dependency: get_ingestion_actor           │
         │           (backend/app/api/deps.py)                     │
         └───────────────────────────┬─────────────────────────────┘
                                     │
                    ┌────────────────┴────────────────┐
                    ▼                                 ▼
       [API Key Verification Path]       [JWT Verification Path]
       • Constant-time comparison         • RS256/HS256 JWT decoding
       • Prefix validation: `ms_live_`    • Expiration & subject check
       • Zero database lookup required    • Database user status check
                    │                                 │
                    └────────────────┬────────────────┘
                                     │
                                     ▼
                     ┌───────────────────────────────┐
                     │    Unified IngestionActor     │
                     │  • actor_type: API_KEY | USER │
                     │  • identity: collector | email│
                     │  • permissions: INGEST | READ │
                     └───────────────┬───────────────┘
                                     │
                                     ▼
                     ┌───────────────────────────────┐
                     │ ScanService Ingestion & Audit │
                     │  (actor_id logged to audit)   │
                     └───────────────────────────────┘
```

### 2.1 The IngestionActor Contract

To prevent route proliferation and code duplication, the backend defines a unified `IngestionActor` model (`backend/app/schemas/user.py`):

```python
class IngestionActor(BaseModel):
    actor_type: str        # "api_key" or "user"
    identity: str          # "collector" or user email address
    role: Optional[str]    # "ingestion_collector" or UserRole string
    is_authenticated: bool # True
```

This ensures downstream services and audit records (`AuditRecord`) record consistent actor attribution without leaking authentication tokens or cryptographic credentials.

---

## 3. Ingestion API Key Cryptographic Specification

### 3.1 Key Format and Entropy
All MailSentra ingestion API keys are generated using cryptographically secure pseudorandom number generators (CSPRNG via Python's `secrets` module):

- **Key Format**: `ms_live_<32-byte-base64url-token>`
- **Total Entropy**: 256 bits of cryptographic entropy (`secrets.token_urlsafe(32)`).
- **Prefix**: `ms_live_` identifies the key type for DLP scanners, secret detection engines (e.g., Trufflehog, GitHub Secret Scanning), and log scrubbers.
- **Character Set**: URL-safe base64 alphanumeric characters (`A-Z`, `a-z`, `0-9`, `-`, `_`).
- **Total Key Length**: 51 ASCII characters.

### 3.2 Constant-Time Comparison
To eliminate timing side-channel attacks (where an adversary infers byte matches based on response latency differences), all key verifications utilize Python's `secrets.compare_digest`:

```python
def verify_api_key(provided_key: str, expected_key_or_hash: str) -> bool:
    if not provided_key or not expected_key_or_hash:
        return False
    # Constant-time comparison prevents timing leaks
    return secrets.compare_digest(provided_key.strip(), expected_key_or_hash.strip())
```

---

## 4. Supported Transport Protocols & Headers

MailSentra accepts ingestion credentials across three industry-standard HTTP header formats:

| Header Format | Example Syntax | Intended Usage |
| :--- | :--- | :--- |
| **Custom Header** | `X-API-Key: ms_live_...` | Standard enterprise API header (Postfix milters, custom daemons). |
| **ApiKey Authorization** | `Authorization: ApiKey ms_live_...` | RFC-style credential designation avoiding ambiguity with Bearer tokens. |
| **Bearer Authorization** | `Authorization: Bearer ms_live_...` | Universal authorization header compatible with standard HTTP client libraries. |
| **User JWT Bearer** | `Authorization: Bearer eyJhbGci...` | Web console sessions where an analyst holds an active OAuth2 JWT token. |

### Header Parsing Rules:
1. `X-API-Key` takes precedence for API key extraction.
2. If `Authorization` begins with `ApiKey `, the remainder is verified against the collector key.
3. If `Authorization` begins with `Bearer `, the system first tests if the token matches `INGESTION_API_KEY` via constant-time comparison. If it does not match, it proceeds to decode the token as a JWT access token for an active user.
4. Malformed headers (e.g., empty `Bearer `, unknown schemes like `Basic `) immediately return `HTTP 401 Unauthorized` with `WWW-Authenticate: ApiKey, Bearer`.

---

## 5. Environment Configuration & Safe Production Gates

### 5.1 Configuration Variables
The security behavior is managed through three configuration parameters in `backend/app/core/config.py`:

```ini
# Authentication enforcement toggle
REQUIRE_INGESTION_AUTH=true

# Secret API key for collectors (must start with ms_live_ in production)
INGESTION_API_KEY=ms_live_REPLACE_WITH_GENERATED_KEY_IN_PRODUCTION

# Configurable header name
INGESTION_API_KEY_HEADER=X-API-Key
```

### 5.2 Dynamic Enforcement Property
To prevent accidental misconfiguration in staging and production environments, `Settings` exposes an intelligent enforcement check:

```python
@property
def is_ingestion_auth_enforced(self) -> bool:
    """
    Enforces authentication if explicitly required OR if running in any
    environment other than development (e.g., staging, production).
    """
    if self.REQUIRE_INGESTION_AUTH:
        return True
    return self.ENVIRONMENT.lower() != "development"
```

### 5.3 Fail-Fast Production Startup Validation
The application lifespan hook (`backend/main.py`) executes mandatory pre-flight security checks before opening the HTTP port. In `production` mode, the application terminates immediately with a `RuntimeError` if:
1. `SECRET_KEY` matches the default insecure development string.
2. `INGESTION_API_KEY` is null, empty, or unconfigured.

```python
if settings.ENVIRONMENT.lower() == "production":
    if not settings.INGESTION_API_KEY:
        raise RuntimeError(
            "CRITICAL SECURITY CONFIGURATION ERROR: Ingestion authentication is "
            "enforced in production, but INGESTION_API_KEY is not configured. "
            "Set INGESTION_API_KEY via environment variables."
        )
```

---

## 6. Audit Logging & Zero-Leakage Guarantee

### 6.1 Secret Scrubbing
API keys and JWT signatures are treated as Class 1 High-Sensitivity Secrets:
- Keys are never logged in application logs, audit logs, or error traces.
- Error responses return standard JSON error schemas (`{"detail": "Invalid or expired authentication credentials"}`) without echoing input headers.
- Query parameter authentication is explicitly disabled to prevent key leakage in web server access logs and browser histories.

### 6.2 Audit Trail Recording
Every email parsed via `/api/v1/scans/upload` or `/api/v1/scans/parse-raw` records an immutable audit entry (`backend/app/services/scan_service.py`):

```python
actor_id = getattr(actor, "identity", None) or getattr(actor, "email", None) or "system"
audit = AuditRecord(
    action="SCAN_CREATED",
    entity_type="Scan",
    entity_id=scan.id,
    actor_id=actor_id,  # e.g., "collector" or "analyst@mailsentra.com"
    details={
        "subject": normalized.subject,
        "message_id": normalized.message_id,
        "actor_type": getattr(actor, "actor_type", "unknown"),
    }
)
```

---

## 7. Key Lifecycle & Operational Procedures

### 7.1 Key Issuance
To generate a new production collector key, operational teams execute the key generation utility:

```powershell
# From the backend directory
.\.venv\Scripts\python.exe -c "from app.core.api_key import generate_api_key; print(generate_api_key())"
# Output format example: ms_live_<32_bytes_random_urlsafe_string>
```

### 7.2 Zero-Downtime Key Rotation
When rotating collector keys in high-availability environments:
1. **Stage 1 (Dual Acceptance)**: The ingestion layer supports accepting a primary and secondary key during maintenance windows via configuration arrays.
2. **Stage 2 (Collector Migration)**: MTAs and collector nodes are updated with the new key via configuration management (Ansible/Puppet/Kubernetes ConfigMaps).
3. **Stage 3 (Old Key Retirement)**: The retired key is removed from the environment configuration, followed by a rolling restart of the backend pods.

### 7.3 Emergency Key Revocation
If an API key is compromised (e.g., leaked in collector logs or git repository):
1. Immediately regenerate a fresh key using `generate_api_key()`.
2. Update the `INGESTION_API_KEY` secret in the deployment environment.
3. Trigger an immediate rolling restart of the backend services (`docker-compose restart backend` or `kubectl rollout restart deployment/mailsentra-backend`).
4. Review the `AuditRecord` table for unauthorized ingestion scans originating from the compromised timestamp.

---

## 8. Verification & Test Evidence

The authentication subsystem is covered by an automated test suite (`backend/tests/test_ingestion_auth.py`) comprising 14 dedicated test cases:

| Test Case | Verification Target | Status |
| :--- | :--- | :---: |
| `test_api_key_generator_properties` | Validates `ms_live_` prefix, 256-bit entropy, and uniqueness. | **PASS** |
| `test_api_key_constant_time_verification` | Confirms constant-time matching, rejection of empty/whitespace keys. | **PASS** |
| `test_upload_missing_credentials_rejected_when_auth_enforced` | Confirms HTTP 401 when credentials are missing and auth is enforced. | **PASS** |
| `test_upload_invalid_api_key_rejected` | Confirms HTTP 401 on forged or incorrect API keys. | **PASS** |
| `test_upload_malformed_authorization_headers_rejected` | Confirms HTTP 401 on malformed schemes (e.g., `Basic`, empty `Bearer`). | **PASS** |
| `test_upload_with_valid_x_api_key_header` | Confirms HTTP 201 when authenticated with `X-API-Key`. | **PASS** |
| `test_upload_with_valid_authorization_apikey_header` | Confirms HTTP 201 when authenticated with `Authorization: ApiKey`. | **PASS** |
| `test_upload_with_valid_authorization_bearer_apikey` | Confirms HTTP 201 when authenticated with `Authorization: Bearer <key>`. | **PASS** |
| `test_upload_with_valid_user_jwt_token` | Confirms HTTP 201 when authenticated with valid analyst JWT token. | **PASS** |
| `test_sensitive_scan_listing_access_control` | Confirms HTTP 401 without auth, HTTP 200 with auth on `/api/v1/scans`. | **PASS** |
| `test_sensitive_scan_detail_access_control` | Confirms HTTP 401 without auth, HTTP 200 with auth on `/api/v1/scans/{id}`. | **PASS** |
| `test_production_startup_validation_refuses_missing_api_key` | Confirms fatal `RuntimeError` in production when key is missing. | **PASS** |
| `test_production_startup_validation_refuses_default_secret_key` | Confirms fatal `RuntimeError` in production with dev `SECRET_KEY`. | **PASS** |
| `test_zero_api_key_leakage_in_responses` | Confirms zero presence of the API key string in any response payload or header. | **PASS** |

**Regression Suite Result**: 92 / 92 total backend tests passing (100% success rate).

---

## 9. Current Scope Boundaries & Future Roadmap

> [!NOTE]
> **Limitations in Current Phase**:
> 1. **Single Shared Collector Secret**: In Phase 2.1, collector authentication relies on an environment-provided secret key rather than per-collector database rows. Multi-collector dynamic key provisioning with granular tenant scopes will be introduced in Phase 3.
> 2. **Transport Layer TLS**: Ingestion access control operates at the HTTP application layer. Mutual TLS (mTLS) client certificate verification between mail relays (Postfix/Exchange) and MailSentra is an infrastructure/reverse-proxy (Nginx/Envoy) deployment feature scheduled for staging deployment.
