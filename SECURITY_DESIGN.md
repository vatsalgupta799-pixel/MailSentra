# MailSentra Security Design & Threat Model

## 1. Threat Modeling (STRIDE Methodology)

Security platforms are high-value targets. An attacker who can compromise an email security gateway or deceive an automated scanning pipeline can evade detection and blind SOC teams. We apply the **STRIDE** model to secure MailSentra against adversarial exploitation.

| Threat Category | Potential Attack Vector | MailSentra Countermeasure & Architectural Defense |
| :--- | :--- | :--- |
| **Spoofing Identity** | Attacker impersonates trusted executives or internal staff via display name or cousin domains. | Strict multi-factor identity verification: Header-From vs Envelope-From validation, Levenshtein distance typosquatting scans, visual homoglyph/Punycode normalization, and DMARC alignment checks. |
| **Tampering with Data** | Attacker injects malicious payloads into MIME headers (e.g., header injection, CRLF attacks) to alter parser behavior. | Strict input sanitization via RFC 2047 compliant decoders. Strict regex normalization preventing header injection. Disabling HTML script execution in preview rendering. |
| **Repudiation** | An analyst modifies threat classifications or an admin disables detection rules without a traceable record. | Cryptographically timestamped, append-only **Audit Logging Module**. Strict database permissions preventing `UPDATE` or `DELETE` operations on audit tables. |
| **Information Disclosure** | Sensitive internal email contents or executive names leaked through verbose API error traces. | Production error masking: generic HTTP exception wrappers. Zero logging of credentials, session keys, or unredacted PII in system logs. Strict tenant data segregation. |
| **Denial of Service (DoS)** | Attacker submits oversized emails, nested zip bombs (decompression bombs), or thousands of recursive URLs to exhaust server CPU/memory. | Strict payload caps (15MB maximum file upload). URL extraction limits (maximum 100 URLs inspected per email). Safe ZIP decompression inspecting uncompressed size headers before byte extraction. Asynchronous execution boundaries with aggressive timeouts. |
| **Elevation of Privilege** | An authenticated user with read-only access calls administrative configuration endpoints. | Role-Based Access Control (RBAC) enforced at the dependency injection level in FastAPI (`SecurityScopes` + `get_current_active_user`). Cryptographically signed JWT tokens with short TTLs. |

---

## 2. Authentication & Authorization Architecture

### 2.1 Password Security
- User credentials are encrypted using **Argon2id** (the winner of the Password Hashing Competition) or **Bcrypt** with a minimum work factor of 12.
- Plaintext passwords are never logged, cached, or persisted in application state.

### 2.2 Token Management
- Access tokens are issued as stateless **JSON Web Tokens (JWT)** signed with `HS256` (symmetric secret) or `RS256` (asymmetric private key).
- Default access token expiration is set to 30 minutes.
- Refresh tokens are persisted as cryptographically hashed tokens in the database with one-time rotation semantics to detect token theft.

### 2.3 Role-Based Access Control (RBAC) Matrix

| Endpoint Group / Action | `SUPER_ADMIN` | `SOC_ANALYST` | `AUDITOR` | `SYSTEM_AGENT` |
| :--- | :---: | :---: | :---: | :---: |
| **Upload & Scan Email** | Yes | Yes | No | Yes |
| **View Incident Queue** | Yes | Yes | Yes | No |
| **Triage / Override Decision** | Yes | Yes | No | No |
| **Download EML Artifact** | Yes | Yes | No | No |
| **View Audit Logs** | Yes | Yes | Yes | No |
| **Manage Users & Tenants** | Yes | No | No | No |
| **Update System Thresholds** | Yes | No | No | No |
| **Query Health Telemetry** | Yes | Yes | Yes | Yes |

---

## 3. Secure Coding & Defensive Implementation Rules

1. **Zero Raw SQL**: All database queries MUST use SQLAlchemy ORM or parameterized Core statements. Raw SQL string concatenation is strictly prohibited to prevent SQL Injection.
2. **Safe HTML Handling**: The Admin Dashboard MUST NEVER use `dangerouslySetInnerHTML` or raw HTML evaluation for email body rendering. All email previews are stripped of `<script>`, `<iframe>`, `object`, and remote tracking pixels.
3. **Defanging by Default**: All suspicious URLs and IP addresses displayed in the UI or emitted in API payloads are defanged (e.g., `hxxps[://]badsite[.]com`, `192[.]168[.]1[.]1`) to prevent accidental analyst click-through.
4. **Environment Isolation**: No production credentials, API secrets, or encryption keys shall ever be committed to the code repository. Configuration is strictly injected through environment variables validated at startup by Pydantic's `BaseSettings`.
5. **Least Privilege System Execution**: Application containers and services run as non-root users (`uid=10001`) with read-only root filesystems where applicable.
