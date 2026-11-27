# MailSentra — Step 3.7.3B Implementation Report: DMARC Enforcement Engine

**Project:** MailSentra  
**Architecture Reference:** `MS-ARCH-SEC-2026-AUTH-PROTOCOLS-REV13` & Revised [STEP_3_7_3A_ARCHITECTURE_INSPECTION.md](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/STEP_3_7_3A_ARCHITECTURE_INSPECTION.md)  
**Remediation & Hardening Authority:** [STEP_3_7_3B_REMEDIATION_REPORT.md](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/STEP_3_7_3B_REMEDIATION_REPORT.md) (`H1`–`H3`, `M1`–`M5`) & [STEP_3_7_3B_FINAL_HARDENING_REPORT.md](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/STEP_3_7_3B_FINAL_HARDENING_REPORT.md) (`L3`, `H2`, `H3`, `M1`, `L1`, `L2`)  
**Repository:** `C:\Users\vatsa\OneDrive\Desktop\MailSantra`  
**Branch:** `main`  
**Baseline HEAD Commit:** `113132f66b37dc71cf681e15db1925d6b9f68069`  
**Scope:** Step 3.7.3B — DMARC Evaluation Corrections, Published-Policy Interpretation & Provenance, Receiver-Local Disposition Engine (`DMARCPolicyEnforcer`), and Final Pre-3.7.3C Security Hardening  
**Stop Boundary:** Complete through Step 3.7.3B + Remediation (`H1`–`H3`, `M1`–`M5`) + Final Security Hardening (`L3`, `H2`, `H3`, `M1`, `L1`, `L2`) only (`Authentication-Results` serialization, `local_authserv_id`, RFC 6008 `header.b`, header prepending, `ScanService` wiring, real SMTP receiver listeners, and admin DB tables/endpoints remain out of scope for Step 3.7.3C and later).

---

## 1. Files Changed & Created Inventory

All pre-existing uncommitted Day 3 files and prior audit/remediation documentation (`STEP_3_7_2D*`, `STEP_3_7_3A*`, `STEP_3_7_3B_REMEDIATION_REPORT.md`) were preserved intact. No `git reset`, `git clean`, `git stash`, `git revert`, `git add`, `git commit`, or `git push` operations were performed.

### 1.1 Newly Created in Step 3.7.3B (+ Remediation & Final Hardening Reports)
- [policy_enforcer.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/policy_enforcer.py) — Implements `DMARCPolicyEnforcer` (Tier 3 Stages 3–6 decision engine) with:
  - Channel-isolated forwarder/mailing-list validation (`_evaluate_indirect_flow_evidence()`) strictly gated to `SMTP_RELAY` with `is_trusted_mta=True`, `mta_sanitization_guaranteed=True`, dual connector ID + relay IP allowlists, optional `trusted_forwarder_bindings`, and strict `ForwarderTrustEvidence` relay-context matching;
  - Domain-separated per-enforcer 256-bit HMAC provenance secrets (`_config_provenance_secret` with `CONFIG_RULE_V1:` via private `_load_and_attest_config_rules()` / `_attest_config_rule()`, vs. `_admin_provenance_secret` with `ADMIN_RULE_V1:` via public `attest_server_rule()` requiring strict non-API-key `authorizing_actor`, matching `tenant_id`, `configured_by_identity`, and `configured_by_role`);
  - Telemetry PII redaction (`_redact_email_identity()` across SPF, DKIM `i=`, and `auth_protocols_summary`), complete SHA-256 audit fingerprinting (`_compute_decision_audit_fingerprint()`), and transaction-safe `record_dmarc_decision_on_incident()` isolating post-commit best-effort `AuditLogger.log_event()` failures via `audit_delivery_status`.
- [test_dmarc_policy_enforcement.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_dmarc_policy_enforcement.py) — Comprehensive enforcement, policy selection, interoperability, override, conflict arbitration, channel separation, `L3` forwarder trust boundary, `H2` attestation/secret separation & tenant isolation, `t=y` vs. local override audit separation, and `M1` SQLite transaction/rollback/post-commit logger isolation/fingerprint/DKIM privacy tests (`17` test functions).
- [STEP_3_7_3B_IMPLEMENTATION_REPORT.md](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/STEP_3_7_3B_IMPLEMENTATION_REPORT.md) — Updated Step 3.7.3B implementation report reflecting final hardening.
- [STEP_3_7_3B_REMEDIATION_REPORT.md](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/STEP_3_7_3B_REMEDIATION_REPORT.md) — Preserved prior remediation report covering `H1`–`H3` and `M1`–`M5`.
- [STEP_3_7_3B_FINAL_HARDENING_REPORT.md](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/STEP_3_7_3B_FINAL_HARDENING_REPORT.md) — Dedicated verification report closing `L3`, `H2`, `H3`, `M1`, `L1`, and `L2`.

### 1.2 Pre-Existing Tracked Modified Files Extended in Step 3.7.3B
- [contracts.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/contracts.py) — Replaced ambiguous `.published_policy` with explicit `record_p_policy` (`DMARCResult` and `DMARCEnforcementDecision`) and `selected_applicable_policy` (`DMARCEnforcementDecision`); added `DKIMEvaluationState` (`NOT_EVALUATED_MISSING_RAW_BYTES`, `EVALUATED_NO_SIGNATURES`, `EVALUATED_COMPLETED`, `INCOMPLETE_INTERNAL_ERROR`, `INCOMPLETE_TRANSIENT_ERROR`), `evaluation_state`, `reason_code`, `alignment_source`, `alignment_is_authoritative`, and `standalone_psl_aligned_relaxed` on `DKIMSignatureResult`, and `dkim_evaluation_state` on `AuthProtocolsResult`; added `subdomain_policy`, `non_existent_subdomain_policy`, `applicable_policy_tag`, `policy_discovery_source`, `policy_domain`, `is_psd_policy`, `is_subdomain`, `is_subdomain_non_existent`, `subdomain_existence_probe_enabled`, `subdomain_existence_status`, `np_evaluation_skipped_reason`, `test_mode`, `raw_tags`, and `diagnostics` on `DMARCResult`; extended `AuthProtocolsResult` (`dmarc_test_mode`, `dmarc_enforcement`); added Tier 3 enforcement contracts (`DMARCDisposition`, `PolicyOverrideType`, `OverrideRuleAction`, `LocalPolicyOverrideRule`, `ForwarderTrustEvidence`, `CorroboratingThreatSignals`, `SMTPAdapterDecisionContract`, `DMARCEnforcementDecision`).
- [__init__.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/__init__.py) — Exported all Step 3.7.3B contracts including `DKIMEvaluationState`, `DNSOutcomeCategory`, `DMARCPolicyEnforcer`, `build_dmarc_enforcement_telemetry`, `record_dmarc_decision_on_incident`, `parse_dmarc_tags_with_metadata`, and `DMARCDiscoveryStatus`.
- [test_contracts.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_contracts.py) — Added `test_step373b_dmarc_enforcement_decision_contract_roundtrip`, `test_step373b_remediation_m5_config_and_policy_serialization`, `test_step373b_remediation_l2_typed_dkim_state_contract_roundtrip`, and updated `test_contracts_import_from_auth_protocols_module`.

### 1.3 Pre-Existing Untracked Day 3 Files Updated in Step 3.7.3B & Hardening
- [config.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/config.py) — Added `dmarc_temperror_smtp_action`, `dmarc_enforce_strict_reject_only_with_corroboration` (fail-closed `@field_validator` rejecting `False` or non-bool values per RFC 9989 §7.4), `dmarc_enable_subdomain_existence_probe: bool = False`, `trusted_forwarder_connector_ids`, `trusted_forwarder_ips`, `trusted_forwarder_bindings`, and `local_override_rules` (`local_authserv_id` explicitly omitted).
- [dns_resolver.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/dns_resolver.py) — Added `DNSErrorType.INTERNAL_ERROR`, `DNSOutcomeCategory` (`VALID_RECORDS`, `AUTHORITATIVE_NXDOMAIN`, `NODATA`, `TRANSIENT_FAILURE`, `RESOLVER_FAILURE`, `INVALID_QUERY`, `MALFORMED_RESPONSE`, `INTERNAL_ERROR`), and helper properties on `DNSResponse` (`is_internal_error`, `is_transient_error`, etc.); excluded `is_internal_error` from `DNSCache.put()`; hardened `AsyncDNSResolver.resolve()` to re-raise `asyncio.CancelledError`, map `YXDOMAIN`/`NameTooLong`/`LabelTooLong`/`EmptyLabel`/`SyntaxError` before `FormError` to `INVALID_QUERY`, `FormError` to `FORMERR`, timeouts to `TIMEOUT`, `NoNameservers` to `SERVFAIL`, `ConnectionError`/`OSError`/`DNSException` to `RESOLVER_ERROR`, and unexpected non-DNS runtime exceptions (including cache/outer guards) to sanitized `INTERNAL_ERROR`; added `MockDNSResolver` helpers (`set_resolver_error`, `set_refused`, `set_formerr`, `set_invalid_query`, `set_internal_error`).
- [evaluators/__init__.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/evaluators/__init__.py) — Exported `DMARCDiscoveryStatus` and `parse_dmarc_tags_with_metadata`.
- [dmarc.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/evaluators/dmarc.py) — Resolved `C1` and `C2` contradictions; added `parse_dmarc_tags_with_metadata()`, RFC 9989 §4.10.1 applicable-policy selection with provenance, `dmarc_enable_subdomain_existence_probe` wiring into `evaluate()` and `evaluate_auth_protocols()` with explicit probe provenance, multi-`From` (`all_from_domains`) `PERMERROR`, strict `L1` `psd=y` candidate filtering requiring `cand_domain == child_org_domain` so intermediate `psd=u` records cannot shadow PSD policies, `L2` typed `DKIMEvaluationState` + `reason_code` checks replacing English substring matching and authoritative DNS Tree Walk override of `DKIMSignatureResult` alignment (`alignment_source="dmarc_tree_walk_authoritative"`, `alignment_is_authoritative=True`), explicit `DMARCDiscoveryStatus.INDETERMINATE` propagation across cached and live alignment paths (`H1`), and `is_internal_error` / DNS error classification across discovery, tree walk, Org Domain resolution, and subdomain probes (`H3`).
- [dkim.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/evaluators/dkim.py) — Classified `DNSResponseStatus.ERROR` / transient / invalid-query / `is_internal_error` responses explicitly without collapsing into false `PERMERROR`; mapped unexpected `verify_headerprep()` and worker exceptions to `ProtocolStatus.INDETERMINATE` with sanitized `type(exc).__name__` errors; populated typed `DKIMEvaluationState` and `reason_code` across all signature/header/bytes/worker paths; marked standalone PSL alignment explicitly diagnostic (`alignment_source="standalone_psl_diagnostic_only"`, `alignment_is_authoritative=False`, `standalone_psl_aligned_relaxed`).
- [spf.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/evaluators/spf.py) — Unified `_classify_dns_failure()` across all SPF DNS lookups so transient/resolver/`FORMERR` failures become `TEMPERROR` and `INVALID_QUERY` / `is_internal_error` become `INDETERMINATE` (never `NONE`), and guarded unexpected internal exceptions as `INDETERMINATE`.
- [test_dmarc_evaluator.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_dmarc_evaluator.py), [test_dmarc_discovery.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_dmarc_discovery.py), [test_dkim_verifier.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_dkim_verifier.py), [test_spf_evaluator.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_spf_evaluator.py), [test_dns_resolver.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/tests/test_dns_resolver.py) — Added targeted regression tests for `H1`, `H3` (including `AsyncDNSResolver` OS/socket/timeout/runtime errors and `CancelledError`), `M3`, `M4`, `L1`, and `L2`.

### 1.4 Pre-Existing Uncommitted Files Preserved Untouched
- `backend/requirements.txt`
- `backend/app/modules/auth_protocols/executor.py`, `backend/tests/test_dkim_executor.py`
- `STEP_3_7_2D_FINAL_COMPLIANCE_AUDIT.md`, `STEP_3_7_2D_F_SPF_SYNTHESIZED_MACRO_VERIFICATION.md`, `STEP_3_7_3A_ARCHITECTURE_INSPECTION.md`, `STEP_3_7_3B_REMEDIATION_REPORT.md`
- All files outside Module 4/contracts/tests (`scan_service.py`, `scans.py`, `models/`, `schemas/`, `main.py`, Alembic migrations) remain unmodified per Step 3.7.3B scope boundaries.

---

## 2. Architecture Mapping

### 2.1 Three-Tier Separation Model
| Tier | Owner Component | Responsibilities & Invariants |
|---|---|---|
| **Tier 1: Published Domain Owner Policy** | `DMARCRecordDiscovery`, `parse_dmarc_tags_with_metadata()`, `DMARCEvaluator` | Discovers DNS record via RFC 9989 §4.10 Tree Walk (preserving `psd=y` fallback whenever `child_org_domain` lacks a record), selects `p`/`sp`/`np` per §4.10.1, preserves raw tags, `record_p_policy` (literal `p=`), `subdomain_policy` (`sp=`), `non_existent_subdomain_policy` (`np=`), `applicable_policy_tag`, `policy_discovery_source` (`author_domain`/`org_domain`/`psd`), `policy_domain`, `is_psd_policy`, `subdomain_existence_probe_enabled`, `subdomain_existence_status`, `np_evaluation_skipped_reason`, and `test_mode` (`t=y`). |
| **Tier 2: Protocol Authentication Result** | `SPFEvaluator`, `DKIMVerifier`, `DMARCEvaluator` | Produces immutable protocol statuses (`ProtocolStatus`), `DKIMEvaluationState`, authoritative Tree Walk alignment (`alignment_is_authoritative=True`, overriding standalone PSL hints), and RFC 9989 §9.2 `standard_status` (`pass`/`fail`/`none`/`permerror`/`temperror`, or `None` for `INDETERMINATE`/`NOT_EVALUATED`). Never rewritten by `t=y`, forwarder exemptions, allowlists, or hard blocks. |
| **Tier 3: Receiver-Local Disposition** | `DMARCPolicyEnforcer` ([policy_enforcer.py](file:///c:/Users/vatsa/OneDrive/Desktop/MailSantra/backend/app/modules/auth_protocols/policy_enforcer.py)) | Pure synchronous receiver-local policy interpretation across Stages 3–6, yielding `DMARCEnforcementDecision` (carrying both `record_p_policy` and `selected_applicable_policy`, distinct `test_mode_applied` vs. `local_override_applied`, complete audit/override provenance, channel-specific `DMARCDisposition`, and optional unexecuted `SMTPAdapterDecisionContract`). |

### 2.2 Six-Stage Enforcement Pipeline & Persistence
1. **Stage 1 (Channel & Evidence Provenance Sanity Checks):** Resolves `channel` (`DIRECT_UPLOAD`, `RAW_PAYLOAD`, `GRAPH_API`, `IMAP_COLLECTOR`, vs. `SMTP_RELAY`); strips untrusted transport metadata (`effective_smtp_meta = None`) on HTTP/non-SMTP channels or when `is_trusted_mta=False`; records `raw_bytes` byte-length invariant.
2. **Stage 2 (Immutable Tier 1 & Tier 2 Snapshot):** Snapshots `spf_status`, `_summarize_dkim_status()`, `dmarc_status`, `dmarc_rfc_status`, `record_p_policy` (literal `p=`), `selected_applicable_policy` (§4.10.1 `np`/`sp`/`p`), `applicable_policy_tag`, `policy_discovery_source`, and `test_mode`.
3. **Stage 3 (`t=y` Test Mode Interpretation):** Strictly on `dmarc_status == ProtocolStatus.FAIL` and `test_mode == True`, maps `reject -> quarantine` and `quarantine -> none` (logging `PolicyOverrideType.POLICY_TEST_MODE` in `override_reasons`), sets `test_mode_applied=True` **without** setting `local_override_applied=True`, and leaves `none`, `PASS`, `NONE`, `PERMERROR`, `TEMPERROR`, `INDETERMINATE`, `NOT_EVALUATED`, `record_p_policy`, and `selected_applicable_policy` untouched.
4. **Stage 4 (RFC 9989 §7.4 Interoperability & Verified Indirect Flows):**
   - Validates indirect flows (`_evaluate_indirect_flow_evidence()`) strictly on `SMTP_RELAY` with `is_trusted_mta=True`, `mta_sanitization_guaranteed=True`, valid IP, `authenticated_connector_id` in configured trusted connector IDs, `connecting_ip` in `trusted_forwarder_ips`, `trusted_forwarder_bindings` match when configured, and if `forwarder_evidence` is supplied requires `is_server_verified=True` plus exact connector ID and relay IP match with `TrustedSMTPMetadata`. Non-SMTP channels (including `DIRECT_UPLOAD` / `GRAPH_API` / `IMAP_COLLECTOR` / `RAW_PAYLOAD`), display names (`via ...`), `List-Id`, `List-Post`, `X-Original-From`, `Resent-From`, and mismatched claims are rejected and flagged in `unverified_indirect_flow_claim_ignored` + `audit_metadata["indirect_flow_evidence"]`.
   - Applies verified forwarder / mailing-list exemption (`QUARANTINE`/`REJECT` -> `NONE`, recording `PolicyOverrideType.TRUSTED_FORWARDER` or `PolicyOverrideType.MAILING_LIST`).
   - Applies mandatory RFC 9989 §7.4 protection: on completed `DMARC FAIL`, `p=reject` without genuine corroborating threat/analysis knowledge (`has_corroboration_for_reject`) is downgraded to `QUARANTINE` (`interoperability_downgrade_applied=True`). `AuthProtocolsConfig` enforces `dmarc_enforce_strict_reject_only_with_corroboration=True` via Pydantic validation, and runtime Stage 4 additionally warns and refuses uncorroborated reject even if validation is bypassed via `model_construct()`.
5. **Stage 5 (Two-Plane Conflict Arbitration & Rule Provenance):**
   - Cryptographically isolates static config rules (`_config_provenance_secret` / `CONFIG_RULE_V1:` attested exclusively via private `_load_and_attest_config_rules()` -> `_attest_config_rule()`) from interactive dynamic rules (`_admin_provenance_secret` / `ADMIN_RULE_V1:` attested via public `attest_server_rule()`), checking `is_authenticated_admin_source` and `reason` inside `_canonical_rule_bytes()`.
   - `attest_server_rule(rule, authorizing_actor=...)` rejects `authorizing_actor=None`, API-key actors (`is_api_key=True` / `SYSTEM_AGENT`), cross-tenant actors, `dev:unauthenticated`, non-admin roles, and any mismatch between `authorizing_actor` and `rule.configured_by_identity` / `rule.configured_by_role`.
   - `_match_authenticated_admin_rules()` validates `_rule_has_verified_config_hmac()` for config rules (`human_admin` or `SYSTEM_AGENT`) vs. `_rule_has_verified_admin_hmac()` for dynamic rules (`human_admin` only), enforcing `admin_actor.tenant_id == scan_tenant_id == rule.tenant_id`.
   - `match_ip_or_cidr` evaluates only verified `TrustedSMTPMetadata.connecting_ip` (never `Received:` or HTTP client IPs).
   - Separates the **Authentication Plane** (`EXEMPT_ACCEPT`) from the **Threat / Hard-Security Plane** (`FORCE_REJECT`, `FORCE_QUARANTINE`, malware/URL/threat-intel, or verified high-confidence impersonation `>= 0.85`). Hard security blocks override `DMARC PASS`, `t=y`, verified forwarders, and allowlists without rewriting `dmarc_status`.
   - Module 3 `IdentityAnalysisResult` Booleans stay strictly advisory under `advisory_signals["module3_identity_analysis"]`.
6. **Stage 6 & DB Audit Persistence (`record_dmarc_decision_on_incident()`):**
   - Produces HTTP inspection dispositions (`smtp_contract=None`, `raw_bytes_modified=False`) vs. `SMTP_RELAY` (`SMTPAdapterDecisionContract` with `executed=False`).
   - Validates actor and decision `tenant_id` match against `incident.tenant_id` before mutation (`DENIED_TENANT_MISMATCH` + `PermissionError`).
   - Flushes `incident` (`await db.flush()`), inserts deduplicated `AuditRecord` (keyed by complete SHA-256 decision fingerprint covering actor role, IP, SPF/DKIM/DMARC statuses, `applicable_policy_tag`, `policy_domain`, `post_interop_policy`, downgrades, exemptions, threat block, conflicts, rejected rules, channel, and channel mode), commits atomically inside `try / except`, rolls back and safely refreshes/restores pre-tx telemetry on failure (emitting `PERSISTENCE_FAILED` + re-raising).
   - Executes best-effort post-commit `AuditLogger.log_event()` inside an isolated `try / except` after `db.commit()`, recording `durable_db_persisted`, `audit_deduplicated`, `audit_delivery_status` (`DELIVERED`, `SECONDARY_LOG_FAILED_DB_COMMITTED`, `SECONDARY_LOG_ONLY_IN_MEMORY`, or `SECONDARY_LOG_FAILED_IN_MEMORY`), and sanitized `audit_delivery_error` so secondary log errors never masquerade as DB failures.
   - Separates `DMARC_TEST_MODE_APPLIED` (`t=y` only) from `DMARC_POLICY_OVERRIDE_APPLIED` (local overrides), preserves `SYSTEM_AGENT` API-key identity (`actor_type="api_key_system_agent"`), and masks mailbox local-part PII (`***@domain`) across SPF, DKIM `i=`, DMARC `from_domain` (if containing `@`), and `auth_protocols_summary`.

---

## 3. RFC Compliance & Design Decision Matrix

| Standard & Section | Requirement Summary | Verification & Implementation Location |
|---|---|---|
| **RFC 9989 §4.7 & §4.8** | `v=DMARC1` first/case-sensitive; unknown/removed tags (including `pct`) ignored; invalid `adkim`/`aspf` -> `r`, invalid `t` -> `n`, invalid `psd` -> `u`; missing `p=` defaults to `p=none`; `t=y` signals testing mode; `psd=n` establishes Org Domain at Author Domain. | `parse_dmarc_tags_with_metadata()`, `DMARCRecordDiscovery.discover()`, `DMARCPolicyEnforcer._apply_stage3_test_mode()` |
| **RFC 9989 §4.10 & §4.10.2** | Tree Walk max 8 queries, `>= 8` labels shortened to 7; `psd=y` yields Org Domain 1 label below PSD and ignores unrelated intermediate `psd=u` records below `child_org_domain`; Author domain never masks Org Domain; DNS resolver/OS/socket errors and malformed responses return `TEMPERROR`/`INDETERMINATE` (never `NONE` or false `FAIL`). | `DMARCRecordDiscovery.discover()`, `determine_org_domain()`, `check_domain_alignment()`, `_resolve_org_domain_with_cache()` |
| **RFC 9989 §4.10.1** | Author Domain uses `p=` only (`sp`/`np` ignored); Org/PSD applies `np -> sp -> p` when subdomain existence probe is enabled via `AuthProtocolsConfig.dmarc_enable_subdomain_existence_probe` and confirms non-existence, and `sp -> p` for existing subdomains or when `np=` probe is disabled/errors (with explicit `subdomain_existence_status` and `np_evaluation_skipped_reason`). | `parse_dmarc_tags_with_metadata()`, `DMARCEvaluator.evaluate()`, `evaluate_auth_protocols()` |
| **RFC 9989 §5.3.1 & §11.5** | Missing or multiple distinct RFC 5322 `From` domains -> DMARC `PERMERROR` (`standard_status="permerror"`). | `DMARCEvaluator.evaluate()` |
| **RFC 9989 §5.3.2 & §5.3.5** | Absent policy record -> `NONE`; `PASS` iff `(SPF PASS & aligned) OR (>=1 DKIM PASS & aligned)` even if another mechanism returned `TEMPERROR`, `FAIL`, `INDETERMINATE`, or `NOT_EVALUATED`. | `DMARCEvaluator.evaluate()` |
| **RFC 9989 §5.3.6 & §9.2** | Standardized outputs strictly `{pass, fail, none, permerror, temperror}`. DNS transient/resolver/OS/socket errors (`TIMEOUT`, `SERVFAIL`, `REFUSED`, `RESOLVER_ERROR`, `FORMERR`) -> `TEMPERROR`; internal software errors (`INTERNAL_ERROR`, `determine_org_domain()` exceptions, DKIM `verify_headerprep()` exceptions, `INVALID_QUERY`) -> `INDETERMINATE` (`standard_status=None`). | `AsyncDNSResolver.resolve()`, `DNSOutcomeCategory`, `DMARCEvaluator.evaluate()`, `SPFEvaluator`, `DKIMVerifier` |
| **RFC 9989 §§7.2, 7.4 & §8** | Receivers MUST NOT reject solely on `p=reject` without corroboration (downgraded to `quarantine`, enforced by config validator + runtime Stage 4 guard); missing/incomplete/internal errors never trigger `p=quarantine`/`p=reject`. | `AuthProtocolsConfig`, `DMARCPolicyEnforcer._apply_stage4_interoperability()`, `_map_stage6_disposition()` |
| **RFC 7960 §§2, 4.1.2 & RFC 9990 §3.1.6** | Forwarders/lists require authenticated `SMTP_RELAY` MTA provenance + allowlists (never direct uploads); overrides emit structured taxonomy (`local_policy`, `mailing_list`, `trusted_forwarder`, `policy_test_mode`, `other`) without conflating Domain-Owner `t=y` with local admin overrides. | `PolicyOverrideType`, `ForwarderTrustEvidence`, `_evaluate_indirect_flow_evidence()` |
| **RFC 8601 §§4, 5, 7** | Untrusted inbound headers stay `UNTRUSTED_SENDER` and never influence evaluation or overrides. | `ParsedAuthResultsHeader.validate_trust_boundary()`, `DMARCPolicyEnforcer._evaluate_indirect_flow_evidence()` |
| **RFC 7208 §§2.4, 2.6 & RFC 6376 §§6.1–6.3** | Null reverse-path `postmaster@helo` vs. standalone `HELO` rejection; typed `DKIMEvaluationState` + `reason_code` decouple missing raw bytes from genuine crypto `PERMERROR`; SPF/DKIM internal exceptions return `INDETERMINATE`; transient/resolver DNS errors return `TEMPERROR`. | `SPFEvaluator._classify_dns_failure()`, `DKIMVerifier`, `DMARCEvaluator` |

---

## 4. Decision Tables

### 4.1 C1 Incomplete / Unavailable / Error Evaluation Matrix
Whenever neither SPF nor DKIM yields an aligned `PASS` (which always produces `DMARC PASS`):

| Case | SPF Status | DKIM Input State / Error | `DMARCEvaluator.evaluate()` | `standard_status` | HTTP Disposition | `SMTP_RELAY` Disposition / Contract |
|---|---|---|---|---|---|---|
| **1** | `NOT_EVALUATED` | `NONE` (no sigs, `EVALUATED_NO_SIGNATURES`) | `INDETERMINATE` | `None` | `MANUAL_REVIEW_INCOMPLETE` | `DEFER` (`DEFER_451`, `451 4.7.1`, policy frozen) |
| **2** | `NOT_EVALUATED` | `FAIL` (`EVALUATED_COMPLETED`) | `INDETERMINATE` | `None` | `MANUAL_REVIEW_INCOMPLETE` | `DEFER` (`DEFER_451`, `451 4.7.1`, policy frozen) |
| **3** | `NOT_EVALUATED` | `PASS` (unaligned) | `INDETERMINATE` | `None` | `MANUAL_REVIEW_INCOMPLETE` | `DEFER` (`DEFER_451`, `451 4.7.1`, policy frozen) |
| **4** | `PASS` (unaligned) / `FAIL` / `NONE` | `dkim_evaluated=False` | `INDETERMINATE` | `None` | `MANUAL_REVIEW_INCOMPLETE` | `DEFER` (`DEFER_451`, `451 4.7.1`, policy frozen) |
| **5** | `PASS` (unaligned) / `FAIL` | `NOT_EVALUATED_MISSING_RAW_BYTES` (`reason_code="MISSING_RAW_MESSAGE_BYTES"`) | `INDETERMINATE` | `None` | `MANUAL_REVIEW_INCOMPLETE` | `DEFER` (`DEFER_451`, `451 4.7.1`, policy frozen) |
| **6** | `INDETERMINATE` (internal/query err) | `FAIL` / `NONE` | `INDETERMINATE` | `None` | `MANUAL_REVIEW_INCOMPLETE` | `DEFER` (`DEFER_451`, `451 4.7.1`, policy frozen) |
| **7** | `FAIL` / `NONE` | `INDETERMINATE` (`INCOMPLETE_INTERNAL_ERROR`) | `INDETERMINATE` | `None` | `MANUAL_REVIEW_INCOMPLETE` | `DEFER` (`DEFER_451`, `451 4.7.1`, policy frozen) |
| **8** | `TEMPERROR` (timeout/SERVFAIL/REFUSED/RESOLVER_ERROR/FORMERR) | `FAIL` / `NONE` / `TEMPERROR` | `TEMPERROR` | `"temperror"` | `RETRY_RECOMMENDED` | `DEFER` (`DEFER_451`, default) or `ACCEPT` (`250 2.0.0`, fail-open) |
| **9** | Completed non-pass | `EVALUATED_COMPLETED` non-aligned (`NONE`/`FAIL`/unaligned `PASS`/crypto `PERMERROR`) | `FAIL` | `"fail"` | Policy-driven (`ACCEPT`/`QUARANTINE`, or `RECOMMEND_REJECT` iff `p=reject` + corroborated threat signals) | Policy-driven (`ACCEPT`/`QUARANTINE`, or `REJECT` iff `p=reject` + corroborated threat signals) |

*(DMARC discovery `LIMIT_EXCEEDED`, `determine_org_domain()` `INDETERMINATE` / `INVALID_QUERY` / `INTERNAL_ERROR`, or unexpected `DMARCEvaluator` exception -> `INDETERMINATE`, `standard_status=None`; discovery / tree-walk `TEMPERROR` / `RESOLVER_ERROR` / `FORMERR` -> `TEMPERROR`, `standard_status="temperror"`.)*

### 4.2 RFC 9989 §4.10.1 Policy Selection Table
| Policy Discovery Source | Author vs. Policy Domain | Target Existence / Probe State | Tag Priority | `policy_discovery_source` | `applicable_policy_tag` |
|---|---|---|---|---|---|
| Author Domain record | `from_domain == policy_domain` | N/A (`not_subdomain`) | **`p` only** (`sp` & `np` ignored) | `"author_domain"` | `"p"` / `"p_default_missing"` / `"p_rua_fallback"` |
| Org Domain / PSD record | Strict subdomain (`is_subdomain=True`) | `confirmed_existing` (`A`/`AAAA`/`MX`/`NODATA`), `unknown_probe_disabled`, `unknown_dns_temperror`, `unknown_dns_error`, or `unknown_budget_exhausted` | **`sp -> p`** (`np` MUST NOT apply) | `"org_domain"` or `"psd"` | `"sp"` or fallback `"p*"` |
| Org Domain / PSD record | Strict subdomain (`is_subdomain=True`) | `confirmed_non_existent` (`NXDOMAIN` when `dmarc_enable_subdomain_existence_probe=True` or explicit hint) | **`np -> sp -> p`** | `"org_domain"` or `"psd"` | `"np"`, fallback `"sp"`, or `"p*"` |

### 4.3 RFC 9989 §4.7 `t=y` Test Mode Table
| `dmarc_status` | `test_mode` | `selected_applicable_policy` | `effective_policy` | `test_mode_applied` | `local_override_applied` | Audit Action (`AuditRecord`) |
|---|---|---|---|---|---|---|
| `FAIL` | `True` | `reject` | `quarantine` | `True` | `False` | `"DMARC_TEST_MODE_APPLIED"` |
| `FAIL` | `True` | `quarantine` | `none` | `True` | `False` | `"DMARC_TEST_MODE_APPLIED"` |
| `FAIL` | `True` | `none` | `none` | `False` | `False` | `"DMARC_POLICY_ENFORCED"` |
| `PASS` / `TEMPERROR` / `PERMERROR` / `INDETERMINATE` / `NONE` | `True` | Any | Preserved | `False` | `False` | `"DMARC_POLICY_ENFORCED"` |

### 4.4 Stage 4/5 Two-Plane Conflict Arbitration Matrix
| Auth Plane State | Threat / Hard-Security Signal | `dmarc_status` Kept | Conflict Flagged | HTTP Disposition | `SMTP_RELAY` Disposition / Contract |
|---|---|---|---|---|---|
| `DMARC PASS` or `EXEMPT_ACCEPT` allowlist | `CONFIRMED_MALICIOUS_ATTACHMENT` / `CONFIRMED_MALICIOUS_URL` / `THREAT_INTEL` / `FORCE_REJECT` | Unchanged (`PASS`/`FAIL`) | `True` | `RECOMMEND_REJECT` | `REJECT` (`REJECT_550`, `550 5.7.1`) |
| `DMARC PASS` or `EXEMPT_ACCEPT` allowlist | `FORCE_QUARANTINE` or verified `high_confidence_impersonation` (`>= 0.85`) | Unchanged (`PASS`/`FAIL`) | `True` | `QUARANTINE` | `QUARANTINE` (`QUARANTINE_HOLD`) |
| `DMARC FAIL` (`p=reject`, `t=n`) | None (or unverified/Module 3 Booleans only) | `FAIL` | `False` (RFC §7.4 downgrade) | `QUARANTINE` | `QUARANTINE` (`QUARANTINE_HOLD`) |
| `DMARC FAIL` (`p=reject`, `t=n`) | Verified `high_confidence_impersonation` (`>= 0.85`) | `FAIL` | `False` (corroborates reject) | `RECOMMEND_REJECT` | `REJECT` (`REJECT_550`, `550 5.7.1`) |
| `DMARC FAIL` (`p=reject`, `t=y`) | `CONFIRMED_MALICIOUS_URL` | `FAIL` | `True` (`THREAT...OVERRIDES_TEST_MODE`) | `RECOMMEND_REJECT` | `REJECT` (`REJECT_550`, `550 5.7.1`) |
| `DMARC FAIL` (Verified `SMTP_RELAY` forwarder/list) | None | `FAIL` | `False` | `ACCEPT` | `ACCEPT` (`ACCEPT_250`) |
| `DMARC FAIL` (Direct upload or forged relay/header hint) | None (`p=quarantine`) | `FAIL` | `False` (`unverified_indirect_flow_claim_ignored=True`) | `QUARANTINE` | `QUARANTINE` (`QUARANTINE_HOLD`) |

---

## 5. Verification Suite Summary (Executed After Final Security Hardening)

All verification commands executed in `C:\Users\vatsa\OneDrive\Desktop\MailSantra` with `$env:PYTHONPATH = "backend"` using `backend\.venv\Scripts\python.exe` (Python `3.13.7`, pytest `9.2.0`, `-p no:cacheprovider`):

1. **CHECK 1 — Focused Policy Enforcement Tests (`backend\tests\test_dmarc_policy_enforcement.py -v`):** **`17 passed in 0.19s`** (`0` failed, `0` skipped, exit `0`)
2. **CHECK 2 — Focused DNS Resolver & Contracts Tests (`backend\tests\test_dns_resolver.py backend\tests\test_contracts.py -v`):** **`41 passed in 0.22s`** (`0` failed, `0` skipped, exit `0`)
3. **CHECK 3 — Focused DMARC Discovery & Evaluator Tests (`backend\tests\test_dmarc_discovery.py backend\tests\test_dmarc_evaluator.py -v`):** **`119 passed in 0.44s`** (`0` failed, `0` skipped, exit `0`)
4. **CHECK 4 — Focused SPF & DKIM Tests (`backend\tests\test_spf_evaluator.py backend\tests\test_dkim_verifier.py backend\tests\test_dkim_executor.py -v`):** **`93 passed in 1.71s`** (`0` failed, `0` skipped, exit `0`)
5. **CHECK 5 — Combined Auth-Protocols & Contracts Regression Suite (8 files):** **`270 passed in 2.16s`** (`0` failed, `0` skipped, exit `0`)
6. **CHECK 6 — Complete Backend Test Suite (`backend\tests -v`):** **`409 passed in 5.37s`** (`0` failed, `0` skipped, exit `0`) *(+9 net new tests over pre-hardening `400 passed`)*
7. **CHECK 7 — Bytecode Compilation (`compileall -q backend\app backend\tests`):** Exit **`0`** *(Note: `ruff`, `mypy`, `flake8`, and `pyright` are not installed in `backend\.venv`.)*

---

## 6. Known Limitations & Remaining Architectural Constraints

- **Scope Boundaries:** No `Authentication-Results` generation (`local_authserv_id` / RFC 6008 `header.b` reserved for Step 3.7.3C), no `ScanService` / `/api/v1/scans` wiring, no DB override-rule CRUD API, no live SMTP MTA socket execution, no ARC/SRS cryptographic mediator verification on non-SMTP channels, and no Module 5–8 threat engines yet.
- **Single-Process Ephemeral Rule Secrets (`H2`):** `_config_provenance_secret` and `_admin_provenance_secret` are ephemeral per-enforcer 256-bit keys; multi-worker deployments or persisted dynamic override rules across process restarts will require an application KMS / persistent HMAC key or DB-backed policy table in a future admin-API milestone.
- **Best-Effort Secondary Audit Logging (`M1`):** `ScanIncident.telemetry` and `AuditRecord` commit atomically in SQLAlchemy; secondary `AuditLogger.log_event()` runs post-commit on Python's structured logger and is not transactional with DB commit (explicitly surfaced via `audit_delivery_status`).
- **Offline Simulation & Defaults:** All verification tests ran offline via `MockDNSResolver`, mocked `_resolver.resolve` targets on `AsyncDNSResolver`, and in-memory SQLite (`sqlite+aiosqlite:///:memory:`) without live Internet DNS or PostgreSQL. `AuthProtocolsConfig.dmarc_enable_subdomain_existence_probe` defaults to `False` for offline mock compatibility. Standalone `DKIMVerifier` computes offline PSL alignment strictly as a non-authoritative diagnostic hint (`alignment_is_authoritative=False`) superseded authoritatively by `DMARCEvaluator`.

---

## 7. Git State Verification

- **HEAD Commit (Before & After):** `113132f66b37dc71cf681e15db1925d6b9f68069` (`main`, `Your branch is up to date with 'origin/main'`)
- **Git Staging / Commit Status:** `no changes added to commit` (`0` staged files, `0` commits, `0` pushes)
- **Tracked Modified (`4`):** `backend/app/modules/auth_protocols/__init__.py`, `backend/app/modules/contracts.py`, `backend/requirements.txt` (pre-existing untouched), `backend/tests/test_contracts.py`
- **Untracked Paths (`18` entries in `git status --long`):** pre-existing audit/remediation reports (`STEP_3_7_2D_FINAL_COMPLIANCE_AUDIT.md`, `STEP_3_7_2D_F_SPF_SYNTHESIZED_MACRO_VERIFICATION.md`, `STEP_3_7_3A_ARCHITECTURE_INSPECTION.md`, `STEP_3_7_3B_REMEDIATION_REPORT.md`), updated `STEP_3_7_3B_IMPLEMENTATION_REPORT.md`, newly created `STEP_3_7_3B_FINAL_HARDENING_REPORT.md`, auth-protocols modules (`config.py`, `dns_resolver.py`, `evaluators/`, `executor.py`, `policy_enforcer.py`), and test suites (`test_dkim_executor.py`, `test_dkim_verifier.py`, `test_dmarc_discovery.py`, `test_dmarc_evaluator.py`, `test_dmarc_policy_enforcement.py`, `test_dns_resolver.py`, `test_spf_evaluator.py`).
