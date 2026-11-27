"""Comprehensive deterministic tests for Step 3.7.3B DMARC Enforcement Engine.

Covers every mandatory scenario in Section 3 of Step 3.7.3B:
- All 9 incomplete-evaluation matrix cases
- SPF NOT_EVALUATED / TEMPERROR & DKIM TEMPERROR permutations
- Both mechanisms unavailable & DMARC discovery TEMPERROR / PERMERROR
- Every t=y transformation, t=n, and default test mode
- RFC 9989 §7.4 p=reject interoperability safeguard (strict tenant policy cannot bypass)
- Existing and non-existent subdomain policy selection (Author / Org / PSD; p, sp, np fallbacks)
- Verified vs spoofed/unverified trusted-forwarder & mailing-list evidence
- Allowlist vs malware, blocklist vs DMARC PASS, blocklist/allowlist conflict & unauthenticated rules
- HTTP `.eml` direct upload without SMTP context, raw byte non-mutation, deterministic decisions,
  telemetry persistence in ScanIncident + AuditRecord, and unexpected evaluator errors.
"""

from __future__ import annotations

import hashlib
import pytest
from sqlalchemy import select

from app.models.audit import AuditRecord
from app.models.scan import RiskTier, ScanIncident, ScanStatus
from app.models.user import UserRole
from app.modules.auth_protocols.config import AuthProtocolsConfig
from app.modules.auth_protocols.dns_resolver import (
    DNSQueryType,
    DNSResponseStatus,
    DNSErrorType,
    MockDNSResolver,
)
from app.modules.auth_protocols.evaluators.dmarc import (
    DMARCEvaluator,
    DMARCRecordDiscovery,
)
from app.modules.auth_protocols.policy_enforcer import (
    DMARCPolicyEnforcer,
    record_dmarc_decision_on_incident,
)
from app.modules.contracts import (
    CorroboratingThreatSignals,
    DKIMEvaluationState,
    DKIMSignatureResult,
    DMARCDisposition,
    DMARCPolicy,
    DMARCResult,
    EmailAddress,
    ForwarderTrustEvidence,
    IdentityAnalysisResult,
    IngestionSource,
    LocalPolicyOverrideRule,
    OverrideRuleAction,
    ParsedEmail,
    PolicyOverrideType,
    ProtocolStatus,
    RawEmailPayload,
    SPFResult,
    TrustedSMTPMetadata,
)
from app.schemas.user import IngestionActor


def _admin_actor(tenant_id: str = "default") -> IngestionActor:
    return IngestionActor(
        identity="secadmin@mailsentra.corp",
        role=UserRole.SUPER_ADMIN.value,
        is_api_key=False,
        tenant_id=tenant_id,
    )


def _api_key_actor(tenant_id: str = "default") -> IngestionActor:
    return IngestionActor(
        identity="collector-key-01",
        role=UserRole.SYSTEM_AGENT.value,
        is_api_key=True,
        tenant_id=tenant_id,
    )


def _auth_allow_rule(
    rule_id: str = "allow-partner",
    from_domain: str = "partner.org",
    tenant_id: str = "default",
) -> LocalPolicyOverrideRule:
    return LocalPolicyOverrideRule(
        rule_id=rule_id,
        action=OverrideRuleAction.EXEMPT_ACCEPT,
        match_from_domain=from_domain,
        tenant_id=tenant_id,
        configured_by_identity="secadmin@mailsentra.corp",
        configured_by_role=UserRole.SUPER_ADMIN.value,
        is_authenticated_admin_source=True,
        reason="Partner domain temporary exception",
    )


def _auth_block_rule(
    rule_id: str = "block-domain",
    from_domain: str = "example.com",
    action: OverrideRuleAction = OverrideRuleAction.FORCE_QUARANTINE,
    tenant_id: str = "default",
) -> LocalPolicyOverrideRule:
    return LocalPolicyOverrideRule(
        rule_id=rule_id,
        action=action,
        match_from_domain=from_domain,
        tenant_id=tenant_id,
        configured_by_identity="secadmin@mailsentra.corp",
        configured_by_role=UserRole.SUPER_ADMIN.value,
        is_authenticated_admin_source=True,
        reason="Security block rule",
    )


# =============================================================================
# 1–6. INCOMPLETE EVALUATION MATRIX (ALL 9 CASES) + SPF/DKIM/DMARC ERRORS
# =============================================================================

@pytest.mark.asyncio
async def test_incomplete_evaluation_matrix_all_nine_cases():
    """Verifies all 9 matrix scenarios end-to-end across DMARCEvaluator and DMARCPolicyEnforcer."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    resolver.add_txt("_dmarc.rua-fallback.example", ["v=DMARC1; p=invalid_val; rua=mailto:rep@rua-fallback.example"])
    resolver.add_txt("_dmarc.bad-perm.example", ["v=DMARC1; p=invalid_val"])
    resolver.set_timeout("_dmarc.temp-err.example", DNSQueryType.TXT)

    evaluator = DMARCEvaluator(resolver=resolver)
    enforcer = DMARCPolicyEnforcer()

    # Row 1: SPF NOT_EVALUATED + DKIM absent -> INDETERMINATE, rfc_status=None, policy frozen
    r1 = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.NOT_EVALUATED),
        dkim_results=[],
    )
    d1 = enforcer.enforce(r1, spf_result=SPFResult(status=ProtocolStatus.NOT_EVALUATED), dkim_results=[])
    assert r1.status == ProtocolStatus.INDETERMINATE
    assert r1.standard_status is None and r1.rfc_status is None
    assert d1.disposition == DMARCDisposition.MANUAL_REVIEW_INCOMPLETE
    assert d1.policy_applied is False
    assert d1.manual_review_recommended is True

    # Row 2: SPF NOT_EVALUATED + DKIM FAIL -> INDETERMINATE, rfc_status=None, policy frozen
    dkim_fail = [DKIMSignatureResult(status=ProtocolStatus.FAIL, domain="example.com", selector="s1")]
    r2 = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.NOT_EVALUATED),
        dkim_results=dkim_fail,
    )
    d2 = enforcer.enforce(r2, spf_result=SPFResult(status=ProtocolStatus.NOT_EVALUATED), dkim_results=dkim_fail)
    assert r2.status == ProtocolStatus.INDETERMINATE
    assert r2.rfc_status is None
    assert d2.disposition == DMARCDisposition.MANUAL_REVIEW_INCOMPLETE
    assert d2.policy_applied is False

    # Row 3: SPF NOT_EVALUATED + DKIM aligned PASS -> DMARC PASS
    dkim_pass = [DKIMSignatureResult(status=ProtocolStatus.PASS, domain="example.com", selector="s1")]
    r3 = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.NOT_EVALUATED),
        dkim_results=dkim_pass,
    )
    d3 = enforcer.enforce(r3, spf_result=SPFResult(status=ProtocolStatus.NOT_EVALUATED), dkim_results=dkim_pass)
    assert r3.status == ProtocolStatus.PASS and r3.rfc_status == "pass"
    assert d3.disposition == DMARCDisposition.ACCEPT

    # Row 4: SPF TEMPERROR + DKIM aligned PASS -> DMARC PASS
    r4 = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.TEMPERROR, domain="example.com"),
        dkim_results=[DKIMSignatureResult(status=ProtocolStatus.PASS, domain="example.com", selector="s1")],
    )
    d4 = enforcer.enforce(r4)
    assert r4.status == ProtocolStatus.PASS and r4.rfc_status == "pass"
    assert d4.disposition == DMARCDisposition.ACCEPT

    # Row 5: SPF PASS aligned + DKIM FAIL -> DMARC PASS
    r5 = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.PASS, domain="example.com", scope="mfrom"),
        dkim_results=[DKIMSignatureResult(status=ProtocolStatus.FAIL, domain="example.com", selector="s1")],
    )
    d5 = enforcer.enforce(r5)
    assert r5.status == ProtocolStatus.PASS and r5.rfc_status == "pass"
    assert d5.disposition == DMARCDisposition.ACCEPT

    # Row 6: SPF PASS unaligned + DKIM absent -> DMARC FAIL, policy applied
    r6 = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.PASS, domain="thirdparty.net", scope="mfrom"),
        dkim_results=[],
    )
    d6_http = enforcer.enforce(r6, channel=IngestionSource.DIRECT_UPLOAD)
    assert r6.status == ProtocolStatus.FAIL and r6.rfc_status == "fail"
    assert d6_http.disposition == DMARCDisposition.QUARANTINE  # RFC 9989 §7.4 safe cap
    assert d6_http.policy_applied is True
    assert d6_http.interoperability_downgrade_applied is True

    # Row 7: Both mechanisms unavailable (SPF NOT_EVALUATED + DKIM missing bytes / not evaluated) -> INDETERMINATE
    r7 = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.NOT_EVALUATED),
        dkim_results=[],
        dkim_evaluated=False,
    )
    d7 = enforcer.enforce(r7, dkim_evaluated=False)
    assert r7.status == ProtocolStatus.INDETERMINATE and r7.rfc_status is None
    assert d7.disposition == DMARCDisposition.MANUAL_REVIEW_INCOMPLETE
    assert d7.policy_applied is False

    # Row 8: DMARC discovery TEMPERROR -> TEMPERROR (HTTP retry, SMTP default DEFER 451 4.7.1)
    r8 = await evaluator.evaluate("temp-err.example", spf_result=SPFResult(status=ProtocolStatus.NONE))
    d8_http = enforcer.enforce(r8, channel=IngestionSource.DIRECT_UPLOAD)
    d8_smtp = enforcer.enforce(r8, channel=IngestionSource.SMTP_RELAY)
    assert r8.status == ProtocolStatus.TEMPERROR and r8.rfc_status == "temperror"
    assert d8_http.disposition == DMARCDisposition.RETRY_RECOMMENDED
    assert d8_http.smtp_contract is None
    assert d8_smtp.disposition == DMARCDisposition.DEFER
    assert d8_smtp.smtp_contract is not None
    assert d8_smtp.smtp_contract.smtp_reply_code == 451
    assert d8_smtp.smtp_contract.enhanced_status_code == "4.7.1"
    assert d8_smtp.smtp_contract.executed is False

    # Row 9a: DMARC discovery PERMERROR (invalid p without rua) -> PERMERROR, policy NOT applied
    r9_perm = await evaluator.evaluate("bad-perm.example", spf_result=SPFResult(status=ProtocolStatus.FAIL))
    d9_perm = enforcer.enforce(r9_perm)
    assert r9_perm.status == ProtocolStatus.PERMERROR and r9_perm.rfc_status == "permerror"
    assert d9_perm.disposition == DMARCDisposition.ACCEPT
    assert d9_perm.policy_applied is False

    # Row 9b: Invalid p with valid rua -> treated as p=none (RFC 9989 §4.10.1)
    r9_rua = await evaluator.evaluate("rua-fallback.example", spf_result=SPFResult(status=ProtocolStatus.FAIL))
    d9_rua = enforcer.enforce(r9_rua)
    assert r9_rua.status == ProtocolStatus.FAIL
    assert r9_rua.policy == DMARCPolicy.NONE
    assert r9_rua.applicable_policy_tag == "p_rua_fallback"
    assert d9_rua.disposition == DMARCDisposition.ACCEPT


@pytest.mark.asyncio
async def test_spf_and_dkim_temperror_and_both_unavailable_cases():
    """Tests Mandatory Scenarios 3, 4, 5: SPF TEMPERROR, DKIM TEMPERROR, and missing-bytes unavailability."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)
    enforcer = DMARCPolicyEnforcer()

    # Scenario 3b: SPF TEMPERROR + DKIM FAIL -> DMARC TEMPERROR (never FAIL)
    res_spf_temp = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.TEMPERROR, domain="example.com"),
        dkim_results=[DKIMSignatureResult(status=ProtocolStatus.FAIL, domain="example.com", selector="s1")],
    )
    assert res_spf_temp.status == ProtocolStatus.TEMPERROR
    assert res_spf_temp.rfc_status == "temperror"
    dec_spf_temp = enforcer.enforce(res_spf_temp, channel=IngestionSource.SMTP_RELAY)
    assert dec_spf_temp.disposition == DMARCDisposition.DEFER
    assert dec_spf_temp.policy_applied is False

    # Scenario 4a: DKIM TEMPERROR + SPF aligned PASS -> DMARC PASS
    res_dkim_temp_pass = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.PASS, domain="example.com", scope="mfrom"),
        dkim_results=[DKIMSignatureResult(status=ProtocolStatus.TEMPERROR, domain="example.com", selector="s1")],
    )
    assert res_dkim_temp_pass.status == ProtocolStatus.PASS
    assert res_dkim_temp_pass.rfc_status == "pass"

    # Scenario 4b: DKIM TEMPERROR + SPF FAIL -> DMARC TEMPERROR (never FAIL)
    res_dkim_temp_fail = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.FAIL, domain="example.com", scope="mfrom"),
        dkim_results=[DKIMSignatureResult(status=ProtocolStatus.TEMPERROR, domain="example.com", selector="s1")],
    )
    assert res_dkim_temp_fail.status == ProtocolStatus.TEMPERROR
    assert res_dkim_temp_fail.rfc_status == "temperror"
    assert enforcer.enforce(res_dkim_temp_fail, channel=IngestionSource.DIRECT_UPLOAD).disposition == DMARCDisposition.RETRY_RECOMMENDED

    # Scenario 5: Both unavailable via DKIM missing-bytes + SPF NOT_EVALUATED -> INDETERMINATE
    res_unavail = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.NOT_EVALUATED),
        dkim_results=[
            DKIMSignatureResult(
                status=ProtocolStatus.PERMERROR,
                evaluation_state=DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES,
                reason_code="MISSING_RAW_MESSAGE_BYTES",
                error_reason="Missing original raw message bytes",
            )
        ],
    )
    assert res_unavail.status == ProtocolStatus.INDETERMINATE
    assert res_unavail.rfc_status is None


# =============================================================================
# 7–8. TEST MODE (t=y, t=n, default t=n)
# =============================================================================

@pytest.mark.asyncio
async def test_t_y_transformations_and_non_mutation_invariants():
    """Verifies every t=y transformation, preservation of auth result/published policy, and non-FAIL exclusion."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.rej-t.example", ["v=DMARC1; p=reject; t=y"])
    resolver.add_txt("_dmarc.quar-t.example", ["v=DMARC1; p=quarantine; t=y"])
    resolver.add_txt("_dmarc.none-t.example", ["v=DMARC1; p=none; t=y"])
    resolver.add_txt("_dmarc.rej-tn.example", ["v=DMARC1; p=reject; t=n"])
    resolver.add_txt("_dmarc.rej-def.example", ["v=DMARC1; p=reject"])

    evaluator = DMARCEvaluator(resolver=resolver)
    enforcer = DMARCPolicyEnforcer()
    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="any.example", scope="mfrom")

    # 1. reject + t=y -> effective quarantine (t=y is NOT a local override)
    r_rej = await evaluator.evaluate("rej-t.example", spf_result=spf_fail)
    d_rej = enforcer.enforce(r_rej, channel=IngestionSource.SMTP_RELAY)
    assert r_rej.status == ProtocolStatus.FAIL and r_rej.policy == DMARCPolicy.REJECT and r_rej.test_mode is True
    assert d_rej.dmarc_status == ProtocolStatus.FAIL  # auth result NEVER rewritten
    assert d_rej.record_p_policy == DMARCPolicy.REJECT
    assert d_rej.selected_applicable_policy == DMARCPolicy.REJECT  # original selected policy preserved
    assert d_rej.effective_policy == DMARCPolicy.QUARANTINE
    assert d_rej.test_mode_applied is True
    assert d_rej.local_override_applied is False
    assert PolicyOverrideType.POLICY_TEST_MODE in d_rej.override_reasons
    assert d_rej.disposition == DMARCDisposition.QUARANTINE

    # 2. quarantine + t=y -> effective none
    r_quar = await evaluator.evaluate("quar-t.example", spf_result=spf_fail)
    d_quar = enforcer.enforce(r_quar, channel=IngestionSource.SMTP_RELAY)
    assert d_quar.dmarc_status == ProtocolStatus.FAIL
    assert d_quar.record_p_policy == DMARCPolicy.QUARANTINE
    assert d_quar.selected_applicable_policy == DMARCPolicy.QUARANTINE
    assert d_quar.effective_policy == DMARCPolicy.NONE
    assert d_quar.test_mode_applied is True
    assert d_quar.local_override_applied is False
    assert PolicyOverrideType.POLICY_TEST_MODE in d_quar.override_reasons
    assert d_quar.disposition == DMARCDisposition.ACCEPT

    # 3. none + t=y -> effective none (no test_mode step-down)
    r_none = await evaluator.evaluate("none-t.example", spf_result=spf_fail)
    d_none = enforcer.enforce(r_none)
    assert d_none.selected_applicable_policy == DMARCPolicy.NONE
    assert d_none.effective_policy == DMARCPolicy.NONE
    assert d_none.test_mode_applied is False
    assert d_none.local_override_applied is False
    assert d_none.disposition == DMARCDisposition.ACCEPT

    # 4. t=n and default (absent t) do NOT step down reject
    for dom in ("rej-tn.example", "rej-def.example"):
        r_std = await evaluator.evaluate(dom, spf_result=spf_fail)
        d_std = enforcer.enforce(r_std, channel=IngestionSource.SMTP_RELAY)
        assert r_std.test_mode is False
        assert d_std.test_mode_applied is False
        assert d_std.effective_policy == DMARCPolicy.REJECT
        # RFC 9989 §7.4 then caps uncorroborated reject -> quarantine
        assert d_std.post_interop_policy == DMARCPolicy.QUARANTINE
        assert d_std.interoperability_downgrade_applied is True

    # 5. t=y MUST NOT apply to PASS, TEMPERROR, INDETERMINATE, or override threat findings
    r_pass = await evaluator.evaluate(
        "rej-t.example",
        spf_result=SPFResult(status=ProtocolStatus.PASS, domain="rej-t.example", scope="mfrom"),
    )
    d_pass = enforcer.enforce(r_pass)
    assert d_pass.test_mode is True
    assert d_pass.test_mode_applied is False
    assert PolicyOverrideType.POLICY_TEST_MODE not in d_pass.override_reasons

    r_indet = await evaluator.evaluate(
        "rej-t.example",
        spf_result=SPFResult(status=ProtocolStatus.NOT_EVALUATED),
    )
    d_indet = enforcer.enforce(r_indet)
    assert d_indet.test_mode_applied is False
    assert PolicyOverrideType.POLICY_TEST_MODE not in d_indet.override_reasons

    # 6. t=y (quarantine -> none) does NOT suppress confirmed malicious URL / malware
    d_quar_threat = enforcer.enforce(
        r_quar,
        threat_signals=CorroboratingThreatSignals(confirmed_malicious_url=True),
        channel=IngestionSource.SMTP_RELAY,
    )
    assert d_quar_threat.test_mode_applied is True
    assert d_quar_threat.threat_block_applied is True
    assert d_quar_threat.policy_conflict_detected is True
    assert d_quar_threat.disposition == DMARCDisposition.REJECT


# =============================================================================
# 9–10. RFC 9989 §7.4 INTEROPERABILITY PROTECTION (p=reject)
# =============================================================================

@pytest.mark.asyncio
async def test_rfc9989_7_4_p_reject_requires_corroborating_evidence():
    """Verifies p=reject without corroboration downgrades to quarantine and cannot be bypassed."""
    from pydantic import ValidationError

    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.strict.example", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="strict.example", scope="mfrom")
    dmarc_res = await evaluator.evaluate("strict.example", spf_result=spf_fail)

    # M5: Setting dmarc_enforce_strict_reject_only_with_corroboration=False fails validation directly
    with pytest.raises(ValidationError):
        AuthProtocolsConfig(dmarc_enforce_strict_reject_only_with_corroboration=False)

    # Defense-in-depth: even if model_construct bypasses validator, Stage 4 still enforces §7.4!
    forced_unsafe_cfg = AuthProtocolsConfig.model_construct(dmarc_enforce_strict_reject_only_with_corroboration=False)
    enforcer = DMARCPolicyEnforcer(config=forced_unsafe_cfg)

    dec_no_corrob = enforcer.enforce(
        dmarc_res,
        spf_result=spf_fail,
        channel=IngestionSource.SMTP_RELAY,
        threat_signals=CorroboratingThreatSignals(
            # Module 3 boolean flags alone are strictly advisory and do NOT satisfy §7.4!
            advisory_identity_analysis=IdentityAnalysisResult(display_name_spoofed=True),
        ),
    )
    assert dec_no_corrob.record_p_policy == DMARCPolicy.REJECT
    assert dec_no_corrob.selected_applicable_policy == DMARCPolicy.REJECT
    assert dec_no_corrob.interoperability_downgrade_applied is True
    assert any("RFC9989_7_4_UNSAFE_CONFIG_IGNORED" in c for c in dec_no_corrob.conflict_details)
    assert dec_no_corrob.post_interop_policy == DMARCPolicy.QUARANTINE
    assert dec_no_corrob.disposition == DMARCDisposition.QUARANTINE
    assert dec_no_corrob.advisory_signals["module3_identity_analysis"]["used_for_rfc7_4_corroboration"] is False

    # With verified independent threat evidence, SMTP contract permits REJECT 550 5.7.1 (HTTP stays inspection-only)
    threat = CorroboratingThreatSignals(confirmed_malicious_url=True)
    dec_smtp_corrob = DMARCPolicyEnforcer().enforce(
        dmarc_res,
        spf_result=spf_fail,
        channel=IngestionSource.SMTP_RELAY,
        threat_signals=threat,
    )
    assert dec_smtp_corrob.interoperability_downgrade_applied is False
    assert dec_smtp_corrob.disposition == DMARCDisposition.REJECT
    assert dec_smtp_corrob.smtp_contract is not None
    assert dec_smtp_corrob.smtp_contract.smtp_reply_code == 550
    assert "DMARC" in dec_smtp_corrob.smtp_contract.reply_text or "security policy" in dec_smtp_corrob.smtp_contract.reply_text
    assert dec_smtp_corrob.smtp_contract.executed is False

    dec_http_corrob = DMARCPolicyEnforcer().enforce(
        dmarc_res,
        spf_result=spf_fail,
        channel=IngestionSource.DIRECT_UPLOAD,
        threat_signals=threat,
    )
    assert dec_http_corrob.disposition == DMARCDisposition.RECOMMEND_REJECT
    assert dec_http_corrob.smtp_contract is None


# =============================================================================
# 11–12. POLICY SELECTION (RFC 9989 §4.10.1: AUTHOR / ORG / PSD / EXISTING vs NX)
# =============================================================================

@pytest.mark.asyncio
async def test_policy_selection_rfc9989_4_10_1_hierarchy_and_provenance():
    """Verifies Author Domain, Org Domain, PSD, existing vs non-existent subdomain, and NO naive np>sp>p."""
    resolver = MockDNSResolver()
    # Org domain with p=none, np=reject (NO sp=!):
    # Existing subdomain MUST get p=none (NOT np=reject!). Non-existent subdomain gets np=reject.
    resolver.add_txt("_dmarc.no-sp.example", ["v=DMARC1; p=none; np=reject; psd=n"])
    # Org domain with sp=quarantine and np=reject
    resolver.add_txt("_dmarc.full.example", ["v=DMARC1; p=none; sp=quarantine; np=reject; psd=n"])
    # Author domain record publishing sp/np MUST ignore them and use p only!
    resolver.add_txt("_dmarc.self.full.example", ["v=DMARC1; p=none; sp=quarantine; np=reject"])
    # PSD record with p=none; sp=quarantine; np=reject; psd=y
    resolver.add_txt("_dmarc.gov.example", ["v=DMARC1; p=none; sp=quarantine; np=reject; psd=y"])
    # DNS existence fixture for check_subdomain_existence=True
    resolver.add_a("exists.full.example", ["192.0.2.10"])
    resolver.set_nxdomain("ghost.full.example")

    evaluator = DMARCEvaluator(resolver=resolver)
    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="fail.example", scope="mfrom")

    # 1. Existing subdomain when sp absent and np=reject -> MUST NOT apply np (no naive np>sp>p)
    r_no_sp_existing = await evaluator.evaluate(
        "live.no-sp.example", spf_result=spf_fail, is_subdomain_non_existent=False
    )
    assert r_no_sp_existing.policy == DMARCPolicy.NONE
    assert r_no_sp_existing.record_p_policy == DMARCPolicy.NONE
    assert r_no_sp_existing.non_existent_subdomain_policy == DMARCPolicy.REJECT
    assert r_no_sp_existing.applicable_policy_tag == "p"
    assert r_no_sp_existing.policy_discovery_source == "org_domain"
    assert r_no_sp_existing.policy_domain == "no-sp.example"

    # 2. Non-existent subdomain on same record -> np=reject applies
    r_no_sp_nx = await evaluator.evaluate(
        "dead.no-sp.example", spf_result=spf_fail, is_subdomain_non_existent=True
    )
    assert r_no_sp_nx.policy == DMARCPolicy.REJECT
    assert r_no_sp_nx.applicable_policy_tag == "np"

    # 3. Author Domain itself ignores its own sp/np and uses p
    r_author = await evaluator.evaluate("self.full.example", spf_result=spf_fail)
    assert r_author.policy == DMARCPolicy.NONE
    assert r_author.applicable_policy_tag == "p"
    assert r_author.policy_discovery_source == "author_domain"
    assert r_author.is_subdomain is False

    # 4. Existing vs Non-existent via live/mock DNS existence probe (RFC 9989 Appendix A.4)
    r_dns_exist = await evaluator.evaluate(
        "exists.full.example", spf_result=spf_fail, check_subdomain_existence=True
    )
    assert r_dns_exist.policy == DMARCPolicy.QUARANTINE
    assert r_dns_exist.applicable_policy_tag == "sp"
    assert r_dns_exist.is_subdomain_non_existent is False

    r_dns_nx = await evaluator.evaluate(
        "ghost.full.example", spf_result=spf_fail, check_subdomain_existence=True
    )
    assert r_dns_nx.policy == DMARCPolicy.REJECT
    assert r_dns_nx.applicable_policy_tag == "np"
    assert r_dns_nx.is_subdomain_non_existent is True

    # 5. PSD policy distinction (gov.example psd=y)
    r_psd_existing = await evaluator.evaluate(
        "dept.gov.example", spf_result=spf_fail, is_subdomain_non_existent=False
    )
    assert r_psd_existing.policy == DMARCPolicy.QUARANTINE
    assert r_psd_existing.is_psd_policy is True
    assert r_psd_existing.policy_discovery_source == "psd"
    assert r_psd_existing.policy_domain == "gov.example"
    assert r_psd_existing.org_domain == "dept.gov.example"

    r_psd_nx = await evaluator.evaluate(
        "nonexistent.gov.example", spf_result=spf_fail, is_subdomain_non_existent=True
    )
    assert r_psd_nx.policy == DMARCPolicy.REJECT
    assert r_psd_nx.is_psd_policy is True
    assert r_psd_nx.policy_discovery_source == "psd"


# =============================================================================
# 13–16. FORWARDER TRUST, MALWARE VS ALLOWLIST, BLOCKLIST VS PASS, CONFLICTS
# =============================================================================

@pytest.mark.asyncio
async def test_forwarder_trust_validation_verified_vs_forged():
    """Verifies only server-verified forwarders/lists grant exemptions; headers/display names are ignored."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.bank.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)
    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="fwd.edu", scope="mfrom")
    dmarc_res = await evaluator.evaluate("bank.com", spf_result=spf_fail)

    cfg = AuthProtocolsConfig(
        trusted_forwarder_connector_ids=["conn-alumni-relay"],
        trusted_forwarder_ips=["198.51.100.10"],
    )
    enforcer = DMARCPolicyEnforcer(config=cfg)

    # 1. Verified connector ID & allowlisted relay IP on trusted SMTP metadata -> TRUSTED_FORWARDER exemption
    trusted_meta = TrustedSMTPMetadata(
        connecting_ip="198.51.100.10",
        authenticated_connector_id="conn-alumni-relay",
        is_trusted_mta=True,
        mta_sanitization_guaranteed=True,
    )
    dec_verified = enforcer.enforce(
        dmarc_res,
        spf_result=spf_fail,
        channel=IngestionSource.SMTP_RELAY,
        trusted_smtp_metadata=trusted_meta,
    )
    assert dec_verified.forwarder_exempted is True
    assert PolicyOverrideType.TRUSTED_FORWARDER in dec_verified.override_reasons
    assert dec_verified.disposition == DMARCDisposition.ACCEPT
    assert dec_verified.dmarc_status == ProtocolStatus.FAIL  # protocol status preserved!

    # 2. Forged display name ("via Alumni Group") & unauthenticated List-Id / unverified ForwarderTrustEvidence -> IGNORED
    spoofed_parsed = ParsedEmail(
        from_sender=EmailAddress(
            raw="Bank via Alumni Forwarder <alert@bank.com>",
            display_name="Bank via Alumni Forwarder",
            address="alert@bank.com",
            domain="bank.com",
        ),
        headers_map={
            "list-id": ["<trusted-list.edu>"],
            "authentication-results": ["alumni.edu; spf=pass"],
        },
    )
    dec_forged = enforcer.enforce(
        dmarc_res,
        spf_result=spf_fail,
        parsed_email=spoofed_parsed,
        channel=IngestionSource.DIRECT_UPLOAD,
        forwarder_evidence=ForwarderTrustEvidence(
            is_verified_forwarder=True,
            is_server_verified=False,  # unverified!
        ),
    )
    assert dec_forged.forwarder_exempted is False
    assert dec_forged.unverified_indirect_flow_claim_ignored is True
    assert dec_forged.disposition == DMARCDisposition.QUARANTINE


@pytest.mark.asyncio
async def test_allowlist_vs_malware_blocklist_vs_dmarc_pass_and_conflicts():
    """Verifies hard security blocks beat allowlists/DMARC PASS/t=y and unauthenticated rules are rejected."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.partner.org", ["v=DMARC1; p=reject"])
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="partner.org")
    dmarc_fail = await evaluator.evaluate("partner.org", spf_result=spf_fail)

    spf_pass = SPFResult(status=ProtocolStatus.PASS, domain="example.com", scope="mfrom")
    dmarc_pass = await evaluator.evaluate("example.com", spf_result=spf_pass)

    allow_rule_raw = _auth_allow_rule(from_domain="partner.org")
    enforcer = DMARCPolicyEnforcer()
    admin = _admin_actor()
    allow_rule = enforcer.attest_server_rule(allow_rule_raw, authorizing_actor=admin)
    assert allow_rule is not None

    # Case 14: Clean DMARC FAIL matching authenticated allowlist -> ACCEPT (while dmarc_status remains FAIL)
    dec_clean_allow = enforcer.enforce(
        dmarc_fail,
        spf_result=spf_fail,
        admin_rules=[allow_rule],
        admin_actor=admin,
        channel=IngestionSource.SMTP_RELAY,
    )
    assert dec_clean_allow.disposition == DMARCDisposition.ACCEPT
    assert dec_clean_allow.dmarc_status == ProtocolStatus.FAIL
    assert dec_clean_allow.local_override_applied is True
    assert PolicyOverrideType.LOCAL_POLICY in dec_clean_allow.override_reasons

    # Allowlist + confirmed malicious attachment -> Malware wins!
    dec_malware = enforcer.enforce(
        dmarc_fail,
        spf_result=spf_fail,
        admin_rules=[allow_rule],
        admin_actor=admin,
        threat_signals=CorroboratingThreatSignals(confirmed_malicious_attachment=True),
        channel=IngestionSource.SMTP_RELAY,
    )
    assert dec_malware.threat_block_applied is True
    assert dec_malware.policy_conflict_detected is True
    assert dec_malware.disposition == DMARCDisposition.REJECT
    assert dec_malware.dmarc_status == ProtocolStatus.FAIL

    # Case 15: Admin blocklist vs DMARC PASS -> Blocklist enforces while dmarc_status strictly stays PASS
    block_example = enforcer.attest_server_rule(
        _auth_block_rule(from_domain="example.com", action=OverrideRuleAction.FORCE_QUARANTINE),
        authorizing_actor=admin,
    )
    assert block_example is not None
    dec_block_pass = enforcer.enforce(
        dmarc_pass,
        spf_result=spf_pass,
        admin_rules=[block_example],
        admin_actor=admin,
        channel=IngestionSource.SMTP_RELAY,
    )
    assert dec_block_pass.dmarc_status == ProtocolStatus.PASS
    assert dec_block_pass.dmarc_rfc_status == "pass"
    assert dec_block_pass.disposition == DMARCDisposition.QUARANTINE
    assert dec_block_pass.policy_conflict_detected is True

    # Case 16: Simultaneous blocklist + allowlist -> Blocklist supersedes allowlist
    block_partner = enforcer.attest_server_rule(
        _auth_block_rule(
            rule_id="block-partner", from_domain="partner.org", action=OverrideRuleAction.FORCE_REJECT
        ),
        authorizing_actor=admin,
    )
    assert block_partner is not None
    dec_conflict = enforcer.enforce(
        dmarc_fail,
        spf_result=spf_fail,
        admin_rules=[allow_rule, block_partner],
        admin_actor=admin,
        channel=IngestionSource.SMTP_RELAY,
    )
    assert dec_conflict.policy_conflict_detected is True
    assert any("ADMIN_POLICY_CONFLICT_DETECTED" in c for c in dec_conflict.conflict_details)
    assert dec_conflict.disposition == DMARCDisposition.REJECT

    # Unauthenticated / API-key actor supplying an unauthenticated allowlist rule -> REJECTED!
    unauth_allow = LocalPolicyOverrideRule(
        rule_id="unauth-allow",
        action=OverrideRuleAction.EXEMPT_ACCEPT,
        match_from_domain="partner.org",
        is_authenticated_admin_source=False,
    )
    dec_unauth = enforcer.enforce(
        dmarc_fail,
        spf_result=spf_fail,
        admin_rules=[unauth_allow],
        admin_actor=_api_key_actor(),
        channel=IngestionSource.SMTP_RELAY,
    )
    assert "unauth-allow" in dec_unauth.rejected_unauthenticated_rules
    assert dec_unauth.disposition == DMARCDisposition.QUARANTINE  # never bypassed!


# =============================================================================
# 17–20. HTTP UPLOAD IMMUTABILITY, DETERMINISM, TELEMETRY & EXCEPTION SAFETY
# =============================================================================

@pytest.mark.asyncio
async def test_http_upload_non_mutation_determinism_and_incident_audit_persistence(db_session):
    """Verifies HTTP upload disposition, raw byte immutability, determinism, and ScanIncident telemetry."""
    raw_bytes = b"From: user@example.com\r\nTo: sec@corp.com\r\nSubject: Uploaded EML\r\n\r\nBody\r\n"
    raw_sha_before = hashlib.sha256(raw_bytes).hexdigest()
    payload = RawEmailPayload(
        raw_bytes=raw_bytes,
        source=IngestionSource.DIRECT_UPLOAD,
        filename="uploaded.eml",
        tenant_id="tenant-a",
    )

    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)
    enforcer = DMARCPolicyEnforcer()

    spf_not_eval = SPFResult(status=ProtocolStatus.NOT_EVALUATED)
    dmarc_res = await evaluator.evaluate("example.com", spf_result=spf_not_eval, dkim_results=[])

    dec1 = enforcer.enforce(
        dmarc_res,
        spf_result=spf_not_eval,
        dkim_results=[],
        raw_payload=payload,
        channel=IngestionSource.DIRECT_UPLOAD,
        tenant_id="tenant-a",
    )
    dec2 = enforcer.enforce(
        dmarc_res,
        spf_result=spf_not_eval,
        dkim_results=[],
        raw_payload=payload,
        channel=IngestionSource.DIRECT_UPLOAD,
        tenant_id="tenant-a",
    )

    # Deterministic JSON output & complete telemetry
    assert dec1.model_dump(mode="json") == dec2.model_dump(mode="json")
    assert dec1.channel_mode == "http_inspection"
    assert dec1.smtp_contract is None
    assert dec1.disposition == DMARCDisposition.MANUAL_REVIEW_INCOMPLETE
    assert dec1.raw_bytes_modified is False
    assert hashlib.sha256(payload.raw_bytes).hexdigest() == raw_sha_before

    # Record into existing ScanIncident & AuditRecord without DB schema migrations
    incident = ScanIncident(
        scan_uuid="11111111-2222-3333-4444-555555555555",
        sender="user@example.com",
        recipient="sec@corp.com",
        subject="Uploaded EML",
        status=ScanStatus.COMPLETED,
        tenant_id="tenant-a",
        risk_score=0.0,
        risk_tier=RiskTier.PENDING,
        verdict_summary="Step 3.7.3B telemetry test",
        telemetry={},
    )
    await record_dmarc_decision_on_incident(
        incident=incident,
        dmarc_result=dmarc_res,
        decision=dec1,
        spf_result=spf_not_eval,
        dkim_results=[],
        db=db_session,
        actor=_admin_actor(tenant_id="tenant-a"),
        ip_address="127.0.0.1",
    )

    assert "auth_protocols" in incident.telemetry
    assert incident.telemetry["auth_protocols"]["dmarc"]["status"] == "INDETERMINATE"
    assert incident.telemetry["auth_protocols"]["dmarc"]["rfc_status"] is None
    assert incident.telemetry["auth_protocols"]["dmarc_enforcement"]["disposition"] == "MANUAL_REVIEW_INCOMPLETE"

    audit_rows = (
        await db_session.execute(
            select(AuditRecord).where(AuditRecord.resource_id == str(incident.id))
        )
    ).scalars().all()
    assert len(audit_rows) == 1
    assert audit_rows[0].action == "DMARC_POLICY_ENFORCED"
    assert audit_rows[0].actor_id == "secadmin@mailsentra.corp"


@pytest.mark.asyncio
async def test_unexpected_dmarc_evaluator_error_returns_indeterminate_and_freezes_policy():
    """Scenario 20: Unexpected software errors in DMARCEvaluator never become FAIL or apply policy."""

    class _CrashingResolver(MockDNSResolver):
        async def resolve(self, domain, query_type, raise_on_error=False):
            raise RuntimeError("Simulated unexpected DMARC discovery crash")

    evaluator = DMARCEvaluator(resolver=_CrashingResolver())
    res = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.FAIL, domain="example.com"),
    )
    assert res.status == ProtocolStatus.INDETERMINATE
    assert res.standard_status is None
    assert res.rfc_status is None

    dec = DMARCPolicyEnforcer().enforce(res, channel=IngestionSource.DIRECT_UPLOAD)
    assert dec.disposition == DMARCDisposition.MANUAL_REVIEW_INCOMPLETE
    assert dec.policy_applied is False


@pytest.mark.asyncio
async def test_additional_edge_cases_impersonation_ip_rules_and_quarantine_behavior():
    """Verifies verified vs unverified impersonation, IP CIDR boundary, quarantine t=n, and fail-open TEMPERROR."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.quar.example", ["v=DMARC1; p=quarantine; t=invalid_flag"])
    resolver.add_txt("_dmarc.reject.example", ["v=DMARC1; p=reject"])
    resolver.set_timeout("_dmarc.timeout.example", DNSQueryType.TXT)
    evaluator = DMARCEvaluator(resolver=resolver)

    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="other.example", scope="mfrom")

    # 1. Invalid t= falls back to t=n; p=quarantine enforces QUARANTINE
    res_quar = await evaluator.evaluate("quar.example", spf_result=spf_fail)
    assert res_quar.test_mode is False
    dec_quar = DMARCPolicyEnforcer().enforce(res_quar, channel=IngestionSource.DIRECT_UPLOAD)
    assert dec_quar.disposition == DMARCDisposition.QUARANTINE
    assert dec_quar.smtp_contract is None

    # 2. Unverified impersonation (provenance=False or low confidence) NEVER grants reject or hard block
    res_rej = await evaluator.evaluate("reject.example", spf_result=spf_fail)
    dec_unverified_imp = DMARCPolicyEnforcer().enforce(
        res_rej,
        threat_signals=CorroboratingThreatSignals(
            high_confidence_impersonation=True,
            impersonation_confidence=0.95,
            impersonation_provenance_verified=False,
        ),
        channel=IngestionSource.SMTP_RELAY,
    )
    assert dec_unverified_imp.threat_block_applied is False
    assert dec_unverified_imp.interoperability_downgrade_applied is True
    assert dec_unverified_imp.disposition == DMARCDisposition.QUARANTINE

    # Verified high-confidence impersonation (>= 0.85 + verified provenance) triggers hard block & corroboration
    dec_verified_imp = DMARCPolicyEnforcer().enforce(
        res_rej,
        threat_signals=CorroboratingThreatSignals(
            high_confidence_impersonation=True,
            impersonation_confidence=0.92,
            impersonation_provenance_verified=True,
        ),
        channel=IngestionSource.SMTP_RELAY,
    )
    assert dec_verified_imp.threat_block_applied is True
    assert dec_verified_imp.interoperability_downgrade_applied is False
    assert dec_verified_imp.disposition == DMARCDisposition.REJECT

    # 3. IP allowlist rule must NOT match Received header hops when SMTP metadata is absent (HTTP upload)
    ip_allow_rule = LocalPolicyOverrideRule(
        rule_id="allow-trusted-ip",
        action=OverrideRuleAction.EXEMPT_ACCEPT,
        match_ip_or_cidr="198.51.100.0/24",
        configured_by_identity="secadmin@mailsentra.corp",
        configured_by_role=UserRole.SUPER_ADMIN.value,
        is_authenticated_admin_source=True,
    )
    parsed_with_forged_received = ParsedEmail(
        from_sender=EmailAddress(
            raw="user@reject.example", address="user@reject.example", domain="reject.example"
        ),
        received_hops=[],
    )
    dec_http_ip = DMARCPolicyEnforcer().enforce(
        res_rej,
        parsed_email=parsed_with_forged_received,
        admin_rules=[ip_allow_rule],
        channel=IngestionSource.DIRECT_UPLOAD,
        trusted_smtp_metadata=TrustedSMTPMetadata(
            connecting_ip="198.51.100.12",
            is_trusted_mta=True,  # HTTP upload channel ignores SMTP metadata bypass!
        ),
    )
    assert "allow-trusted-ip" not in dec_http_ip.matched_rule_ids
    assert dec_http_ip.disposition == DMARCDisposition.QUARANTINE

    # 4. SMTP_RELAY TEMPERROR respects configurable fail-open ("accept") while defaulting to "defer"
    res_temp = await evaluator.evaluate("timeout.example", spf_result=spf_fail)
    fail_open_enforcer = DMARCPolicyEnforcer(
        config=AuthProtocolsConfig(dmarc_temperror_smtp_action="accept")
    )
    dec_open = fail_open_enforcer.enforce(res_temp, channel=IngestionSource.SMTP_RELAY)
    assert dec_open.disposition == DMARCDisposition.ACCEPT
    assert dec_open.smtp_contract is not None
    assert dec_open.smtp_contract.smtp_reply_code == 250


@pytest.mark.asyncio
async def test_multi_from_permerror_and_internal_dkim_indeterminate_in_dmarc():
    """Verifies multi-From rejection (RFC 9989 §5.3.1/§11.5) and internal DKIM INDETERMINATE safety."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    # Multiple distinct RFC5322.From domains -> PERMERROR
    res_multi = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.PASS, domain="example.com", scope="mfrom"),
        all_from_domains=["example.com", "bank.com"],
    )
    assert res_multi.status == ProtocolStatus.PERMERROR
    assert res_multi.rfc_status == "permerror"
    assert res_multi.diagnostics.get("from_domains_checked") == ["example.com", "bank.com"]

    # Completed SPF FAIL + DKIM INDETERMINATE (internal error) -> DMARC INDETERMINATE (not FAIL!)
    res_dkim_err = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.FAIL, domain="example.com", scope="mfrom"),
        dkim_results=[
            DKIMSignatureResult(
                status=ProtocolStatus.INDETERMINATE,
                domain="example.com",
                selector="s1",
                error_reason="DKIM internal verification exception",
            )
        ],
    )
    assert res_dkim_err.status == ProtocolStatus.INDETERMINATE
    assert res_dkim_err.rfc_status is None
    dec_err = DMARCPolicyEnforcer().enforce(res_dkim_err, channel=IngestionSource.DIRECT_UPLOAD)
    assert dec_err.disposition == DMARCDisposition.MANUAL_REVIEW_INCOMPLETE
    assert dec_err.policy_applied is False


# =============================================================================
# 21–23. STEP 3.7.3B REMEDIATION TESTS (H2, M1, M2)
# =============================================================================

@pytest.mark.asyncio
async def test_h2_rule_provenance_actor_auth_and_tenant_isolation():
    """H2: Enforces server HMAC provenance, non-bypassable actor auth, tenant isolation, and role separation."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.partner.org", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)
    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="evil.org", scope="mfrom")
    dmarc_fail = await evaluator.evaluate("partner.org", spf_result=spf_fail)

    soc_a = IngestionActor(identity="soc@corp.example", role=UserRole.SOC_ANALYST.value, is_api_key=False, tenant_id="tenant-a")
    admin_a = IngestionActor(identity="super@corp.example", role=UserRole.SUPER_ADMIN.value, is_api_key=False, tenant_id="tenant-a")
    admin_b = IngestionActor(identity="super-b@corp.example", role=UserRole.SUPER_ADMIN.value, is_api_key=False, tenant_id="tenant-b")
    sys_agent_a = IngestionActor(identity="ingest-collector-1", role=UserRole.SYSTEM_AGENT.value, is_api_key=True, tenant_id="tenant-a")
    missing_tenant_actor = IngestionActor(identity="notenant@corp.example", role=UserRole.SUPER_ADMIN.value, is_api_key=False, tenant_id="   ")

    # Configure one legitimate server rule on tenant-a and one on tenant-b
    srv_rule_a = _auth_allow_rule(rule_id="srv-allow-a", from_domain="partner.org", tenant_id="tenant-a")
    srv_rule_b = _auth_allow_rule(rule_id="srv-allow-b", from_domain="partner.org", tenant_id="tenant-b")
    cfg = AuthProtocolsConfig(local_override_rules=[srv_rule_a, srv_rule_b])
    enforcer = DMARCPolicyEnforcer(config=cfg)

    # 1. Unauthenticated rule + authenticated SOC_ANALYST -> REJECTED
    unauth_rule = LocalPolicyOverrideRule(
        rule_id="unauth-soc", action=OverrideRuleAction.EXEMPT_ACCEPT, match_from_domain="partner.org",
        tenant_id="tenant-a", is_authenticated_admin_source=False,
    )
    dec_1 = enforcer.enforce(dmarc_fail, admin_rules=[unauth_rule], admin_actor=soc_a, tenant_id="tenant-a")
    assert "unauth-soc" in dec_1.rejected_unauthenticated_rules
    assert dec_1.local_override_applied is True  # srv-allow-a from config applies, unauth-soc rejected!
    assert "unauth-soc" not in dec_1.matched_rule_ids

    # Evaluate on isolated bare enforcer without config rule to verify disposition stays QUARANTINE
    bare_enforcer = DMARCPolicyEnforcer()
    dec_unauth_soc = bare_enforcer.enforce(dmarc_fail, admin_rules=[unauth_rule], admin_actor=soc_a, tenant_id="tenant-a")
    assert "unauth-soc" in dec_unauth_soc.rejected_unauthenticated_rules
    assert dec_unauth_soc.disposition == DMARCDisposition.QUARANTINE

    # 2. Unauthenticated rule + authenticated SUPER_ADMIN -> REJECTED
    dec_unauth_admin = bare_enforcer.enforce(dmarc_fail, admin_rules=[unauth_rule], admin_actor=admin_a, tenant_id="tenant-a")
    assert "unauth-soc" in dec_unauth_admin.rejected_unauthenticated_rules
    assert dec_unauth_admin.disposition == DMARCDisposition.QUARANTINE

    # 3. Forged server-authentication boolean + fake HMAC alongside valid SUPER_ADMIN -> REJECTED!
    forged_rule = LocalPolicyOverrideRule(
        rule_id="forged-bool-rule",
        action=OverrideRuleAction.EXEMPT_ACCEPT,
        match_from_domain="partner.org",
        tenant_id="tenant-a",
        configured_by_identity="fakeadmin@corp.example",
        configured_by_role=UserRole.SUPER_ADMIN.value,
        is_authenticated_admin_source=True,
        server_provenance_hmac="deadbeef" * 8,
    )
    dec_forged = bare_enforcer.enforce(dmarc_fail, admin_rules=[forged_rule], admin_actor=admin_a, tenant_id="tenant-a")
    assert "forged-bool-rule" in dec_forged.rejected_unauthenticated_rules
    assert dec_forged.disposition == DMARCDisposition.QUARANTINE

    # 4. Missing rule provenance (no configured_by_identity / role) -> REJECTED
    missing_prov = LocalPolicyOverrideRule(
        rule_id="missing-prov",
        action=OverrideRuleAction.EXEMPT_ACCEPT,
        match_from_domain="partner.org",
        tenant_id="tenant-a",
        configured_by_identity=None,
        configured_by_role=None,
        is_authenticated_admin_source=True,
    )
    assert bare_enforcer.attest_server_rule(missing_prov, authorizing_actor=admin_a) is None
    dec_missing_prov = bare_enforcer.enforce(dmarc_fail, admin_rules=[missing_prov], admin_actor=admin_a, tenant_id="tenant-a")
    assert "missing-prov" in dec_missing_prov.rejected_unauthenticated_rules
    assert dec_missing_prov.disposition == DMARCDisposition.QUARANTINE

    # 5. Authenticated rule (tenant-a) + actor from another tenant (tenant-b) -> REJECTED
    dyn_rule_a = _auth_allow_rule(rule_id="dyn-allow-a", from_domain="partner.org", tenant_id="tenant-a").model_copy(
        update={"configured_by_identity": "super@corp.example"}
    )
    attested_a = bare_enforcer.attest_server_rule(dyn_rule_a, authorizing_actor=admin_a)
    assert attested_a is not None
    dec_cross_actor = bare_enforcer.enforce(dmarc_fail, admin_rules=[attested_a], admin_actor=admin_b, tenant_id="tenant-a")
    assert "dyn-allow-a" in dec_cross_actor.rejected_unauthenticated_rules
    assert dec_cross_actor.disposition == DMARCDisposition.QUARANTINE

    # 6. Authenticated rule (tenant-b) + tenant-a scan/actor -> REJECTED
    dyn_rule_b = _auth_allow_rule(rule_id="dyn-allow-b", from_domain="partner.org", tenant_id="tenant-b").model_copy(
        update={"configured_by_identity": "super-b@corp.example"}
    )
    attested_b = bare_enforcer.attest_server_rule(dyn_rule_b, authorizing_actor=admin_b)
    assert attested_b is not None
    assert "srv-allow-b" in enforcer.enforce(dmarc_fail, admin_actor=admin_a, tenant_id="tenant-a").rejected_unauthenticated_rules
    assert "dyn-allow-b" in bare_enforcer.enforce(dmarc_fail, admin_rules=[attested_b], admin_actor=admin_a, tenant_id="tenant-a").rejected_unauthenticated_rules

    # 7. Missing actor tenant -> REJECTED
    dec_missing_tenant = enforcer.enforce(dmarc_fail, admin_actor=missing_tenant_actor, tenant_id="tenant-a")
    assert "srv-allow-a" in dec_missing_tenant.rejected_unauthenticated_rules
    assert dec_missing_tenant.disposition == DMARCDisposition.QUARANTINE

    # 8. Missing actor (admin_actor=None) -> REJECTED (cannot authorize overrides!)
    dec_no_actor = bare_enforcer.enforce(dmarc_fail, admin_rules=[attested_a], admin_actor=None, tenant_id="tenant-a")
    assert "dyn-allow-a" in dec_no_actor.rejected_unauthenticated_rules
    assert dec_no_actor.disposition == DMARCDisposition.QUARANTINE

    # 9. Valid authenticated rule + correctly authorized same-tenant matching actor -> ACCEPTED
    dec_valid_admin = bare_enforcer.enforce(dmarc_fail, admin_rules=[attested_a], admin_actor=admin_a, tenant_id="tenant-a")
    assert dec_valid_admin.matched_rule_ids == ["dyn-allow-a"]
    assert dec_valid_admin.disposition == DMARCDisposition.ACCEPT

    # 10. Authorized SYSTEM_AGENT flow preserves provenance on server config rules, blocks dynamic overrides
    dec_sys_cfg = enforcer.enforce(dmarc_fail, admin_actor=sys_agent_a, tenant_id="tenant-a")
    assert dec_sys_cfg.matched_rule_ids == ["srv-allow-a"]
    assert dec_sys_cfg.disposition == DMARCDisposition.ACCEPT
    assert dec_sys_cfg.audit_metadata["actor_type"] == "api_key_system_agent"
    assert dec_sys_cfg.audit_metadata["actor_identity"] == "ingest-collector-1"

    dec_sys_dyn = bare_enforcer.enforce(dmarc_fail, admin_rules=[attested_a], admin_actor=sys_agent_a, tenant_id="tenant-a")
    assert "dyn-allow-a" in dec_sys_dyn.rejected_unauthenticated_rules
    assert dec_sys_dyn.disposition == DMARCDisposition.QUARANTINE


@pytest.mark.asyncio
async def test_m1_persistence_transaction_safety_attribution_and_dedup(db_session, monkeypatch):
    """M1: Tests flush/ID availability, rollback & error propagation on commit failure, SYSTEM_AGENT preservation, tenant rejection, and deduplication."""
    from app.core.audit import AuditLogger

    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=quarantine"])
    evaluator = DMARCEvaluator(resolver=resolver)
    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="other.org", identity="secret_user@other.org", scope="mfrom")
    dmarc_res = await evaluator.evaluate("example.com", spf_result=spf_fail)
    enforcer = DMARCPolicyEnforcer()

    logged_events = []
    orig_log = AuditLogger.log_event

    def _capture_log(**kwargs):
        ev = orig_log(**kwargs)
        logged_events.append(ev)
        return ev

    monkeypatch.setattr(AuditLogger, "log_event", staticmethod(_capture_log))

    sys_actor = IngestionActor(
        identity="collector-prod-eu-01",
        role=UserRole.SYSTEM_AGENT.value,
        is_api_key=True,
        tenant_id="tenant-m1",
    )
    decision_sys = enforcer.enforce(dmarc_res, spf_result=spf_fail, admin_actor=sys_actor, tenant_id="tenant-m1")

    incident = ScanIncident(
        scan_uuid="aaaa1111-2222-3333-4444-555566667777",
        sender="secret_user@other.org",
        recipient="sec@example.com",
        subject="M1 Persistence",
        status=ScanStatus.COMPLETED,
        tenant_id="tenant-m1",
        risk_score=0.5,
        risk_tier=RiskTier.SUSPICIOUS,
        verdict_summary="M1 check",
        telemetry={"preexisting": True},
    )

    # 1. Commit success + SYSTEM_AGENT attribution + PII redaction + flush ID
    await record_dmarc_decision_on_incident(
        incident=incident,
        dmarc_result=dmarc_res,
        decision=decision_sys,
        spf_result=spf_fail,
        db=db_session,
        actor=sys_actor,
        ip_address="198.51.100.5",
    )
    assert incident.id is not None
    assert incident.telemetry["auth_protocols"]["spf"]["identity"] == "***@other.org"
    rows = (await db_session.execute(select(AuditRecord).where(AuditRecord.resource_id == str(incident.id)))).scalars().all()
    assert len(rows) == 1
    assert rows[0].actor_id == "collector-prod-eu-01"
    assert rows[0].status == "SUCCESS"
    assert rows[0].details["actor_type"] == "api_key_system_agent"
    assert rows[0].details["durable_db_persisted"] is True
    assert logged_events[-1]["status"] == "SUCCESS"

    # 2. Repeated identical invocation deduplicates AuditRecord cleanly
    res_dup = await record_dmarc_decision_on_incident(
        incident=incident,
        dmarc_result=dmarc_res,
        decision=decision_sys,
        spf_result=spf_fail,
        db=db_session,
        actor=sys_actor,
        ip_address="198.51.100.5",
    )
    assert res_dup.get("audit_deduplicated") is True
    rows_after_dup = (await db_session.execute(select(AuditRecord).where(AuditRecord.resource_id == str(incident.id)))).scalars().all()
    assert len(rows_after_dup) == 1

    # 3. Cross-tenant actor rejected BEFORE DB mutation or AuditRecord insertion
    wrong_tenant_actor = IngestionActor(
        identity="evil-admin@corp.example", role=UserRole.SUPER_ADMIN.value, is_api_key=False, tenant_id="tenant-other"
    )
    with pytest.raises(PermissionError):
        await record_dmarc_decision_on_incident(
            incident=incident, dmarc_result=dmarc_res, decision=decision_sys, db=db_session, actor=wrong_tenant_actor
        )
    assert logged_events[-1]["status"] == "DENIED_TENANT_MISMATCH"

    # 4. Commit failure triggers rollback, restores prior telemetry, emits PERSISTENCE_FAILED (NEVER SUCCESS), and re-raises
    human_actor = _admin_actor(tenant_id="tenant-m1")
    decision_human = enforcer.enforce(
        dmarc_res,
        spf_result=spf_fail,
        threat_signals=CorroboratingThreatSignals(confirmed_malicious_url=True),
        admin_actor=human_actor,
        tenant_id="tenant-m1",
    )
    prior_snapshot = dict(incident.telemetry)
    events_before_fail = len(logged_events)

    orig_commit = db_session.commit
    rollback_called = False
    orig_rollback = db_session.rollback

    async def _failing_commit():
        raise RuntimeError("Simulated DB commit failure")

    async def _spy_rollback():
        nonlocal rollback_called
        rollback_called = True
        await orig_rollback()

    monkeypatch.setattr(db_session, "commit", _failing_commit)
    monkeypatch.setattr(db_session, "rollback", _spy_rollback)

    with pytest.raises(RuntimeError, match="Simulated DB commit failure"):
        await record_dmarc_decision_on_incident(
            incident=incident,
            dmarc_result=dmarc_res,
            decision=decision_human,
            spf_result=spf_fail,
            db=db_session,
            actor=human_actor,
        )

    assert rollback_called is True
    assert incident.telemetry == prior_snapshot
    new_events = logged_events[events_before_fail:]
    assert len(new_events) == 1
    assert new_events[0]["status"] == "PERSISTENCE_FAILED"
    assert new_events[0]["details"]["durable_db_persisted"] is False

    # Restore commit and verify subsequent different decision writes 2nd AuditRecord row for human admin
    monkeypatch.setattr(db_session, "commit", orig_commit)
    monkeypatch.setattr(db_session, "rollback", orig_rollback)
    await record_dmarc_decision_on_incident(
        incident=incident, dmarc_result=dmarc_res, decision=decision_human, db=db_session, actor=human_actor
    )
    rows_final = (await db_session.execute(select(AuditRecord).where(AuditRecord.resource_id == str(incident.id)))).scalars().all()
    assert len(rows_final) == 2

    # 5. In-memory (db=None) never falsely emits SUCCESS
    await record_dmarc_decision_on_incident(
        incident=incident, dmarc_result=dmarc_res, decision=decision_human, db=None, actor=human_actor
    )
    assert logged_events[-1]["status"] == "IN_MEMORY_ONLY_NOT_PERSISTED"
    assert logged_events[-1]["details"]["durable_db_persisted"] is False


@pytest.mark.asyncio
async def test_m2_t_y_testing_mode_audit_separation_from_local_overrides(db_session):
    """M2: Verifies t=y alone emits DMARC_TEST_MODE_APPLIED (local_override_applied=False) and coexists cleanly with local overrides."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.testonly.example", ["v=DMARC1; p=reject; t=y"])
    evaluator = DMARCEvaluator(resolver=resolver)
    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="other.org", scope="mfrom")
    dmarc_ty = await evaluator.evaluate("testonly.example", spf_result=spf_fail)

    actor = _admin_actor(tenant_id="tenant-m2")
    enforcer = DMARCPolicyEnforcer()
    dec_ty_only = enforcer.enforce(dmarc_ty, spf_result=spf_fail, admin_actor=actor, tenant_id="tenant-m2")
    assert dec_ty_only.test_mode_applied is True
    assert dec_ty_only.local_override_applied is False
    assert dec_ty_only.record_p_policy == DMARCPolicy.REJECT
    assert dec_ty_only.effective_policy == DMARCPolicy.QUARANTINE

    inc_ty = ScanIncident(
        scan_uuid="bbbb1111-2222-3333-4444-555566667777",
        sender="a@other.org",
        recipient="b@testonly.example",
        subject="t=y only",
        status=ScanStatus.COMPLETED,
        tenant_id="tenant-m2",
        risk_score=0.2,
        risk_tier=RiskTier.CLEAN,
        telemetry={},
    )
    await record_dmarc_decision_on_incident(inc_ty, dmarc_ty, dec_ty_only, db=db_session, actor=actor)
    rows_ty = (await db_session.execute(select(AuditRecord).where(AuditRecord.resource_id == str(inc_ty.id)))).scalars().all()
    assert len(rows_ty) == 1
    assert rows_ty[0].action == "DMARC_TEST_MODE_APPLIED"
    assert rows_ty[0].details["record_p_policy"] == "reject"
    assert rows_ty[0].details["effective_policy"] == "quarantine"
    assert rows_ty[0].details["test_mode_applied"] is True
    assert rows_ty[0].details["local_override_applied"] is False
    assert rows_ty[0].details["domain_owner_policy_preserved"] is True

    # Combined: Domain Owner t=y AND genuine local admin allowlist override
    allow_rule = enforcer.attest_server_rule(
        _auth_allow_rule(rule_id="allow-ty", from_domain="testonly.example", tenant_id="tenant-m2"),
        authorizing_actor=actor,
    )
    assert allow_rule is not None
    dec_both = enforcer.enforce(
        dmarc_ty, spf_result=spf_fail, admin_rules=[allow_rule], admin_actor=actor, tenant_id="tenant-m2"
    )
    assert dec_both.test_mode_applied is True
    assert dec_both.local_override_applied is True
    assert PolicyOverrideType.POLICY_TEST_MODE in dec_both.override_reasons
    assert PolicyOverrideType.LOCAL_POLICY in dec_both.override_reasons
    assert dec_both.disposition == DMARCDisposition.ACCEPT

    inc_both = ScanIncident(
        scan_uuid="cccc1111-2222-3333-4444-555566667777",
        sender="a@other.org",
        recipient="b@testonly.example",
        subject="t=y + allow",
        status=ScanStatus.COMPLETED,
        tenant_id="tenant-m2",
        risk_score=0.1,
        risk_tier=RiskTier.CLEAN,
        telemetry={},
    )
    await record_dmarc_decision_on_incident(inc_both, dmarc_ty, dec_both, db=db_session, actor=actor)
    rows_both = (await db_session.execute(select(AuditRecord).where(AuditRecord.resource_id == str(inc_both.id)))).scalars().all()
    assert len(rows_both) == 1
    assert rows_both[0].action == "DMARC_POLICY_OVERRIDE_APPLIED"
    assert rows_both[0].details["record_p_policy"] == "reject"
    assert rows_both[0].details["test_mode_applied"] is True
    assert rows_both[0].details["local_override_applied"] is True


# =============================================================================
# 24–27. STEP 3.7.3B FINAL SECURITY HARDENING TESTS (L3, H2, M1)
# =============================================================================

@pytest.mark.asyncio
async def test_l3_forwarder_trust_boundary_all_negative_and_positive_cases():
    """L3: Strictly blocks ForwarderTrustEvidence bypass on DIRECT_UPLOAD/non-SMTP and enforces allowlist+context binding on SMTP_RELAY."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.quar-target.example", ["v=DMARC1; p=quarantine"])
    resolver.add_txt("_dmarc.rej-target.example", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="fwd.org", scope="mfrom")
    dmarc_quar = await evaluator.evaluate("quar-target.example", spf_result=spf_fail)
    dmarc_rej = await evaluator.evaluate("rej-target.example", spf_result=spf_fail)

    cfg = AuthProtocolsConfig(
        trusted_forwarder_connector_ids=["conn-alumni-relay", "conn-partner-relay"],
        trusted_forwarder_ips=["198.51.100.10", "198.51.100.20"],
        trusted_forwarder_bindings={
            "conn-alumni-relay": ["198.51.100.10"],
            "conn-partner-relay": ["198.51.100.20"],
        },
    )
    enforcer = DMARCPolicyEnforcer(config=cfg)

    for dmarc_res, exp_policy in (
        (dmarc_quar, DMARCPolicy.QUARANTINE),
        (dmarc_rej, DMARCPolicy.REJECT),
    ):
        # 1. DIRECT_UPLOAD with fabricated verified evidence -> REJECTED (never ACCEPT!)
        dec_dir_ev = enforcer.enforce(
            dmarc_res,
            spf_result=spf_fail,
            channel=IngestionSource.DIRECT_UPLOAD,
            forwarder_evidence=ForwarderTrustEvidence(
                is_verified_forwarder=True,
                is_server_verified=True,
                connector_id="conn-alumni-relay",
                relay_ip="198.51.100.10",
            ),
        )
        assert dec_dir_ev.forwarder_exempted is False
        assert dec_dir_ev.unverified_indirect_flow_claim_ignored is True
        assert dec_dir_ev.disposition == DMARCDisposition.QUARANTINE  # never ACCEPT

        # 2. DIRECT_UPLOAD with trusted connector ID & IP in SMTP metadata -> REJECTED
        dec_dir_meta = enforcer.enforce(
            dmarc_res,
            spf_result=spf_fail,
            channel=IngestionSource.DIRECT_UPLOAD,
            trusted_smtp_metadata=TrustedSMTPMetadata(
                connecting_ip="198.51.100.10",
                authenticated_connector_id="conn-alumni-relay",
                is_trusted_mta=True,
                mta_sanitization_guaranteed=True,
            ),
        )
        assert dec_dir_meta.forwarder_exempted is False
        assert dec_dir_meta.disposition == DMARCDisposition.QUARANTINE

        # 3. Other non-relay channels (GRAPH_API / RAW_PAYLOAD) with ForwarderTrustEvidence -> REJECTED
        for ch in (IngestionSource.GRAPH_API, IngestionSource.RAW_PAYLOAD, IngestionSource.IMAP_COLLECTOR):
            dec_non_smtp = enforcer.enforce(
                dmarc_res,
                spf_result=spf_fail,
                channel=ch,
                forwarder_evidence=ForwarderTrustEvidence(
                    is_verified_forwarder=True,
                    is_server_verified=True,
                    connector_id="conn-alumni-relay",
                    relay_ip="198.51.100.10",
                ),
            )
            assert dec_non_smtp.forwarder_exempted is False
            assert dec_non_smtp.disposition == DMARCDisposition.QUARANTINE

        # 4. SMTP_RELAY with unknown connector (even with allowlisted IP!) -> REJECTED
        dec_unk_conn = enforcer.enforce(
            dmarc_res,
            spf_result=spf_fail,
            channel=IngestionSource.SMTP_RELAY,
            trusted_smtp_metadata=TrustedSMTPMetadata(
                connecting_ip="198.51.100.10",
                authenticated_connector_id="conn-rogue",
                is_trusted_mta=True,
                mta_sanitization_guaranteed=True,
            ),
        )
        assert dec_unk_conn.forwarder_exempted is False
        assert dec_unk_conn.disposition == DMARCDisposition.QUARANTINE

        # 5. SMTP_RELAY with untrusted relay IP (even with allowlisted connector!) -> REJECTED
        dec_bad_ip = enforcer.enforce(
            dmarc_res,
            spf_result=spf_fail,
            channel=IngestionSource.SMTP_RELAY,
            trusted_smtp_metadata=TrustedSMTPMetadata(
                connecting_ip="203.0.113.55",
                authenticated_connector_id="conn-alumni-relay",
                is_trusted_mta=True,
                mta_sanitization_guaranteed=True,
            ),
        )
        assert dec_bad_ip.forwarder_exempted is False
        assert dec_bad_ip.disposition == DMARCDisposition.QUARANTINE

        # 6a. SMTP_RELAY with mismatched connector & bound relay IP (cross-connector IP mix) -> REJECTED
        dec_mismatch_bind = enforcer.enforce(
            dmarc_res,
            spf_result=spf_fail,
            channel=IngestionSource.SMTP_RELAY,
            trusted_smtp_metadata=TrustedSMTPMetadata(
                connecting_ip="198.51.100.20",  # belongs to conn-partner-relay, NOT conn-alumni-relay!
                authenticated_connector_id="conn-alumni-relay",
                is_trusted_mta=True,
                mta_sanitization_guaranteed=True,
            ),
        )
        assert dec_mismatch_bind.forwarder_exempted is False
        assert dec_mismatch_bind.disposition == DMARCDisposition.QUARANTINE

        # 6b. SMTP_RELAY with mismatched ForwarderTrustEvidence vs TrustedSMTPMetadata -> REJECTED
        dec_mismatch_ev = enforcer.enforce(
            dmarc_res,
            spf_result=spf_fail,
            channel=IngestionSource.SMTP_RELAY,
            trusted_smtp_metadata=TrustedSMTPMetadata(
                connecting_ip="198.51.100.10",
                authenticated_connector_id="conn-alumni-relay",
                is_trusted_mta=True,
                mta_sanitization_guaranteed=True,
            ),
            forwarder_evidence=ForwarderTrustEvidence(
                is_verified_forwarder=True,
                is_server_verified=True,
                connector_id="conn-partner-relay",
                relay_ip="198.51.100.10",
            ),
        )
        assert dec_mismatch_ev.forwarder_exempted is False
        assert dec_mismatch_ev.unverified_indirect_flow_claim_ignored is True
        assert dec_mismatch_ev.disposition == DMARCDisposition.QUARANTINE

        # 7. SMTP_RELAY with missing authenticated provenance (mta_sanitization_guaranteed=False) -> REJECTED
        dec_no_auth = enforcer.enforce(
            dmarc_res,
            spf_result=spf_fail,
            channel=IngestionSource.SMTP_RELAY,
            trusted_smtp_metadata=TrustedSMTPMetadata(
                connecting_ip="198.51.100.10",
                authenticated_connector_id="conn-alumni-relay",
                is_trusted_mta=True,
                mta_sanitization_guaranteed=False,
            ),
            forwarder_evidence=ForwarderTrustEvidence(
                is_verified_forwarder=True,
                is_server_verified=True,
                connector_id="conn-alumni-relay",
                relay_ip="198.51.100.10",
            ),
        )
        assert dec_no_auth.forwarder_exempted is False
        assert dec_no_auth.disposition == DMARCDisposition.QUARANTINE

        # 8. Positive: SMTP_RELAY with authenticated, allowlisted, bound, matching provenance -> ACCEPT + preserves DMARC FAIL/policy
        dec_ok = enforcer.enforce(
            dmarc_res,
            spf_result=spf_fail,
            channel=IngestionSource.SMTP_RELAY,
            trusted_smtp_metadata=TrustedSMTPMetadata(
                connecting_ip="198.51.100.10",
                authenticated_connector_id="conn-alumni-relay",
                is_trusted_mta=True,
                mta_sanitization_guaranteed=True,
            ),
            forwarder_evidence=ForwarderTrustEvidence(
                is_verified_forwarder=True,
                is_server_verified=True,
                connector_id="conn-alumni-relay",
                relay_ip="198.51.100.10",
                evidence_source="verified_relay_connector",
            ),
        )
        assert dec_ok.forwarder_exempted is True
        assert dec_ok.disposition == DMARCDisposition.ACCEPT
        assert dec_ok.dmarc_status == ProtocolStatus.FAIL
        assert dec_ok.selected_applicable_policy == exp_policy
        assert dec_ok.audit_metadata["indirect_flow_evidence"]["connector_id"] == "conn-alumni-relay"
        assert dec_ok.audit_metadata["indirect_flow_evidence"]["relay_ip"] == "198.51.100.10"
        assert dec_ok.local_policy_inputs["indirect_flow_details"]["verified"] is True


@pytest.mark.asyncio
async def test_h2_attestation_authorization_and_domain_separation():
    """H2: Verifies strict actor identity/role/tenant binding on attest_server_rule() and config vs dynamic key separation."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.partner.org", ["v=DMARC1; p=reject"])
    dmarc_fail = await DMARCEvaluator(resolver=resolver).evaluate(
        "partner.org", spf_result=SPFResult(status=ProtocolStatus.FAIL, domain="evil.org", scope="mfrom")
    )

    admin_a = IngestionActor(identity="admin-a@corp.example", role=UserRole.SUPER_ADMIN.value, is_api_key=False, tenant_id="tenant-a")
    admin_other = IngestionActor(identity="other@corp.example", role=UserRole.SUPER_ADMIN.value, is_api_key=False, tenant_id="tenant-a")
    soc_a = IngestionActor(identity="admin-a@corp.example", role=UserRole.SOC_ANALYST.value, is_api_key=False, tenant_id="tenant-a")
    admin_b = IngestionActor(identity="admin-a@corp.example", role=UserRole.SUPER_ADMIN.value, is_api_key=False, tenant_id="tenant-b")
    sys_a = IngestionActor(identity="admin-a@corp.example", role=UserRole.SUPER_ADMIN.value, is_api_key=True, tenant_id="tenant-a")
    sys_agent_a = IngestionActor(identity="collector-1", role=UserRole.SYSTEM_AGENT.value, is_api_key=True, tenant_id="tenant-a")

    rule_a = LocalPolicyOverrideRule(
        rule_id="rule-a",
        action=OverrideRuleAction.EXEMPT_ACCEPT,
        match_from_domain="partner.org",
        tenant_id="tenant-a",
        configured_by_identity="admin-a@corp.example",
        configured_by_role=UserRole.SUPER_ADMIN.value,
        is_authenticated_admin_source=True,
        reason="Approved partner exception",
    )

    srv_rule_a = LocalPolicyOverrideRule(
        rule_id="cfg-rule-a",
        action=OverrideRuleAction.EXEMPT_ACCEPT,
        match_from_domain="partner.org",
        tenant_id="tenant-a",
        configured_by_identity="admin-a@corp.example",
        configured_by_role=UserRole.SUPER_ADMIN.value,
        is_authenticated_admin_source=True,
    )
    untrusted_cfg_entry = LocalPolicyOverrideRule(
        rule_id="bad-cfg-entry",
        action=OverrideRuleAction.EXEMPT_ACCEPT,
        match_from_domain="partner.org",
        tenant_id="tenant-a",
        is_authenticated_admin_source=False,
    )
    enforcer = DMARCPolicyEnforcer(
        config=AuthProtocolsConfig(local_override_rules=[srv_rule_a, untrusted_cfg_entry])
    )

    # 1. authorizing_actor=None cannot attest an interactive rule
    assert enforcer.attest_server_rule(rule_a) is None
    assert enforcer.attest_server_rule(rule_a, authorizing_actor=None) is None

    # 2. Mismatched configured identity -> rejected
    assert enforcer.attest_server_rule(rule_a, authorizing_actor=admin_other) is None

    # 3. Mismatched configured role -> rejected
    assert enforcer.attest_server_rule(rule_a, authorizing_actor=soc_a) is None

    # 4. Cross-tenant actor -> rejected
    assert enforcer.attest_server_rule(rule_a, authorizing_actor=admin_b) is None

    # 5. API-key actor cannot masquerade as interactive administrator
    assert enforcer.attest_server_rule(rule_a, authorizing_actor=sys_a) is None
    assert enforcer.attest_server_rule(rule_a, authorizing_actor=sys_agent_a) is None

    # 6. Valid matching administrator can attest; forged or modified rule invalidates old HMAC
    attested = enforcer.attest_server_rule(rule_a, authorizing_actor=admin_a)
    assert attested is not None and attested.server_provenance_hmac

    bare = DMARCPolicyEnforcer()
    attested_bare = bare.attest_server_rule(rule_a, authorizing_actor=admin_a)
    assert attested_bare is not None

    mutated = attested_bare.model_copy(update={"match_from_domain": "attacker.org"})
    dec_mutated = bare.enforce(dmarc_fail, admin_rules=[mutated], admin_actor=admin_a, tenant_id="tenant-a")
    assert dec_mutated.matched_rule_ids == []

    # Mutating action or reason while still matching target must reject old HMAC explicitly
    mutated_action = attested_bare.model_copy(update={"action": OverrideRuleAction.FORCE_REJECT})
    assert "rule-a" in bare.enforce(dmarc_fail, admin_rules=[mutated_action], admin_actor=admin_a, tenant_id="tenant-a").rejected_unauthenticated_rules

    mutated_reason = attested_bare.model_copy(update={"reason": "Tampered reason"})
    assert "rule-a" in bare.enforce(dmarc_fail, admin_rules=[mutated_reason], admin_actor=admin_a, tenant_id="tenant-a").rejected_unauthenticated_rules

    # Passing internal config-attested rule via untrusted admin_rules= fails domain-separated HMAC check!
    internal_cfg_rule = enforcer._verified_config_rules[0]
    assert "cfg-rule-a" in enforcer.enforce(
        dmarc_fail, admin_rules=[internal_cfg_rule], admin_actor=admin_a, tenant_id="tenant-a"
    ).rejected_unauthenticated_rules
    assert len(enforcer._verified_config_rules) == 1  # untrusted_cfg_entry dropped by internal loader

    # Valid dynamic admin rule works
    assert bare.enforce(dmarc_fail, admin_rules=[attested_bare], admin_actor=admin_a, tenant_id="tenant-a").disposition == DMARCDisposition.ACCEPT

    # Valid SYSTEM_AGENT server-config workflow stays functional
    assert enforcer.enforce(dmarc_fail, admin_actor=sys_agent_a, tenant_id="tenant-a").disposition == DMARCDisposition.ACCEPT


@pytest.mark.asyncio
async def test_m1_post_commit_logger_failure_fingerprints_and_dkim_privacy(db_session, monkeypatch):
    """M1: Tests post-commit logger failure isolation, immediate rollback DB verification, complete fingerprints, and DKIM PII redaction."""
    from app.core.audit import AuditLogger

    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=quarantine"])
    evaluator = DMARCEvaluator(resolver=resolver)
    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="other.org", identity="secret_user@other.org", scope="mfrom")
    spf_softfail = SPFResult(status=ProtocolStatus.SOFTFAIL, domain="other.org", identity="secret_user@other.org", scope="mfrom")
    dkim_sig = DKIMSignatureResult(
        index=0,
        status=ProtocolStatus.FAIL,
        domain="other.org",
        selector="s1",
        identity="alice.private@other.org",
        evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
    )
    dmarc_res = await evaluator.evaluate("example.com", spf_result=spf_fail, dkim_results=[dkim_sig])
    dmarc_res_soft = await evaluator.evaluate("example.com", spf_result=spf_softfail, dkim_results=[dkim_sig])
    enforcer = DMARCPolicyEnforcer()

    admin = _admin_actor(tenant_id="tenant-m1p")
    soc = IngestionActor(identity="secadmin@mailsentra.corp", role=UserRole.SOC_ANALYST.value, is_api_key=False, tenant_id="tenant-m1p")

    dec_fail = enforcer.enforce(dmarc_res, spf_result=spf_fail, dkim_results=[dkim_sig], admin_actor=admin, tenant_id="tenant-m1p")
    dec_soft = enforcer.enforce(dmarc_res_soft, spf_result=spf_softfail, dkim_results=[dkim_sig], admin_actor=admin, tenant_id="tenant-m1p")

    incident = ScanIncident(
        scan_uuid="dddd1111-2222-3333-4444-555566667777",
        sender="secret_user@other.org",
        recipient="victim@example.com",
        subject="M1 Deep",
        status=ScanStatus.COMPLETED,
        tenant_id="tenant-m1p",
        risk_score=0.5,
        risk_tier=RiskTier.SUSPICIOUS,
        telemetry={"initial_marker": True},
    )

    # 1. Verify immediate DB persistence state after rollback BEFORE any retry
    rows_before_rb = (
        await db_session.execute(
            select(AuditRecord).where(AuditRecord.resource_type == "scan_incident")
        )
    ).scalars().all()
    orig_commit = db_session.commit
    async def _fail_commit():
        raise RuntimeError("Simulated DB commit crash")
    monkeypatch.setattr(db_session, "commit", _fail_commit)

    with pytest.raises(RuntimeError, match="Simulated DB commit crash"):
        await record_dmarc_decision_on_incident(
            incident, dmarc_res, dec_fail, spf_result=spf_fail, dkim_results=[dkim_sig], db=db_session, actor=admin
        )
    monkeypatch.setattr(db_session, "commit", orig_commit)

    # Query DB directly immediately after rollback: ZERO new AuditRecord rows or ScanIncident persisted!
    rows_post_rb = (
        await db_session.execute(
            select(AuditRecord).where(AuditRecord.resource_type == "scan_incident")
        )
    ).scalars().all()
    db_inc = (
        await db_session.execute(
            select(ScanIncident).where(ScanIncident.scan_uuid == "dddd1111-2222-3333-4444-555566667777")
        )
    ).scalar_one_or_none()
    assert len(rows_post_rb) == len(rows_before_rb)
    assert not any(
        isinstance(r.details, dict) and r.details.get("scan_uuid") == "dddd1111-2222-3333-4444-555566667777"
        for r in rows_post_rb
    )
    assert db_inc is None  # first insert rolled back cleanly from DB

    # 2. Succeed DB commit while secondary AuditLogger raises -> DB commit preserved + SECONDARY_LOG_FAILED_DB_COMMITTED!
    def _failing_logger(**kwargs):
        raise OSError("LOG_SINK_SECRET_URL unreachable")

    monkeypatch.setattr(AuditLogger, "log_event", staticmethod(_failing_logger))
    tel1 = await record_dmarc_decision_on_incident(
        incident, dmarc_res, dec_fail, spf_result=spf_fail, dkim_results=[dkim_sig], db=db_session, actor=admin, ip_address="198.51.100.1"
    )
    assert tel1["durable_db_persisted"] is True
    assert tel1["audit_delivery_status"] == "SECONDARY_LOG_FAILED_DB_COMMITTED"
    assert "OSError" in (tel1["audit_delivery_error"] or "")
    assert "LOG_SINK_SECRET_URL" not in (tel1["audit_delivery_error"] or "")
    assert tel1["dkim_signatures"][0]["identity"] == "***@other.org"
    assert tel1["dkim_signatures"][0]["domain"] == "other.org"
    assert tel1["dkim_signatures"][0]["selector"] == "s1"
    assert dkim_sig.identity == "alice.private@other.org"  # caller input not mutated!

    # Verify build_dmarc_enforcement_telemetry redacts AuthProtocolsResult nested identities too
    from app.modules.auth_protocols.policy_enforcer import build_dmarc_enforcement_telemetry
    from app.modules.contracts import AuthProtocolsResult
    auth_sum = AuthProtocolsResult(
        spf_details=spf_fail,
        dkim_signatures=[dkim_sig],
        dmarc_details=dmarc_res,
    )
    tel_sum = build_dmarc_enforcement_telemetry(dmarc_res, dec_fail, spf_result=spf_fail, dkim_results=[dkim_sig], auth_result=auth_sum)
    assert tel_sum["auth_protocols_summary"]["spf_details"]["identity"] == "***@other.org"
    assert tel_sum["auth_protocols_summary"]["dkim_signatures"][0]["identity"] == "***@other.org"

    monkeypatch.undo()

    # 3. Verify identical replay deduplicates, while changes in SPF status, IP, or actor role create distinct fingerprints & rows
    tel_dup = await record_dmarc_decision_on_incident(
        incident, dmarc_res, dec_fail, spf_result=spf_fail, dkim_results=[dkim_sig], db=db_session, actor=admin, ip_address="198.51.100.1"
    )
    assert tel_dup["audit_deduplicated"] is True
    assert tel_dup["audit_delivery_status"] == "DELIVERED"

    # Change SPF status (FAIL -> SOFTFAIL) -> distinct fingerprint!
    tel_spf_change = await record_dmarc_decision_on_incident(
        incident, dmarc_res_soft, dec_soft, spf_result=spf_softfail, dkim_results=[dkim_sig], db=db_session, actor=admin, ip_address="198.51.100.1"
    )
    assert tel_spf_change["audit_deduplicated"] is False
    assert tel_spf_change["audit_fingerprint"] != tel1["audit_fingerprint"]

    # Change IP address -> distinct fingerprint!
    tel_ip_change = await record_dmarc_decision_on_incident(
        incident, dmarc_res, dec_fail, spf_result=spf_fail, dkim_results=[dkim_sig], db=db_session, actor=admin, ip_address="198.51.100.99"
    )
    assert tel_ip_change["audit_deduplicated"] is False

    # Change actor role -> distinct fingerprint!
    tel_role_change = await record_dmarc_decision_on_incident(
        incident, dmarc_res, dec_fail, spf_result=spf_fail, dkim_results=[dkim_sig], db=db_session, actor=soc, ip_address="198.51.100.1"
    )
    assert tel_role_change["audit_deduplicated"] is False

    all_rows = (await db_session.execute(select(AuditRecord).where(AuditRecord.resource_id == str(incident.id)))).scalars().all()
    assert len(all_rows) == 4  # initial + spf_change + ip_change + role_change (duplicate suppressed)

