"""Unit tests for DMARC Identifier Alignment and Authentication Evaluator.

Architecture reference: MS-ARCH-SEC-2026-AUTH-PROTOCOLS-REV13
Standards: RFC 9989 (DMARCbis), RFC 7208, RFC 6376, RFC 5322
"""

import pytest

from app.modules.auth_protocols.config import AuthProtocolsConfig
from app.modules.auth_protocols.dns_resolver import (
    DNSQueryType,
    DNSResponseStatus,
    DNSErrorType,
    MockDNSResolver,
)
from app.modules.auth_protocols.evaluators.dmarc import (
    DMARCDiscoveryStatus,
    DMARCEvaluator,
    DMARCRecordDiscovery,
    check_domain_alignment,
)
from app.modules.contracts import (
    AlignmentMode,
    AuthProtocolsResult,
    DKIMSignatureResult,
    DMARCPolicy,
    DMARCResult,
    ProtocolStatus,
    SPFResult,
)


# =============================================================================
# 1. IDENTIFIER ALIGNMENT UNIT TESTS (SPF & DKIM)
# =============================================================================

@pytest.mark.asyncio
async def test_alignment_strict_matching():
    """Verify strict mode requires exact normalized case-insensitive domain match."""
    # Exact match
    aligned, strict, relaxed = await check_domain_alignment("example.com", "example.com", AlignmentMode.STRICT)
    assert aligned is True
    assert strict is True
    assert relaxed is True

    # Case-insensitive
    aligned, strict, relaxed = await check_domain_alignment("EXAMPLE.COM", "example.com", AlignmentMode.STRICT)
    assert aligned is True
    assert strict is True
    assert relaxed is True

    # Subdomain mismatch in strict mode
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    aligned, strict, relaxed = await check_domain_alignment("mail.example.com", "example.com", AlignmentMode.STRICT, resolver=resolver)
    assert aligned is False
    assert strict is False
    assert relaxed is True  # still relaxed aligned


@pytest.mark.asyncio
async def test_alignment_relaxed_matching_dns_derived():
    """Verify relaxed mode determines common Organizational Domain via authoritative RFC 9989 Tree Walk."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])

    # Subdomain to parent
    aligned, strict, relaxed = await check_domain_alignment("mail.example.com", "example.com", AlignmentMode.RELAXED, resolver=resolver)
    assert aligned is True
    assert strict is False
    assert relaxed is True

    # Parent to subdomain
    aligned, strict, relaxed = await check_domain_alignment("example.com", "sub.example.com", AlignmentMode.RELAXED, resolver=resolver)
    assert aligned is True
    assert strict is False
    assert relaxed is True

    # Sibling subdomains
    aligned, strict, relaxed = await check_domain_alignment("mail.example.com", "news.example.com", AlignmentMode.RELAXED, resolver=resolver)
    assert aligned is True
    assert strict is False
    assert relaxed is True

    # Multi-level subdomains
    aligned, strict, relaxed = await check_domain_alignment("a.b.corp.example.com", "dept.example.com", AlignmentMode.RELAXED, resolver=resolver)
    assert aligned is True
    assert strict is False
    assert relaxed is True

    # Complete mismatch across TLDs
    aligned, strict, relaxed = await check_domain_alignment("example.org", "example.com", AlignmentMode.RELAXED, resolver=resolver)
    assert aligned is False
    assert strict is False
    assert relaxed is False


@pytest.mark.asyncio
async def test_alignment_with_psd_organizational_domain_hint():
    """Verify alignment check respects PSD-discovered Organizational Domain boundary via DNS."""
    resolver = MockDNSResolver()
    # gov.uk is a PSD with psd=y
    resolver.add_txt("_dmarc.gov.uk", ["v=DMARC1; p=reject; psd=y"])

    # Child of the same PSD Org Domain (dept.gov.uk)
    aligned, strict, relaxed = await check_domain_alignment(
        "mail.dept.gov.uk", "portal.dept.gov.uk", AlignmentMode.RELAXED, resolver=resolver
    )
    assert aligned is True
    assert strict is False
    assert relaxed is True

    # Outside the PSD Org Domain (other.gov.uk vs portal.dept.gov.uk)
    aligned, strict, relaxed = await check_domain_alignment(
        "other.gov.uk", "portal.dept.gov.uk", AlignmentMode.RELAXED, resolver=resolver
    )
    assert aligned is False
    assert strict is False
    assert relaxed is False


@pytest.mark.asyncio
async def test_alignment_empty_or_malformed_inputs():
    """Verify alignment safely handles empty or None domains."""
    res1 = await check_domain_alignment(None, "example.com", AlignmentMode.RELAXED)
    assert (res1[0], res1[1], res1[2]) == (False, False, False)

    res2 = await check_domain_alignment("example.com", None, AlignmentMode.RELAXED)
    assert (res2[0], res2[1], res2[2]) == (False, False, False)

    res3 = await check_domain_alignment("", "example.com", AlignmentMode.RELAXED)
    assert (res3[0], res3[1], res3[2]) == (False, False, False)

    res4 = await check_domain_alignment("example.com", "", AlignmentMode.RELAXED)
    assert (res4[0], res4[1], res4[2]) == (False, False, False)


# =============================================================================
# 2. SPF ALIGNMENT SCENARIOS
# =============================================================================

@pytest.mark.asyncio
async def test_dmarc_spf_strict_alignment_success():
    """Verify SPF strict alignment passes when spf_domain exactly matches From domain."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=s"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf_res = SPFResult(status=ProtocolStatus.PASS, domain="example.com", scope="mfrom")
    res = await evaluator.evaluate(from_domain="example.com", spf_result=spf_res)

    assert res.status == ProtocolStatus.PASS
    assert res.spf_aligned is True
    assert res.spf_aligned_strict is True
    assert res.spf_aligned_relaxed is True
    assert res.spf_alignment_mode == AlignmentMode.STRICT


@pytest.mark.asyncio
async def test_dmarc_spf_strict_alignment_mismatch():
    """Verify SPF strict alignment fails when spf_domain is a subdomain of From domain."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=s"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf_res = SPFResult(status=ProtocolStatus.PASS, domain="mail.example.com", scope="mfrom")
    res = await evaluator.evaluate(from_domain="example.com", spf_result=spf_res)

    # In strict mode, mail.example.com != example.com -> unaligned -> DMARC FAIL
    assert res.status == ProtocolStatus.FAIL
    assert res.spf_aligned is False
    assert res.spf_aligned_strict is False
    assert res.spf_aligned_relaxed is True
    assert res.spf_alignment_mode == AlignmentMode.STRICT


@pytest.mark.asyncio
async def test_dmarc_spf_relaxed_alignment_success():
    """Verify SPF relaxed alignment passes when domains share common Org Domain."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=r"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf_res = SPFResult(status=ProtocolStatus.PASS, domain="mail.example.com", scope="mfrom")
    res = await evaluator.evaluate(from_domain="example.com", spf_result=spf_res)

    assert res.status == ProtocolStatus.PASS
    assert res.spf_aligned is True
    assert res.spf_aligned_strict is False
    assert res.spf_aligned_relaxed is True
    assert res.spf_alignment_mode == AlignmentMode.RELAXED


@pytest.mark.asyncio
async def test_dmarc_spf_relaxed_alignment_mismatch():
    """Verify SPF relaxed alignment fails when domains have different Org Domains."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=r"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf_res = SPFResult(status=ProtocolStatus.PASS, domain="mail.otherdomain.com", scope="mfrom")
    res = await evaluator.evaluate(from_domain="example.com", spf_result=spf_res)

    assert res.status == ProtocolStatus.FAIL
    assert res.spf_aligned is False
    assert res.spf_aligned_relaxed is False


@pytest.mark.asyncio
async def test_dmarc_spf_non_pass_statuses_never_align():
    """Verify SPF non-PASS results never align and preserve completed vs incomplete/transient semantics (C1 & C2)."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    # Completed SPF failures with absent DKIM yield DMARC FAIL per RFC 9989 §5.3.5
    completed_fail_statuses = [
        ProtocolStatus.FAIL,
        ProtocolStatus.SOFTFAIL,
        ProtocolStatus.NEUTRAL,
        ProtocolStatus.NONE,
        ProtocolStatus.PERMERROR,
    ]
    for st in completed_fail_statuses:
        spf_res = SPFResult(status=st, domain="example.com", scope="mfrom")
        res = await evaluator.evaluate(from_domain="example.com", spf_result=spf_res)
        assert res.status == ProtocolStatus.FAIL, f"Expected DMARC FAIL for completed SPF {st.value}"
        assert res.standard_status == "fail"
        assert res.rfc_status == "fail"
        assert res.spf_aligned is False
        assert res.spf_aligned_strict is False
        assert res.spf_aligned_relaxed is False

    # Transient SPF DNS error with no aligned PASS yields DMARC TEMPERROR (RFC 9989 §5.3.6 & §9.2)
    res_temp = await evaluator.evaluate(
        from_domain="example.com",
        spf_result=SPFResult(status=ProtocolStatus.TEMPERROR, domain="example.com", scope="mfrom"),
    )
    assert res_temp.status == ProtocolStatus.TEMPERROR
    assert res_temp.standard_status == "temperror"
    assert res_temp.rfc_status == "temperror"
    assert res_temp.spf_aligned is False

    # Incomplete SPF states (NOT_EVALUATED, INDETERMINATE) with no aligned PASS yield INDETERMINATE (C1 safety rule)
    for st in (ProtocolStatus.NOT_EVALUATED, ProtocolStatus.INDETERMINATE):
        res_indet = await evaluator.evaluate(
            from_domain="example.com",
            spf_result=SPFResult(status=st, domain="example.com", scope="mfrom"),
        )
        assert res_indet.status == ProtocolStatus.INDETERMINATE
        assert res_indet.standard_status is None
        assert res_indet.rfc_status is None
        assert res_indet.spf_aligned is False


@pytest.mark.asyncio
async def test_dmarc_spf_null_reverse_path_helo_alignment():
    """Verify RFC 9989 Section 4.4.2 & RFC 7208 Section 2.4: authenticated HELO identity aligns for null bounce."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=r"])
    evaluator = DMARCEvaluator(resolver=resolver)

    # Bounce message: scope='helo', authenticated domain is outbox.example.com
    spf_res = SPFResult(
        status=ProtocolStatus.PASS,
        domain="outbox.example.com",
        scope="helo",
        is_null_reverse_path=True,
        is_synthesized_mfrom=True,
    )
    res = await evaluator.evaluate(from_domain="example.com", spf_result=spf_res)

    assert res.status == ProtocolStatus.PASS
    assert res.spf_aligned is True
    assert res.spf_aligned_relaxed is True


# =============================================================================
# 3. DKIM ALIGNMENT SCENARIOS
# =============================================================================

@pytest.mark.asyncio
async def test_dmarc_dkim_strict_alignment_success():
    """Verify DKIM strict alignment passes when d= exactly matches From domain."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; adkim=s"])
    evaluator = DMARCEvaluator(resolver=resolver)

    dkim_res = [
        DKIMSignatureResult(status=ProtocolStatus.PASS, domain="example.com", selector="s1")
    ]
    res = await evaluator.evaluate(from_domain="example.com", dkim_results=dkim_res)

    assert res.status == ProtocolStatus.PASS
    assert res.dkim_aligned is True
    assert res.dkim_aligned_strict is True
    assert res.dkim_aligned_relaxed is True
    assert res.dkim_alignment_mode == AlignmentMode.STRICT


@pytest.mark.asyncio
async def test_dmarc_dkim_strict_alignment_mismatch():
    """Verify DKIM strict alignment fails when d= is a subdomain in strict mode."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; adkim=s"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf_res = SPFResult(status=ProtocolStatus.NONE, domain=None, scope="mfrom")
    dkim_res = [
        DKIMSignatureResult(status=ProtocolStatus.PASS, domain="mail.example.com", selector="s1")
    ]
    res = await evaluator.evaluate(from_domain="example.com", spf_result=spf_res, dkim_results=dkim_res)

    assert res.status == ProtocolStatus.FAIL
    assert res.dkim_aligned is False
    assert res.dkim_aligned_strict is False
    assert res.dkim_aligned_relaxed is True

    # Under C1 safety model, unaligned DKIM alone without SPF evaluation remains INDETERMINATE
    res_no_spf = await evaluator.evaluate(from_domain="example.com", dkim_results=dkim_res)
    assert res_no_spf.status == ProtocolStatus.INDETERMINATE
    assert res_no_spf.rfc_status is None
    assert res_no_spf.dkim_aligned is False
    assert res_no_spf.dkim_aligned_relaxed is True


@pytest.mark.asyncio
async def test_dmarc_dkim_relaxed_alignment_success():
    """Verify DKIM relaxed alignment passes when d= shares common Org Domain."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; adkim=r"])
    evaluator = DMARCEvaluator(resolver=resolver)

    dkim_res = [
        DKIMSignatureResult(status=ProtocolStatus.PASS, domain="mail.example.com", selector="s1")
    ]
    res = await evaluator.evaluate(from_domain="example.com", dkim_results=dkim_res)

    assert res.status == ProtocolStatus.PASS
    assert res.dkim_aligned is True
    assert res.dkim_aligned_strict is False
    assert res.dkim_aligned_relaxed is True


@pytest.mark.asyncio
async def test_dmarc_dkim_multiple_signatures_one_aligned_is_sufficient():
    """Verify RFC 9989 Section 4.4.1: at least one valid, aligned signature produces DKIM alignment."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; adkim=r"])
    evaluator = DMARCEvaluator(resolver=resolver)

    # Sig 0: Third party ESP (PASS, unaligned)
    # Sig 1: Failed signature (PERMERROR, matching domain)
    # Sig 2: Domain Owner signature (PASS, aligned)
    dkim_res = [
        DKIMSignatureResult(index=0, status=ProtocolStatus.PASS, domain="sendgrid.net", selector="s1"),
        DKIMSignatureResult(index=1, status=ProtocolStatus.PERMERROR, domain="example.com", selector="s2"),
        DKIMSignatureResult(index=2, status=ProtocolStatus.PASS, domain="sub.example.com", selector="s3"),
    ]
    res = await evaluator.evaluate(from_domain="example.com", dkim_results=dkim_res)

    assert res.status == ProtocolStatus.PASS
    assert res.dkim_aligned is True
    assert dkim_res[0].is_aligned_with_from is False
    assert dkim_res[1].is_aligned_with_from is False
    assert dkim_res[2].is_aligned_with_from is True


@pytest.mark.asyncio
async def test_dmarc_dkim_all_signatures_fail():
    """Verify DKIM failure outcomes distinguish completed permanent failure vs transient TEMPERROR (C2)."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)
    spf_none = SPFResult(status=ProtocolStatus.NONE, domain=None, scope="mfrom")

    # Permanent failures (PERMERROR, FAIL) with completed non-passing SPF -> DMARC FAIL
    dkim_perm_fail = [
        DKIMSignatureResult(status=ProtocolStatus.PERMERROR, domain="example.com", selector="s1"),
        DKIMSignatureResult(status=ProtocolStatus.FAIL, domain="example.com", selector="s2"),
    ]
    res_fail = await evaluator.evaluate(
        from_domain="example.com", spf_result=spf_none, dkim_results=dkim_perm_fail
    )
    assert res_fail.status == ProtocolStatus.FAIL
    assert res_fail.standard_status == "fail"
    assert res_fail.dkim_aligned is False

    # Including TEMPERROR unrescued by aligned PASS -> DMARC TEMPERROR per RFC 9989 §5.3.6 & §9.2 (C2)
    dkim_with_temp = dkim_perm_fail + [
        DKIMSignatureResult(status=ProtocolStatus.TEMPERROR, domain="example.com", selector="s3"),
    ]
    res_temp = await evaluator.evaluate(
        from_domain="example.com", spf_result=spf_none, dkim_results=dkim_with_temp
    )
    assert res_temp.status == ProtocolStatus.TEMPERROR
    assert res_temp.standard_status == "temperror"
    assert res_temp.dkim_aligned is False


@pytest.mark.asyncio
async def test_dmarc_dkim_no_signatures():
    """Verify unsigned messages fail when SPF completed non-passing, and stay INDETERMINATE when SPF is NOT_EVALUATED."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf_none = SPFResult(status=ProtocolStatus.NONE, domain=None, scope="mfrom")
    res_fail = await evaluator.evaluate(from_domain="example.com", spf_result=spf_none, dkim_results=[])
    assert res_fail.status == ProtocolStatus.FAIL
    assert res_fail.dkim_aligned is False

    res_indet = await evaluator.evaluate(
        from_domain="example.com",
        spf_result=SPFResult(status=ProtocolStatus.NOT_EVALUATED),
        dkim_results=[],
    )
    assert res_indet.status == ProtocolStatus.INDETERMINATE
    assert res_indet.rfc_status is None
    assert res_indet.dkim_aligned is False


# =============================================================================
# 4. DMARC EVALUATION MATRIX & COMBINATIONS
# =============================================================================

@pytest.mark.asyncio
async def test_dmarc_matrix_spf_pass_aligned_dkim_fail():
    """Matrix: SPF PASS & aligned, DKIM FAIL -> DMARC PASS."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf = SPFResult(status=ProtocolStatus.PASS, domain="example.com")
    dkim = [DKIMSignatureResult(status=ProtocolStatus.FAIL, domain="example.com")]

    res = await evaluator.evaluate("example.com", spf_result=spf, dkim_results=dkim)
    assert res.status == ProtocolStatus.PASS
    assert res.spf_aligned is True
    assert res.dkim_aligned is False


@pytest.mark.asyncio
async def test_dmarc_matrix_dkim_pass_aligned_spf_fail():
    """Matrix: DKIM PASS & aligned, SPF FAIL -> DMARC PASS."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf = SPFResult(status=ProtocolStatus.FAIL, domain="example.com")
    dkim = [DKIMSignatureResult(status=ProtocolStatus.PASS, domain="example.com")]

    res = await evaluator.evaluate("example.com", spf_result=spf, dkim_results=dkim)
    assert res.status == ProtocolStatus.PASS
    assert res.spf_aligned is False
    assert res.dkim_aligned is True


@pytest.mark.asyncio
async def test_dmarc_matrix_both_pass_and_aligned():
    """Matrix: Both SPF and DKIM PASS & aligned -> DMARC PASS."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf = SPFResult(status=ProtocolStatus.PASS, domain="example.com")
    dkim = [DKIMSignatureResult(status=ProtocolStatus.PASS, domain="example.com")]

    res = await evaluator.evaluate("example.com", spf_result=spf, dkim_results=dkim)
    assert res.status == ProtocolStatus.PASS
    assert res.spf_aligned is True
    assert res.dkim_aligned is True


@pytest.mark.asyncio
async def test_dmarc_matrix_both_pass_but_neither_aligned():
    """Matrix: Both SPF and DKIM PASS on third-party domains (unaligned) -> DMARC FAIL."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf = SPFResult(status=ProtocolStatus.PASS, domain="esp-mail.net")
    dkim = [DKIMSignatureResult(status=ProtocolStatus.PASS, domain="esp-mail.net")]

    res = await evaluator.evaluate("example.com", spf_result=spf, dkim_results=dkim)
    assert res.status == ProtocolStatus.FAIL
    assert res.spf_aligned is False
    assert res.dkim_aligned is False


@pytest.mark.asyncio
async def test_dmarc_matrix_both_fail():
    """Matrix: Both SPF and DKIM FAIL -> DMARC FAIL."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf = SPFResult(status=ProtocolStatus.FAIL, domain="example.com")
    dkim = [DKIMSignatureResult(status=ProtocolStatus.FAIL, domain="example.com")]

    res = await evaluator.evaluate("example.com", spf_result=spf, dkim_results=dkim)
    assert res.status == ProtocolStatus.FAIL


@pytest.mark.asyncio
async def test_dmarc_p_none_policy_does_not_convert_fail_to_pass():
    """Verify critical semantic requirement: p=none is the Domain Owner policy,
    it does NOT convert an authentication failure into a PASS result."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=none"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf = SPFResult(status=ProtocolStatus.FAIL, domain="example.com")
    dkim = [DKIMSignatureResult(status=ProtocolStatus.FAIL, domain="example.com")]

    res = await evaluator.evaluate("example.com", spf_result=spf, dkim_results=dkim)
    assert res.status == ProtocolStatus.FAIL  # Authentication status is FAIL!
    assert res.policy == DMARCPolicy.NONE    # Policy is NONE


@pytest.mark.asyncio
async def test_dmarc_independent_mode_enforcement():
    """Verify adkim=s (strict) and aspf=r (relaxed) are independently enforced."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=r; adkim=s"])
    evaluator = DMARCEvaluator(resolver=resolver)

    # Subdomain mail.example.com aligns under aspf=r, but fails under adkim=s
    spf = SPFResult(status=ProtocolStatus.PASS, domain="mail.example.com")
    dkim = [DKIMSignatureResult(status=ProtocolStatus.PASS, domain="mail.example.com")]

    res = await evaluator.evaluate("example.com", spf_result=spf, dkim_results=dkim)
    assert res.status == ProtocolStatus.PASS
    assert res.spf_aligned is True            # relaxed mode accepted subdomain
    assert res.dkim_aligned is False          # strict mode rejected subdomain
    assert res.spf_alignment_mode == AlignmentMode.RELAXED
    assert res.dkim_alignment_mode == AlignmentMode.STRICT


# =============================================================================
# 5. POLICY SELECTION & DISCOVERY ERROR HANDLING
# =============================================================================

@pytest.mark.asyncio
async def test_dmarc_no_policy_record_returns_none():
    """Verify missing DMARC record returns ProtocolStatus.NONE and NOT_CONFIGURED policy."""
    resolver = MockDNSResolver()  # No TXT records
    evaluator = DMARCEvaluator(resolver=resolver)

    res = await evaluator.evaluate("example.com")
    assert res.status == ProtocolStatus.NONE
    assert res.policy == DMARCPolicy.NOT_CONFIGURED


@pytest.mark.asyncio
async def test_dmarc_discovery_temperror_preserved():
    """Verify DNS query timeout during discovery maps to TEMPERROR."""
    resolver = MockDNSResolver()
    resolver.set_error(
        "_dmarc.timeout.com",
        status=DNSResponseStatus.TIMEOUT,
        error_type=DNSErrorType.TIMEOUT,
        query_type=DNSQueryType.TXT,
    )
    evaluator = DMARCEvaluator(resolver=resolver)

    res = await evaluator.evaluate("timeout.com")
    assert res.status == ProtocolStatus.TEMPERROR
    assert res.policy == DMARCPolicy.NOT_CONFIGURED


@pytest.mark.asyncio
async def test_dmarc_discovery_permerror_preserved():
    """Verify permanent discovery error (e.g. malformed record without rua) maps to PERMERROR."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.bad.com", ["v=DMARC1; p=invalid_policy"])
    evaluator = DMARCEvaluator(resolver=resolver)

    res = await evaluator.evaluate("bad.com")
    assert res.status == ProtocolStatus.PERMERROR
    assert res.policy == DMARCPolicy.NOT_CONFIGURED


@pytest.mark.asyncio
async def test_dmarc_subdomain_policy_sp_applied_for_subdomain():
    """Verify subdomain applies sp policy over p policy."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; sp=quarantine"])
    evaluator = DMARCEvaluator(resolver=resolver)

    # Subdomain with authentication failure
    spf = SPFResult(status=ProtocolStatus.FAIL, domain="mail.example.com")
    res = await evaluator.evaluate("mail.example.com", spf_result=spf)

    assert res.status == ProtocolStatus.FAIL
    assert res.policy == DMARCPolicy.QUARANTINE  # Subdomain policy sp took precedence
    assert res.subdomain_policy == DMARCPolicy.QUARANTINE


@pytest.mark.asyncio
async def test_dmarc_missing_or_malformed_from_domain():
    """Verify missing or malformed From domain returns PERMERROR."""
    resolver = MockDNSResolver()
    evaluator = DMARCEvaluator(resolver=resolver)

    res_none = await evaluator.evaluate(None)
    assert res_none.status == ProtocolStatus.PERMERROR

    res_empty = await evaluator.evaluate("")
    assert res_empty.status == ProtocolStatus.PERMERROR

    res_no_tld = await evaluator.evaluate("localhost")
    assert res_no_tld.status == ProtocolStatus.PERMERROR


@pytest.mark.asyncio
async def test_dmarc_email_address_format_extracted_safely():
    """Verify email address strings passed as from_domain are cleanly extracted."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf = SPFResult(status=ProtocolStatus.PASS, domain="example.com")
    res = await evaluator.evaluate("<user@example.com>", spf_result=spf)

    assert res.status == ProtocolStatus.PASS
    assert res.from_domain == "example.com"
    assert res.spf_aligned is True


@pytest.mark.asyncio
async def test_dmarc_psd_policy_applied_with_authentication_evaluation():
    """Verify PSD policy discovered in Step 3.7.1 is integrated with authentication evaluation."""
    resolver = MockDNSResolver()
    # gov.uk is a PSD with psd=y
    resolver.add_txt("_dmarc.gov.uk", ["v=DMARC1; p=reject; psd=y"])
    evaluator = DMARCEvaluator(resolver=resolver)

    # Department subdomain with aligned SPF
    spf = SPFResult(status=ProtocolStatus.PASS, domain="dept.gov.uk")
    res = await evaluator.evaluate("dept.gov.uk", spf_result=spf)

    assert res.status == ProtocolStatus.PASS
    assert res.org_domain == "dept.gov.uk"
    assert res.psd_type == "y"
    assert res.spf_aligned is True


@pytest.mark.asyncio
async def test_dmarc_evaluate_auth_protocols_integration():
    """Verify evaluate_auth_protocols directly updates AuthProtocolsResult container."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=quarantine; aspf=r; adkim=r"])
    evaluator = DMARCEvaluator(resolver=resolver)

    auth_container = AuthProtocolsResult(
        spf_status=ProtocolStatus.PASS,
        spf_domain="mail.example.com",
        spf_details=SPFResult(status=ProtocolStatus.PASS, domain="mail.example.com"),
        dkim_status=ProtocolStatus.PASS,
        dkim_signatures=[
            DKIMSignatureResult(status=ProtocolStatus.PASS, domain="mail.example.com")
        ],
    )

    dmarc_res = await evaluator.evaluate_auth_protocols("example.com", auth_container)

    assert dmarc_res.status == ProtocolStatus.PASS
    assert auth_container.dmarc_status == ProtocolStatus.PASS
    assert auth_container.dmarc_policy == DMARCPolicy.QUARANTINE
    assert auth_container.dmarc_aligned_spf is True
    assert auth_container.dmarc_aligned_dkim is True
    assert auth_container.dmarc_details is not None


# =============================================================================
# 6. RFC 9989 STEP 3.7.2A: ORGANIZATIONAL DOMAIN & ERROR HANDLING TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_alignment_idn_unicode_uts46():
    """Verify internationalized domain names (IDNs) normalize via UTS #46 before alignment."""
    resolver = MockDNSResolver()
    # Punycode for bücher.example is xn--bcher-kva.example
    resolver.add_txt("_dmarc.xn--bcher-kva.example", ["v=DMARC1; p=reject"])

    # Both Unicode and Punycode forms should align
    aligned, strict, relaxed = await check_domain_alignment(
        "mail.xn--bcher-kva.example", "bücher.example", AlignmentMode.RELAXED, resolver=resolver
    )
    assert aligned is True
    assert relaxed is True


@pytest.mark.asyncio
async def test_alignment_psd_different_org_domains_below_psd():
    """Verify domains under different Org Domains below a PSD do not align."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.gov.uk", ["v=DMARC1; p=reject; psd=y"])

    # dept-a.gov.uk and dept-b.gov.uk are separate Org Domains below PSD gov.uk
    aligned, strict, relaxed = await check_domain_alignment(
        "sub.dept-a.gov.uk", "mail.dept-b.gov.uk", AlignmentMode.RELAXED, resolver=resolver
    )
    assert aligned is False
    assert strict is False
    assert relaxed is False


@pytest.mark.asyncio
async def test_alignment_intermediate_candidate_below_psd():
    """Verify intermediate candidate below PSD defines the Org Domain boundary."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.dept-a.gov.uk", ["v=DMARC1; p=quarantine; psd=u"])
    resolver.add_txt("_dmarc.gov.uk", ["v=DMARC1; p=reject; psd=y"])

    # Both subdomains share the candidate Org Domain dept-a.gov.uk
    aligned, strict, relaxed = await check_domain_alignment(
        "mail.dept-a.gov.uk", "portal.dept-a.gov.uk", AlignmentMode.RELAXED, resolver=resolver
    )
    assert aligned is True
    assert relaxed is True


@pytest.mark.asyncio
async def test_dmarc_spf_dns_failure_during_alignment():
    """Verify DNS timeout during SPF identifier Org Domain tree walk yields TEMPERROR, not FAIL."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=r"])
    # DNS timeout when resolving SPF domain's DMARC tree
    resolver.set_error(
        "_dmarc.mail.example.com",
        status=DNSResponseStatus.TIMEOUT,
        error_type=DNSErrorType.TIMEOUT,
        query_type=DNSQueryType.TXT,
    )
    evaluator = DMARCEvaluator(resolver=resolver)

    spf = SPFResult(status=ProtocolStatus.PASS, domain="mail.example.com", scope="mfrom")
    res = await evaluator.evaluate("example.com", spf_result=spf)

    # Must NOT silently fail; transient DNS error yields TEMPERROR per RFC 9989 §9.2
    assert res.status == ProtocolStatus.TEMPERROR
    assert res.spf_aligned is False


@pytest.mark.asyncio
async def test_dmarc_spf_query_limit_exhausted_during_alignment():
    """Verify query limit exhaustion during SPF alignment yields INDETERMINATE."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=r"])
    # 10-label domain with no records: requires > 8 queries to traverse
    deep_domain = "l1.l2.l3.l4.l5.l6.l7.l8.otherdomain.com"
    evaluator = DMARCEvaluator(resolver=resolver)

    spf = SPFResult(status=ProtocolStatus.PASS, domain=deep_domain, scope="mfrom")
    res = await evaluator.evaluate("example.com", spf_result=spf)

    assert res.status == ProtocolStatus.INDETERMINATE
    assert res.spf_aligned is False


@pytest.mark.asyncio
async def test_dmarc_spf_missing_domain_identifier():
    """Verify SPFResult with missing/empty domain never aligns."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf = SPFResult(status=ProtocolStatus.PASS, domain=None, scope="mfrom")
    res = await evaluator.evaluate("example.com", spf_result=spf)

    assert res.status == ProtocolStatus.FAIL
    assert res.spf_aligned is False


@pytest.mark.asyncio
async def test_dmarc_spf_null_reverse_path_no_helo_fails():
    """Verify bounce message with null reverse-path and no HELO identity fails alignment."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    # When HELO identity was missing during null reverse-path SPF check
    spf = SPFResult(status=ProtocolStatus.NONE, domain=None, scope="helo")
    res = await evaluator.evaluate("example.com", spf_result=spf)

    assert res.status == ProtocolStatus.FAIL
    assert res.spf_aligned is False


@pytest.mark.asyncio
async def test_dmarc_dkim_dns_failure_during_alignment():
    """Verify DNS timeout during DKIM d= Org Domain tree walk yields TEMPERROR."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; adkim=r"])
    resolver.set_error(
        "_dmarc.mail.example.com",
        status=DNSResponseStatus.TIMEOUT,
        error_type=DNSErrorType.TIMEOUT,
        query_type=DNSQueryType.TXT,
    )
    evaluator = DMARCEvaluator(resolver=resolver)

    dkim = [DKIMSignatureResult(status=ProtocolStatus.PASS, domain="mail.example.com")]
    res = await evaluator.evaluate("example.com", dkim_results=dkim)

    assert res.status == ProtocolStatus.TEMPERROR
    assert res.dkim_aligned is False


@pytest.mark.asyncio
async def test_dmarc_dkim_dns_failure_with_other_aligned_dkim_passes():
    """Verify that if one DKIM signature has a DNS failure, but another is aligned, DMARC passes."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; adkim=r"])
    resolver.set_error(
        "_dmarc.other.example.com",
        status=DNSResponseStatus.TIMEOUT,
        error_type=DNSErrorType.TIMEOUT,
        query_type=DNSQueryType.TXT,
    )
    evaluator = DMARCEvaluator(resolver=resolver)

    dkim = [
        # Sig 0: encounters DNS timeout during tree walk
        DKIMSignatureResult(index=0, status=ProtocolStatus.PASS, domain="other.example.com"),
        # Sig 1: strictly aligned domain (example.com == example.com)
        DKIMSignatureResult(index=1, status=ProtocolStatus.PASS, domain="example.com"),
    ]
    res = await evaluator.evaluate("example.com", dkim_results=dkim)

    # Passing aligned signature fulfills DMARC authentication
    assert res.status == ProtocolStatus.PASS
    assert res.dkim_aligned is True


@pytest.mark.asyncio
async def test_dmarc_dkim_missing_d_domain():
    """Verify DKIM signature missing domain (d=) never aligns."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf_none = SPFResult(status=ProtocolStatus.NONE, domain=None, scope="mfrom")
    dkim = [DKIMSignatureResult(status=ProtocolStatus.PASS, domain=None)]
    res = await evaluator.evaluate("example.com", spf_result=spf_none, dkim_results=dkim)

    assert res.status == ProtocolStatus.FAIL
    assert res.dkim_aligned is False


@pytest.mark.asyncio
async def test_dmarc_matrix_spf_temperror_dkim_aligned_pass():
    """Verify RFC 9989 Section 5.3.5: DKIM PASS & aligned overrides SPF TEMPERROR."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=r; adkim=s"])
    resolver.set_error(
        "_dmarc.mail.example.com",
        status=DNSResponseStatus.TIMEOUT,
        error_type=DNSErrorType.TIMEOUT,
        query_type=DNSQueryType.TXT,
    )
    evaluator = DMARCEvaluator(resolver=resolver)

    spf = SPFResult(status=ProtocolStatus.PASS, domain="mail.example.com")
    dkim = [DKIMSignatureResult(status=ProtocolStatus.PASS, domain="example.com")]

    res = await evaluator.evaluate("example.com", spf_result=spf, dkim_results=dkim)

    assert res.status == ProtocolStatus.PASS
    assert res.spf_aligned is False
    assert res.dkim_aligned is True


@pytest.mark.asyncio
async def test_dmarc_tree_walk_nine_query_blocked():
    """Verify 8-query limit is enforced and 9th query is blocked during tree walk."""
    resolver = MockDNSResolver()
    discovery = DMARCRecordDiscovery(resolver=resolver)

    # 10-label domain: 1.2.3.4.5.6.7.8.example.com
    deep_domain = "l1.l2.l3.l4.l5.l6.l7.l8.example.com"
    res = await discovery.discover(deep_domain)

    assert res.status == DMARCDiscoveryStatus.LIMIT_EXCEEDED
    assert res.tree_walk_queries == 8


@pytest.mark.asyncio
async def test_dmarc_tree_walk_dns_error_distinctions():
    """Verify DNS error distinctions (NXDOMAIN, NODATA, SERVFAIL, TIMEOUT) during tree walk."""
    resolver = MockDNSResolver()
    discovery = DMARCRecordDiscovery(resolver=resolver)

    # 1. TIMEOUT -> TEMPERROR
    resolver.set_error(
        "_dmarc.timeout.test",
        status=DNSResponseStatus.TIMEOUT,
        error_type=DNSErrorType.TIMEOUT,
        query_type=DNSQueryType.TXT,
    )
    res_timeout = await discovery.discover("timeout.test")
    assert res_timeout.status == DMARCDiscoveryStatus.TEMPERROR

    # 2. SERVFAIL -> TEMPERROR
    resolver.set_error(
        "_dmarc.servfail.test",
        status=DNSResponseStatus.SERVFAIL,
        error_type=DNSErrorType.SERVFAIL,
        query_type=DNSQueryType.TXT,
    )
    res_servfail = await discovery.discover("servfail.test")
    assert res_servfail.status == DMARCDiscoveryStatus.TEMPERROR

    # 3. NODATA / VOID -> ABSENT (when tree walk exhausts without error)
    res_absent = await discovery.discover("nodata.test")
    assert res_absent.status == DMARCDiscoveryStatus.ABSENT


# =============================================================================
# 11. STEP 3.7.2B COMPLIANCE AUDIT TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_dmarc_audit1_author_domain_record_does_not_mask_org_domain():
    """Audit 1: Record at Author Domain does not make it the Org Domain under RFC 9989 §4.10.1 vs §4.10.2."""
    resolver = MockDNSResolver()
    # mail.example.com publishes DMARC record without psd=n (defaults to psd=u)
    resolver.add_txt("_dmarc.mail.example.com", ["v=DMARC1; p=none; aspf=r; adkim=r"])
    # example.com publishes DMARC record
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=r; adkim=r"])

    evaluator = DMARCEvaluator(resolver=resolver)

    # Policy discovery for mail.example.com discovers p=none at mail.example.com (RFC 9989 §4.10.1)
    disc = await evaluator.discovery.discover("mail.example.com")
    assert disc.status == DMARCDiscoveryStatus.FOUND
    assert disc.discovered_domain == "mail.example.com"
    assert disc.tags["p"] == "none"

    # For relaxed identifier alignment (RFC 9989 §4.10.2), Org Domain of mail.example.com is example.com (Rule 3)
    org_dom, status, _ = await evaluator.discovery.determine_org_domain("mail.example.com")
    assert org_dom == "example.com"
    assert status == DMARCDiscoveryStatus.FOUND

    # DKIM signature with d=marketing.example.com aligns relaxed with From: user@mail.example.com
    dkim_sig = DKIMSignatureResult(status=ProtocolStatus.PASS, domain="marketing.example.com")
    res = await evaluator.evaluate("mail.example.com", dkim_results=[dkim_sig])

    assert res.status == ProtocolStatus.PASS
    assert res.dkim_aligned is True
    assert res.dkim_aligned_relaxed is True
    assert res.policy == DMARCPolicy.NONE  # discovered from mail.example.com
    assert res.org_domain == "example.com"  # RFC 9989 §4.10.2 Org Domain
    assert res.rfc_status == "pass"


@pytest.mark.asyncio
async def test_dmarc_audit1_author_domain_with_psd_n_is_its_own_org_domain():
    """Audit 1: Record at Author Domain with psd=n terminates tree walk as Org Domain (RFC 9989 §4.10.2 Rule 1)."""
    resolver = MockDNSResolver()
    # mail.example.com explicitly publishes psd=n
    resolver.add_txt("_dmarc.mail.example.com", ["v=DMARC1; p=none; psd=n; adkim=r"])
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; adkim=r"])

    evaluator = DMARCEvaluator(resolver=resolver)

    org_dom, status, _ = await evaluator.discovery.determine_org_domain("mail.example.com")
    assert org_dom == "mail.example.com"
    assert status == DMARCDiscoveryStatus.FOUND

    # marketing.example.com (Org Domain example.com) does NOT align with mail.example.com (Org Domain mail.example.com)
    spf_none = SPFResult(status=ProtocolStatus.NONE, domain=None, scope="mfrom")
    dkim_sig = DKIMSignatureResult(status=ProtocolStatus.PASS, domain="marketing.example.com")
    res = await evaluator.evaluate("mail.example.com", spf_result=spf_none, dkim_results=[dkim_sig])

    assert res.status == ProtocolStatus.FAIL
    assert res.dkim_aligned is False
    assert res.org_domain == "mail.example.com"
    assert res.rfc_status == "fail"


@pytest.mark.asyncio
async def test_dmarc_audit1_determine_org_domain_direct_cases():
    """Audit 1: Comprehensive verification of RFC 9989 §4.10.2 Rules 1-4."""
    resolver = MockDNSResolver()
    # Rule 1: psd=n
    resolver.add_txt("_dmarc.corp.example.com", ["v=DMARC1; p=reject; psd=n"])
    # Rule 2: psd=y at parent
    resolver.add_txt("_dmarc.gov.uk", ["v=DMARC1; p=reject; psd=y"])
    # Rule 3: psd=u candidates
    resolver.add_txt("_dmarc.sub.brand.com", ["v=DMARC1; p=none"])
    resolver.add_txt("_dmarc.brand.com", ["v=DMARC1; p=reject"])

    disc = DMARCRecordDiscovery(resolver=resolver)

    # Rule 1: psd=n marks Org Domain immediately
    org1, s1, _ = await disc.determine_org_domain("sub.corp.example.com")
    assert org1 == "corp.example.com"
    assert s1 == DMARCDiscoveryStatus.FOUND

    # Rule 2: psd=y marks parent as PSD, child 1 label below is Org Domain
    org2, s2, _ = await disc.determine_org_domain("agency.dept.gov.uk")
    assert org2 == "dept.gov.uk"
    assert s2 == DMARCDiscoveryStatus.FOUND

    # Rule 3: Fewest labels among psd=u candidates
    org3, s3, _ = await disc.determine_org_domain("sub.brand.com")
    assert org3 == "brand.com"
    assert s3 == DMARCDiscoveryStatus.FOUND

    # Rule 4: No records found across tree -> initial target domain
    org4, s4, _ = await disc.determine_org_domain("nodomain.example.net")
    assert org4 == "nodomain.example.net"
    assert s4 == DMARCDiscoveryStatus.ABSENT


@pytest.mark.asyncio
async def test_dmarc_audit2_standalone_helo_on_non_null_reverse_path_never_aligns():
    """Audit 2: Standalone HELO check on non-null reverse path must NOT replace MAIL FROM (RFC 9989 §4.4.2)."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=r"])
    evaluator = DMARCEvaluator(resolver=resolver)

    # Non-null reverse path message: HELO was evaluated standalone, is_null_reverse_path is False
    spf_res = SPFResult(
        status=ProtocolStatus.PASS,
        domain="outbox.example.com",
        scope="helo",
        is_null_reverse_path=False,
        is_standalone_helo=True,
    )
    res = await evaluator.evaluate(from_domain="example.com", spf_result=spf_res)

    assert res.status == ProtocolStatus.FAIL
    assert res.spf_aligned is False
    assert res.error_reason is not None
    assert "RFC 9989 §4.4.2" in res.error_reason
    assert res.rfc_status == "fail"


@pytest.mark.asyncio
async def test_dmarc_audit2_null_reverse_path_bounce_synthesized_helo_aligns():
    """Audit 2: Null reverse path bounce (MAIL FROM:<>) synthesized postmaster@helo aligns (RFC 9989 §3.2.4 & §4.4.2)."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=r"])
    evaluator = DMARCEvaluator(resolver=resolver)

    # Null reverse path bounce: scope='helo', is_null_reverse_path=True
    spf_res = SPFResult(
        status=ProtocolStatus.PASS,
        domain="outbox.example.com",
        scope="helo",
        is_null_reverse_path=True,
        is_synthesized_mfrom=True,
    )
    res = await evaluator.evaluate(from_domain="example.com", spf_result=spf_res)

    assert res.status == ProtocolStatus.PASS
    assert res.spf_aligned is True
    assert res.spf_aligned_relaxed is True
    assert res.rfc_status == "pass"


@pytest.mark.asyncio
async def test_dmarc_audit3_standardized_result_values_compliance():
    """Audit 3: Standardized DMARC result values strictly follow RFC 9989 §9.2 IANA registry."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    # 1. PASS
    spf_pass = SPFResult(status=ProtocolStatus.PASS, domain="example.com", scope="mfrom")
    res_pass = await evaluator.evaluate("example.com", spf_result=spf_pass)
    assert res_pass.status == ProtocolStatus.PASS
    assert res_pass.standard_status == "pass"
    assert res_pass.rfc_status == "pass"
    assert res_pass.internal_status == ProtocolStatus.PASS

    # 2. FAIL
    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="example.com", scope="mfrom")
    res_fail = await evaluator.evaluate("example.com", spf_result=spf_fail)
    assert res_fail.status == ProtocolStatus.FAIL
    assert res_fail.standard_status == "fail"
    assert res_fail.rfc_status == "fail"
    assert res_fail.internal_status == ProtocolStatus.FAIL

    # 3. NONE (no policy record)
    res_none = await evaluator.evaluate("nopolicy.org")
    assert res_none.status == ProtocolStatus.NONE
    assert res_none.standard_status == "none"
    assert res_none.rfc_status == "none"
    assert res_none.internal_status == ProtocolStatus.NONE

    # 4. PERMERROR (malformed From domain)
    res_perm = await evaluator.evaluate("invalid..domain")
    assert res_perm.status == ProtocolStatus.PERMERROR
    assert res_perm.standard_status == "permerror"
    assert res_perm.rfc_status == "permerror"
    assert res_perm.internal_status == ProtocolStatus.PERMERROR

    # 5. TEMPERROR (DNS timeout during discovery)
    resolver.set_error(
        "_dmarc.temp.org",
        status=DNSResponseStatus.TIMEOUT,
        error_type=DNSErrorType.TIMEOUT,
        query_type=DNSQueryType.TXT,
    )
    res_temp = await evaluator.evaluate("temp.org")
    assert res_temp.status == ProtocolStatus.TEMPERROR
    assert res_temp.standard_status == "temperror"
    assert res_temp.rfc_status == "temperror"
    assert res_temp.internal_status == ProtocolStatus.TEMPERROR

    # 6. INDETERMINATE (query limit exceeded): RFC 9989 §9.2 standardized status is None, rfc_status is None
    # Incomplete evaluation must NOT be silently converted into fail or none
    deep_domain = "l1.l2.l3.l4.l5.l6.l7.l8.otherdomain.com"
    spf_deep = SPFResult(status=ProtocolStatus.PASS, domain=deep_domain, scope="mfrom")
    res_indet = await evaluator.evaluate("example.com", spf_result=spf_deep)
    assert res_indet.status == ProtocolStatus.INDETERMINATE
    assert res_indet.internal_status == ProtocolStatus.INDETERMINATE
    assert res_indet.standard_status is None
    assert res_indet.rfc_status is None


# =============================================================================
# 10. STEP 3.7.2C AUDIT TESTS (RFC 9989 STANDARDS CORRECTIONS)
# =============================================================================

@pytest.mark.asyncio
async def test_dmarc_audit_task1_starting_domain_psd_y_and_parent_psd_u():
    """Task 1: Starting domain publishes psd=y and parent publishes psd=u.
    
    RFC 9989 §4.10.2:
    - Rule 2 applies only to records found other than at the starting domain of the walk.
      Therefore, _dmarc.example.com does NOT trigger the parent-PSD rule.
    - example.com is recorded as a candidate under Rule 3.
    - com publishes psd=u, recorded as candidate under Rule 3.
    - Tree walk completes, and candidate with fewest labels is selected: 'com' (1 label) vs 'example.com' (2 labels).
    """
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; psd=y"])
    resolver.add_txt("_dmarc.com", ["v=DMARC1; p=reject; psd=u"])

    disc = DMARCRecordDiscovery(resolver=resolver)
    org, status, queries = await disc.determine_org_domain("example.com")

    assert org == "com"
    assert status == DMARCDiscoveryStatus.FOUND
    assert queries == 2


@pytest.mark.asyncio
async def test_dmarc_audit_task1_starting_domain_psd_y_and_parent_no_record():
    """Task 1: Starting domain publishes psd=y and parent domain has no DMARC record.
    
    RFC 9989 §4.10.2:
    - Starting domain example.com with psd=y is recorded as candidate under Rule 3.
    - Parent domain com has no record.
    - Tree walk completes, candidate with fewest labels is example.com.
    """
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; psd=y"])

    disc = DMARCRecordDiscovery(resolver=resolver)
    org, status, queries = await disc.determine_org_domain("example.com")

    assert org == "example.com"
    assert status == DMARCDiscoveryStatus.FOUND
    assert queries == 2


@pytest.mark.asyncio
async def test_dmarc_audit_task2_standalone_helo_with_null_reverse_path_flag_fails():
    """Task 2: Merely setting is_null_reverse_path=True on an independently evaluated HELO result
    must NOT make that result eligible for DMARC (must represent actual synthesized MailFrom).
    """
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=r"])
    evaluator = DMARCEvaluator(resolver=resolver)

    # Standalone HELO result where someone set is_null_reverse_path=True but is_standalone_helo=True
    spf_res = SPFResult(
        status=ProtocolStatus.PASS,
        domain="outbox.example.com",
        scope="helo",
        is_null_reverse_path=True,
        is_standalone_helo=True,
        is_synthesized_mfrom=False,
    )
    res = await evaluator.evaluate(from_domain="example.com", spf_result=spf_res)

    assert res.status == ProtocolStatus.FAIL
    assert res.spf_aligned is False
    assert "RFC 9989 §4.4.2" in (res.error_reason or "")
    assert res.standard_status == "fail"
    assert res.rfc_status == "fail"


@pytest.mark.asyncio
async def test_dmarc_audit_task2_standalone_helo_without_synthesized_flag_fails():
    """Task 2: Standalone HELO without is_synthesized_mfrom=True fails DMARC even if is_null_reverse_path=True."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=r"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf_res = SPFResult(
        status=ProtocolStatus.PASS,
        domain="outbox.example.com",
        scope="helo",
        is_null_reverse_path=True,
        is_standalone_helo=False,
        is_synthesized_mfrom=False,
    )
    res = await evaluator.evaluate(from_domain="example.com", spf_result=spf_res)

    assert res.status == ProtocolStatus.FAIL
    assert res.spf_aligned is False
    assert res.standard_status == "fail"
    assert res.rfc_status == "fail"


@pytest.mark.asyncio
async def test_dmarc_audit_task2_genuine_synthesized_bounce_passes():
    """Task 2: Genuine null reverse-path bounce with synthesized postmaster@helo passes DMARC alignment."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=r"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf_res = SPFResult(
        status=ProtocolStatus.PASS,
        domain="outbox.example.com",
        scope="helo",
        is_null_reverse_path=True,
        is_synthesized_mfrom=True,
        is_standalone_helo=False,
        identity="postmaster@outbox.example.com",
    )
    res = await evaluator.evaluate(from_domain="example.com", spf_result=spf_res)

    assert res.status == ProtocolStatus.PASS
    assert res.spf_aligned is True
    assert res.spf_aligned_relaxed is True
    assert res.standard_status == "pass"
    assert res.rfc_status == "pass"


@pytest.mark.asyncio
async def test_dmarc_audit_task2_untrusted_missing_metadata_no_phantom_pass():
    """Task 2: Missing or untrusted transport metadata produces no phantom SPF PASS or DMARC alignment."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=r"])
    evaluator = DMARCEvaluator(resolver=resolver)

    # 1. Missing spf_result -> INDETERMINATE under C1 safety rule (never invents false DMARC FAIL)
    res1 = await evaluator.evaluate(from_domain="example.com", spf_result=None)
    assert res1.status == ProtocolStatus.INDETERMINATE
    assert res1.standard_status is None
    assert res1.rfc_status is None
    assert res1.spf_aligned is False

    # 2. Untrusted / failed SPF status
    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="example.com", scope="mfrom")
    res2 = await evaluator.evaluate(from_domain="example.com", spf_result=spf_fail)
    assert res2.status == ProtocolStatus.FAIL
    assert res2.spf_aligned is False

    # 3. SPF None / no domain
    spf_none = SPFResult(status=ProtocolStatus.NONE, domain=None, scope="mfrom")
    res3 = await evaluator.evaluate(from_domain="example.com", spf_result=spf_none)
    assert res3.status == ProtocolStatus.FAIL
    assert res3.spf_aligned is False


@pytest.mark.asyncio
async def test_dmarc_audit_task3_indeterminate_standard_and_rfc_status_are_none():
    """Task 3: DMARC INDETERMINATE has standard_status=None, rfc_status=None, not 'fail' or 'none'.
    
    RFC 9989 §9.2 standardized values: pass, fail, none, permerror, temperror.
    Query-limit exhaustion or incomplete evaluation must NOT be converted to fail or none.
    """
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    # Query limit exceeded during identifier alignment tree walk
    deep_domain = "l1.l2.l3.l4.l5.l6.l7.l8.otherdomain.com"
    spf_deep = SPFResult(status=ProtocolStatus.PASS, domain=deep_domain, scope="mfrom")
    res_indet = await evaluator.evaluate("example.com", spf_result=spf_deep)

    assert res_indet.status == ProtocolStatus.INDETERMINATE
    assert res_indet.internal_status == ProtocolStatus.INDETERMINATE
    assert res_indet.standard_status is None
    assert res_indet.rfc_status is None

    # Completed FAIL evaluation has standardized 'fail'
    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="example.com", scope="mfrom")
    res_fail = await evaluator.evaluate("example.com", spf_result=spf_fail)
    assert res_fail.status == ProtocolStatus.FAIL
    assert res_fail.standard_status == "fail"
    assert res_fail.rfc_status == "fail"

    # Completed no-policy evaluation has standardized 'none'
    res_none = await evaluator.evaluate("nopolicy.org")
    assert res_none.status == ProtocolStatus.NONE
    assert res_none.standard_status == "none"
    assert res_none.rfc_status == "none"


# =============================================================================
# 11. STEP 3.7.2D AUDIT TESTS (SAME-DOMAIN ALIGNMENT & ORG DOMAIN DETERMINATION)
# =============================================================================

@pytest.mark.asyncio
async def test_dmarc_step372d_subdomain_same_domain_spf_inherits_parent_org_domain():
    """Task 1 Scenario:
    RFC 5322 From domain: mail.example.com
    Authenticated SPF identifier: mail.example.com
    DMARC policy exists only at: _dmarc.example.com
    No DMARC policy exists at: _dmarc.mail.example.com

    Standards Verification:
    - Policy Discovery: discovers policy at _dmarc.example.com (Section 4.10.1).
    - Identifier Alignment (Section 4.4):
      Strict: exact match between mail.example.com and mail.example.com (satisfied).
      Relaxed: shares common Organizational Domain example.com (satisfied).
    - Organizational Domain Determination (Section 4.10.2):
      Author domain mail.example.com has Organizational Domain 'example.com',
      NOT 'mail.example.com'.
    - DMARC outcome must return PASS, with org_domain='example.com' and from_domain='mail.example.com'.
    """
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=r"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf = SPFResult(status=ProtocolStatus.PASS, domain="mail.example.com", scope="mfrom")
    res = await evaluator.evaluate("mail.example.com", spf_result=spf)

    assert res.status == ProtocolStatus.PASS
    assert res.standard_status == "pass"
    assert res.rfc_status == "pass"
    assert res.org_domain == "example.com"
    assert res.from_domain == "mail.example.com"
    assert res.spf_aligned is True
    assert res.spf_aligned_strict is True
    assert res.spf_aligned_relaxed is True
    assert res.policy == DMARCPolicy.REJECT


@pytest.mark.asyncio
async def test_dmarc_step372d_subdomain_same_domain_dkim_inherits_parent_org_domain():
    """Task 1: Same scenario as above but authenticated via DKIM (d=mail.example.com)."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; adkim=r"])
    evaluator = DMARCEvaluator(resolver=resolver)

    dkim_sigs = [
        DKIMSignatureResult(status=ProtocolStatus.PASS, domain="mail.example.com", selector="s1")
    ]
    res = await evaluator.evaluate("mail.example.com", dkim_results=dkim_sigs)

    assert res.status == ProtocolStatus.PASS
    assert res.standard_status == "pass"
    assert res.rfc_status == "pass"
    assert res.org_domain == "example.com"
    assert res.from_domain == "mail.example.com"
    assert res.dkim_aligned is True
    assert res.dkim_aligned_strict is True
    assert res.dkim_aligned_relaxed is True


@pytest.mark.asyncio
async def test_dmarc_step372d_subdomain_same_domain_subdomain_policy_applied():
    """Task 1: Subdomain policy (sp=) published at parent is applied to subdomain author."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=none; sp=reject; aspf=s"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf = SPFResult(status=ProtocolStatus.PASS, domain="mail.example.com", scope="mfrom")
    res = await evaluator.evaluate("mail.example.com", spf_result=spf)

    assert res.status == ProtocolStatus.PASS
    assert res.policy == DMARCPolicy.REJECT
    assert res.subdomain_policy == DMARCPolicy.REJECT
    assert res.org_domain == "example.com"


@pytest.mark.asyncio
async def test_dmarc_step372d_subdomain_same_domain_no_policy_anywhere_returns_none():
    """Task 1 Negative: Same-domain identifier without any DMARC policy anywhere must return NONE."""
    resolver = MockDNSResolver()
    evaluator = DMARCEvaluator(resolver=resolver)

    spf = SPFResult(status=ProtocolStatus.PASS, domain="mail.example.com", scope="mfrom")
    res = await evaluator.evaluate("mail.example.com", spf_result=spf)

    assert res.status == ProtocolStatus.NONE
    assert res.standard_status == "none"
    assert res.rfc_status == "none"
    assert res.policy == DMARCPolicy.NOT_CONFIGURED
    assert res.spf_aligned is False


@pytest.mark.asyncio
async def test_dmarc_step372d_subdomain_different_domain_fails_alignment():
    """Task 1 Negative: Different domain identifier fails alignment under discovered parent policy."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    spf = SPFResult(status=ProtocolStatus.PASS, domain="attacker.com", scope="mfrom")
    res = await evaluator.evaluate("mail.example.com", spf_result=spf)

    assert res.status == ProtocolStatus.FAIL
    assert res.standard_status == "fail"
    assert res.rfc_status == "fail"
    assert res.spf_aligned is False
    assert res.org_domain == "example.com"


# =============================================================================
# 12. STEP 3.7.3B REMEDIATION TESTS (H1, H3, M3)
# =============================================================================

@pytest.mark.asyncio
async def test_h1_alignment_indeterminate_never_masked_into_dmarc_fail():
    """H1: INDETERMINATE during org_domain determination propagates and never becomes DMARC FAIL."""
    from app.modules.auth_protocols.evaluators.dmarc import (
        DMARCDiscoveryStatus,
        check_domain_alignment,
    )

    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; aspf=r; adkim=r"])
    resolver.add_txt("_dmarc.other.net", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)

    # 1. Author-domain policy discovery succeeds, org-domain determination raises exception -> INDETERMINATE
    orig_det = evaluator.discovery.determine_org_domain

    async def _raise_on_other(dom):
        if dom == "mail.other.net":
            raise RuntimeError("Simulated determine_org_domain exception")
        return await orig_det(dom)

    evaluator.discovery.determine_org_domain = _raise_on_other  # type: ignore[method-assign]
    res_exc = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.PASS, domain="mail.other.net", scope="mfrom"),
    )
    assert res_exc.status == ProtocolStatus.INDETERMINATE
    assert res_exc.standard_status is None
    assert res_exc.rfc_status is None

    # 2. One path INDETERMINATE while other path FOUND -> check_domain_alignment propagates INDETERMINATE
    async def _indet_on_other(dom):
        if dom == "other.net":
            return dom, DMARCDiscoveryStatus.INDETERMINATE, 1
        return await orig_det(dom)

    evaluator.discovery.determine_org_domain = _indet_on_other  # type: ignore[method-assign]
    outcome_live = await check_domain_alignment(
        auth_domain="other.net",
        from_domain="example.com",
        mode=AlignmentMode.RELAXED,
        discovery=evaluator.discovery,
    )
    assert outcome_live.is_aligned is False
    assert outcome_live.discovery_status == DMARCDiscoveryStatus.INDETERMINATE

    # Also test when author domain returns INDETERMINATE while auth domain returns FOUND
    async def _indet_on_author(dom):
        if dom == "sub.example.com":
            return dom, DMARCDiscoveryStatus.INDETERMINATE, 1
        return await orig_det(dom)

    evaluator.discovery.determine_org_domain = _indet_on_author  # type: ignore[method-assign]
    outcome_author_indet = await check_domain_alignment(
        auth_domain="other.net",
        from_domain="sub.example.com",
        mode=AlignmentMode.RELAXED,
        discovery=evaluator.discovery,
    )
    assert outcome_author_indet.discovery_status == DMARCDiscoveryStatus.INDETERMINATE

    # 3. Cached INDETERMINATE tuple & DMARCDiscoveryResult in org_domain_cache
    cache_tuple = {
        "example.com": ("example.com", DMARCDiscoveryStatus.FOUND),
        "cached-indet.net": ("cached-indet.net", DMARCDiscoveryStatus.INDETERMINATE),
    }
    out_cached_tuple = await check_domain_alignment(
        auth_domain="cached-indet.net",
        from_domain="example.com",
        mode=AlignmentMode.RELAXED,
        discovery=evaluator.discovery,
        org_domain_cache=cache_tuple,
    )
    assert out_cached_tuple.discovery_status == DMARCDiscoveryStatus.INDETERMINATE

    from app.modules.auth_protocols.evaluators.dmarc import DMARCDiscoveryResult
    cache_obj = {
        "example.com": ("example.com", DMARCDiscoveryStatus.FOUND),
        "obj-indet.net": DMARCDiscoveryResult(
            status=DMARCDiscoveryStatus.INDETERMINATE,
            protocol_status=ProtocolStatus.INDETERMINATE,
            domain="obj-indet.net",
            org_domain="obj-indet.net",
        ),
    }
    out_cached_obj = await check_domain_alignment(
        auth_domain="obj-indet.net",
        from_domain="example.com",
        mode=AlignmentMode.RELAXED,
        discovery=evaluator.discovery,
        org_domain_cache=cache_obj,
    )
    assert out_cached_obj.discovery_status == DMARCDiscoveryStatus.INDETERMINATE

    # 4. Valid aligned DKIM PASS establishes DMARC PASS even with SPF NOT_EVALUATED and another broken path
    evaluator.discovery.determine_org_domain = _indet_on_other  # type: ignore[method-assign]
    res_dkim_win = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.NOT_EVALUATED),
        dkim_results=[
            DKIMSignatureResult(status=ProtocolStatus.PASS, domain="other.net", selector="s1"),
            DKIMSignatureResult(status=ProtocolStatus.PASS, domain="example.com", selector="s2"),
        ],
    )
    assert res_dkim_win.status == ProtocolStatus.PASS
    assert res_dkim_win.dkim_aligned is True
    assert res_dkim_win.rfc_status == "pass"

    # Restore and verify permanent vs transient DNS errors remain properly distinguished
    evaluator.discovery.determine_org_domain = orig_det  # type: ignore[method-assign]
    resolver.set_timeout("_dmarc.temp-walk.net", DNSQueryType.TXT)
    res_temp = await evaluator.evaluate(
        "example.com",
        spf_result=SPFResult(status=ProtocolStatus.PASS, domain="temp-walk.net", scope="mfrom"),
    )
    assert res_temp.status == ProtocolStatus.TEMPERROR and res_temp.rfc_status == "temperror"

    resolver.add_txt("_dmarc.perm-bad.net", ["v=DMARC1; p=not_a_policy"])
    res_perm = await evaluator.evaluate("perm-bad.net", spf_result=SPFResult(status=ProtocolStatus.FAIL))
    assert res_perm.status == ProtocolStatus.PERMERROR and res_perm.rfc_status == "permerror"


@pytest.mark.asyncio
async def test_h3_and_m3_subdomain_existence_probing_and_provenance():
    """M3 & H3: Explicit np= probe config, NXDOMAIN/NODATA/A, error safety, and budget bounds."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=none; sp=quarantine; np=reject; psd=n"])
    resolver.add_a("web.example.com", ["192.0.2.50"])
    resolver.add_mx("mxonly.example.com", [(10, "mx1.example.com")])  # triggers NODATA on A probe (exists!)
    resolver.set_nxdomain("dead.example.com")
    resolver.set_resolver_error("neterr.example.com", DNSQueryType.A)
    resolver.set_invalid_query("badq.example.com", DNSQueryType.A)

    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="evil.org", scope="mfrom")

    # 1. Default config (dmarc_enable_subdomain_existence_probe=False): np= NOT falsely active, provenance explicit
    eval_disabled = DMARCEvaluator(resolver=resolver)
    r_dis = await eval_disabled.evaluate("dead.example.com", spf_result=spf_fail)
    assert r_dis.status == ProtocolStatus.FAIL
    assert r_dis.policy == DMARCPolicy.QUARANTINE  # falls back to sp=quarantine (probe disabled)
    assert r_dis.applicable_policy_tag == "sp"
    assert r_dis.record_p_policy == DMARCPolicy.NONE
    assert r_dis.is_subdomain_non_existent is None
    assert r_dis.subdomain_existence_probe_enabled is False
    assert r_dis.subdomain_existence_status == "unknown_probe_disabled"
    assert r_dis.np_evaluation_skipped_reason == "subdomain_existence_probe_disabled"

    # 2. Enabled via AuthProtocolsConfig AND via evaluate_auth_protocols()
    cfg_enabled = AuthProtocolsConfig(dmarc_enable_subdomain_existence_probe=True)
    eval_enabled = DMARCEvaluator(resolver=resolver, config=cfg_enabled)

    # NXDOMAIN -> confirmed non-existent -> np=reject applies
    auth_nx = AuthProtocolsResult(spf_status=ProtocolStatus.FAIL, spf_details=spf_fail, dkim_signatures=[])
    r_nx = await eval_enabled.evaluate_auth_protocols("dead.example.com", auth_nx)
    assert r_nx.policy == DMARCPolicy.REJECT
    assert r_nx.applicable_policy_tag == "np"
    assert r_nx.record_p_policy == DMARCPolicy.NONE
    assert r_nx.is_subdomain_non_existent is True
    assert r_nx.subdomain_existence_probe_enabled is True
    assert r_nx.subdomain_existence_status == "confirmed_non_existent"

    # NODATA on A record (domain has MX only) -> Appendix A.4 exists -> sp=quarantine (NOT np!)
    r_nodata = await eval_enabled.evaluate("mxonly.example.com", spf_result=spf_fail)
    assert r_nodata.policy == DMARCPolicy.QUARANTINE
    assert r_nodata.applicable_policy_tag == "sp"
    assert r_nodata.is_subdomain_non_existent is False
    assert r_nodata.subdomain_existence_status == "confirmed_existing"

    # A record exists -> confirmed_existing -> sp=quarantine
    r_a = await eval_enabled.evaluate("web.example.com", spf_result=spf_fail)
    assert r_a.policy == DMARCPolicy.QUARANTINE
    assert r_a.subdomain_existence_status == "confirmed_existing"

    # 3. Resolver error during probe NEVER selects np= and yields TEMPERROR / INDETERMINATE
    r_err = await eval_enabled.evaluate("neterr.example.com", spf_result=spf_fail)
    assert r_err.status == ProtocolStatus.TEMPERROR
    assert r_err.applicable_policy_tag != "np"
    assert r_err.is_subdomain_non_existent is None
    assert r_err.subdomain_existence_status == "unknown_dns_temperror"

    r_inv = await eval_enabled.evaluate("badq.example.com", spf_result=spf_fail)
    assert r_inv.status == ProtocolStatus.INDETERMINATE
    assert r_inv.applicable_policy_tag != "np"
    assert r_inv.is_subdomain_non_existent is None
    assert r_inv.subdomain_existence_status == "unknown_dns_error"

    # 4. Query budget exhaustion prevents probe & never selects np=
    cfg_tight = AuthProtocolsConfig(dmarc_enable_subdomain_existence_probe=True, max_total_dns_queries_per_scan=2)
    eval_tight = DMARCEvaluator(resolver=resolver, config=cfg_tight)
    r_budget = await eval_tight.evaluate("dead.sub.example.com", spf_result=spf_fail)
    assert r_budget.status == ProtocolStatus.INDETERMINATE
    assert r_budget.subdomain_existence_status == "unknown_budget_exhausted"
    assert r_budget.np_evaluation_skipped_reason == "dns_query_budget_exhausted"
    assert r_budget.applicable_policy_tag != "np"


@pytest.mark.asyncio
async def test_h3_dmarc_async_resolver_os_socket_runtime_and_np_safety():
    """H3: Real AsyncDNSResolver OSError/ConnectionError/socket/TimeoutError/RuntimeError propagate safely and never trigger np=."""
    import socket
    import dns.resolver
    from app.modules.auth_protocols.dns_resolver import AsyncDNSResolver

    cfg = AuthProtocolsConfig(dmarc_enable_subdomain_existence_probe=True)
    async_res = AsyncDNSResolver(config=cfg)
    evaluator = DMARCEvaluator(resolver=async_res, config=cfg)
    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="evil.org", scope="mfrom")

    # 1. Discovery OS/socket/TimeoutError -> TEMPERROR, RuntimeError -> INDETERMINATE (never NONE)
    for exc_obj, expected_status in (
        (OSError("socket err"), ProtocolStatus.TEMPERROR),
        (ConnectionError("conn reset"), ProtocolStatus.TEMPERROR),
        (socket.gaierror(-2, "addr err"), ProtocolStatus.TEMPERROR),
        (TimeoutError("io timeout"), ProtocolStatus.TEMPERROR),
        (dns.resolver.NoNameservers(), ProtocolStatus.TEMPERROR),
        (RuntimeError("internal resolver bug"), ProtocolStatus.INDETERMINATE),
        (dns.resolver.YXDOMAIN(), ProtocolStatus.INDETERMINATE),
        (dns.resolver.NXDOMAIN(), ProtocolStatus.NONE),
    ):
        async_res.cache.clear()

        async def _boom_disc(name, rdtype, _e=exc_obj):
            raise _e

        async_res._resolver.resolve = _boom_disc  # type: ignore[method-assign]
        res = await evaluator.evaluate("example.com", spf_result=spf_fail)
        assert res.status == expected_status, f"Discovery mismatch for {type(exc_obj).__name__}: {res.status}"

    # 2. Subdomain existence probe errors NEVER activate np=reject!
    for probe_exc, expected_status in (
        (OSError("net unreachable"), ProtocolStatus.TEMPERROR),
        (ConnectionError("reset"), ProtocolStatus.TEMPERROR),
        (TimeoutError("probe timeout"), ProtocolStatus.TEMPERROR),
        (RuntimeError("probe software crash"), ProtocolStatus.INDETERMINATE),
    ):
        async_res.cache.clear()

        async def _mixed_probe(name, rdtype, _pe=probe_exc):
            if name == "_dmarc.sub.example.com":
                raise dns.resolver.NXDOMAIN()
            if name == "_dmarc.example.com":
                class _Rdata:
                    strings = [b"v=DMARC1; p=none; sp=quarantine; np=reject; psd=n"]
                class _Ans(list):
                    rrset = type("_RR", (), {"ttl": 300})()
                return _Ans([_Rdata()])
            if name == "sub.example.com":
                raise _pe
            raise dns.resolver.NXDOMAIN()

        async_res._resolver.resolve = _mixed_probe  # type: ignore[method-assign]
        res_p = await evaluator.evaluate("sub.example.com", spf_result=spf_fail)
        assert res_p.status == expected_status
        assert res_p.applicable_policy_tag != "np"
        assert res_p.is_subdomain_non_existent is None


@pytest.mark.asyncio
async def test_l2_typed_dkim_states_and_authoritative_dmarc_alignment():
    """L2: Verify typed DKIM states replace substring checks and DMARC Tree Walk overrides standalone PSL hints."""
    from app.modules.auth_protocols.evaluators.dkim import DKIMVerifier
    from app.modules.contracts import DKIMEvaluationState

    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])
    evaluator = DMARCEvaluator(resolver=resolver)
    spf_fail = SPFResult(status=ProtocolStatus.FAIL, domain="other.org", scope="mfrom")

    # State 1: Missing raw bytes (via DKIMVerifier AND non-English error reason with typed state) -> INDETERMINATE
    async with DKIMVerifier(dns_resolver=resolver) as verifier:
        auth_missing = await verifier.evaluate_auth_protocol(None, from_domain="example.com")
    assert auth_missing.dkim_evaluation_state == DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES
    res_missing = await evaluator.evaluate_auth_protocols("example.com", auth_missing)
    assert res_missing.status == ProtocolStatus.INDETERMINATE
    assert res_missing.rfc_status is None
    assert res_missing.diagnostics["dkim_evaluation_state"] == "NOT_EVALUATED_MISSING_RAW_BYTES"

    # Typed missing-bytes reason works even with completely non-English diagnostic text
    typed_custom_missing = [
        DKIMSignatureResult(
            index=0,
            status=ProtocolStatus.PERMERROR,
            evaluation_state=DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES,
            reason_code="MISSING_RAW_MESSAGE_BYTES",
            error_reason="ro_octeti_bruti_lipsa",
        )
    ]
    res_typed = await evaluator.evaluate("example.com", spf_result=spf_fail, dkim_results=typed_custom_missing)
    assert res_typed.status == ProtocolStatus.INDETERMINATE
    assert res_typed.rfc_status is None

    # Genuine PERMERROR with legacy phrase ONLY (no typed state) is no longer misread by prose substring matching!
    real_perm = [
        DKIMSignatureResult(
            index=0,
            status=ProtocolStatus.PERMERROR,
            evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
            reason_code="MALFORMED_DKIM_SIGNATURE",
            error_reason="legacy phrase without typed missing-bytes flag",
        )
    ]
    res_real_perm = await evaluator.evaluate("example.com", spf_result=spf_fail, dkim_results=real_perm)
    assert res_real_perm.status == ProtocolStatus.FAIL
    assert res_real_perm.diagnostics["dkim_evaluation_state"] == "EVALUATED_COMPLETED"

    # State 2: Evaluated and no signatures -> EVALUATED_NO_SIGNATURES -> DMARC FAIL
    async with DKIMVerifier(dns_resolver=resolver) as verifier2:
        auth_nosig = await verifier2.evaluate_auth_protocol(
            b"From: u@example.com\r\nSubject: Plain\r\n\r\nBody\r\n", from_domain="example.com"
        )
    assert auth_nosig.dkim_evaluation_state == DKIMEvaluationState.EVALUATED_NO_SIGNATURES
    auth_nosig.spf_details = spf_fail
    res_nosig = await evaluator.evaluate_auth_protocols("example.com", auth_nosig)
    assert res_nosig.status == ProtocolStatus.FAIL
    assert res_nosig.diagnostics["dkim_evaluation_state"] == "EVALUATED_NO_SIGNATURES"

    # State 3: Evaluated and signature failed -> EVALUATED_COMPLETED -> DMARC FAIL
    res_sigfail = await evaluator.evaluate(
        "example.com",
        spf_result=spf_fail,
        dkim_results=[
            DKIMSignatureResult(
                index=0,
                status=ProtocolStatus.FAIL,
                domain="example.com",
                evaluation_state=DKIMEvaluationState.EVALUATED_COMPLETED,
                reason_code="SIGNATURE_VERIFICATION_FAILED",
            )
        ],
    )
    assert res_sigfail.status == ProtocolStatus.FAIL
    assert res_sigfail.diagnostics["dkim_evaluation_state"] == "EVALUATED_COMPLETED"

    # State 4: Incomplete internal error -> INCOMPLETE_INTERNAL_ERROR -> DMARC INDETERMINATE
    res_int = await evaluator.evaluate(
        "example.com",
        spf_result=spf_fail,
        dkim_results=[
            DKIMSignatureResult(
                index=0,
                status=ProtocolStatus.INDETERMINATE,
                domain="example.com",
                evaluation_state=DKIMEvaluationState.INCOMPLETE_INTERNAL_ERROR,
                reason_code="DKIM_INTERNAL_HEADERPREP_ERROR",
            )
        ],
    )
    assert res_int.status == ProtocolStatus.INDETERMINATE
    assert res_int.rfc_status is None
    assert res_int.diagnostics["dkim_evaluation_state"] == "INCOMPLETE_INTERNAL_ERROR"

    # PSL contradiction test:
    # Standalone PSL treats dept.corp.co.uk & mail.corp.co.uk as sharing corp.co.uk,
    # whereas DNS publishes psd=y at _dmarc.corp.co.uk (making them separate Org Domains)!
    # DMARCEvaluator MUST override the standalone PSL hint authoritatively.
    psl_resolver = MockDNSResolver()
    psl_resolver.add_txt("_dmarc.corp.co.uk", ["v=DMARC1; p=reject; psd=y"])
    psl_eval = DMARCEvaluator(resolver=psl_resolver)

    sig_psl_conflict = DKIMSignatureResult(
        index=0,
        status=ProtocolStatus.PASS,
        domain="dept.corp.co.uk",
        is_aligned_with_from=True,  # stale/contradictory PSL hint
        aligned_relaxed=True,
        aligned_strict=False,
        alignment_source="standalone_psl_diagnostic_only",
        alignment_is_authoritative=False,
        standalone_psl_aligned_relaxed=True,
    )
    res_conflict = await psl_eval.evaluate(
        "mail.corp.co.uk",
        spf_result=spf_fail,
        dkim_results=[sig_psl_conflict],
    )
    assert res_conflict.status == ProtocolStatus.FAIL
    assert res_conflict.dkim_aligned is False
    assert sig_psl_conflict.is_aligned_with_from is False
    assert sig_psl_conflict.aligned_relaxed is False
    assert sig_psl_conflict.alignment_source == "dmarc_tree_walk_authoritative"
    assert sig_psl_conflict.alignment_is_authoritative is True
    assert sig_psl_conflict.standalone_psl_aligned_relaxed is True  # diagnostic preserved!

