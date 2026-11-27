"""Comprehensive unit and adversarial test suite for RFC 7208 SPF Evaluator."""

import asyncio
import ipaddress
import pytest

from app.modules.auth_protocols import (
    AuthProtocolsConfig,
    DNSQueryType,
    MockDNSResolver,
    ProtocolStatus,
    SPFEvaluator,
    SPFResult,
    TrustedSMTPMetadata,
)
from app.modules.auth_protocols.evaluators.spf import _SPFEvaluationContext


@pytest.fixture
def mock_resolver():
    return MockDNSResolver()


@pytest.fixture
def evaluator(mock_resolver):
    return SPFEvaluator(resolver=mock_resolver)


@pytest.fixture
def trusted_v4_meta():
    return TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="mail.sender.org",
        mail_from_envelope="alice@sender.org",
        is_trusted_mta=True,
    )


@pytest.fixture
def trusted_v6_meta():
    return TrustedSMTPMetadata(
        connecting_ip="2001:db8::1",
        helo_domain="mail6.sender.org",
        mail_from_envelope="bob@sender.org",
        is_trusted_mta=True,
    )


# ==============================================================================
# 1. Transport Metadata Security Boundary & Scopes
# ==============================================================================

@pytest.mark.asyncio
async def test_missing_or_untrusted_transport_metadata_returns_not_evaluated(evaluator, mock_resolver):
    # Case A: None metadata
    res_none = await evaluator.evaluate(domain="sender.org", smtp_metadata=None)
    assert res_none.status == ProtocolStatus.NOT_EVALUATED
    assert "Missing or unverified" in res_none.error_reason
    assert mock_resolver.total_queries == 0  # Zero DNS queries allowed

    # Case B: Untrusted MTA flag
    untrusted_meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        mail_from_envelope="user@sender.org",
        is_trusted_mta=False,
    )
    res_untrusted = await evaluator.evaluate(domain="sender.org", smtp_metadata=untrusted_meta)
    assert res_untrusted.status == ProtocolStatus.NOT_EVALUATED
    assert mock_resolver.total_queries == 0

    # Case C: Missing connecting IP
    no_ip_meta = TrustedSMTPMetadata(
        connecting_ip=None,
        mail_from_envelope="user@sender.org",
        is_trusted_mta=True,
    )
    res_no_ip = await evaluator.evaluate(domain="sender.org", smtp_metadata=no_ip_meta)
    assert res_no_ip.status == ProtocolStatus.NOT_EVALUATED
    assert mock_resolver.total_queries == 0


@pytest.mark.asyncio
async def test_null_reverse_path_falls_back_to_helo_scope(evaluator, mock_resolver):
    # RFC 7208 Section 2.4: Bounce messages with MAIL FROM: <> evaluate HELO identity
    bounce_meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="bounce-gateway.org",
        mail_from_envelope="<>",
        is_trusted_mta=True,
    )
    mock_resolver.add_txt("bounce-gateway.org", ["v=spf1 ip4:192.0.2.1 -all"])

    res = await evaluator.evaluate(smtp_metadata=bounce_meta, scope="mfrom")
    assert res.status == ProtocolStatus.PASS
    assert res.scope == "helo"
    assert res.domain == "bounce-gateway.org"


# ==============================================================================
# 2. Basic Outcomes, Qualifiers, and Record Discovery
# ==============================================================================

@pytest.mark.asyncio
async def test_spf_pass_fail_softfail_neutral(evaluator, mock_resolver, trusted_v4_meta):
    # PASS (+)
    mock_resolver.add_txt("pass.org", ["v=spf1 +ip4:192.0.2.1 -all"])
    r_pass = await evaluator.evaluate(domain="pass.org", smtp_metadata=trusted_v4_meta)
    assert r_pass.status == ProtocolStatus.PASS

    # FAIL (-)
    mock_resolver.add_txt("fail.org", ["v=spf1 -ip4:192.0.2.1 +all"])
    r_fail = await evaluator.evaluate(domain="fail.org", smtp_metadata=trusted_v4_meta)
    assert r_fail.status == ProtocolStatus.FAIL

    # SOFTFAIL (~)
    mock_resolver.add_txt("softfail.org", ["v=spf1 ~ip4:192.0.2.1 +all"])
    r_soft = await evaluator.evaluate(domain="softfail.org", smtp_metadata=trusted_v4_meta)
    assert r_soft.status == ProtocolStatus.SOFTFAIL

    # NEUTRAL (?)
    mock_resolver.add_txt("neutral.org", ["v=spf1 ?ip4:192.0.2.1 -all"])
    r_neut = await evaluator.evaluate(domain="neutral.org", smtp_metadata=trusted_v4_meta)
    assert r_neut.status == ProtocolStatus.NEUTRAL

    # Default qualifier is PASS (+) when omitted
    mock_resolver.add_txt("default-qual.org", ["v=spf1 ip4:192.0.2.1 -all"])
    r_def = await evaluator.evaluate(domain="default-qual.org", smtp_metadata=trusted_v4_meta)
    assert r_def.status == ProtocolStatus.PASS


@pytest.mark.asyncio
async def test_no_spf_record_returns_none(evaluator, mock_resolver, trusted_v4_meta):
    mock_resolver.add_txt("other-txt.org", ["some-token=abc", "v=notspf1 -all"])
    res = await evaluator.evaluate(domain="other-txt.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.NONE


@pytest.mark.asyncio
async def test_multiple_spf_records_returns_permerror(evaluator, mock_resolver, trusted_v4_meta):
    # RFC 7208 Section 3.2: More than one SPF record is an immediate PERMERROR
    mock_resolver.add_txt("multi-spf.org", ["v=spf1 ip4:192.0.2.1 -all", "v=spf1 ip4:192.0.2.2 -all"])
    res = await evaluator.evaluate(domain="multi-spf.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PERMERROR
    assert "Multiple SPF records" in res.error_reason


@pytest.mark.asyncio
async def test_invalid_syntax_returns_permerror(evaluator, mock_resolver, trusted_v4_meta):
    mock_resolver.add_txt("invalid-syntax.org", ["v=spf1 unknown_mech:foo -all"])
    res = await evaluator.evaluate(domain="invalid-syntax.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PERMERROR
    assert "Unknown SPF mechanism" in res.error_reason


# ==============================================================================
# 3. Mechanisms: all, ip4, ip6, a, mx, ptr, exists, include
# ==============================================================================

@pytest.mark.asyncio
async def test_mechanism_ip4_and_ip6_cidr(evaluator, mock_resolver, trusted_v4_meta, trusted_v6_meta):
    # ip4 with CIDR /24
    mock_resolver.add_txt("cidr4.org", ["v=spf1 ip4:192.0.2.0/24 -all"])
    res4 = await evaluator.evaluate(domain="cidr4.org", smtp_metadata=trusted_v4_meta)
    assert res4.status == ProtocolStatus.PASS

    # ip6 with CIDR /64
    mock_resolver.add_txt("cidr6.org", ["v=spf1 ip6:2001:db8::/64 -all"])
    res6 = await evaluator.evaluate(domain="cidr6.org", smtp_metadata=trusted_v6_meta)
    assert res6.status == ProtocolStatus.PASS


@pytest.mark.asyncio
async def test_mechanism_a_with_dual_cidr(evaluator, mock_resolver, trusted_v4_meta, trusted_v6_meta):
    mock_resolver.add_txt("a-test.org", ["v=spf1 a:mail.target.com/24//64 -all"])
    mock_resolver.add_a("mail.target.com", ["192.0.2.50"])
    mock_resolver.add_aaaa("mail.target.com", ["2001:db8::50"])

    # IPv4 client matches /24
    r4 = await evaluator.evaluate(domain="a-test.org", smtp_metadata=trusted_v4_meta)
    assert r4.status == ProtocolStatus.PASS

    # IPv6 client matches //64
    r6 = await evaluator.evaluate(domain="a-test.org", smtp_metadata=trusted_v6_meta)
    assert r6.status == ProtocolStatus.PASS


@pytest.mark.asyncio
async def test_mechanism_mx(evaluator, mock_resolver, trusted_v4_meta):
    mock_resolver.add_txt("mx-test.org", ["v=spf1 mx:mx-target.org -all"])
    mock_resolver.add_mx("mx-target.org", [(10, "mail1.mx-target.org"), (20, "mail2.mx-target.org")])
    mock_resolver.add_a("mail1.mx-target.org", ["192.0.2.1"])
    mock_resolver.add_a("mail2.mx-target.org", ["198.51.100.1"])

    res = await evaluator.evaluate(domain="mx-test.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PASS


@pytest.mark.asyncio
async def test_mechanism_ptr_rfc7208_rev13_rules(evaluator, mock_resolver, trusted_v4_meta):
    # Target domain: ptr-corp.com
    # PTR lookup for 192.0.2.1 returns 2 hosts:
    # 1. isp-dynamic-pool-88.broadband.net (pre-filter mismatch -> never forward queried!)
    # 2. outbound.ptr-corp.com (matches suffix -> forward queried)
    mock_resolver.add_txt("ptr-corp.com", ["v=spf1 ptr -all"])
    mock_resolver.add_ptr("192.0.2.1", ["isp-dynamic-pool-88.broadband.net", "outbound.ptr-corp.com"])
    mock_resolver.add_a("outbound.ptr-corp.com", ["192.0.2.1"])

    res = await evaluator.evaluate(domain="ptr-corp.com", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PASS

    # Check query count: PTR lookup (+2 terms for 2 PTR records)
    assert res.dns_terms_queried == 2


@pytest.mark.asyncio
async def test_mechanism_exists(evaluator, mock_resolver, trusted_v4_meta):
    mock_resolver.add_txt("exists-test.org", ["v=spf1 exists:%{i}.validator.net -all"])
    mock_resolver.add_a("192.0.2.1.validator.net", ["127.0.0.2"])

    res = await evaluator.evaluate(domain="exists-test.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PASS


@pytest.mark.asyncio
async def test_mechanism_include_success_and_failure(evaluator, mock_resolver, trusted_v4_meta):
    # Outer includes inner
    mock_resolver.add_txt("outer.org", ["v=spf1 include:_spf.service.com -all"])
    mock_resolver.add_txt("_spf.service.com", ["v=spf1 ip4:192.0.2.1 -all"])

    res = await evaluator.evaluate(domain="outer.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PASS

    # Inner does NOT match -> outer continues to next mechanism (-all -> FAIL)
    mock_resolver.add_txt("_spf.other.com", ["v=spf1 ip4:198.51.100.1 -all"])
    mock_resolver.add_txt("outer2.org", ["v=spf1 include:_spf.other.com -all"])

    res2 = await evaluator.evaluate(domain="outer2.org", smtp_metadata=trusted_v4_meta)
    assert res2.status == ProtocolStatus.FAIL


# ==============================================================================
# 4. Modifiers & Redirect Behavior
# ==============================================================================

@pytest.mark.asyncio
async def test_redirect_modifier_behavior(evaluator, mock_resolver, trusted_v4_meta):
    # redirect= is only evaluated if all mechanisms fail to match
    mock_resolver.add_txt("source.org", ["v=spf1 ip4:10.0.0.1 redirect=target.org"])
    mock_resolver.add_txt("target.org", ["v=spf1 ip4:192.0.2.1 -all"])

    res = await evaluator.evaluate(domain="source.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PASS
    assert res.dns_terms_queried == 1  # 1 for redirect=


@pytest.mark.asyncio
async def test_redirect_to_nonexistent_record_returns_permerror(evaluator, mock_resolver, trusted_v4_meta):
    mock_resolver.add_txt("bad-redirect.org", ["v=spf1 redirect=missing-target.org"])
    # missing-target.org has no SPF record -> PERMERROR
    res = await evaluator.evaluate(domain="bad-redirect.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PERMERROR


# ==============================================================================
# 5. Resource Limits, Loops, and Edge Cases
# ==============================================================================

@pytest.mark.asyncio
async def test_recursion_loop_detection(evaluator, mock_resolver, trusted_v4_meta):
    # A includes B, B includes A
    mock_resolver.add_txt("loop-a.com", ["v=spf1 include:loop-b.com -all"])
    mock_resolver.add_txt("loop-b.com", ["v=spf1 include:loop-a.com -all"])

    res = await evaluator.evaluate(domain="loop-a.com", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PERMERROR
    assert "loop detected" in res.error_reason.lower()


@pytest.mark.asyncio
async def test_global_10_term_dns_limit_exceeded(evaluator, mock_resolver, trusted_v4_meta):
    # Record has 11 'a' mechanisms (11 DNS terms > 10 global limit)
    mechs = " ".join([f"a:host{i}.limit.com" for i in range(11)])
    mock_resolver.add_txt("limit.com", [f"v=spf1 {mechs} -all"])
    for i in range(11):
        mock_resolver.add_a(f"host{i}.limit.com", [f"10.0.0.{i}"])

    res = await evaluator.evaluate(domain="limit.com", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PERMERROR
    assert "global limit of 10 DNS terms exceeded" in res.error_reason


@pytest.mark.asyncio
async def test_mx_subordinate_address_limit_exceeded_returns_permerror(evaluator, mock_resolver, trusted_v4_meta):
    # MX record returns 1 host, but that host publishes 11 A records (> 10 limit)
    mock_resolver.add_txt("mx-limit.org", ["v=spf1 mx -all"])
    mock_resolver.add_mx("mx-limit.org", [(10, "big-mx.org")])
    mock_resolver.add_a("big-mx.org", [f"198.51.100.{i}" for i in range(12)])

    res = await evaluator.evaluate(domain="mx-limit.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PERMERROR
    assert "MX subordinate address record limit" in res.error_reason


@pytest.mark.asyncio
async def test_ptr_subordinate_address_limit_ignores_excess_without_permerror(evaluator, mock_resolver, trusted_v4_meta):
    # PTR host returns 15 forward addresses. The 15th matches client_ip.
    # RFC 7208 Section 4.6.4: Excess records beyond the first 10 are IGNORED, so
    # the 15th address is not matched, resulting in FAIL, but NOT PERMERROR!
    mock_resolver.add_txt("ptr-limit.org", ["v=spf1 ptr -all"])
    mock_resolver.add_ptr("192.0.2.1", ["host.ptr-limit.org"])

    addresses = [f"10.0.0.{i}" for i in range(10)] + ["192.0.2.1"]  # 192.0.2.1 is at index 10 (11th)
    mock_resolver.add_a("host.ptr-limit.org", addresses)

    res = await evaluator.evaluate(domain="ptr-limit.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.FAIL  # 11th record ignored; mechanism did not match -> -all evaluates to FAIL


@pytest.mark.asyncio
async def test_ptr_global_accounting_trace_15_ptr_records_exceeds_global_limit(evaluator, mock_resolver, trusted_v4_meta):
    # 15 PTR records returned for client IP.
    # REV13: The 15 PTR records contribute +15 to the global term counter.
    # 15 > 10 global limit -> PERMERROR immediately!
    mock_resolver.add_txt("ptr-15.org", ["v=spf1 ptr -all"])
    ptr_hosts = [f"ptr{i}.ptr-15.org" for i in range(15)]
    mock_resolver.add_ptr("192.0.2.1", ptr_hosts)

    res = await evaluator.evaluate(domain="ptr-15.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PERMERROR
    assert "global limit of 10 DNS terms exceeded by PTR resource records" in res.error_reason


@pytest.mark.asyncio
async def test_void_lookup_budget_exceeded_returns_permerror(evaluator, mock_resolver, trusted_v4_meta):
    # 3 void lookups (> max 2 limit)
    mock_resolver.add_txt("voids.org", ["v=spf1 a:nx1.com a:nx2.com a:nx3.com -all"])
    # nx1, nx2, nx3 all return NXDOMAIN
    res = await evaluator.evaluate(domain="voids.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PERMERROR
    assert "void lookup limit exceeded" in res.error_reason


@pytest.mark.asyncio
async def test_uts46_internationalized_domains(evaluator, mock_resolver, trusted_v4_meta):
    # Internationalized domain with non-ASCII characters: "münchen.de" -> xn--mnchen-3ya.de
    mock_resolver.add_txt("xn--mnchen-3ya.de", ["v=spf1 ip4:192.0.2.1 -all"])

    # Evaluating with native UTF-8 domain
    res = await evaluator.evaluate(domain="münchen.de", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PASS
    assert res.domain == "xn--mnchen-3ya.de"


@pytest.mark.asyncio
async def test_macro_p_evaluates_to_indeterminate(evaluator, mock_resolver, trusted_v4_meta):
    # %{p} is unsupported for security reasons per REV13
    mock_resolver.add_txt("macro-p.org", ["v=spf1 exists:%{p}.validator.net -all"])
    res = await evaluator.evaluate(domain="macro-p.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.INDETERMINATE
    assert "Macro %{p} is unsupported" in res.error_reason


@pytest.mark.asyncio
async def test_dns_transient_failures_return_temperror(evaluator, mock_resolver, trusted_v4_meta):
    mock_resolver.set_timeout("timeout-spf.org")
    res = await evaluator.evaluate(domain="timeout-spf.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.TEMPERROR
    assert "DNS transient error" in res.error_reason


# ==============================================================================
# 6. Audit Step 3.5A Invariant Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_mx_multiple_hosts_combined_over_10_individual_under_10_allowed(evaluator, mock_resolver, trusted_v4_meta):
    # RFC 7208 Section 4.6.4: The subordinate 10-address limit applies PER MX RECORD (per host).
    # Two MX hosts: host1 has 8 addresses, host2 has 8 addresses (combined = 16 > 10).
    # Since neither individual host exceeds 10, this is completely valid!
    mock_resolver.add_txt("multi-mx-valid.org", ["v=spf1 mx -all"])
    mock_resolver.add_mx("multi-mx-valid.org", [(10, "mx1.multi-mx-valid.org"), (20, "mx2.multi-mx-valid.org")])

    mock_resolver.add_a("mx1.multi-mx-valid.org", [f"198.51.100.{i}" for i in range(8)])
    mock_resolver.add_a("mx2.multi-mx-valid.org", [f"203.0.113.{i}" for i in range(7)] + ["192.0.2.1"])

    res = await evaluator.evaluate(domain="multi-mx-valid.org", smtp_metadata=trusted_v4_meta)
    # Connecting IP 192.0.2.1 matches in mx2 -> PASS, no PERMERROR
    assert res.status == ProtocolStatus.PASS


@pytest.mark.asyncio
async def test_diamond_dag_includes_without_false_loop_detection(evaluator, mock_resolver, trusted_v4_meta):
    # Diamond include graph (DAG):
    # root.org includes branch1.org and branch2.org.
    # Both branch1.org and branch2.org legitimately include common-auth.org.
    # When active recursion stack is used, common-auth.org is evaluated in branch1 (finished and popped),
    # then evaluated in branch2 without false loop detection!
    mock_resolver.add_txt("root.org", ["v=spf1 include:branch1.org include:branch2.org -all"])
    mock_resolver.add_txt("branch1.org", ["v=spf1 include:common-auth.org ?all"])
    mock_resolver.add_txt("branch2.org", ["v=spf1 include:common-auth.org -all"])
    mock_resolver.add_txt("common-auth.org", ["v=spf1 ip4:192.0.2.1 -all"])

    res = await evaluator.evaluate(domain="root.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PASS


@pytest.mark.asyncio
async def test_circular_include_cycle_detected(evaluator, mock_resolver, trusted_v4_meta):
    # Direct cycle: A -> B -> C -> A
    mock_resolver.add_txt("cycle-a.org", ["v=spf1 include:cycle-b.org -all"])
    mock_resolver.add_txt("cycle-b.org", ["v=spf1 include:cycle-c.org -all"])
    mock_resolver.add_txt("cycle-c.org", ["v=spf1 include:cycle-a.org -all"])

    res = await evaluator.evaluate(domain="cycle-a.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PERMERROR
    assert "loop detected" in res.error_reason.lower()


@pytest.mark.asyncio
async def test_null_reverse_path_postmaster_helo_semantics(evaluator, mock_resolver):
    # Genuinely empty reverse-path ("" or "<>") sets identity to postmaster@<helo>
    meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="relay.trusted-mta.com",
        mail_from_envelope="<>",
        is_trusted_mta=True,
    )
    # Record verifies macro expansion of postmaster and helo domain
    mock_resolver.add_txt("relay.trusted-mta.com", ["v=spf1 exists:%{l}.%{o} -all"])
    mock_resolver.add_a("postmaster.relay.trusted-mta.com", ["127.0.0.2"])

    res = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res.status == ProtocolStatus.PASS
    assert res.scope == "helo"
    assert res.domain == "relay.trusted-mta.com"
    assert res.is_null_reverse_path is True
    assert res.is_synthesized_mfrom is True
    assert res.is_standalone_helo is False
    assert res.identity == "postmaster@relay.trusted-mta.com"

    # In contrast, an explicitly requested standalone HELO evaluation has is_standalone_helo=True
    res_standalone = await evaluator.evaluate(smtp_metadata=meta, scope="helo")
    assert res_standalone.status == ProtocolStatus.PASS
    assert res_standalone.is_standalone_helo is True
    assert res_standalone.is_synthesized_mfrom is False
    assert res_standalone.is_null_reverse_path is False


@pytest.mark.asyncio
async def test_ordinary_bounce_mailbox_not_confused_with_null_reverse_path(evaluator, mock_resolver):
    # A mailbox named 'bounce@corp.org' or 'postmaster@corp.org' is an ordinary mailbox, NOT a null reverse-path!
    meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="helo-gateway.net",
        mail_from_envelope="postmaster@corp.org",
        is_trusted_mta=True,
    )
    mock_resolver.add_txt("corp.org", ["v=spf1 ip4:192.0.2.1 -all"])

    res = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res.status == ProtocolStatus.PASS
    assert res.scope == "mfrom"
    assert res.domain == "corp.org"


@pytest.mark.asyncio
async def test_null_reverse_path_missing_helo_returns_none(evaluator):
    meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain=None,
        mail_from_envelope="",
        is_trusted_mta=True,
    )
    res = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res.status == ProtocolStatus.NONE
    assert "Null reverse-path without HELO" in res.error_reason


@pytest.mark.asyncio
async def test_null_reverse_path_untrusted_metadata_returns_not_evaluated(evaluator):
    meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="gateway.org",
        mail_from_envelope="<>",
        is_trusted_mta=False,
    )
    res = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res.status == ProtocolStatus.NOT_EVALUATED


@pytest.mark.asyncio
async def test_redirect_ignored_when_all_mechanism_appears(evaluator, mock_resolver, trusted_v4_meta):
    # RFC 7208 Section 6.1: If an 'all' mechanism appears anywhere in the record,
    # redirect modifier MUST NOT be evaluated.
    mock_resolver.add_txt("all-with-redirect.org", ["v=spf1 ip4:10.0.0.1 -all redirect=target.org"])
    # Connecting IP 192.0.2.1 will hit -all -> FAIL. Target.org must NOT be evaluated!
    mock_resolver.add_txt("target.org", ["v=spf1 +all"])

    res = await evaluator.evaluate(domain="all-with-redirect.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.FAIL
    assert res.dns_terms_queried == 0  # redirect target was never queried


@pytest.mark.asyncio
async def test_duplicate_redirect_or_exp_modifiers_produce_permerror(evaluator, mock_resolver, trusted_v4_meta):
    # RFC 7208 Section 6: Duplicate redirect= is a PERMERROR
    mock_resolver.add_txt("dup-red.org", ["v=spf1 redirect=t1.org redirect=t2.org"])
    res_red = await evaluator.evaluate(domain="dup-red.org", smtp_metadata=trusted_v4_meta)
    assert res_red.status == ProtocolStatus.PERMERROR
    assert "Duplicate 'redirect' modifier" in res_red.error_reason

    # Duplicate exp= is a PERMERROR
    mock_resolver.add_txt("dup-exp.org", ["v=spf1 exp=e1.org exp=e2.org -all"])
    res_exp = await evaluator.evaluate(domain="dup-exp.org", smtp_metadata=trusted_v4_meta)
    assert res_exp.status == ProtocolStatus.PERMERROR
    assert "Duplicate 'exp' modifier" in res_exp.error_reason


@pytest.mark.asyncio
async def test_unknown_modifiers_are_ignored_even_if_repeated(evaluator, mock_resolver, trusted_v4_meta):
    # RFC 7208 Section 6: Unrecognized modifiers must be ignored, even if repeated
    mock_resolver.add_txt("unknown-mod.org", ["v=spf1 unknown1=foo unknown1=bar ip4:192.0.2.1 -all"])
    res = await evaluator.evaluate(domain="unknown-mod.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PASS


@pytest.mark.asyncio
async def test_include_propagates_temperror_and_permerror(evaluator, mock_resolver, trusted_v4_meta):
    # 1. Include propagates TEMPERROR
    mock_resolver.add_txt("inc-temp.org", ["v=spf1 include:temp-inner.org -all"])
    mock_resolver.set_timeout("temp-inner.org")
    r_temp = await evaluator.evaluate(domain="inc-temp.org", smtp_metadata=trusted_v4_meta)
    assert r_temp.status == ProtocolStatus.TEMPERROR

    # 2. Include propagates PERMERROR
    mock_resolver.add_txt("inc-perm.org", ["v=spf1 include:perm-inner.org -all"])
    mock_resolver.add_txt("perm-inner.org", ["v=spf1 invalid_mech:bad -all"])
    r_perm = await evaluator.evaluate(domain="inc-perm.org", smtp_metadata=trusted_v4_meta)
    assert r_perm.status == ProtocolStatus.PERMERROR


@pytest.mark.asyncio
async def test_include_target_missing_spf_produces_permerror(evaluator, mock_resolver, trusted_v4_meta):
    # RFC 7208 Section 5.2: If included domain does not publish SPF, result is PERMERROR
    mock_resolver.add_txt("inc-missing.org", ["v=spf1 include:no-spf-target.org -all"])
    # no-spf-target.org has no TXT
    res = await evaluator.evaluate(domain="inc-missing.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PERMERROR
    assert "has no valid SPF record" in res.error_reason


@pytest.mark.asyncio
async def test_implicit_no_match_result_is_neutral(evaluator, mock_resolver, trusted_v4_meta):
    # RFC 7208 Section 4.7: If all mechanisms fail to match and no redirect exists, result is NEUTRAL
    mock_resolver.add_txt("implicit-neutral.org", ["v=spf1 ip4:10.0.0.1 ip4:10.0.0.2"])
    res = await evaluator.evaluate(domain="implicit-neutral.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.NEUTRAL


@pytest.mark.asyncio
async def test_macro_expansion_and_escaping_forms(evaluator, mock_resolver, trusted_v4_meta):
    # 1. Test macro expansion helper directly across all supported macro letters and escapes:
    # Supported letters: %{s}, %{l}, %{o}, %{d}, %{i}, %{v}, %{h}
    # Supported escape sequences: %%, %_, %-
    dummy_ctx = _SPFEvaluationContext(
        client_ip=ipaddress.ip_address("192.0.2.1"),
        sender_domain="sender.org",
        mail_from="alice@sender.org",
        helo_domain="mail.sender.org",
        resolver=mock_resolver,
        config=AuthProtocolsConfig(),
    )
    assert evaluator._expand_macros("%%", "example.com", dummy_ctx) == "%"
    assert evaluator._expand_macros("%_", "example.com", dummy_ctx) == " "
    assert evaluator._expand_macros("%-", "example.com", dummy_ctx) == "%20"
    assert evaluator._expand_macros("%{s}", "example.com", dummy_ctx) == "alice@sender.org"
    assert evaluator._expand_macros("%{l}", "example.com", dummy_ctx) == "alice"
    assert evaluator._expand_macros("%{o}", "example.com", dummy_ctx) == "sender.org"
    assert evaluator._expand_macros("%{d}", "example.com", dummy_ctx) == "example.com"
    assert evaluator._expand_macros("%{i}", "example.com", dummy_ctx) == "192.0.2.1"
    assert evaluator._expand_macros("%{v}", "example.com", dummy_ctx) == "in-addr"
    assert evaluator._expand_macros("%{h}", "example.com", dummy_ctx) == "mail.sender.org"

    # 2. Test exists mechanism with macros expanding to a valid DNS domain name
    mock_resolver.add_txt(
        "macro-valid.org",
        ["v=spf1 exists:%{l}.%{v}.%{h}.test.org -all"],
    )
    # Expected target domain: alice.in-addr.mail.sender.org.test.org
    mock_resolver.add_a("alice.in-addr.mail.sender.org.test.org", ["127.0.0.2"])
    res = await evaluator.evaluate(domain="macro-valid.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PASS

    # 3. Test RFC 7208 Section 7.1: If macro expansion produces an invalid domain name
    # (e.g. %{s} containing '@' or %_ containing ' ' in an exists domain-spec), result is PERMERROR
    mock_resolver.add_txt(
        "macro-invalid-dns.org",
        ["v=spf1 exists:%{s}.test.org -all"],
    )
    res_inv = await evaluator.evaluate(domain="macro-invalid-dns.org", smtp_metadata=trusted_v4_meta)
    assert res_inv.status == ProtocolStatus.PERMERROR
    assert "Invalid domain in exists mechanism" in res_inv.error_reason


@pytest.mark.asyncio
async def test_rfc7208_macro_transformers_numeric(evaluator, mock_resolver, trusted_v4_meta):
    # RFC 7208 Section 7.2: Numeric transformers keep N right-hand parts
    dummy_ctx = _SPFEvaluationContext(
        client_ip=ipaddress.ip_address("192.0.2.1"),
        sender_domain="example.com",
        mail_from="alice.smith@example.com",
        helo_domain="mail.example.com",
        resolver=mock_resolver,
        config=AuthProtocolsConfig(),
    )
    assert evaluator._expand_macros("%{d1}", "email.example.com", dummy_ctx) == "com"
    assert evaluator._expand_macros("%{d2}", "email.example.com", dummy_ctx) == "example.com"
    assert evaluator._expand_macros("%{d3}", "email.example.com", dummy_ctx) == "email.example.com"
    assert evaluator._expand_macros("%{d4}", "email.example.com", dummy_ctx) == "email.example.com"
    assert evaluator._expand_macros("%{l1}", "email.example.com", dummy_ctx) == "smith"

    # Evaluation test
    mock_resolver.add_txt("num-trans.org", ["v=spf1 exists:%{d2}.test.org -all"])
    mock_resolver.add_a("num-trans.org.test.org", ["127.0.0.2"])
    res = await evaluator.evaluate(domain="num-trans.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PASS


@pytest.mark.asyncio
async def test_rfc7208_macro_transformers_reverse(evaluator, mock_resolver, trusted_v4_meta):
    # RFC 7208 Section 7.2 & 7.3: Reverse transformer 'r'
    dummy_ctx_v4 = _SPFEvaluationContext(
        client_ip=ipaddress.ip_address("192.0.2.1"),
        sender_domain="example.com",
        mail_from="alice@example.com",
        helo_domain="mail.example.com",
        resolver=mock_resolver,
        config=AuthProtocolsConfig(),
    )
    assert evaluator._expand_macros("%{dr}", "email.example.com", dummy_ctx_v4) == "com.example.email"
    assert evaluator._expand_macros("%{ir}", "email.example.com", dummy_ctx_v4) == "1.2.0.192"

    # IPv6 reverse test (RFC 7208 Section 7.3 example with 2001:DB8::CB01)
    dummy_ctx_v6 = _SPFEvaluationContext(
        client_ip=ipaddress.ip_address("2001:db8::cb01"),
        sender_domain="example.com",
        mail_from="alice@example.com",
        helo_domain="mail.example.com",
        resolver=mock_resolver,
        config=AuthProtocolsConfig(),
    )
    assert evaluator._expand_macros("%{i}", "example.com", dummy_ctx_v6) == (
        "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"
    )
    assert evaluator._expand_macros("%{ir}", "example.com", dummy_ctx_v6) == (
        "2.0.0.1.0.d.b.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.c.b.0.1"
    )

    # Evaluation test for IPv4 reverse lookup pattern in exists mechanism
    mock_resolver.add_txt("rev-macro.org", ["v=spf1 exists:%{ir}.%{v}._spf.test.org -all"])
    mock_resolver.add_a("1.2.0.192.in-addr._spf.test.org", ["127.0.0.2"])
    res = await evaluator.evaluate(domain="rev-macro.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PASS


@pytest.mark.asyncio
async def test_rfc7208_macro_transformers_numeric_plus_reverse(evaluator, mock_resolver, trusted_v4_meta):
    # RFC 7208 Section 7.3: %{d2r} on email.example.com produces example.email
    dummy_ctx = _SPFEvaluationContext(
        client_ip=ipaddress.ip_address("192.0.2.1"),
        sender_domain="example.com",
        mail_from="alice.smith@example.com",
        helo_domain="mail.example.com",
        resolver=mock_resolver,
        config=AuthProtocolsConfig(),
    )
    assert evaluator._expand_macros("%{d2r}", "email.example.com", dummy_ctx) == "example.email"
    assert evaluator._expand_macros("%{l1r}", "email.example.com", dummy_ctx) == "alice"

    # Evaluation test
    mock_resolver.add_txt("combo.corp.org", ["v=spf1 exists:%{d2r}.test.org -all"])
    mock_resolver.add_a("corp.combo.test.org", ["127.0.0.2"])
    res = await evaluator.evaluate(domain="combo.corp.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PASS


@pytest.mark.asyncio
async def test_rfc7208_macro_transformers_custom_delimiters(evaluator, mock_resolver):
    # RFC 7208 Section 7.2 & 7.3: Delimiters '.', '-', '+', ',', '/', '_', '='
    dummy_ctx = _SPFEvaluationContext(
        client_ip=ipaddress.ip_address("192.0.2.1"),
        sender_domain="example.com",
        mail_from="strong-bad@example.com",
        helo_domain="mail.example.com",
        resolver=mock_resolver,
        config=AuthProtocolsConfig(),
    )
    assert evaluator._expand_macros("%{l-}", "example.com", dummy_ctx) == "strong.bad"
    assert evaluator._expand_macros("%{lr-}", "example.com", dummy_ctx) == "bad.strong"
    assert evaluator._expand_macros("%{l1r-}", "example.com", dummy_ctx) == "strong"

    # Test all RFC delimiters: +, ,, /, _, =
    ctx_plus = _SPFEvaluationContext(
        client_ip=ipaddress.ip_address("192.0.2.1"),
        sender_domain="example.com",
        mail_from="part1+part2@example.com",
        helo_domain="mail.example.com",
        resolver=mock_resolver,
        config=AuthProtocolsConfig(),
    )
    assert evaluator._expand_macros("%{l+}", "example.com", ctx_plus) == "part1.part2"

    ctx_multi = _SPFEvaluationContext(
        client_ip=ipaddress.ip_address("192.0.2.1"),
        sender_domain="example.com",
        mail_from="p1-p2.p3_p4=p5/p6,p7@example.com",
        helo_domain="mail.example.com",
        resolver=mock_resolver,
        config=AuthProtocolsConfig(),
    )
    assert evaluator._expand_macros("%{l.-_+/=,}", "example.com", ctx_multi) == (
        "p1.p2.p3.p4.p5.p6.p7"
    )

    # Evaluation test with custom delimiter
    meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="mail.example.com",
        mail_from_envelope="strong-bad@example.com",
        is_trusted_mta=True,
    )
    mock_resolver.add_txt("delim-test.org", ["v=spf1 exists:%{lr-}.test.org -all"])
    mock_resolver.add_a("bad.strong.test.org", ["127.0.0.2"])
    res = await evaluator.evaluate(domain="delim-test.org", smtp_metadata=meta)
    assert res.status == ProtocolStatus.PASS


@pytest.mark.asyncio
async def test_rfc7208_macro_max_parts_127_and_domain_limits(evaluator, mock_resolver, trusted_v4_meta):
    # RFC 7208 Section 7.4 / 7.2: Implementations MUST support at least 127 parts.
    # 1. Verify abstract string expansion with 130 parts:
    labels_130 = [f"p{i}" for i in range(130)]
    str_130 = ".".join(labels_130)
    dummy_ctx = _SPFEvaluationContext(
        client_ip=ipaddress.ip_address("192.0.2.1"),
        sender_domain="example.com",
        mail_from="alice@example.com",
        helo_domain="mail.example.com",
        resolver=mock_resolver,
        config=AuthProtocolsConfig(),
    )
    expanded_127 = evaluator._expand_macros("%{d127}", str_130, dummy_ctx)
    parts_127 = expanded_127.split(".")
    assert len(parts_127) == 127
    assert parts_127[0] == "p3"
    assert parts_127[-1] == "p129"

    # 2. Valid 127-label DNS domain within the RFC 1035 / RFC 7208 253-character limit:
    # 127 single-character labels + 126 dots = exactly 253 characters!
    valid_127_labels = ["a"] * 127
    valid_127_domain = ".".join(valid_127_labels)
    assert len(valid_127_domain) == 253
    # Validates cleanly under normalize_domain without length error
    assert evaluator.normalize_domain(valid_127_domain) == valid_127_domain

    # %{d127} on valid 127-label domain returns all 127 parts
    expanded_valid_127 = evaluator._expand_macros("%{d127}", valid_127_domain, dummy_ctx)
    assert expanded_valid_127 == valid_127_domain
    assert len(expanded_valid_127.split(".")) == 127

    # 3. Transformer requesting MORE parts than available returns ALL available parts:
    # RFC 7208 Section 7.2: "If the number of parts is less than the number specified, all parts are kept."
    # Case A: Requesting 200 parts on the 127-label domain
    expanded_over_127 = evaluator._expand_macros("%{d200}", valid_127_domain, dummy_ctx)
    assert expanded_over_127 == valid_127_domain
    assert len(expanded_over_127.split(".")) == 127

    # Case B: Requesting 127 parts on a 3-label domain (email.example.com)
    expanded_over_3 = evaluator._expand_macros("%{d127}", "email.example.com", dummy_ctx)
    assert expanded_over_3 == "email.example.com"

    # Case C: Requesting 5 parts on a 3-label domain
    assert evaluator._expand_macros("%{d5}", "email.example.com", dummy_ctx) == "email.example.com"

    # Case D: Requesting 10 parts on local-part alice.smith (2 parts)
    ctx_split_local = _SPFEvaluationContext(
        client_ip=ipaddress.ip_address("192.0.2.1"),
        sender_domain="example.com",
        mail_from="alice.smith@example.com",
        helo_domain="mail.example.com",
        resolver=mock_resolver,
        config=AuthProtocolsConfig(),
    )
    assert evaluator._expand_macros("%{l10}", "example.com", ctx_split_local) == "alice.smith"

    # 4. Enforce strict DNS domain presentation limits (never weakened):
    # A 128-label domain of 1-char labels: 128 chars + 127 dots = 255 chars (> 253)
    invalid_128_domain = ".".join(["a"] * 128)
    assert len(invalid_128_domain) == 255
    with pytest.raises(ValueError, match="exceeds RFC 7208 limit of 253 characters"):
        evaluator.normalize_domain(invalid_128_domain)

    # In SPF evaluation, exceeding 253 characters produces PERMERROR
    mock_resolver.add_txt("len-overflow.org", [f"v=spf1 exists:{invalid_128_domain} +all"])
    res_len = await evaluator.evaluate(domain="len-overflow.org", smtp_metadata=trusted_v4_meta)
    assert res_len.status == ProtocolStatus.PERMERROR
    assert "exceeds RFC 7208 limit" in res_len.error_reason

    # Label exceeding 63 characters produces PERMERROR
    invalid_label_domain = f"{'a' * 64}.example.com"
    with pytest.raises(ValueError, match="exceeds RFC 7208 limit of 63 characters"):
        evaluator.normalize_domain(invalid_label_domain)


@pytest.mark.asyncio
async def test_rfc7208_uppercase_macro_url_encoding(evaluator, mock_resolver, trusted_v4_meta):
    # RFC 7208 Section 7.3: Uppercase macro letters expand exactly as their lowercase equivalents,
    # and then the whole resulting string is URL-escaped using RFC 3986 unreserved rules.

    # 1. Test all supported uppercase letters: %S, %L, %O, %D, %I, %V, %H
    complex_ctx = _SPFEvaluationContext(
        client_ip=ipaddress.ip_address("192.0.2.1"),
        sender_domain="ex ample.org",
        mail_from="user name+tag@ex ample.org",
        helo_domain="mail srv.org",
        resolver=mock_resolver,
        config=AuthProtocolsConfig(),
    )
    # %S URL-encodes sender: spaces -> %20, + -> %2B, @ -> %40 (dots remain unescaped)
    assert evaluator._expand_macros("%{S}", "curr domain.org", complex_ctx) == (
        "user%20name%2Btag%40ex%20ample.org"
    )
    # %s preserves normal unencoded sender
    assert evaluator._expand_macros("%{s}", "curr domain.org", complex_ctx) == (
        "user name+tag@ex ample.org"
    )

    # %L URL-encodes local-part
    assert evaluator._expand_macros("%{L}", "curr domain.org", complex_ctx) == (
        "user%20name%2Btag"
    )
    assert evaluator._expand_macros("%{l}", "curr domain.org", complex_ctx) == (
        "user name+tag"
    )

    # %O URL-encodes sender domain
    assert evaluator._expand_macros("%{O}", "curr domain.org", complex_ctx) == (
        "ex%20ample.org"
    )
    assert evaluator._expand_macros("%{o}", "curr domain.org", complex_ctx) == (
        "ex ample.org"
    )

    # %D URL-encodes current evaluation domain
    assert evaluator._expand_macros("%{D}", "curr domain.org", complex_ctx) == (
        "curr%20domain.org"
    )
    assert evaluator._expand_macros("%{d}", "curr domain.org", complex_ctx) == (
        "curr domain.org"
    )

    # %H URL-encodes HELO identity
    assert evaluator._expand_macros("%{H}", "curr domain.org", complex_ctx) == (
        "mail%20srv.org"
    )
    assert evaluator._expand_macros("%{h}", "curr domain.org", complex_ctx) == (
        "mail srv.org"
    )

    # %I and %V on IPv4 client
    assert evaluator._expand_macros("%{I}", "curr domain.org", complex_ctx) == "192.0.2.1"
    assert evaluator._expand_macros("%{V}", "curr domain.org", complex_ctx) == "in-addr"

    # 2. Non-ASCII characters and RFC 3986 reserved characters URL-encoding:
    intl_ctx = _SPFEvaluationContext(
        client_ip=ipaddress.ip_address("192.0.2.1"),
        sender_domain="bäcker.de",
        mail_from="münchen@bäcker.de",
        helo_domain="münchen-mail.de",
        resolver=mock_resolver,
        config=AuthProtocolsConfig(),
    )
    assert evaluator._expand_macros("%{L}", "test.org", intl_ctx) == "m%C3%BCnchen"
    assert evaluator._expand_macros("%{l}", "test.org", intl_ctx) == "münchen"
    assert evaluator._expand_macros("%{O}", "test.org", intl_ctx) == "b%C3%A4cker.de"
    assert evaluator._expand_macros("%{o}", "test.org", intl_ctx) == "bäcker.de"

    # Other reserved characters in local-part: '/', '=', ','
    reserved_ctx = _SPFEvaluationContext(
        client_ip=ipaddress.ip_address("192.0.2.1"),
        sender_domain="example.org",
        mail_from="user/sub=1,2@example.org",
        helo_domain="mail.example.org",
        resolver=mock_resolver,
        config=AuthProtocolsConfig(),
    )
    assert evaluator._expand_macros("%{L}", "test.org", reserved_ctx) == "user%2Fsub%3D1%2C2"
    assert evaluator._expand_macros("%{l}", "test.org", reserved_ctx) == "user/sub=1,2"

    # 3. RFC 7208 §7.3 Processing Order:
    # Delimiter splitting, reversal, and truncation happen on the raw value FIRST,
    # rejoined with '.', and THEN the whole resulting string is URL-escaped.

    # Case A: %{S+} versus %{s+} with a sender containing '+'
    # Raw sender: 'user name+tag@ex ample.org'
    # Split on '+' -> ['user name', 'tag@ex ample.org']
    # Rejoin with '.' -> 'user name.tag@ex ample.org'
    # %s+: not uppercase -> 'user name.tag@ex ample.org'
    # %S+: uppercase -> URL-encode('user name.tag@ex ample.org') -> 'user%20name.tag%40ex%20ample.org'
    assert evaluator._expand_macros("%{s+}", "test.org", complex_ctx) == (
        "user name.tag@ex ample.org"
    )
    assert evaluator._expand_macros("%{S+}", "test.org", complex_ctx) == (
        "user%20name.tag%40ex%20ample.org"
    )

    # Case B: %{L-} and %{l-} with a local-part containing spaces and dots
    dash_space_ctx = _SPFEvaluationContext(
        client_ip=ipaddress.ip_address("192.0.2.1"),
        sender_domain="example.org",
        mail_from="foo bar.baz-qux@example.org",
        helo_domain="mail.example.org",
        resolver=mock_resolver,
        config=AuthProtocolsConfig(),
    )
    # Raw local-part: 'foo bar.baz-qux'
    # Split on '-' -> ['foo bar.baz', 'qux']
    # Rejoin with '.' -> 'foo bar.baz.qux'
    # %l-: not uppercase -> 'foo bar.baz.qux'
    # %L-: uppercase -> URL-encode('foo bar.baz.qux') -> 'foo%20bar.baz.qux'
    assert evaluator._expand_macros("%{l-}", "test.org", dash_space_ctx) == (
        "foo bar.baz.qux"
    )
    assert evaluator._expand_macros("%{L-}", "test.org", dash_space_ctx) == (
        "foo%20bar.baz.qux"
    )

    # Case C: Uppercase with numeric transformers and reversal
    rev_upper_ctx = _SPFEvaluationContext(
        client_ip=ipaddress.ip_address("192.0.2.1"),
        sender_domain="example.org",
        mail_from="fi rst.la st@example.org",
        helo_domain="mail.example.org",
        resolver=mock_resolver,
        config=AuthProtocolsConfig(),
    )
    # %{Lr} on local-part 'fi rst.la st':
    # Split on '.' -> ['fi rst', 'la st'], reversed -> ['la st', 'fi rst'], rejoin -> 'la st.fi rst'
    # URL-encode -> 'la%20st.fi%20rst'
    assert evaluator._expand_macros("%{Lr}", "test.org", rev_upper_ctx) == (
        "la%20st.fi%20rst"
    )
    # %{L1r}:
    # Reversal -> ['la st', 'fi rst'], keep 1 right-hand part -> ['fi rst'], rejoin -> 'fi rst'
    # URL-encode -> 'fi%20rst'
    assert evaluator._expand_macros("%{L1r}", "test.org", rev_upper_ctx) == (
        "fi%20rst"
    )
    # %{D2r} on current domain 'corp.domain.org':
    assert evaluator._expand_macros("%{D2r}", "corp.domain.org", rev_upper_ctx) == (
        "domain.corp"
    )

    # 4. Security Check: URL-encoding CANNOT bypass domain validation:
    # Injected '%' from URL-encoded characters (like %40, %20, %C3%BC) is strictly illegal in DNS hostnames
    # and MUST produce PERMERROR, never PASS or FAIL!
    mock_resolver.add_txt("url-bypass-test.org", ["v=spf1 exists:%{S}.validator.net +all"])
    res_bypass = await evaluator.evaluate(domain="url-bypass-test.org", smtp_metadata=trusted_v4_meta)
    assert res_bypass.status == ProtocolStatus.PERMERROR
    assert "Invalid characters in DNS label" in res_bypass.error_reason

    # Local-part with spaces via %L
    space_meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="mail.sender.org",
        mail_from_envelope="john doe@sender.org",
        is_trusted_mta=True,
    )
    mock_resolver.add_txt("space-url-test.org", ["v=spf1 exists:%{L}.validator.net +all"])
    res_space = await evaluator.evaluate(domain="space-url-test.org", smtp_metadata=space_meta)
    assert res_space.status == ProtocolStatus.PERMERROR
    assert "Invalid characters in DNS label" in res_space.error_reason


@pytest.mark.asyncio
async def test_rfc7208_macro_syntax_rejection_never_produces_pass_or_fail(
    evaluator, mock_resolver, trusted_v4_meta
):
    # All malformed or illegal macro forms must be rejected as PERMERROR or INDETERMINATE,
    # and MUST NEVER produce PASS or FAIL even if a trailing '+all' is present!

    # 1. Unbraced macro forms (%d, %s)
    mock_resolver.add_txt("bad-unbraced-d.org", ["v=spf1 exists:%d.validator.net +all"])
    res1 = await evaluator.evaluate(domain="bad-unbraced-d.org", smtp_metadata=trusted_v4_meta)
    assert res1.status == ProtocolStatus.PERMERROR
    assert "Invalid unbraced macro" in res1.error_reason

    mock_resolver.add_txt("bad-unbraced-s.org", ["v=spf1 exists:%s.validator.net +all"])
    res2 = await evaluator.evaluate(domain="bad-unbraced-s.org", smtp_metadata=trusted_v4_meta)
    assert res2.status == ProtocolStatus.PERMERROR
    assert "Invalid unbraced macro" in res2.error_reason

    # 2. Zero numeric transformer %{d0} (RFC 7208 Section 7.2 syntax error)
    mock_resolver.add_txt("bad-zero-trans.org", ["v=spf1 exists:%{d0}.validator.net +all"])
    res3 = await evaluator.evaluate(domain="bad-zero-trans.org", smtp_metadata=trusted_v4_meta)
    assert res3.status == ProtocolStatus.PERMERROR
    assert "Invalid zero numeric transformer" in res3.error_reason

    # 3. Invalid transformer order %{dr2} (digits must precede 'r')
    mock_resolver.add_txt("bad-trans-order.org", ["v=spf1 exists:%{dr2}.validator.net +all"])
    res4 = await evaluator.evaluate(domain="bad-trans-order.org", smtp_metadata=trusted_v4_meta)
    assert res4.status == ProtocolStatus.PERMERROR
    assert "Malformed macro transformer" in res4.error_reason

    # 4. Invalid transformer characters %{d2z}
    mock_resolver.add_txt("bad-trans-char.org", ["v=spf1 exists:%{d2z}.validator.net +all"])
    res5 = await evaluator.evaluate(domain="bad-trans-char.org", smtp_metadata=trusted_v4_meta)
    assert res5.status == ProtocolStatus.PERMERROR

    # 5. Invalid delimiter characters %{d?}
    mock_resolver.add_txt("bad-delim.org", ["v=spf1 exists:%{d?}.validator.net +all"])
    res6 = await evaluator.evaluate(domain="bad-delim.org", smtp_metadata=trusted_v4_meta)
    assert res6.status == ProtocolStatus.PERMERROR

    # 6. Empty macro %{}
    mock_resolver.add_txt("empty-macro.org", ["v=spf1 exists:%{}.validator.net +all"])
    res7 = await evaluator.evaluate(domain="empty-macro.org", smtp_metadata=trusted_v4_meta)
    assert res7.status == ProtocolStatus.PERMERROR
    assert "Empty macro" in res7.error_reason

    # 7. Malformed unclosed brace %{s
    mock_resolver.add_txt("unclosed-brace.org", ["v=spf1 exists:%{s.validator.net +all"])
    res8 = await evaluator.evaluate(domain="unclosed-brace.org", smtp_metadata=trusted_v4_meta)
    assert res8.status == ProtocolStatus.PERMERROR
    assert "Malformed or unclosed" in res8.error_reason

    # 8. Explanation-only macros %{c}, %{r}, %{t} in domain-spec
    for exp_macro in ("%{c}", "%{r}", "%{t}"):
        dom = f"exp-only-{exp_macro[2]}.org"
        mock_resolver.add_txt(dom, [f"v=spf1 exists:{exp_macro}.validator.net +all"])
        res = await evaluator.evaluate(domain=dom, smtp_metadata=trusted_v4_meta)
        assert res.status == ProtocolStatus.PERMERROR
        assert "reserved for explanation records" in res.error_reason

    # 9. Unsupported macro %{p} evaluates to INDETERMINATE
    mock_resolver.add_txt("unsupported-p.org", ["v=spf1 exists:%{p}.validator.net +all"])
    res_p = await evaluator.evaluate(domain="unsupported-p.org", smtp_metadata=trusted_v4_meta)
    assert res_p.status == ProtocolStatus.INDETERMINATE
    assert "Macro %{p} is unsupported" in res_p.error_reason

    # 10. Unknown macro letter %{z}
    mock_resolver.add_txt("unknown-letter.org", ["v=spf1 exists:%{z}.validator.net +all"])
    res_z = await evaluator.evaluate(domain="unknown-letter.org", smtp_metadata=trusted_v4_meta)
    assert res_z.status == ProtocolStatus.PERMERROR
    assert "Unknown macro letter" in res_z.error_reason

    # 11. Malformed macro in redirect modifier
    mock_resolver.add_txt("bad-redir-macro.org", ["v=spf1 redirect=%d.target.org"])
    res_redir = await evaluator.evaluate(domain="bad-redir-macro.org", smtp_metadata=trusted_v4_meta)
    assert res_redir.status == ProtocolStatus.PERMERROR
    assert "Invalid unbraced macro" in res_redir.error_reason


@pytest.mark.asyncio
async def test_rfc7208_macro_context_consistency_across_include_and_redirect(
    evaluator, mock_resolver, trusted_v4_meta
):
    # Sender identity (%s, %l, %o) must remain constant across recursion,
    # while current domain (%d) must track the actively evaluated domain.
    # Top-level: origin.org -> include:partner.net
    mock_resolver.add_txt(
        "origin.org",
        ["v=spf1 include:partner.net -all"],
    )
    # Partner SPF uses: %{l}.%{o}.%{d}.verify.com
    # Expected target: alice.sender.org.partner.net.verify.com
    mock_resolver.add_txt(
        "partner.net",
        ["v=spf1 exists:%{l}.%{o}.%{d}.verify.com -all"],
    )
    mock_resolver.add_a("alice.sender.org.partner.net.verify.com", ["127.0.0.2"])

    res = await evaluator.evaluate(domain="origin.org", smtp_metadata=trusted_v4_meta)
    assert res.status == ProtocolStatus.PASS

    # Redirect consistency test
    mock_resolver.add_txt(
        "redir-origin.org",
        ["v=spf1 redirect=target-%{d}.net"],
    )
    mock_resolver.add_txt(
        "target-redir-origin.org.net",
        ["v=spf1 exists:%{o}.%{d}.verify.com -all"],
    )
    # Expected target: sender.org.target-redir-origin.org.net.verify.com
    mock_resolver.add_a("sender.org.target-redir-origin.org.net.verify.com", ["127.0.0.2"])

    res_redir = await evaluator.evaluate(domain="redir-origin.org", smtp_metadata=trusted_v4_meta)
    assert res_redir.status == ProtocolStatus.PASS


@pytest.mark.asyncio
async def test_rfc7208_macro_context_null_reverse_path(evaluator, mock_resolver):
    # RFC 7208 Section 2.4 & Section 7.1: For null reverse-path (<>),
    # local-part (%l) is 'postmaster', sender domain (%o) is HELO identity,
    # and sender (%s) is 'postmaster@<helo>'. The evaluated domain is HELO identity.
    null_meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="outbound.mailrelay.com",
        mail_from_envelope="<>",
        is_trusted_mta=True,
    )
    mock_resolver.add_txt(
        "outbound.mailrelay.com",
        ["v=spf1 exists:%{l}.%{o}.test.org -all"],
    )
    # Expected: postmaster.outbound.mailrelay.com.test.org
    mock_resolver.add_a("postmaster.outbound.mailrelay.com.test.org", ["127.0.0.2"])

    res = await evaluator.evaluate(smtp_metadata=null_meta)
    assert res.status == ProtocolStatus.PASS
    assert res.scope == "helo"
    assert res.domain == "outbound.mailrelay.com"


# =============================================================================
# STEP 3.7.2D AUDIT TESTS (SYNTHESIZED MAIL FROM MACRO EXPANSION & DMARC INTEGRATION)
# =============================================================================

@pytest.mark.asyncio
async def test_step372d_null_reverse_path_macro_expansion_and_dns_queries(evaluator, mock_resolver):
    """Task 2: Verify that for null reverse-path (MAIL FROM:<>), SPF evaluates under the
    synthesized identity postmaster@<helo>, with actual macro expansion and DNS queries for
    %{s}, %{l}, %{d}, %{h}, %{o}.
    """
    meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="outbound.mailrelay.com",
        mail_from_envelope="<>",
        is_trusted_mta=True,
    )

    # Record uses %{l} (postmaster), %{o} (outbound.mailrelay.com), %{d} (outbound.mailrelay.com)
    mock_resolver.add_txt(
        "outbound.mailrelay.com",
        ["v=spf1 exists:%{l}._spf.%{d} exists:%{s}._spf.%{h} -all"],
    )
    # Target 1: postmaster._spf.outbound.mailrelay.com
    mock_resolver.add_a("postmaster._spf.outbound.mailrelay.com", ["127.0.0.2"])
    # Target 2: postmaster@outbound.mailrelay.com._spf.outbound.mailrelay.com
    mock_resolver.add_a("postmaster@outbound.mailrelay.com._spf.outbound.mailrelay.com", ["127.0.0.2"])

    res = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")

    assert res.status == ProtocolStatus.PASS
    assert res.scope == "helo"
    assert res.domain == "outbound.mailrelay.com"
    assert res.is_null_reverse_path is True
    assert res.is_synthesized_mfrom is True
    assert res.is_standalone_helo is False
    assert res.identity == "postmaster@outbound.mailrelay.com"

    # Verify that the MockDNSResolver actually recorded the query for the expanded macro!
    recorded = mock_resolver.recorded_queries
    assert any(q[0] == "postmaster._spf.outbound.mailrelay.com" for q in recorded), (
        f"Expected query for 'postmaster._spf.outbound.mailrelay.com' in {recorded}"
    )


@pytest.mark.asyncio
async def test_step372d_standalone_helo_vs_synthesized_mfrom_dmarc_rejection(evaluator, mock_resolver):
    """Task 2: Verify DMARC accepts synthesized MAIL FROM bounce but strictly rejects standalone HELO."""
    from app.modules.auth_protocols.evaluators.dmarc import DMARCEvaluator

    meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="outbound.mailrelay.com",
        mail_from_envelope="<>",
        is_trusted_mta=True,
    )
    mock_resolver.add_txt("outbound.mailrelay.com", ["v=spf1 ip4:192.0.2.1 -all"])
    mock_resolver.add_txt("_dmarc.mailrelay.com", ["v=DMARC1; p=reject; aspf=r"])

    dmarc_evaluator = DMARCEvaluator(resolver=mock_resolver)

    # 1. Standalone HELO evaluation (scope="helo")
    res_helo = await evaluator.evaluate(smtp_metadata=meta, scope="helo")
    assert res_helo.is_standalone_helo is True
    assert res_helo.is_synthesized_mfrom is False

    dmarc_helo = await dmarc_evaluator.evaluate("mailrelay.com", spf_result=res_helo)
    assert dmarc_helo.status == ProtocolStatus.FAIL
    assert dmarc_helo.spf_aligned is False
    assert "RFC 9989 §4.4.2" in (dmarc_helo.error_reason or "")

    # 2. Synthesized MAIL FROM bounce evaluation (scope="mfrom" with null envelope)
    res_bounce = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res_bounce.is_synthesized_mfrom is True
    assert res_bounce.is_standalone_helo is False

    dmarc_bounce = await dmarc_evaluator.evaluate("mailrelay.com", spf_result=res_bounce)
    assert dmarc_bounce.status == ProtocolStatus.PASS
    assert dmarc_bounce.spf_aligned is True


@pytest.mark.asyncio
async def test_step372d_untrusted_smtp_metadata_produces_no_spf_pass(evaluator):
    """Task 2: Untrusted SMTP metadata (is_trusted_mta=False) returns NOT_EVALUATED."""
    meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="outbound.mailrelay.com",
        mail_from_envelope="<>",
        is_trusted_mta=False,
    )
    res = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res.status == ProtocolStatus.NOT_EVALUATED


# =============================================================================
# STEP 3.7.2D-F SYNTHESIZED SPF SENDER MACRO & DNS VERIFICATION TESTS
# =============================================================================

@pytest.mark.asyncio
async def test_step372df_null_reverse_path_macro_expansions_in_live_context(
    evaluator, mock_resolver, monkeypatch
):
    """Step 3.7.2D-F §3: Verify exact expansion of %{s}, %{l}, %{o}, and %{d} on the live
    _SPFEvaluationContext created during null reverse-path evaluation (MAIL FROM:<>),
    including dynamic %{d} updates inside an included SPF domain.
    """
    meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="outbound.mailrelay.com",
        mail_from_envelope="<>",
        is_trusted_mta=True,
    )

    mock_resolver.add_txt("outbound.mailrelay.com", ["v=spf1 include:_policy.%{d} -all"])
    mock_resolver.add_txt(
        "_policy.outbound.mailrelay.com",
        ["v=spf1 exists:%{l}.%{o}.%{d}.verify.net -all"],
    )
    mock_resolver.add_a(
        "postmaster.outbound.mailrelay.com._policy.outbound.mailrelay.com.verify.net",
        ["127.0.0.2"],
    )

    captured_calls: list[tuple[str, str, str]] = []
    captured_contexts: list[_SPFEvaluationContext] = []
    orig_expand = evaluator._expand_macros

    def spy_expand(text: str, current_domain: str, ctx: _SPFEvaluationContext) -> str:
        expanded = orig_expand(text, current_domain, ctx)
        captured_calls.append((text, current_domain, expanded))
        captured_contexts.append(ctx)
        return expanded

    monkeypatch.setattr(evaluator, "_expand_macros", spy_expand)

    res = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res.status == ProtocolStatus.PASS

    # Verify the live context created by evaluate()
    assert len(captured_contexts) >= 2
    live_ctx = captured_contexts[0]
    assert live_ctx.mail_from == "postmaster@outbound.mailrelay.com"
    assert live_ctx.helo_domain == "outbound.mailrelay.com"
    assert live_ctx.sender_domain == "outbound.mailrelay.com"

    # Verify exact real macro expansions observed during evaluate()
    assert ("_policy.%{d}", "outbound.mailrelay.com", "_policy.outbound.mailrelay.com") in captured_calls
    assert (
        "%{l}.%{o}.%{d}.verify.net",
        "_policy.outbound.mailrelay.com",
        "postmaster.outbound.mailrelay.com._policy.outbound.mailrelay.com.verify.net",
    ) in captured_calls

    # Verify %{s}, %{l}, %{o}, %{d} explicitly against the live context at top-level and included scope
    assert orig_expand("%{s}", "outbound.mailrelay.com", live_ctx) == "postmaster@outbound.mailrelay.com"
    assert orig_expand("%{l}", "outbound.mailrelay.com", live_ctx) == "postmaster"
    assert orig_expand("%{o}", "outbound.mailrelay.com", live_ctx) == "outbound.mailrelay.com"
    assert orig_expand("%{d}", "outbound.mailrelay.com", live_ctx) == "outbound.mailrelay.com"

    assert orig_expand("%{s}", "_policy.outbound.mailrelay.com", live_ctx) == "postmaster@outbound.mailrelay.com"
    assert orig_expand("%{l}", "_policy.outbound.mailrelay.com", live_ctx) == "postmaster"
    assert orig_expand("%{o}", "_policy.outbound.mailrelay.com", live_ctx) == "outbound.mailrelay.com"
    assert orig_expand("%{d}", "_policy.outbound.mailrelay.com", live_ctx) == "_policy.outbound.mailrelay.com"

    # Also verify observable %{s} expansion inside an actual DNS mechanism evaluation:
    # %{s} expands to 'postmaster@outbound.mailrelay.com'; raw '@' in DNS label triggers RFC 7208 §4.8 PERMERROR
    mock_resolver.clear()
    captured_calls.clear()
    mock_resolver.add_txt("outbound.mailrelay.com", ["v=spf1 exists:%{s}.verify.net -all"])
    res_raw_s = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")

    assert (
        "%{s}.verify.net",
        "outbound.mailrelay.com",
        "postmaster@outbound.mailrelay.com.verify.net",
    ) in captured_calls
    assert res_raw_s.status == ProtocolStatus.PERMERROR
    assert "postmaster@outbound" in (res_raw_s.error_reason or "")
    # Malformed target domain must NOT be dispatched to DNS resolver
    assert ("postmaster@outbound.mailrelay.com.verify.net", DNSQueryType.A) not in mock_resolver.recorded_queries


@pytest.mark.asyncio
async def test_step372df_null_reverse_path_dns_queries_and_deterministic_outcomes(evaluator, mock_resolver):
    """Step 3.7.2D-F §4: Verify macro-dependent DNS mechanisms (include, a, exists, redirect)
    issue exact expanded queries with correct DNSQueryType recorded in MockDNSResolver.recorded_queries,
    and match deterministic PASS / FAIL DNS responses.
    """
    meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="outbound.mailrelay.com",
        mail_from_envelope="<>",
        is_trusted_mta=True,
    )

    # A. Deterministic PASS across include -> non-matching a -> matching exists
    mock_resolver.add_txt("outbound.mailrelay.com", ["v=spf1 include:_policy.%{d} -all"])
    mock_resolver.add_txt(
        "_policy.outbound.mailrelay.com",
        ["v=spf1 a:%{l}.%{o}.lookup.net exists:%{l}._o.%{o}._d.%{d}.check.net -all"],
    )
    # Non-matching IP on a: so evaluator proceeds to exists: without a void lookup
    mock_resolver.add_a("postmaster.outbound.mailrelay.com.lookup.net", ["198.51.100.99"])
    mock_resolver.add_a(
        "postmaster._o.outbound.mailrelay.com._d._policy.outbound.mailrelay.com.check.net",
        ["127.0.0.2"],
    )

    res_pass = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res_pass.status == ProtocolStatus.PASS
    assert res_pass.domain == "outbound.mailrelay.com"
    assert mock_resolver.recorded_queries == [
        ("outbound.mailrelay.com", DNSQueryType.TXT),
        ("_policy.outbound.mailrelay.com", DNSQueryType.TXT),
        ("postmaster.outbound.mailrelay.com.lookup.net", DNSQueryType.A),
        ("postmaster._o.outbound.mailrelay.com._d._policy.outbound.mailrelay.com.check.net", DNSQueryType.A),
    ]

    # B. Deterministic FAIL when exists: A-record is NXDOMAIN -> falls through to -all
    mock_resolver.clear()
    mock_resolver.add_txt("outbound.mailrelay.com", ["v=spf1 include:_policy.%{d} -all"])
    mock_resolver.add_txt(
        "_policy.outbound.mailrelay.com",
        ["v=spf1 a:%{l}.%{o}.lookup.net exists:%{l}._o.%{o}._d.%{d}.check.net -all"],
    )
    mock_resolver.add_a("postmaster.outbound.mailrelay.com.lookup.net", ["198.51.100.99"])
    mock_resolver.set_nxdomain("postmaster._o.outbound.mailrelay.com._d._policy.outbound.mailrelay.com.check.net")

    res_fail = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res_fail.status == ProtocolStatus.FAIL
    assert mock_resolver.recorded_queries == [
        ("outbound.mailrelay.com", DNSQueryType.TXT),
        ("_policy.outbound.mailrelay.com", DNSQueryType.TXT),
        ("postmaster.outbound.mailrelay.com.lookup.net", DNSQueryType.A),
        ("postmaster._o.outbound.mailrelay.com._d._policy.outbound.mailrelay.com.check.net", DNSQueryType.A),
    ]

    # C. Deterministic redirect= with %{d} context switch while preserving %{l} and %{o}
    mock_resolver.clear()
    mock_resolver.add_txt("outbound.mailrelay.com", ["v=spf1 redirect=_bounce.%{d}"])
    mock_resolver.add_txt(
        "_bounce.outbound.mailrelay.com",
        ["v=spf1 exists:%{l}.%{o}._ctx.%{d} -all"],
    )
    mock_resolver.add_a(
        "postmaster.outbound.mailrelay.com._ctx._bounce.outbound.mailrelay.com",
        ["127.0.0.2"],
    )

    res_redir = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res_redir.status == ProtocolStatus.PASS
    assert mock_resolver.recorded_queries == [
        ("outbound.mailrelay.com", DNSQueryType.TXT),
        ("_bounce.outbound.mailrelay.com", DNSQueryType.TXT),
        ("postmaster.outbound.mailrelay.com._ctx._bounce.outbound.mailrelay.com", DNSQueryType.A),
    ]


@pytest.mark.asyncio
async def test_step372df_identity_helo_distinction_trust_and_normal_mfrom(evaluator, mock_resolver):
    """Step 3.7.2D-F §5: Confirm synthesized vs standalone HELO flags, DMARC separation,
    untrusted metadata rejection with zero DNS queries, and unchanged normal MAIL FROM behavior.
    """
    from app.modules.auth_protocols.evaluators.dmarc import DMARCEvaluator

    mock_resolver.add_txt("outbound.mailrelay.com", ["v=spf1 ip4:192.0.2.1 -all"])
    mock_resolver.add_txt("_dmarc.mailrelay.com", ["v=DMARC1; p=reject; aspf=r"])
    dmarc = DMARCEvaluator(resolver=mock_resolver)

    trusted_bounce_meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="outbound.mailrelay.com",
        mail_from_envelope="<>",
        is_trusted_mta=True,
    )

    # 1. Synthesized MAIL FROM marks synthesized + null reverse path, ignores unrelated header domain hint
    res_synth = await evaluator.evaluate(
        domain="header-spoof.example", smtp_metadata=trusted_bounce_meta, scope="mfrom"
    )
    assert res_synth.status == ProtocolStatus.PASS
    assert res_synth.domain == "outbound.mailrelay.com"
    assert res_synth.identity == "postmaster@outbound.mailrelay.com"
    assert res_synth.is_synthesized_mfrom is True
    assert res_synth.is_null_reverse_path is True
    assert res_synth.is_standalone_helo is False

    # DMARC aligns synthesized MAIL FROM pass with From: mailrelay.com
    dmarc_synth = await dmarc.evaluate("mailrelay.com", spf_result=res_synth)
    assert dmarc_synth.status == ProtocolStatus.PASS
    assert dmarc_synth.spf_aligned is True

    # 2. Standalone HELO evaluation is marked is_standalone_helo=True and rejected by DMARC
    res_helo = await evaluator.evaluate(smtp_metadata=trusted_bounce_meta, scope="helo")
    assert res_helo.status == ProtocolStatus.PASS
    assert res_helo.domain == "outbound.mailrelay.com"
    assert res_helo.is_standalone_helo is True
    assert res_helo.is_synthesized_mfrom is False
    assert res_helo.is_null_reverse_path is False

    dmarc_helo = await dmarc.evaluate("mailrelay.com", spf_result=res_helo)
    assert dmarc_helo.status == ProtocolStatus.FAIL
    assert dmarc_helo.spf_aligned is False

    # Even if is_null_reverse_path is manually mutated on a standalone HELO result, DMARC rejects it
    res_helo_tampered = res_helo.model_copy(update={"is_null_reverse_path": True})
    dmarc_tampered = await dmarc.evaluate("mailrelay.com", spf_result=res_helo_tampered)
    assert dmarc_tampered.status == ProtocolStatus.FAIL
    assert dmarc_tampered.spf_aligned is False

    # 3. Untrusted SMTP metadata (and missing metadata) cannot synthesize identity or execute DNS lookups
    mock_resolver.clear()
    untrusted_meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="outbound.mailrelay.com",
        mail_from_envelope="<>",
        is_trusted_mta=False,
    )
    res_untrusted = await evaluator.evaluate(smtp_metadata=untrusted_meta, scope="mfrom")
    assert res_untrusted.status == ProtocolStatus.NOT_EVALUATED
    assert res_untrusted.identity is None
    assert res_untrusted.is_synthesized_mfrom is False
    assert res_untrusted.is_null_reverse_path is False
    assert mock_resolver.recorded_queries == []

    res_none_meta = await evaluator.evaluate(domain="outbound.mailrelay.com", smtp_metadata=None, scope="mfrom")
    assert res_none_meta.status == ProtocolStatus.NOT_EVALUATED
    assert res_none_meta.identity is None
    assert res_none_meta.is_synthesized_mfrom is False
    assert mock_resolver.recorded_queries == []

    mock_resolver.add_txt("_dmarc.mailrelay.com", ["v=DMARC1; p=reject; aspf=r"])
    dmarc_untrusted = await dmarc.evaluate("mailrelay.com", spf_result=res_untrusted)
    # C1 safety rule: missing/untrusted SPF context must NOT invent a DMARC FAIL
    assert dmarc_untrusted.status == ProtocolStatus.INDETERMINATE
    assert dmarc_untrusted.rfc_status is None
    assert dmarc_untrusted.spf_aligned is False

    # 4. Normal non-empty MAIL FROM preserves sender identity, macros, and mfrom scope
    mock_resolver.clear()
    normal_meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="outbound.mailrelay.com",
        mail_from_envelope="alice@sender.org",
        is_trusted_mta=True,
    )
    mock_resolver.add_txt("sender.org", ["v=spf1 exists:%{l}.%{o}.%{d}.check.net -all"])
    mock_resolver.add_a("alice.sender.org.sender.org.check.net", ["127.0.0.2"])

    res_normal = await evaluator.evaluate(smtp_metadata=normal_meta, scope="mfrom")
    assert res_normal.status == ProtocolStatus.PASS
    assert res_normal.scope == "mfrom"
    assert res_normal.domain == "sender.org"
    assert res_normal.identity == "alice@sender.org"
    assert res_normal.is_null_reverse_path is False
    assert res_normal.is_synthesized_mfrom is False
    assert res_normal.is_standalone_helo is False
    assert ("alice.sender.org.sender.org.check.net", DNSQueryType.A) in mock_resolver.recorded_queries


@pytest.mark.asyncio
async def test_spf_unexpected_internal_exception_returns_indeterminate():
    """Step 3.7.3B: Unexpected software errors in SPF evaluation must never become authentication FAIL."""

    class _ExplodingResolver(MockDNSResolver):
        async def resolve(self, domain, query_type, raise_on_error=False):
            raise RuntimeError("Simulated unexpected SPF resolver bug")

    spf_eval = SPFEvaluator(resolver=_ExplodingResolver())
    meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="mail.example.com",
        mail_from_envelope="sender@example.com",
        is_trusted_mta=True,
    )
    res = await spf_eval.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res.status == ProtocolStatus.INDETERMINATE
    assert "SPF internal evaluation error" in (res.error_reason or "")


@pytest.mark.asyncio
async def test_h3_spf_dns_error_categories_never_collapse_to_none(evaluator, mock_resolver):
    """H3: Resolver failures and malformed/invalid DNS responses map to TEMPERROR/INDETERMINATE across SPF lookups."""
    meta = TrustedSMTPMetadata(
        connecting_ip="192.0.2.1",
        helo_domain="mail.example.com",
        mail_from_envelope="sender@example.com",
        is_trusted_mta=True,
    )

    # 1. TXT discovery RESOLVER_ERROR, REFUSED, FORMERR -> TEMPERROR (never NONE)
    for err_method in ("set_resolver_error", "set_refused", "set_formerr"):
        mock_resolver.clear()
        getattr(mock_resolver, err_method)("example.com", DNSQueryType.TXT)
        res = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
        assert res.status == ProtocolStatus.TEMPERROR, f"Expected TEMPERROR for {err_method}"

    # 2. TXT discovery INVALID_QUERY -> INDETERMINATE (never NONE)
    mock_resolver.clear()
    mock_resolver.set_invalid_query("example.com", DNSQueryType.TXT)
    res_inv = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res_inv.status == ProtocolStatus.INDETERMINATE

    # 3. Forward A / MX / PTR / exists resolver failures propagate TEMPERROR/INDETERMINATE
    mock_resolver.clear()
    mock_resolver.add_txt("example.com", ["v=spf1 a:mail.example.com -all"])
    mock_resolver.set_resolver_error("mail.example.com", DNSQueryType.A)
    res_a = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res_a.status == ProtocolStatus.TEMPERROR

    mock_resolver.clear()
    mock_resolver.add_txt("example.com", ["v=spf1 mx:example.com -all"])
    mock_resolver.set_invalid_query("example.com", DNSQueryType.MX)
    res_mx = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res_mx.status == ProtocolStatus.INDETERMINATE

    mock_resolver.clear()
    mock_resolver.add_txt("example.com", ["v=spf1 ptr:example.com -all"])
    mock_resolver.set_refused("192.0.2.1", DNSQueryType.PTR)
    res_ptr = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res_ptr.status == ProtocolStatus.TEMPERROR

    mock_resolver.clear()
    mock_resolver.add_txt("example.com", ["v=spf1 exists:check.example.com -all"])
    mock_resolver.set_formerr("check.example.com", DNSQueryType.A)
    res_exists = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res_exists.status == ProtocolStatus.TEMPERROR

    # 4. Authoritative NXDOMAIN on root TXT still yields SPF NONE
    mock_resolver.clear()
    mock_resolver.set_nxdomain("example.com")
    res_nx = await evaluator.evaluate(smtp_metadata=meta, scope="mfrom")
    assert res_nx.status == ProtocolStatus.NONE

    # 5. Real AsyncDNSResolver OS/socket/TimeoutError/RuntimeError propagation through SPFEvaluator
    import socket
    import dns.resolver
    from app.modules.auth_protocols.dns_resolver import AsyncDNSResolver

    async_res = AsyncDNSResolver()
    spf_async = SPFEvaluator(resolver=async_res)
    for exc_obj, expected_status in (
        (OSError("socket down"), ProtocolStatus.TEMPERROR),
        (ConnectionError("conn reset"), ProtocolStatus.TEMPERROR),
        (socket.gaierror(-2, "addr err"), ProtocolStatus.TEMPERROR),
        (TimeoutError("io timeout"), ProtocolStatus.TEMPERROR),
        (dns.resolver.NoNameservers(), ProtocolStatus.TEMPERROR),
        (RuntimeError("unexpected spf bug"), ProtocolStatus.INDETERMINATE),
        (dns.resolver.YXDOMAIN(), ProtocolStatus.INDETERMINATE),
        (dns.resolver.NXDOMAIN(), ProtocolStatus.NONE),
    ):
        async_res.cache.clear()

        async def _boom_spf(name, rdtype, _exc=exc_obj):
            raise _exc

        async_res._resolver.resolve = _boom_spf  # type: ignore[method-assign]
        out = await spf_async.evaluate(smtp_metadata=meta, scope="mfrom")
        assert out.status == expected_status, f"SPF unexpected status for {type(exc_obj).__name__}: {out.status}"
