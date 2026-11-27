"""Targeted tests for DMARC Record Discovery and Bounded DNS Tree Walking.

Architecture reference: MS-ARCH-SEC-2026-AUTH-PROTOCOLS-REV13
Standards: RFC 9989 (DMARCbis), RFC 9091
"""

import pytest

from app.modules.auth_protocols.config import AuthProtocolsConfig
from app.modules.auth_protocols.dns_resolver import (
    DNSErrorType,
    DNSQueryType,
    DNSResponseStatus,
    MockDNSResolver,
)
from app.modules.auth_protocols.evaluators.dmarc import (
    DMARCDiscoveryResult,
    DMARCDiscoveryStatus,
    DMARCRecordDiscovery,
    is_dmarc_version1_record,
    parse_dmarc_tags,
)
from app.modules.contracts import DMARCPolicy, ProtocolStatus


# =============================================================================
# 1. BASIC DISCOVERY AND PARSING
# =============================================================================

@pytest.mark.asyncio
async def test_dmarc_exact_lookup_found():
    """Verify exact DMARC TXT lookup on Author Domain succeeds on query 1."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("example.com")

    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.protocol_status == ProtocolStatus.PASS
    assert res.discovered_domain == "example.com"
    assert res.org_domain == "example.com"
    assert res.tree_walk_queries == 1
    assert res.tags["p"] == "reject"
    assert res.tags["rua"] == "mailto:dmarc@example.com"
    assert res.is_psd is False

    dmarc_res = res.to_dmarc_result()
    assert dmarc_res.status == ProtocolStatus.PASS
    assert dmarc_res.policy == DMARCPolicy.REJECT
    assert dmarc_res.org_domain == "example.com"
    assert dmarc_res.tree_walk_queries == 1


@pytest.mark.asyncio
async def test_dmarc_missing_record_returns_absent():
    """Verify NXDOMAIN across tree walk returns ABSENT with ProtocolStatus.NONE."""
    resolver = MockDNSResolver()

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("sub.example.com")

    assert res.status == DMARCDiscoveryStatus.ABSENT
    assert res.protocol_status == ProtocolStatus.NONE
    assert res.discovered_domain is None
    assert res.org_domain == "sub.example.com"
    assert "no dmarc policy record found" in res.error_reason.lower()

    dmarc_res = res.to_dmarc_result()
    assert dmarc_res.status == ProtocolStatus.NONE
    assert dmarc_res.policy == DMARCPolicy.NOT_CONFIGURED


@pytest.mark.asyncio
async def test_dmarc_valid_record_tag_parsing():
    """Verify comprehensive tag parsing for RFC 9989 valid tags."""
    raw = (
        "v=DMARC1; p=quarantine; sp=reject; np=reject; psd=n; "
        "adkim=s; aspf=s; t=y; fo=1; rua=mailto:agg@ex.com; ruf=mailto:forensic@ex.com"
    )
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.corp.org", [raw])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("corp.org")

    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.tags["p"] == "quarantine"
    assert res.tags["sp"] == "reject"
    assert res.tags["np"] == "reject"
    assert res.tags["psd"] == "n"
    assert res.tags["adkim"] == "s"
    assert res.tags["aspf"] == "s"
    assert res.tags["t"] == "y"
    assert res.tags["fo"] == "1"
    assert res.tags["rua"] == "mailto:agg@ex.com"
    assert res.tags["ruf"] == "mailto:forensic@ex.com"
    assert res.psd_type == "n"

    dmarc_res = res.to_dmarc_result()
    assert dmarc_res.policy == DMARCPolicy.QUARANTINE
    assert dmarc_res.subdomain_policy == DMARCPolicy.REJECT


@pytest.mark.asyncio
async def test_dmarc_missing_p_tag_defaults_to_none():
    """Verify RFC 9989 Section 4.7 & 4.10.1: missing p tag defaults to p=none."""
    raw = "v=DMARC1; sp=reject; rua=mailto:dmarc@ex.com"
    tags, err = parse_dmarc_tags(raw)

    assert err is None
    assert tags is not None
    assert tags["p"] == "none"
    assert tags["sp"] == "reject"


@pytest.mark.asyncio
async def test_dmarc_invalid_empty_domain():
    """Verify empty or whitespace-only domain returns INVALID / PERMERROR."""
    resolver = MockDNSResolver()
    discovery = DMARCRecordDiscovery(resolver=resolver)

    res_empty = await discovery.discover("")
    assert res_empty.status == DMARCDiscoveryStatus.INVALID
    assert res_empty.protocol_status == ProtocolStatus.PERMERROR

    res_none = await discovery.discover(None)
    assert res_none.status == DMARCDiscoveryStatus.INVALID
    assert res_none.protocol_status == ProtocolStatus.PERMERROR


# =============================================================================
# 2. SECTION 1: PSD (psd=y) POLICY DISCOVERY AND ORGANIZATIONAL DOMAINS
# =============================================================================

@pytest.mark.asyncio
async def test_dmarc_psd_y_child_domain_inherits_psd_policy():
    """Verify RFC 9989 Section 4.10.1: child domain with no closer policy inherits PSD policy.
    
    Distinguishes the PSD (discovered_domain='gov.uk') from the child's Organizational Domain
    (org_domain='department.gov.uk') per Section 4.10.2 rule 2.
    """
    resolver = MockDNSResolver()
    # gov.uk is a Public Suffix Domain with psd=y
    resolver.add_txt("_dmarc.gov.uk", ["v=DMARC1; p=reject; sp=quarantine; psd=y"])
    # department.gov.uk publishes no record

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("department.gov.uk")

    # Policy discovery succeeds: PSD policy applies to child
    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.protocol_status == ProtocolStatus.PASS
    assert res.discovered_domain == "gov.uk"
    assert res.org_domain == "department.gov.uk"
    assert res.is_psd is True
    assert res.psd_type == "y"
    assert res.tags["p"] == "reject"
    assert res.tags["sp"] == "quarantine"

    dmarc_res = res.to_dmarc_result()
    assert dmarc_res.status == ProtocolStatus.PASS
    assert dmarc_res.org_domain == "department.gov.uk"
    assert dmarc_res.psd_type == "y"


@pytest.mark.asyncio
async def test_dmarc_psd_y_deep_child_domain_inherits_psd_policy():
    """Verify deep child domain (3 levels below PSD) inherits PSD policy and identifies Org Domain."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.gov.uk", ["v=DMARC1; p=reject; psd=y"])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("sub.department.gov.uk")

    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.discovered_domain == "gov.uk"
    # Section 4.10.2 rule 2: domain one label below gov.uk is department.gov.uk
    assert res.org_domain == "department.gov.uk"
    assert res.is_psd is True


@pytest.mark.asyncio
async def test_dmarc_psd_y_intermediate_candidate_takes_precedence_over_psd():
    """Verify RFC 9989 Section 4.10.1 note: PSD policy is NOT used for Org Domains with a policy."""
    resolver = MockDNSResolver()
    # company.co.uk has a candidate record (psd=u or default)
    resolver.add_txt("_dmarc.company.co.uk", ["v=DMARC1; p=quarantine; psd=u"])
    # co.uk is a PSD with psd=y
    resolver.add_txt("_dmarc.co.uk", ["v=DMARC1; p=reject; psd=y"])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("sales.company.co.uk")

    # Intermediate candidate company.co.uk takes precedence
    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.discovered_domain == "company.co.uk"
    assert res.org_domain == "company.co.uk"
    assert res.is_psd is False
    assert res.tags["p"] == "quarantine"
    assert res.tree_walk_queries == 3  # sales... -> company... -> co.uk


@pytest.mark.asyncio
async def test_dmarc_psd_n_stops_tree_walk_at_org_boundary():
    """Verify parent with psd=n explicitly defines Org Domain and halts upward walk."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.company.co.uk", ["v=DMARC1; p=reject; psd=n"])
    resolver.add_txt("_dmarc.co.uk", ["v=DMARC1; p=none; psd=y"])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("mail.company.co.uk")

    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.discovered_domain == "company.co.uk"
    assert res.org_domain == "company.co.uk"
    assert res.psd_type == "n"
    assert res.is_psd is False
    assert res.tree_walk_queries == 2  # halts at company.co.uk; co.uk is not queried


@pytest.mark.asyncio
async def test_dmarc_author_domain_itself_is_psd():
    """Verify exact match when author domain itself is the PSD."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.gov.uk", ["v=DMARC1; p=reject; psd=y"])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("gov.uk")

    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.discovered_domain == "gov.uk"
    assert res.org_domain == "gov.uk"
    assert res.is_psd is True
    assert res.tree_walk_queries == 1


# =============================================================================
# 3. SECTION 2: REMOVE OBSOLETE pct TAG & UNKNOWN TAG HANDLING
# =============================================================================

@pytest.mark.asyncio
async def test_dmarc_pct_tag_50_ignored():
    """Verify historical pct=50 tag is ignored per RFC 9989 Section 4.7 and not in tags."""
    raw = "v=DMARC1; p=reject; pct=50"
    tags, err = parse_dmarc_tags(raw)

    assert err is None
    assert tags is not None
    assert tags["p"] == "reject"
    assert "pct" not in tags


@pytest.mark.asyncio
async def test_dmarc_pct_tag_0_ignored():
    """Verify historical pct=0 tag is ignored per RFC 9989 Section 4.7 and not in tags."""
    raw = "v=DMARC1; p=quarantine; pct=0"
    tags, err = parse_dmarc_tags(raw)

    assert err is None
    assert tags is not None
    assert tags["p"] == "quarantine"
    assert "pct" not in tags


@pytest.mark.asyncio
async def test_dmarc_pct_tag_invalid_historical_value_ignored():
    """Verify historical invalid pct=200 is treated as an unknown tag and ignored without error."""
    raw = "v=DMARC1; p=reject; pct=200"
    tags, err = parse_dmarc_tags(raw)

    assert err is None
    assert tags is not None
    assert tags["p"] == "reject"
    assert "pct" not in tags


@pytest.mark.asyncio
async def test_dmarc_unknown_extension_tags_ignored():
    """Verify RFC 9989 Section 4.7: unknown extension tags MUST be ignored."""
    raw = "v=DMARC1; p=reject; custom_tag=value; future_extension=yes; ri=3600"
    tags, err = parse_dmarc_tags(raw)

    assert err is None
    assert tags is not None
    assert tags["p"] == "reject"
    assert "custom_tag" not in tags
    assert "future_extension" not in tags
    assert "ri" not in tags


@pytest.mark.asyncio
async def test_dmarc_duplicate_tags_rejected():
    """Verify duplicate tags produce INVALID / syntax error per RFC 9989."""
    cases = [
        "v=DMARC1; p=reject; p=quarantine",
        "v=DMARC1; p=reject; sp=none; sp=quarantine",
        "v=DMARC1; p=reject; pct=50; pct=100",
        "v=DMARC1; p=reject; t=y; t=n",
        "v=DMARC1; p=reject; adkim=r; adkim=s",
        "v=DMARC1; p=reject; v=DMARC1",
        "v=DMARC1; p=reject; psd=y; psd=n",
        "v=DMARC1; p=reject; psd=u; psd=u",
    ]
    for raw in cases:
        tags, err = parse_dmarc_tags(raw)
        assert tags is None
        assert "duplicate tag" in err.lower()


@pytest.mark.asyncio
async def test_dmarc_malformed_syntax_records():
    """Verify malformed tag-value syntax produces syntax errors."""
    cases = [
        ("v=DMARC1; p=invalid_policy", "invalid 'p' tag value"),
        ("v=DMARC1; missing_equals_tag", "malformed tag-value pair"),
        ("v=DMARC1; =value_without_tag_name", "malformed tag-value pair"),
        ("p=reject; v=DMARC1", "must be the first tag"),
        ("v=DMARC2; p=reject", "invalid dmarc version"),
        ("v=DMARC1; p=reject; sp=drop", "invalid 'sp' tag value"),
        ("v=DMARC1; p=reject; np=drop", "invalid 'np' tag value"),
    ]
    for raw, expected_err in cases:
        tags, err = parse_dmarc_tags(raw)
        assert tags is None, f"Expected error for {raw}"
        assert expected_err in err.lower(), f"Expected '{expected_err}' in '{err}'"


# =============================================================================
# RFC 9989 STEP 3.7.1B: DMARC TAG-HANDLING VERIFICATION
# =============================================================================

@pytest.mark.asyncio
async def test_dmarc_adkim_default_and_valid_values():
    """Verify RFC 9989 Section 4.7: missing adkim defaults to 'r', valid 'r' and 's' accepted."""
    # Missing adkim defaults to 'r'
    tags, err = parse_dmarc_tags("v=DMARC1; p=reject")
    assert err is None
    assert tags["adkim"] == "r"

    # Explicit adkim=r
    tags, err = parse_dmarc_tags("v=DMARC1; p=reject; adkim=r")
    assert err is None
    assert tags["adkim"] == "r"

    # Explicit adkim=s
    tags, err = parse_dmarc_tags("v=DMARC1; p=reject; adkim=s")
    assert err is None
    assert tags["adkim"] == "s"

    # Case-insensitivity: adkim=R, adkim=S
    tags, err = parse_dmarc_tags("v=DMARC1; p=reject; adkim=R")
    assert err is None
    assert tags["adkim"] == "r"

    tags, err = parse_dmarc_tags("v=DMARC1; p=reject; adkim=S")
    assert err is None
    assert tags["adkim"] == "s"


@pytest.mark.asyncio
async def test_dmarc_adkim_invalid_values_fall_back_to_default_r():
    """Verify RFC 9989 Section 4.7 & 4.8: invalid adkim values fall back to 'r' without invalidating record."""
    invalid_cases = [
        "v=DMARC1; p=reject; adkim=x",
        "v=DMARC1; p=reject; adkim=strict",
        "v=DMARC1; p=reject; adkim=relaxed",
        "v=DMARC1; p=reject; adkim=1",
        "v=DMARC1; p=reject; adkim=",
    ]
    for raw in invalid_cases:
        tags, err = parse_dmarc_tags(raw)
        assert err is None, f"Expected successful parse with fallback for {raw}, got error: {err}"
        assert tags is not None
        assert tags["adkim"] == "r"
        assert tags["p"] == "reject"


@pytest.mark.asyncio
async def test_dmarc_aspf_default_and_invalid_fallback():
    """Verify RFC 9989 Section 4.7 & 4.8: aspf defaults to 'r' and invalid values fall back to 'r'."""
    # Missing aspf defaults to 'r'
    tags, err = parse_dmarc_tags("v=DMARC1; p=reject")
    assert err is None
    assert tags["aspf"] == "r"

    # Explicit aspf=s
    tags, err = parse_dmarc_tags("v=DMARC1; p=reject; aspf=s")
    assert err is None
    assert tags["aspf"] == "s"

    # Invalid aspf falls back to 'r'
    tags, err = parse_dmarc_tags("v=DMARC1; p=reject; aspf=invalid_mode")
    assert err is None
    assert tags["aspf"] == "r"


@pytest.mark.asyncio
async def test_dmarc_t_tag_default_and_valid_values():
    """Verify RFC 9989 Section 4.7: missing t defaults to 'n', valid 'y' and 'n' accepted."""
    # Missing t defaults to 'n'
    tags, err = parse_dmarc_tags("v=DMARC1; p=reject")
    assert err is None
    assert tags["t"] == "n"

    # Explicit t=y
    tags, err = parse_dmarc_tags("v=DMARC1; p=reject; t=y")
    assert err is None
    assert tags["t"] == "y"

    # Explicit t=n
    tags, err = parse_dmarc_tags("v=DMARC1; p=reject; t=n")
    assert err is None
    assert tags["t"] == "n"

    # Case-insensitivity: t=Y, t=N
    tags, err = parse_dmarc_tags("v=DMARC1; p=reject; t=Y")
    assert err is None
    assert tags["t"] == "y"

    tags, err = parse_dmarc_tags("v=DMARC1; p=reject; t=N")
    assert err is None
    assert tags["t"] == "n"


@pytest.mark.asyncio
async def test_dmarc_t_tag_invalid_values_fall_back_to_default_n():
    """Verify RFC 9989 Section 4.7 & 4.8: invalid t values fall back to 'n' without invalidating record."""
    invalid_cases = [
        "v=DMARC1; p=reject; t=x",
        "v=DMARC1; p=reject; t=maybe",
        "v=DMARC1; p=reject; t=yes",
        "v=DMARC1; p=reject; t=1",
        "v=DMARC1; p=reject; t=",
    ]
    for raw in invalid_cases:
        tags, err = parse_dmarc_tags(raw)
        assert err is None, f"Expected successful parse with fallback for {raw}, got error: {err}"
        assert tags is not None
        assert tags["t"] == "n"
        assert tags["p"] == "reject"


@pytest.mark.asyncio
async def test_dmarc_policy_tags_missing_and_valid():
    """Verify RFC 9989 Section 4.7: missing p defaults to none, valid values accepted."""
    # Missing p defaults to none
    tags, err = parse_dmarc_tags("v=DMARC1; rua=mailto:dmarc@example.com")
    assert err is None
    assert tags["p"] == "none"

    # Valid p values
    for val in ("none", "quarantine", "reject", "NONE", "QUARANTINE", "REJECT"):
        tags, err = parse_dmarc_tags(f"v=DMARC1; p={val}")
        assert err is None
        assert tags["p"] == val.lower()


@pytest.mark.asyncio
async def test_dmarc_invalid_p_with_valid_rua_falls_back_to_none():
    """Verify RFC 9989 Section 4.10.1: invalid p tag with valid rua acts as if p=none retrieved."""
    resolver = MockDNSResolver()
    raw = "v=DMARC1; p=invalid_policy; rua=mailto:dmarc-reports@example.com"
    resolver.add_txt("_dmarc.example.com", [raw])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("example.com")

    # MUST act as if record containing p=none was retrieved and continue processing
    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.protocol_status == ProtocolStatus.PASS
    assert res.tags["p"] == "none"
    assert res.tags["rua"] == "mailto:dmarc-reports@example.com"

    dmarc_res = res.to_dmarc_result()
    assert dmarc_res.status == ProtocolStatus.PASS
    assert dmarc_res.policy == DMARCPolicy.NONE


@pytest.mark.asyncio
async def test_dmarc_invalid_p_without_rua_applies_no_dmarc_processing():
    """Verify RFC 9989 Section 4.10.1: invalid p tag without rua applies no DMARC processing (INVALID)."""
    resolver = MockDNSResolver()
    raw = "v=DMARC1; p=invalid_policy"
    resolver.add_txt("_dmarc.example.com", [raw])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("example.com")

    assert res.status == DMARCDiscoveryStatus.INVALID
    assert res.protocol_status == ProtocolStatus.PERMERROR
    assert "without valid rua fallback" in res.error_reason


@pytest.mark.asyncio
async def test_dmarc_invalid_p_with_invalid_rua_applies_no_dmarc_processing():
    """Verify RFC 9989 Section 4.10.1: invalid p tag with syntactically invalid rua URI is rejected."""
    resolver = MockDNSResolver()
    raw = "v=DMARC1; p=bogus_policy; rua=not_a_valid_uri"
    resolver.add_txt("_dmarc.example.com", [raw])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("example.com")

    assert res.status == DMARCDiscoveryStatus.INVALID
    assert res.protocol_status == ProtocolStatus.PERMERROR
    assert "without valid rua fallback" in res.error_reason


@pytest.mark.asyncio
async def test_dmarc_invalid_sp_with_valid_rua_falls_back_to_p_none():
    """Verify RFC 9989 Section 4.10.1: invalid sp tag with valid rua acts as if p=none was retrieved."""
    resolver = MockDNSResolver()
    # Even if p=reject was published, invalid sp causes entire record to act as p=none
    raw = "v=DMARC1; p=reject; sp=invalid_sub_policy; rua=mailto:dmarc@example.com"
    resolver.add_txt("_dmarc.example.com", [raw])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("example.com")

    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.protocol_status == ProtocolStatus.PASS
    assert res.tags["p"] == "none"
    assert "sp" not in res.tags

    dmarc_res = res.to_dmarc_result()
    assert dmarc_res.status == ProtocolStatus.PASS
    assert dmarc_res.policy == DMARCPolicy.NONE
    assert dmarc_res.subdomain_policy is None


@pytest.mark.asyncio
async def test_dmarc_invalid_sp_without_rua_rejected():
    """Verify RFC 9989 Section 4.10.1: invalid sp tag without rua applies no DMARC processing."""
    resolver = MockDNSResolver()
    raw = "v=DMARC1; p=reject; sp=invalid_sub_policy"
    resolver.add_txt("_dmarc.example.com", [raw])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("example.com")

    assert res.status == DMARCDiscoveryStatus.INVALID
    assert res.protocol_status == ProtocolStatus.PERMERROR
    assert "without valid rua fallback" in res.error_reason


@pytest.mark.asyncio
async def test_dmarc_invalid_np_with_valid_rua_falls_back_to_p_none():
    """Verify RFC 9989 Section 4.10.1: invalid np tag with valid rua acts as if p=none was retrieved."""
    resolver = MockDNSResolver()
    raw = "v=DMARC1; p=quarantine; np=invalid_non_existent; rua=mailto:dmarc@example.com"
    resolver.add_txt("_dmarc.example.com", [raw])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("example.com")

    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.protocol_status == ProtocolStatus.PASS
    assert res.tags["p"] == "none"
    assert "np" not in res.tags

    dmarc_res = res.to_dmarc_result()
    assert dmarc_res.status == ProtocolStatus.PASS
    assert dmarc_res.policy == DMARCPolicy.NONE


@pytest.mark.asyncio
async def test_dmarc_invalid_np_without_rua_rejected():
    """Verify RFC 9989 Section 4.10.1: invalid np tag without rua applies no DMARC processing."""
    resolver = MockDNSResolver()
    raw = "v=DMARC1; p=quarantine; np=invalid_non_existent"
    resolver.add_txt("_dmarc.example.com", [raw])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("example.com")

    assert res.status == DMARCDiscoveryStatus.INVALID
    assert res.protocol_status == ProtocolStatus.PERMERROR
    assert "without valid rua fallback" in res.error_reason


@pytest.mark.asyncio
async def test_dmarc_multiple_rua_uris_one_valid_triggers_fallback():
    """Verify RFC 9989 Section 4.10.1: rua with multiple URIs where at least one is valid triggers fallback."""
    raw = "v=DMARC1; p=invalid_p; rua=invalid_scheme_uri, mailto:backup@example.com!10m"
    tags, err = parse_dmarc_tags(raw)

    assert err is None
    assert tags is not None
    assert tags["p"] == "none"
    assert tags["rua"] == "invalid_scheme_uri, mailto:backup@example.com!10m"


# =============================================================================
# 4. SECTION 3: MULTIPLE TXT RESOURCE RECORDS VS MULTI-STRING TXT
# =============================================================================

@pytest.mark.asyncio
async def test_dmarc_one_valid_dmarc_record_accepted():
    """Verify exactly one valid DMARC record is accepted."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject"])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("example.com")

    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.tags["p"] == "reject"


@pytest.mark.asyncio
async def test_dmarc_one_valid_dmarc_record_plus_unrelated_txt():
    """Verify RFC 9989 Section 4.10: non-DMARC TXT record in same response is discarded."""
    resolver = MockDNSResolver()
    resolver.add_txt(
        "_dmarc.example.com",
        [
            "v=DMARC1; p=reject",
            "v=spf1 include:_spf.example.com ~all",
            "heritage-verification=12345",
        ],
    )

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("example.com")

    # Unrelated TXT records are discarded; valid DMARC record is accepted
    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.tags["p"] == "reject"
    assert res.discovered_domain == "example.com"


@pytest.mark.asyncio
async def test_dmarc_multiple_dmarc_policy_records_discarded():
    """Verify RFC 9989 Section 4.10: multiple DMARC policy records are all discarded."""
    resolver = MockDNSResolver()
    resolver.add_txt(
        "_dmarc.example.com",
        ["v=DMARC1; p=reject", "v=DMARC1; p=none"],
    )

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("example.com")

    # Both records start with v=DMARC1; per RFC 9989 they are both discarded.
    # Because all records at example.com are discarded and no parent exists, result is ABSENT.
    assert res.status == DMARCDiscoveryStatus.ABSENT
    assert res.protocol_status == ProtocolStatus.NONE


@pytest.mark.asyncio
async def test_dmarc_multiple_dmarc_records_at_subdomain_discarded_walks_to_parent():
    """Verify multiple DMARC records at child are discarded, and tree walk continues to parent."""
    resolver = MockDNSResolver()
    # Subdomain has multiple conflicting DMARC records (both will be discarded)
    resolver.add_txt(
        "_dmarc.sub.example.com",
        ["v=DMARC1; p=reject", "v=DMARC1; p=quarantine"],
    )
    # Parent has exactly one valid record
    resolver.add_txt(
        "_dmarc.example.com",
        ["v=DMARC1; p=reject; psd=n"],
    )

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("sub.example.com")

    # Subdomain records discarded; walk continues up to example.com
    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.discovered_domain == "example.com"
    assert res.org_domain == "example.com"
    assert res.tree_walk_queries == 2


@pytest.mark.asyncio
async def test_dmarc_multiple_non_dmarc_txt_records_discarded():
    """Verify multiple non-DMARC TXT records are all discarded without error."""
    resolver = MockDNSResolver()
    resolver.add_txt(
        "_dmarc.sub.example.com",
        ["v=spf1 ~all", "some-token=abc", "google-site-verification=xyz"],
    )
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; psd=n"])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("sub.example.com")

    # Child TXT records discarded; walk reaches example.com
    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.discovered_domain == "example.com"


@pytest.mark.asyncio
async def test_dmarc_multiple_strings_within_single_txt_record_accepted():
    """Verify a single TXT resource record composed of multiple strings is concatenated and parsed."""
    resolver = MockDNSResolver()
    concatenated_str = "v=DMARC1; p=quarantine; " + "rua=mailto:rep@example.com"
    resolver.add_txt("_dmarc.example.com", [concatenated_str])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("example.com")

    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.tags["p"] == "quarantine"
    assert res.tags["rua"] == "mailto:rep@example.com"


@pytest.mark.asyncio
async def test_dmarc_invalid_or_unsupported_dmarc_version_discarded():
    """Verify RFC 9989 Section 4.7: records without v=DMARC1 (case-sensitive) are discarded."""
    resolver = MockDNSResolver()
    # v=DMARC2 is unsupported version
    resolver.add_txt("_dmarc.sub.example.com", ["v=DMARC2; p=reject"])
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; psd=n"])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("sub.example.com")

    # sub.example.com record is discarded; walk finds example.com
    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.discovered_domain == "example.com"


def test_is_dmarc_version1_record_helper():
    """Unit test for is_dmarc_version1_record helper."""
    assert is_dmarc_version1_record("v=DMARC1; p=reject") is True
    assert is_dmarc_version1_record("v = DMARC1 ; p=reject") is True
    assert is_dmarc_version1_record("v=DMARC1") is True
    # Case-sensitive
    assert is_dmarc_version1_record("v=dmarc1; p=reject") is False
    # Non-first tag
    assert is_dmarc_version1_record("p=reject; v=DMARC1") is False
    # Unsupported version
    assert is_dmarc_version1_record("v=DMARC2; p=reject") is False
    # Unrelated TXT
    assert is_dmarc_version1_record("v=spf1 ~all") is False
    assert is_dmarc_version1_record("") is False


# =============================================================================
# 5. TREE WALK BOUNDARIES, QUERY LIMITS & DNS ERRORS
# =============================================================================

@pytest.mark.asyncio
async def test_dmarc_dns_timeout_returns_temperror():
    """Verify DNS query timeout immediately yields TEMPERROR without walking further."""
    resolver = MockDNSResolver()
    resolver.set_error(
        "_dmarc.sub.timeout.com",
        status=DNSResponseStatus.TIMEOUT,
        error_type=DNSErrorType.TIMEOUT,
        query_type=DNSQueryType.TXT,
        message="DNS timeout",
    )

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("sub.timeout.com")

    assert res.status == DMARCDiscoveryStatus.TEMPERROR
    assert res.protocol_status == ProtocolStatus.TEMPERROR
    assert res.tree_walk_queries == 1
    assert "dns temporary error" in res.error_reason.lower()


@pytest.mark.asyncio
async def test_dmarc_dns_servfail_returns_temperror():
    """Verify DNS SERVFAIL immediately yields TEMPERROR."""
    resolver = MockDNSResolver()
    resolver.set_error(
        "_dmarc.servfail.com",
        status=DNSResponseStatus.SERVFAIL,
        error_type=DNSErrorType.SERVFAIL,
        query_type=DNSQueryType.TXT,
        message="Server failure",
    )

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("servfail.com")

    assert res.status == DMARCDiscoveryStatus.TEMPERROR
    assert res.protocol_status == ProtocolStatus.TEMPERROR
    assert res.tree_walk_queries == 1


@pytest.mark.asyncio
async def test_dmarc_parent_domain_traversal_success():
    """Verify upward tree walking from child domain to parent organizational domain."""
    resolver = MockDNSResolver()
    resolver.add_txt(
        "_dmarc.example.com",
        ["v=DMARC1; p=reject; sp=quarantine; psd=n"],
    )

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("mail.dept.corp.example.com")

    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.discovered_domain == "example.com"
    assert res.org_domain == "example.com"
    assert res.tags["p"] == "reject"
    assert res.tags["sp"] == "quarantine"
    assert res.psd_type == "n"
    assert res.tree_walk_queries == 4
    assert res.traversed_domains == [
        "mail.dept.corp.example.com",
        "dept.corp.example.com",
        "corp.example.com",
        "example.com",
    ]


@pytest.mark.asyncio
async def test_dmarc_eight_query_limit_and_ninth_query_blocked():
    """Verify strict query cap: exactly max queries executed, attempted next query blocked."""
    resolver = MockDNSResolver()
    config = AuthProtocolsConfig(dmarc_tree_walk_max_queries=4)
    discovery = DMARCRecordDiscovery(resolver=resolver, config=config)

    res = await discovery.discover("a.b.c.d.e.f.org")

    assert res.status == DMARCDiscoveryStatus.LIMIT_EXCEEDED
    assert res.protocol_status == ProtocolStatus.INDETERMINATE
    assert res.tree_walk_queries == 4
    assert len(res.traversed_domains) == 4
    assert "query limit (4) reached" in res.error_reason.lower()
    assert "blocked" in res.error_reason.lower()


@pytest.mark.asyncio
async def test_dmarc_label_shortening_for_deep_domain():
    """Verify RFC 9989 Section 4.10: domains with >= 8 labels are shortened to 7 labels."""
    resolver = MockDNSResolver()
    # 9 labels: sub.mail.dept.corp.team.alpha.beta.example.com
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject; psd=n"])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("sub.mail.dept.corp.team.alpha.beta.example.com")

    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.discovered_domain == "example.com"
    # Query 1: sub.mail.dept.corp.team.alpha.beta.example.com (original 9-label)
    # Query 2: shortened 7-label suffix -> dept.corp.team.alpha.beta.example.com (skipping mail)
    # Query 3: corp.team.alpha.beta.example.com
    # Query 4: team.alpha.beta.example.com
    # Query 5: alpha.beta.example.com
    # Query 6: beta.example.com
    # Query 7: example.com (FOUND)
    assert res.tree_walk_queries == 7
    assert res.traversed_domains[0] == "sub.mail.dept.corp.team.alpha.beta.example.com"
    assert res.traversed_domains[1] == "dept.corp.team.alpha.beta.example.com"
    assert "mail.dept.corp.team.alpha.beta.example.com" not in res.traversed_domains


@pytest.mark.asyncio
async def test_dmarc_default_eight_query_limit_enforced():
    """Verify standard default config limit of 8 queries strictly prevents 9th query."""
    resolver = MockDNSResolver()
    discovery = DMARCRecordDiscovery(resolver=resolver)  # default max_queries = 8

    # Mock domain with 8 subdomains (9 labels total)
    deep_domain = "1.2.3.4.5.6.7.8.test"
    res = await discovery.discover(deep_domain)

    # Must execute exactly 8 queries and block any 9th query
    assert res.tree_walk_queries == 8
    assert len(res.traversed_domains) == 8
    assert res.status == DMARCDiscoveryStatus.LIMIT_EXCEEDED
    assert res.protocol_status == ProtocolStatus.INDETERMINATE
    assert "query limit (8) reached" in res.error_reason.lower()


@pytest.mark.asyncio
async def test_dmarc_repeated_domain_prevention():
    """Verify repeated domain detection terminates walk without infinite loop."""
    resolver = MockDNSResolver()
    discovery = DMARCRecordDiscovery(resolver=resolver)

    res = await discovery.discover("loop.loop.loop")
    assert res.tree_walk_queries <= 3
    assert len(set(res.traversed_domains)) == len(res.traversed_domains)


# =============================================================================
# 6. RFC 9989 STEP 3.7.1C: PSD (psd=) DEFAULT AND FALLBACK VERIFICATION
# =============================================================================

@pytest.mark.asyncio
async def test_dmarc_psd_default_and_valid_values():
    """Verify RFC 9989 Section 4.7: missing psd defaults to 'u', valid 'y', 'n', 'u' accepted."""
    # Missing psd defaults to 'u'
    tags, err = parse_dmarc_tags("v=DMARC1; p=reject")
    assert err is None
    assert tags["psd"] == "u"

    # Explicit psd=y
    tags, err = parse_dmarc_tags("v=DMARC1; p=reject; psd=y")
    assert err is None
    assert tags["psd"] == "y"

    # Explicit psd=n
    tags, err = parse_dmarc_tags("v=DMARC1; p=reject; psd=n")
    assert err is None
    assert tags["psd"] == "n"

    # Explicit psd=u
    tags, err = parse_dmarc_tags("v=DMARC1; p=reject; psd=u")
    assert err is None
    assert tags["psd"] == "u"

    # Case-insensitivity: psd=Y, psd=N, psd=U normalize and accept
    tags, err = parse_dmarc_tags("v=DMARC1; p=reject; psd=Y")
    assert err is None
    assert tags["psd"] == "y"

    tags, err = parse_dmarc_tags("v=DMARC1; p=reject; psd=N")
    assert err is None
    assert tags["psd"] == "n"

    tags, err = parse_dmarc_tags("v=DMARC1; p=reject; psd=U")
    assert err is None
    assert tags["psd"] == "u"


@pytest.mark.asyncio
async def test_dmarc_psd_invalid_values_fall_back_to_default_u():
    """Verify RFC 9989 Section 4.7 & 4.8: invalid psd values fall back to 'u' without invalidating record."""
    invalid_cases = [
        "v=DMARC1; p=reject; psd=x",
        "v=DMARC1; p=reject; psd=invalid",
        "v=DMARC1; p=reject; psd=yes",
        "v=DMARC1; p=reject; psd=no",
        "v=DMARC1; p=reject; psd=1",
        "v=DMARC1; p=reject; psd=",
        "v=DMARC1; p=reject; psd=unknown_psd_mode",
    ]
    for raw in invalid_cases:
        tags, err = parse_dmarc_tags(raw)
        assert err is None, f"Expected successful parse with fallback for {raw}, got error: {err}"
        assert tags is not None
        assert tags["psd"] == "u"
        assert tags["p"] == "reject"


@pytest.mark.asyncio
async def test_dmarc_psd_duplicate_tags_strictly_rejected():
    """Verify duplicate psd tags remain strictly rejected as duplicate tag errors."""
    cases = [
        "v=DMARC1; p=reject; psd=y; psd=n",
        "v=DMARC1; p=reject; psd=u; psd=u",
        "v=DMARC1; p=reject; psd=y; psd=y",
        "v=DMARC1; p=reject; psd=n; psd=x",
    ]
    for raw in cases:
        tags, err = parse_dmarc_tags(raw)
        assert tags is None
        assert "duplicate tag 'psd'" in err.lower()


@pytest.mark.asyncio
async def test_dmarc_psd_invalid_value_in_tree_walk_discovery():
    """Verify invalid psd value does not invalidate record during DNS tree walk discovery."""
    resolver = MockDNSResolver()
    raw = "v=DMARC1; p=reject; psd=invalid_flag"
    resolver.add_txt("_dmarc.example.com", [raw])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("example.com")

    # Invalid psd falls back to default u; record discovery succeeds
    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.protocol_status == ProtocolStatus.PASS
    assert res.tags["psd"] == "u"
    assert res.psd_type == "u"
    assert res.is_psd is False

    dmarc_res = res.to_dmarc_result()
    assert dmarc_res.status == ProtocolStatus.PASS
    assert dmarc_res.policy == DMARCPolicy.REJECT
    assert dmarc_res.psd_type == "u"


@pytest.mark.asyncio
async def test_dmarc_psd_invalid_value_at_parent_treated_as_candidate():
    """Verify invalid psd at parent domain falls back to 'u' and acts as candidate org domain."""
    resolver = MockDNSResolver()
    # Parent published invalid psd value
    resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=quarantine; psd=x"])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("mail.example.com")

    # Parent record falls back to psd=u, stored as candidate, and successfully selected
    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.discovered_domain == "example.com"
    assert res.org_domain == "example.com"
    assert res.tags["psd"] == "u"
    assert res.psd_type == "u"
    assert res.is_psd is False


@pytest.mark.asyncio
async def test_dmarc_psd_y_multi_candidates_selects_fewest_labels_org_domain():
    """Step 3.7.3B: When multiple psd=u candidates exist below a psd=y PSD, select the Org Domain (fewest labels)."""
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.sub.company.co.uk", ["v=DMARC1; p=none; psd=u"])
    resolver.add_txt("_dmarc.company.co.uk", ["v=DMARC1; p=reject; psd=u"])
    resolver.add_txt("_dmarc.co.uk", ["v=DMARC1; p=none; psd=y"])

    discovery = DMARCRecordDiscovery(resolver=resolver)
    res = await discovery.discover("leaf.sub.company.co.uk")

    assert res.status == DMARCDiscoveryStatus.FOUND
    assert res.discovered_domain == "company.co.uk"
    assert res.org_domain == "company.co.uk"
    assert res.policy_discovery_source == "org_domain"
    assert res.tags["p"] == "reject"
    assert res.is_psd is False


@pytest.mark.asyncio
async def test_h3_dmarc_discovery_and_org_domain_resolver_errors_never_become_absent():
    """H3: DNSResponseStatus.ERROR (RESOLVER_ERROR/REFUSED/FORMERR -> TEMPERROR; INVALID_QUERY -> INDETERMINATE)."""
    for setter in ("set_resolver_error", "set_refused", "set_formerr"):
        resolver = MockDNSResolver()
        getattr(resolver, setter)("_dmarc.example.com", DNSQueryType.TXT)
        disc = DMARCRecordDiscovery(resolver=resolver)

        res = await disc.discover("example.com")
        assert res.status == DMARCDiscoveryStatus.TEMPERROR, f"discover() must not yield ABSENT for {setter}"
        assert res.protocol_status == ProtocolStatus.TEMPERROR

        org, org_status, _ = await disc.determine_org_domain("sub.example.com")
        assert org_status == DMARCDiscoveryStatus.TEMPERROR

    resolver_inv = MockDNSResolver()
    resolver_inv.set_invalid_query("_dmarc.example.com", DNSQueryType.TXT)
    disc_inv = DMARCRecordDiscovery(resolver=resolver_inv)

    res_inv = await disc_inv.discover("example.com")
    assert res_inv.status == DMARCDiscoveryStatus.INDETERMINATE
    assert res_inv.protocol_status == ProtocolStatus.INDETERMINATE

    _, org_inv_status, _ = await disc_inv.determine_org_domain("sub.example.com")
    assert org_inv_status == DMARCDiscoveryStatus.INDETERMINATE


@pytest.mark.asyncio
async def test_l1_psd_y_candidate_selection_ignores_intermediate_subdomains():
    """L1: Under psd=y, unrelated intermediate psd=u records below child_org_domain must NOT shadow PSD policy."""
    # 1. Missing child_org_domain (_dmarc.company.co.uk) with intermediate _dmarc.dept.company.co.uk (p=none; psd=u)
    #    must fall back to PSD _dmarc.co.uk (p=reject; psd=y), never selecting dept.company.co.uk!
    resolver = MockDNSResolver()
    resolver.add_txt("_dmarc.dept.company.co.uk", ["v=DMARC1; p=none; psd=u"])
    resolver.add_txt("_dmarc.a.dept.company.co.uk", ["v=DMARC1; p=none"])
    resolver.add_txt("_dmarc.co.uk", ["v=DMARC1; p=reject; sp=quarantine; psd=y"])

    disc = DMARCRecordDiscovery(resolver=resolver)
    res_shadow_blocked = await disc.discover("leaf.a.dept.company.co.uk")
    assert res_shadow_blocked.status == DMARCDiscoveryStatus.FOUND
    assert res_shadow_blocked.discovered_domain == "co.uk"
    assert res_shadow_blocked.org_domain == "company.co.uk"
    assert res_shadow_blocked.policy_discovery_source == "psd"
    assert res_shadow_blocked.is_psd is True
    assert res_shadow_blocked.tags["p"] == "reject"
    assert res_shadow_blocked.tags["sp"] == "quarantine"

    # 2. When exact child_org_domain (_dmarc.company.co.uk) exists alongside intermediate dept.company.co.uk,
    #    direct child_org_domain IS selected cleanly as org_domain.
    resolver.add_txt("_dmarc.company.co.uk", ["v=DMARC1; p=quarantine; psd=u"])
    res_child = await disc.discover("leaf.a.dept.company.co.uk")
    assert res_child.status == DMARCDiscoveryStatus.FOUND
    assert res_child.discovered_domain == "company.co.uk"
    assert res_child.org_domain == "company.co.uk"
    assert res_child.policy_discovery_source == "org_domain"
    assert res_child.is_psd is False
    assert res_child.tags["p"] == "quarantine"

    # 3. Direct Author Domain match still wins when querying author domain directly
    res_author = await disc.discover("dept.company.co.uk")
    assert res_author.discovered_domain == "dept.company.co.uk"
    assert res_author.policy_discovery_source == "author_domain"

    # 4. psd=n at dept.company.co.uk stops tree walk at dept.company.co.uk cleanly
    resolver2 = MockDNSResolver()
    resolver2.add_txt("_dmarc.dept.company.co.uk", ["v=DMARC1; p=reject; psd=n"])
    resolver2.add_txt("_dmarc.co.uk", ["v=DMARC1; p=none; psd=y"])
    disc2 = DMARCRecordDiscovery(resolver=resolver2)
    res_psdn = await disc2.discover("leaf.dept.company.co.uk")
    assert res_psdn.discovered_domain == "dept.company.co.uk"
    assert res_psdn.org_domain == "dept.company.co.uk"
    assert res_psdn.policy_discovery_source == "org_domain"
    assert res_psdn.is_psd is False
