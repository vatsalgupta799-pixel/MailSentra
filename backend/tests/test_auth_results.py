"""Comprehensive Unit and Security Tests for Authentication-Results Generator and Trust Evaluator.

Standards: RFC 8601, RFC 7601, RFC 6008, RFC 5322, RFC 9989, RFC 7208, RFC 6376
Component: Step 3.7.3C Stage 1
"""

import pytest
from pydantic import ValidationError

from app.modules.auth_protocols.config import AuthProtocolsConfig
from app.modules.auth_protocols.evaluators.auth_results import (
    AuthResultsGenerator,
    AuthResultsTrustEvaluator,
    redact_local_part,
    sanitize_header_token,
    sanitize_quoted_comment,
)
from app.modules.contracts import (
    AuthProtocolsResult,
    AuthResultsTrustProvenance,
    DKIMEvaluationState,
    DKIMSignatureResult,
    DMARCDisposition,
    DMARCEnforcementDecision,
    DMARCPolicy,
    DMARCResult,
    IngestionSource,
    ParsedAuthResultItem,
    ParsedAuthResultsHeader,
    PolicyOverrideType,
    ProtocolStatus,
    SPFResult,
    TrustedSMTPMetadata,
)


# =====================================================================
# 1. Configuration & local_authserv_id Syntax Validation Tests
# =====================================================================

def test_local_authserv_id_valid_syntax():
    """Verify valid FQDN and RFC 8601 atom tokens are accepted."""
    cfg1 = AuthProtocolsConfig(local_authserv_id="mailsentra.local")
    assert cfg1.local_authserv_id == "mailsentra.local"

    cfg2 = AuthProtocolsConfig(local_authserv_id="mx1.secops.corp.example.com")
    assert cfg2.local_authserv_id == "mx1.secops.corp.example.com"

    cfg3 = AuthProtocolsConfig(local_authserv_id="secops_authserv_01")
    assert cfg3.local_authserv_id == "secops_authserv_01"

    cfg_none = AuthProtocolsConfig(local_authserv_id=None)
    assert cfg_none.local_authserv_id is None

    cfg_empty = AuthProtocolsConfig(local_authserv_id="   ")
    assert cfg_empty.local_authserv_id is None


def test_local_authserv_id_invalid_syntax_and_injection():
    """Verify control characters, whitespace, semicolons, and CRLF injection are rejected."""
    # Semicolons / header delimiter injection
    with pytest.raises(ValidationError):
        AuthProtocolsConfig(local_authserv_id="mailsentra.local; dkim=pass")

    # CRLF injection
    with pytest.raises(ValidationError):
        AuthProtocolsConfig(local_authserv_id="mailsentra.local\r\nBcc: victim@secops.local")

    # Quotes / slashes
    with pytest.raises(ValidationError):
        AuthProtocolsConfig(local_authserv_id="\"mailsentra.local\"")

    # Whitespace
    with pytest.raises(ValidationError):
        AuthProtocolsConfig(local_authserv_id="mailsentra local")

    # Non-ASCII / control chars
    with pytest.raises(ValidationError):
        AuthProtocolsConfig(local_authserv_id="mailsentra\x00.local")

    # Length > 255 chars
    oversize = "a" * 256 + ".com"
    with pytest.raises(ValidationError):
        AuthProtocolsConfig(local_authserv_id=oversize)


def test_trusted_authserv_ids_validation():
    """Verify trusted_authserv_ids items are validated against the same syntax rules."""
    cfg = AuthProtocolsConfig(
        trusted_authserv_ids=["mx1.partner.com", "gateway.inbound.org"]
    )
    assert len(cfg.trusted_authserv_ids) == 2

    with pytest.raises(ValidationError):
        AuthProtocolsConfig(trusted_authserv_ids=["bad;id.com"])


# =====================================================================
# 2. Generator: Valid Serialization & Full Method Mapping
# =====================================================================

def test_generator_standard_pass_all_methods():
    """Verify complete header serialization with SPF pass, DKIM pass, and DMARC pass."""
    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.local")
    gen = AuthResultsGenerator(cfg)

    spf_res = SPFResult(
        status=ProtocolStatus.PASS,
        domain="example.com",
        scope="mfrom",
        identity="sender@example.com",
    )
    dkim_sig = DKIMSignatureResult(
        index=0,
        domain="example.com",
        selector="s2024",
        identity="@example.com",
        algorithm="rsa-sha256",
        signature_b_prefix="a1b2c3d4",
        status=ProtocolStatus.PASS,
    )
    dmarc_res = DMARCResult(
        status=ProtocolStatus.PASS,
        standard_status="pass",
        from_domain="example.com",
        policy=DMARCPolicy.REJECT,
        record_p_policy=DMARCPolicy.REJECT,
    )

    header = gen.generate(
        spf_result=spf_res,
        dkim_results=[dkim_sig],
        dmarc_result=dmarc_res,
    )

    assert header is not None
    assert header.startswith("Authentication-Results: mailsentra.local;")
    assert "spf=pass" in header
    assert "smtp.mailfrom=example.com" in header
    assert "dkim=pass" in header
    assert "header.d=example.com" in header
    assert "header.s=s2024" in header
    assert "header.b=a1b2c3d4" in header
    assert "dmarc=pass" in header
    assert "header.from=example.com" in header
    assert "policy.dmarc=reject" in header


def test_generator_null_reverse_path_spf_helo_scope():
    """Verify that null reverse-path SPF evaluates to smtp.helo property per RFC 8601 §2.7.2."""
    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.local")
    gen = AuthResultsGenerator(cfg)

    spf_res = SPFResult(
        status=ProtocolStatus.PASS,
        domain="outbound.mailrelay.com",
        scope="helo",
        identity="postmaster@outbound.mailrelay.com",
        is_null_reverse_path=True,
    )

    header = gen.generate(spf_result=spf_res)
    assert header is not None
    assert "spf=pass" in header
    assert "smtp.helo=outbound.mailrelay.com" in header
    assert "smtp.mailfrom=" not in header


def test_generator_all_valid_protocol_statuses():
    """Verify that all valid protocol status values map correctly to lowercase tokens."""
    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.local")
    gen = AuthResultsGenerator(cfg)

    # Test softfail & neutral for SPF
    spf_soft = SPFResult(status=ProtocolStatus.SOFTFAIL, domain="soft.com")
    h_soft = gen.generate(spf_result=spf_soft)
    assert "spf=softfail" in h_soft

    spf_neutral = SPFResult(status=ProtocolStatus.NEUTRAL, domain="neutral.com")
    h_neutral = gen.generate(spf_result=spf_neutral)
    assert "spf=neutral" in h_neutral

    spf_permerr = SPFResult(status=ProtocolStatus.PERMERROR, domain="perm.com", error_reason="syntax error")
    h_perm = gen.generate(spf_result=spf_permerr)
    assert "spf=permerror" in h_perm
    assert "(syntax error)" in h_perm

    # Test temperror for DMARC
    dmarc_temp = DMARCResult(
        status=ProtocolStatus.TEMPERROR,
        standard_status="temperror",
        from_domain="temp.com",
    )
    h_dmarc_temp = gen.generate(dmarc_result=dmarc_temp)
    assert "dmarc=temperror" in h_dmarc_temp
    assert "header.from=temp.com" in h_dmarc_temp


# =====================================================================
# 3. Generator: Multiple DKIM Signatures & RFC 6008 header.b
# =====================================================================

def test_generator_multiple_dkim_signatures_and_header_b():
    """Verify independent clauses for multiple DKIM signatures with RFC 6008 header.b disambiguation."""
    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.local")
    gen = AuthResultsGenerator(cfg)

    sig1 = DKIMSignatureResult(
        index=0,
        domain="example.com",
        selector="s1",
        algorithm="rsa-sha256",
        signature_b_prefix="ABCDEF12",
        status=ProtocolStatus.PASS,
    )
    sig2 = DKIMSignatureResult(
        index=1,
        domain="partner.net",
        selector="p2024",
        algorithm="ed25519-sha256",
        signature_b_prefix="98765432",
        status=ProtocolStatus.FAIL,
        error_reason="Bad body hash",
    )

    header = gen.generate(dkim_results=[sig1, sig2])
    assert header is not None
    assert "dkim=pass" in header
    assert "header.d=example.com" in header
    assert "header.b=ABCDEF12" in header

    assert "dkim=fail" in header
    assert "header.d=partner.net" in header
    assert "header.b=98765432" in header
    assert "(Bad body hash)" in header


def test_generator_multiple_dkim_signatures_prefix_collision():
    """Verify that if two signatures share the exact same 8-char b= prefix, disambiguation is applied."""
    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.local")
    gen = AuthResultsGenerator(cfg)

    sig1 = DKIMSignatureResult(
        index=0,
        domain="example.com",
        selector="s1",
        signature_b_prefix="SAMEPREF",
        status=ProtocolStatus.PASS,
    )
    sig2 = DKIMSignatureResult(
        index=1,
        domain="example.com",
        selector="s2",
        signature_b_prefix="SAMEPREF",
        status=ProtocolStatus.PASS,
    )

    header = gen.generate(dkim_results=[sig1, sig2])
    assert "header.b=SAMEPREF-1" in header
    assert "header.b=SAMEPREF-2" in header


def test_generator_dkim_zero_signatures_evaluated():
    """Verify that when DKIM was evaluated and 0 signatures were found, dkim=none is emitted."""
    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.local")
    gen = AuthResultsGenerator(cfg)

    header = gen.generate(dkim_results=[], dkim_evaluated=True)
    assert header is not None
    assert "dkim=none (no signatures found)" in header


# =====================================================================
# 4. Generator: Missing & Indeterminate Results (RFC 8601 §2.2)
# =====================================================================

def test_generator_all_methods_unrun_or_indeterminate_emits_none():
    """RFC 8601 §2.2: When no authentication results are available, emit '; none'."""
    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.local")
    gen = AuthResultsGenerator(cfg)

    # All None
    h_all_none = gen.generate()
    assert h_all_none == "Authentication-Results: mailsentra.local; none"

    # All NOT_EVALUATED or INDETERMINATE
    spf_indet = SPFResult(status=ProtocolStatus.INDETERMINATE)
    dmarc_indet = DMARCResult(status=ProtocolStatus.INDETERMINATE)
    h_indet = gen.generate(
        spf_result=spf_indet,
        dkim_results=None,
        dmarc_result=dmarc_indet,
        dkim_evaluated=False,
    )
    assert h_indet == "Authentication-Results: mailsentra.local; none"


def test_generator_omits_internal_indeterminate_and_not_evaluated():
    """Verify that INDETERMINATE or NOT_EVALUATED is strictly omitted and never fabricated as fail or pass."""
    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.local")
    gen = AuthResultsGenerator(cfg)

    # SPF is INDETERMINATE (e.g. internal resolver error)
    # DKIM is PASS
    # DMARC is NOT_EVALUATED
    spf_err = SPFResult(status=ProtocolStatus.INDETERMINATE, domain="err.com")
    dkim_pass = DKIMSignatureResult(
        index=0,
        domain="ok.com",
        status=ProtocolStatus.PASS,
        signature_b_prefix="12345678",
    )
    dmarc_unrun = DMARCResult(status=ProtocolStatus.NOT_EVALUATED)

    header = gen.generate(
        spf_result=spf_err,
        dkim_results=[dkim_pass],
        dmarc_result=dmarc_unrun,
    )

    assert "spf=" not in header
    assert "dmarc=" not in header
    assert "dkim=pass" in header
    assert "header.d=ok.com" in header


def test_generator_unconfigured_authserv_id_returns_none():
    """Verify that when local_authserv_id is None, generate() returns None."""
    cfg = AuthProtocolsConfig(local_authserv_id=None)
    gen = AuthResultsGenerator(cfg)

    spf_res = SPFResult(status=ProtocolStatus.PASS, domain="example.com")
    assert gen.generate(spf_result=spf_res) is None


# =====================================================================
# 5. Generator: DMARC Local Overrides & RFC 9989 Policy Emitted
# =====================================================================

def test_generator_dmarc_local_override_emits_policy_override():
    """Verify that local policy overrides are safely emitted in comments and policy.override."""
    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.local")
    gen = AuthResultsGenerator(cfg)

    dmarc_res = DMARCResult(
        status=ProtocolStatus.FAIL,
        standard_status="fail",
        from_domain="bank.com",
        record_p_policy=DMARCPolicy.REJECT,
    )
    enforcement = DMARCEnforcementDecision(
        disposition=DMARCDisposition.ACCEPT,
        local_override_applied=True,
        override_reasons=[PolicyOverrideType.LOCAL_POLICY],
        forwarder_exempted=True,
        effective_policy=DMARCPolicy.REJECT,
    )

    header = gen.generate(
        dmarc_result=dmarc_res,
        enforcement_decision=enforcement,
    )

    assert "dmarc=fail" in header
    assert "header.from=bank.com" in header
    assert "policy.dmarc=reject" in header
    assert "policy.override=local_policy" in header
    assert "local policy override" in header


# =====================================================================
# 6. Generator: CRLF Injection Defense & Line Folding
# =====================================================================

def test_generator_crlf_injection_neutralized():
    """Verify that adversarial CRLF injections inside domains, selectors, or reasons are neutralized."""
    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.local")
    gen = AuthResultsGenerator(cfg)

    # Malicious injection in domain and reason
    spf_evil = SPFResult(
        status=ProtocolStatus.PASS,
        domain="evil.com\r\nBcc: victim@secops.local",
        error_reason="Legit error\r\nInjected-Header: evil",
    )
    dkim_evil = DKIMSignatureResult(
        index=0,
        domain="evil.com\r\nX-Injected: test",
        selector="s1\0evil",
        signature_b_prefix="b123\r\n",
        status=ProtocolStatus.PASS,
    )

    header = gen.generate(spf_result=spf_evil, dkim_results=[dkim_evil])
    assert header is not None

    # Check each line: no line may start with Bcc: or X-Injected: or contain unescaped CRLF
    lines = header.split("\r\n")
    for line in lines:
        assert not line.startswith("Bcc:")
        assert not line.startswith("X-Injected:")
        assert not line.startswith("Injected-Header:")
        assert "\0" not in line


def test_generator_header_line_folding_rfc5322():
    """Verify lines are clamped to <= 78 chars and folded with RFC 5322 CRLF + WSP."""
    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.local")
    gen = AuthResultsGenerator(cfg)

    # Construct multiple verbose clauses
    sig_list = [
        DKIMSignatureResult(
            index=i,
            domain=f"subdomain-very-long-name-number-{i}.enterprise-example-domain.com",
            selector=f"selector-key-rot-2026-q1-{i}",
            algorithm="rsa-sha256",
            signature_b_prefix=f"PREFIX{i:04d}",
            status=ProtocolStatus.PASS,
            error_reason=f"Signature {i} verified successfully with 2048-bit key",
        )
        for i in range(4)
    ]

    header = gen.generate(dkim_results=sig_list)
    assert header is not None

    lines = header.split("\r\n")
    assert len(lines) > 1

    for line in lines:
        # Every folded line must be <= 78 chars (or strictly < 998 in extreme un-splittable cases)
        assert len(line) <= 78, f"Line exceeds 78 chars: '{line}' (len={len(line)})"
        # Folded lines must begin with whitespace
        if line != lines[0]:
            assert line.startswith(" ") or line.startswith("\t")


def test_redact_local_part():
    """Verify local-part PII redaction rules."""
    assert redact_local_part("user@example.com") == "***@example.com"
    assert redact_local_part("POSTMASTER@example.com") == "postmaster@example.com"
    assert redact_local_part("mailer-daemon@example.com") == "mailer-daemon@example.com"
    assert redact_local_part("@example.com") == "@example.com"
    assert redact_local_part("bare-domain.com") == "bare-domain.com"
    assert redact_local_part(None) is None


# =====================================================================
# 7. Trust Evaluator: Inbound Authentication-Results Parsing & Trust
# =====================================================================

def test_evaluator_untrusted_by_default():
    """Verify that an arbitrary inbound Authentication-Results header defaults to UNTRUSTED_SENDER."""
    cfg = AuthProtocolsConfig(
        local_authserv_id="mailsentra.local",
        trusted_authserv_ids=["trusted-partner.com"],
    )
    evaluator = AuthResultsTrustEvaluator(cfg)

    raw = "Authentication-Results: foreign-mail.com; spf=pass smtp.mailfrom=foreign.com"
    parsed = evaluator.parse_auth_results_header(raw)

    assert parsed.authserv_id == "foreign-mail.com"
    assert parsed.provenance == AuthResultsTrustProvenance.UNTRUSTED_SENDER
    assert parsed.is_trusted is False
    assert len(parsed.results) == 1
    assert parsed.results[0].method == "spf"
    assert parsed.results[0].status == ProtocolStatus.PASS


def test_evaluator_inbound_claiming_local_authserv_id_is_untrusted():
    """RFC 8601 §5: An inbound header claiming the receiver's own local authserv-id is strictly untrusted."""
    cfg = AuthProtocolsConfig(
        local_authserv_id="mailsentra.local",
        trusted_authserv_ids=["gateway.partner.com"],
    )
    evaluator = AuthResultsTrustEvaluator(cfg)

    raw = "Authentication-Results: mailsentra.local; dkim=pass (forged); dmarc=pass"
    parsed = evaluator.parse_auth_results_header(raw)

    assert parsed.authserv_id == "mailsentra.local"
    assert parsed.provenance == AuthResultsTrustProvenance.UNTRUSTED_SENDER
    assert parsed.is_trusted is False
    assert "claims receiver's local authserv-id" in parsed.trust_evidence_reason


def test_evaluator_trusted_upstream_satisfied_on_smtp():
    """Verify that an inbound header claiming a trusted authserv-id on SMTP with MTA evidence is TRUSTED_UPSTREAM."""
    cfg = AuthProtocolsConfig(
        local_authserv_id="mailsentra.local",
        trusted_authserv_ids=["trusted-mta.corp.com"],
        trusted_forwarder_connector_ids=["connector-corp-01"],
    )
    evaluator = AuthResultsTrustEvaluator(cfg)

    mta_meta = TrustedSMTPMetadata(
        is_trusted_mta=True,
        mta_sanitization_guaranteed=True,
        authenticated_connector_id="connector-corp-01",
        connecting_ip="10.0.0.1",
    )

    raw = "Authentication-Results: trusted-mta.corp.com; dmarc=pass header.from=partner.com"
    parsed = evaluator.parse_auth_results_header(
        raw,
        trusted_smtp_metadata=mta_meta,
        ingress_channel=IngestionSource.SMTP_RELAY,
    )

    assert parsed.authserv_id == "trusted-mta.corp.com"
    assert parsed.provenance == AuthResultsTrustProvenance.TRUSTED_UPSTREAM
    assert parsed.is_trusted is True
    assert "connector-corp-01" in parsed.trust_evidence_reason


def test_evaluator_trusted_upstream_fails_on_non_smtp_channel():
    """Verify that even with matching trusted authserv-id, non-SMTP channel remains UNTRUSTED_SENDER."""
    cfg = AuthProtocolsConfig(
        local_authserv_id="mailsentra.local",
        trusted_authserv_ids=["trusted-mta.corp.com"],
        trusted_forwarder_connector_ids=["connector-corp-01"],
    )
    evaluator = AuthResultsTrustEvaluator(cfg)

    mta_meta = TrustedSMTPMetadata(
        is_trusted_mta=True,
        mta_sanitization_guaranteed=True,
        authenticated_connector_id="connector-corp-01",
    )

    raw = "Authentication-Results: trusted-mta.corp.com; dmarc=pass"
    parsed = evaluator.parse_auth_results_header(
        raw,
        trusted_smtp_metadata=mta_meta,
        ingress_channel=IngestionSource.DIRECT_UPLOAD,  # HTTP upload!
    )

    assert parsed.provenance == AuthResultsTrustProvenance.UNTRUSTED_SENDER
    assert parsed.is_trusted is False
    assert "Non-SMTP ingress channel" in parsed.trust_evidence_reason


def test_evaluator_trusted_upstream_fails_missing_sanitization_guarantee():
    """Verify that missing MTA sanitization guarantee demotes trusted ID to UNTRUSTED_SENDER."""
    cfg = AuthProtocolsConfig(
        local_authserv_id="mailsentra.local",
        trusted_authserv_ids=["trusted-mta.corp.com"],
        trusted_forwarder_connector_ids=["connector-corp-01"],
    )
    evaluator = AuthResultsTrustEvaluator(cfg)

    mta_meta = TrustedSMTPMetadata(
        is_trusted_mta=True,
        mta_sanitization_guaranteed=False,  # NOT guaranteed!
        authenticated_connector_id="connector-corp-01",
    )

    raw = "Authentication-Results: trusted-mta.corp.com; dmarc=pass"
    parsed = evaluator.parse_auth_results_header(
        raw,
        trusted_smtp_metadata=mta_meta,
        ingress_channel=IngestionSource.SMTP_RELAY,
    )

    assert parsed.provenance == AuthResultsTrustProvenance.UNTRUSTED_SENDER
    assert parsed.is_trusted is False


def test_evaluator_multi_clause_parsing():
    """Verify parser extracts multiple method clauses and properties accurately."""
    evaluator = AuthResultsTrustEvaluator()
    raw = (
        "Authentication-Results: gateway.example.com 1; "
        "spf=pass (mailsentra: SPF matches) smtp.mailfrom=example.com; "
        "dkim=pass (2048-bit RSA) header.d=example.com header.s=s1 header.b=abcdef12; "
        "dmarc=fail (p=reject) header.from=example.com policy.dmarc=reject"
    )

    parsed = evaluator.parse_auth_results_header(raw)
    assert parsed.authserv_id == "gateway.example.com"
    assert parsed.version == 1
    assert len(parsed.results) == 3

    spf_item = parsed.results[0]
    assert spf_item.method == "spf"
    assert spf_item.status == ProtocolStatus.PASS
    assert spf_item.properties.get("smtp.mailfrom") == "example.com"
    assert "SPF matches" in (spf_item.reason or "")

    dkim_item = parsed.results[1]
    assert dkim_item.method == "dkim"
    assert dkim_item.status == ProtocolStatus.PASS
    assert dkim_item.properties.get("header.b") == "abcdef12"

    dmarc_item = parsed.results[2]
    assert dmarc_item.method == "dmarc"
    assert dmarc_item.status == ProtocolStatus.FAIL
    assert dmarc_item.properties.get("policy.dmarc") == "reject"


# =====================================================================
# 8. Regression Tests: Contracts & Model Roundtrips
# =====================================================================

def test_contract_dkim_signature_b_prefix_and_generated_header_roundtrip():
    """Verify DKIMSignatureResult.signature_b_prefix and AuthProtocolsResult.generated_auth_results_header."""
    sig = DKIMSignatureResult(
        index=0,
        domain="example.com",
        signature_b_prefix="A1B2C3D4",
    )
    assert sig.signature_b_prefix == "A1B2C3D4"

    auth_res = AuthProtocolsResult(
        spf_status=ProtocolStatus.PASS,
        dkim_status=ProtocolStatus.PASS,
        generated_auth_results_header="Authentication-Results: mailsentra.local; spf=pass",
    )
    assert auth_res.generated_auth_results_header == "Authentication-Results: mailsentra.local; spf=pass"
    d = auth_res.model_dump(mode="json")
    assert d["generated_auth_results_header"] == "Authentication-Results: mailsentra.local; spf=pass"
