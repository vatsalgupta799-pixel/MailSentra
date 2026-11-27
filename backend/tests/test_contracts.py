"""Tests for module data contracts and serialization."""

import pytest
from app.modules.contracts import (
    AlignmentMode,
    AnalysisCompletionStatus,
    AuthFinding,
    AuthProtocolsResult,
    AuthResultsTrustProvenance,
    DecisionTier,
    DKIMSignatureResult,
    DMARCPolicy,
    DMARCResult,
    IdentityAnalysisResult,
    ParsedAuthResultItem,
    ParsedAuthResultsHeader,
    ParsedEmail,
    ProtocolStatus,
    RiskDecisionReport,
    ScoredFactor,
    SPFResult,
    TrustedSMTPMetadata,
    UrlAnalysisResult,
    UrlFinding,
    UrlRiskSeverity,
)


def test_contracts_initialization_and_serialization():
    # 1. ParsedEmail contract
    parsed = ParsedEmail(
        message_id="<test@domain.com>",
        subject="Urgent: Wire Transfer Request",
        sender_header="CEO <ceo@legitcorp.com>",
        sender_address="ceo@legitcorp.com",
        sender_domain="legitcorp.com",
        recipient_addresses=["cfo@legitcorp.com"],
        body_plain="Please wire the invoice funds immediately.",
    )
    assert parsed.subject == "Urgent: Wire Transfer Request"
    assert len(parsed.urls) == 0

    # 2. AuthProtocolsResult contract
    auth_res = AuthProtocolsResult(
        spf_status=ProtocolStatus.PASS,
        spf_domain="legitcorp.com",
        dkim_status=ProtocolStatus.PASS,
        dmarc_status=ProtocolStatus.PASS,
        dmarc_policy=DMARCPolicy.REJECT,
    )
    assert auth_res.spf_status == ProtocolStatus.PASS

    # 3. UrlAnalysisResult contract
    url_finding = UrlFinding(
        url="http://192.168.1.1/login",
        defanged_url="hxxp[://]192[.]168[.]1[.]1/login",
        is_ip_host=True,
        severity=UrlRiskSeverity.SUSPICIOUS,
        reason="Direct IP address in URL host",
    )
    url_res = UrlAnalysisResult(
        total_urls_scanned=1,
        highest_severity=UrlRiskSeverity.SUSPICIOUS,
        findings=[url_finding],
    )
    assert len(url_res.findings) == 1
    assert url_res.findings[0].is_ip_host is True

    # 4. RiskDecisionReport contract
    report = RiskDecisionReport(
        composite_score=85.0,
        tier=DecisionTier.MALICIOUS,
        confidence=0.95,
        primary_threat_vector="Direct IP Phishing",
        explanation_summary="High-risk IP URL detected with mismatched sender.",
        contributing_factors=[
            ScoredFactor(
                category="URL_SECURITY",
                rule_id="IP_HOST_DETECTED",
                weight=1.0,
                score_delta=40.0,
                justification="Raw IP address used as URL host",
            )
        ],
    )
    assert report.tier == DecisionTier.MALICIOUS
    assert report.composite_score == 85.0
    assert len(report.contributing_factors) == 1


def test_protocol_status_enum_complete_set():
    expected_statuses = {
        "PASS",
        "FAIL",
        "SOFTFAIL",
        "NEUTRAL",
        "NONE",
        "PERMERROR",
        "TEMPERROR",
        "NOT_EVALUATED",
        "INDETERMINATE",
    }
    actual_statuses = {status.value for status in ProtocolStatus}
    assert actual_statuses == expected_statuses
    assert len(ProtocolStatus) == 9

    # Valid instantiation
    assert ProtocolStatus("NOT_EVALUATED") == ProtocolStatus.NOT_EVALUATED
    assert ProtocolStatus("INDETERMINATE") == ProtocolStatus.INDETERMINATE

    # Invalid status rejection
    with pytest.raises(ValueError):
        ProtocolStatus("UNKNOWN_STATUS")


def test_auth_protocols_result_backward_compatibility_and_defaults():
    # Instantiation without arguments retains full Day 1/2 compatibility defaults
    result = AuthProtocolsResult()
    assert result.spf_status == ProtocolStatus.NONE
    assert result.dkim_status == ProtocolStatus.NONE
    assert result.dmarc_status == ProtocolStatus.NONE
    assert result.dmarc_policy == DMARCPolicy.NOT_CONFIGURED
    assert result.dmarc_aligned_spf is False
    assert result.dmarc_aligned_dkim is False
    assert result.analysis_status == AnalysisCompletionStatus.COMPLETED
    assert result.failed_evaluators == []
    assert result.findings == []
    assert result.dkim_signatures == []

    # Serialization roundtrip
    dumped = result.model_dump()
    assert dumped["spf_status"] == "NONE"
    assert dumped["analysis_status"] == "COMPLETED"
    restored = AuthProtocolsResult.model_validate(dumped)
    assert restored.spf_status == ProtocolStatus.NONE
    assert restored.analysis_status == AnalysisCompletionStatus.COMPLETED


def test_missing_smtp_metadata_and_indeterminate_dmarc():
    # Missing / untrusted SMTP metadata leads to SPF NOT_EVALUATED
    smtp_meta = TrustedSMTPMetadata(connecting_ip=None, helo_domain=None, is_trusted_mta=False)
    assert smtp_meta.connecting_ip is None
    assert smtp_meta.is_trusted_mta is False

    spf_res = SPFResult(
        status=ProtocolStatus.NOT_EVALUATED,
        domain=None,
        error_reason="Missing trusted SMTP metadata; direct upload",
    )
    assert spf_res.status == ProtocolStatus.NOT_EVALUATED

    # When SPF is NOT_EVALUATED and DKIM is FAIL or NONE, DMARC must be represented
    # as INDETERMINATE rather than inventing a false DMARC failure
    auth_result = AuthProtocolsResult(
        spf_status=ProtocolStatus.NOT_EVALUATED,
        spf_domain=None,
        dkim_status=ProtocolStatus.FAIL,
        dkim_domain="attacker.com",
        dmarc_status=ProtocolStatus.INDETERMINATE,
        dmarc_policy=DMARCPolicy.REJECT,
        dmarc_aligned_spf=False,
        dmarc_aligned_dkim=False,
        spf_details=spf_res,
        dmarc_details=DMARCResult(
            status=ProtocolStatus.INDETERMINATE,
            policy=DMARCPolicy.REJECT,
            from_domain="target.com",
            error_reason="SPF is NOT_EVALUATED and DKIM failed; evaluation incomplete",
        ),
    )
    assert auth_result.spf_status == ProtocolStatus.NOT_EVALUATED
    assert auth_result.dmarc_status == ProtocolStatus.INDETERMINATE
    assert auth_result.dmarc_details.status == ProtocolStatus.INDETERMINATE


def test_multiple_dkim_signatures_representation():
    sig1 = DKIMSignatureResult(
        index=0,
        selector="s1",
        domain="example.com",
        algorithm="rsa-sha256",
        status=ProtocolStatus.PASS,
        key_size_bits=2048,
        canonicalization="relaxed/relaxed",
        is_aligned_with_from=True,
        aligned_relaxed=True,
        aligned_strict=True,
    )
    sig2 = DKIMSignatureResult(
        index=1,
        selector="ed2026",
        domain="mailservice.net",
        algorithm="ed25519-sha256",
        status=ProtocolStatus.PASS,
        is_aligned_with_from=False,
        aligned_relaxed=False,
        aligned_strict=False,
    )

    auth_res = AuthProtocolsResult(
        dkim_status=ProtocolStatus.PASS,
        dkim_domain="example.com",
        dkim_signatures=[sig1, sig2],
    )
    assert len(auth_res.dkim_signatures) == 2
    assert auth_res.dkim_signatures[0].algorithm == "rsa-sha256"
    assert auth_res.dkim_signatures[0].aligned_strict is True
    assert auth_res.dkim_signatures[1].algorithm == "ed25519-sha256"
    assert auth_res.dkim_signatures[1].is_aligned_with_from is False


def test_dmarc_alignment_strict_and_relaxed_outcomes():
    # Relaxed pass but strict fail (e.g. sub.domain.com vs domain.com)
    dmarc = DMARCResult(
        status=ProtocolStatus.PASS,
        policy=DMARCPolicy.QUARANTINE,
        org_domain="domain.com",
        from_domain="sub.domain.com",
        spf_aligned=True,
        dkim_aligned=False,
        spf_alignment_mode=AlignmentMode.RELAXED,
        dkim_alignment_mode=AlignmentMode.STRICT,
        spf_aligned_relaxed=True,
        spf_aligned_strict=False,
        dkim_aligned_relaxed=False,
        dkim_aligned_strict=False,
    )
    assert dmarc.spf_aligned_relaxed is True
    assert dmarc.spf_aligned_strict is False
    assert dmarc.spf_alignment_mode == AlignmentMode.RELAXED

    # In AuthProtocolsResult
    auth_res = AuthProtocolsResult(
        dmarc_status=ProtocolStatus.PASS,
        dmarc_policy=DMARCPolicy.QUARANTINE,
        dmarc_aligned_spf=True,
        spf_aligned_relaxed=True,
        spf_aligned_strict=False,
        dmarc_details=dmarc,
    )
    assert auth_res.spf_aligned_relaxed is True
    assert auth_res.spf_aligned_strict is False


def test_contracts_spf_and_dmarc_rfc_status_and_identities():
    # SPFResult contracts for synthesized bounce and standalone HELO
    spf_bounce = SPFResult(
        status=ProtocolStatus.PASS,
        domain="outbox.example.com",
        scope="helo",
        is_null_reverse_path=True,
        is_synthesized_mfrom=True,
        is_standalone_helo=False,
        identity="postmaster@outbox.example.com",
    )
    assert spf_bounce.is_null_reverse_path is True
    assert spf_bounce.is_synthesized_mfrom is True
    assert spf_bounce.is_standalone_helo is False
    assert spf_bounce.identity == "postmaster@outbox.example.com"

    # DMARCResult rfc_status returns standard_status, None when indeterminate
    dmarc_indet = DMARCResult(
        status=ProtocolStatus.INDETERMINATE,
        standard_status=None,
        internal_status=ProtocolStatus.INDETERMINATE,
    )
    assert dmarc_indet.standard_status is None
    assert dmarc_indet.rfc_status is None

    dmarc_pass = DMARCResult(
        status=ProtocolStatus.PASS,
        standard_status="pass",
    )
    assert dmarc_pass.rfc_status == "pass"

    dmarc_fail = DMARCResult(
        status=ProtocolStatus.FAIL,
        standard_status="fail",
    )
    assert dmarc_fail.rfc_status == "fail"


def test_step372d_dmarc_result_api_serialization_all_statuses():
    """Task 3: Trace result through DMARC evaluation, internal result objects, API schemas,
    and JSON serialization for INDETERMINATE, NOT_EVALUATED, NONE, PASS, FAIL, PERMERROR, TEMPERROR.
    """
    import json

    test_cases = [
        (ProtocolStatus.PASS, "pass", "pass"),
        (ProtocolStatus.FAIL, "fail", "fail"),
        (ProtocolStatus.NONE, "none", "none"),
        (ProtocolStatus.PERMERROR, "permerror", "permerror"),
        (ProtocolStatus.TEMPERROR, "temperror", "temperror"),
        (ProtocolStatus.INDETERMINATE, None, None),
        (ProtocolStatus.NOT_EVALUATED, None, None),
    ]

    for proto_status, expected_std, expected_rfc in test_cases:
        res = DMARCResult(
            status=proto_status,
            standard_status=expected_std,
            internal_status=proto_status if proto_status == ProtocolStatus.INDETERMINATE else None,
        )

        # 1. Python attribute inspection
        assert res.status == proto_status
        assert res.standard_status == expected_std
        assert res.rfc_status == expected_rfc

        # 2. model_dump dict serialization (verifies computed_field inclusion)
        dumped = res.model_dump()
        assert dumped["status"] == proto_status
        assert dumped["standard_status"] == expected_std
        assert dumped["rfc_status"] == expected_rfc

        # 3. model_dump_json JSON serialization
        json_str = res.model_dump_json()
        parsed = json.loads(json_str)
        assert parsed["status"] == proto_status.value
        assert parsed["standard_status"] == expected_std
        assert parsed["rfc_status"] == expected_rfc

        # 4. Crucial: INDETERMINATE and NOT_EVALUATED are NEVER serialized as 'fail' or 'none'
        if proto_status in (ProtocolStatus.INDETERMINATE, ProtocolStatus.NOT_EVALUATED):
            assert parsed["rfc_status"] is None
            assert parsed["standard_status"] is None
            assert parsed["rfc_status"] != "fail"
            assert parsed["rfc_status"] != "none"


def test_step372d_auth_protocols_result_nested_dmarc_json_serialization():
    """Task 3: Verify AuthProtocolsResult JSON serialization properly embeds DMARCResult with computed rfc_status."""
    import json

    dmarc = DMARCResult(
        status=ProtocolStatus.PASS,
        standard_status="pass",
        policy=DMARCPolicy.REJECT,
        org_domain="example.com",
        from_domain="mail.example.com",
        spf_aligned=True,
    )
    auth_res = AuthProtocolsResult(
        dmarc_status=ProtocolStatus.PASS,
        dmarc_policy=DMARCPolicy.REJECT,
        dmarc_aligned_spf=True,
        dmarc_details=dmarc,
    )

    dumped = auth_res.model_dump()
    assert dumped["dmarc_details"]["rfc_status"] == "pass"
    assert dumped["dmarc_details"]["standard_status"] == "pass"

    json_str = auth_res.model_dump_json()
    parsed = json.loads(json_str)
    assert parsed["dmarc_details"]["rfc_status"] == "pass"
    assert parsed["dmarc_details"]["standard_status"] == "pass"
    assert parsed["dmarc_details"]["org_domain"] == "example.com"


def test_auth_results_trust_provenance_and_untrusted_sender_flag():
    # 1. Locally verified by MailSentra
    local_header = ParsedAuthResultsHeader(
        authserv_id="mailsentra.local",
        provenance=AuthResultsTrustProvenance.LOCALLY_VERIFIED,
        is_trusted=True,
        results=[
            ParsedAuthResultItem(method="spf", status=ProtocolStatus.PASS),
            ParsedAuthResultItem(method="dkim", status=ProtocolStatus.PASS),
        ],
        raw_header="mailsentra.local; spf=pass; dkim=pass",
    )
    assert local_header.provenance == AuthResultsTrustProvenance.LOCALLY_VERIFIED
    assert local_header.is_trusted is True
    assert "Locally verified" in local_header.trust_evidence_reason

    # 2. Trusted upstream gateway with full verified evidence
    trusted_upstream = ParsedAuthResultsHeader(
        authserv_id="mx.corp-gateway.com",
        provenance=AuthResultsTrustProvenance.TRUSTED_UPSTREAM,
        authserv_id_matched_config=True,
        authenticated_connector_id="connector-corp-inbound-01",
        mta_sanitization_guaranteed=True,
        results=[ParsedAuthResultItem(method="dmarc", status=ProtocolStatus.PASS)],
        raw_header="mx.corp-gateway.com; dmarc=pass",
    )
    assert trusted_upstream.provenance == AuthResultsTrustProvenance.TRUSTED_UPSTREAM
    assert trusted_upstream.is_trusted is True
    assert "connector-corp-inbound-01" in trusted_upstream.trust_evidence_reason

    # 3. Untrusted sender-supplied header
    untrusted_header = ParsedAuthResultsHeader(
        authserv_id="fake-gateway.org",
        provenance=AuthResultsTrustProvenance.UNTRUSTED_SENDER,
        is_trusted=False,
        results=[ParsedAuthResultItem(method="spf", status=ProtocolStatus.PASS)],
        raw_header="fake-gateway.org; spf=pass",
    )
    assert untrusted_header.provenance == AuthResultsTrustProvenance.UNTRUSTED_SENDER
    assert untrusted_header.is_trusted is False


def test_forged_header_with_matching_authserv_id_remains_untrusted():
    # An attacker injects an Authentication-Results header containing a trusted authserv-id.
    # Even if authserv_id matches the configured string, without authenticated connector
    # evidence and MTA sanitization guarantee, it MUST be demoted to UNTRUSTED_SENDER!
    forged_header = ParsedAuthResultsHeader(
        authserv_id="mx.corp-gateway.com",
        authserv_id_matched_config=True,
        provenance=AuthResultsTrustProvenance.TRUSTED_UPSTREAM,
        authenticated_connector_id=None,  # Missing authenticated connector!
        mta_sanitization_guaranteed=False,  # Missing sanitization guarantee!
        results=[
            ParsedAuthResultItem(method="spf", status=ProtocolStatus.PASS),
            ParsedAuthResultItem(method="dkim", status=ProtocolStatus.PASS),
            ParsedAuthResultItem(method="dmarc", status=ProtocolStatus.PASS),
        ],
        raw_header="mx.corp-gateway.com; spf=pass; dkim=pass; dmarc=pass",
    )
    assert forged_header.provenance == AuthResultsTrustProvenance.UNTRUSTED_SENDER
    assert forged_header.is_trusted is False
    assert "Insufficient trust evidence" in forged_header.trust_evidence_reason
    assert "authserv-id match without authenticated connector" in forged_header.trust_evidence_reason


def test_missing_or_incomplete_trust_evidence_defaults_to_untrusted():
    # Case A: Matching authserv-id and connector, but NO sanitization guarantee
    case_a = ParsedAuthResultsHeader(
        authserv_id="mx.corp-gateway.com",
        authserv_id_matched_config=True,
        authenticated_connector_id="connector-1",
        mta_sanitization_guaranteed=False,
        raw_header="mx.corp-gateway.com; spf=pass",
        provenance=AuthResultsTrustProvenance.TRUSTED_UPSTREAM,
    )
    assert case_a.provenance == AuthResultsTrustProvenance.UNTRUSTED_SENDER
    assert case_a.is_trusted is False

    # Case B: Matching authserv-id and sanitization guarantee, but NO authenticated connector ID
    case_b = ParsedAuthResultsHeader(
        authserv_id="mx.corp-gateway.com",
        authserv_id_matched_config=True,
        authenticated_connector_id=None,
        mta_sanitization_guaranteed=True,
        raw_header="mx.corp-gateway.com; spf=pass",
        provenance=AuthResultsTrustProvenance.TRUSTED_UPSTREAM,
    )
    assert case_b.provenance == AuthResultsTrustProvenance.UNTRUSTED_SENDER
    assert case_b.is_trusted is False

    # Case C: Authenticated connector and sanitization guarantee, but authserv-id NOT matched
    case_c = ParsedAuthResultsHeader(
        authserv_id="foreign-id.net",
        authserv_id_matched_config=False,
        authenticated_connector_id="connector-1",
        mta_sanitization_guaranteed=True,
        raw_header="foreign-id.net; spf=pass",
        provenance=AuthResultsTrustProvenance.TRUSTED_UPSTREAM,
    )
    assert case_c.provenance == AuthResultsTrustProvenance.UNTRUSTED_SENDER
    assert case_c.is_trusted is False

    # Case D: Default construction with no trust evidence
    case_d = ParsedAuthResultsHeader(
        authserv_id="any.domain.com",
        raw_header="any.domain.com; spf=pass",
    )
    assert case_d.provenance == AuthResultsTrustProvenance.UNTRUSTED_SENDER
    assert case_d.is_trusted is False


def test_untrusted_headers_cannot_override_local_verification_results():
    # Local verification strictly failed
    local_spf = ProtocolStatus.FAIL
    local_dkim = ProtocolStatus.FAIL
    local_dmarc = ProtocolStatus.FAIL

    # Forged upstream header attempting to spoof PASS
    spoofed_header = ParsedAuthResultsHeader(
        authserv_id="mx.corp-gateway.com",
        authserv_id_matched_config=True,
        authenticated_connector_id=None,
        mta_sanitization_guaranteed=False,
        provenance=AuthResultsTrustProvenance.TRUSTED_UPSTREAM,  # Demoted to UNTRUSTED_SENDER
        results=[
            ParsedAuthResultItem(method="spf", status=ProtocolStatus.PASS),
            ParsedAuthResultItem(method="dkim", status=ProtocolStatus.PASS),
            ParsedAuthResultItem(method="dmarc", status=ProtocolStatus.PASS),
        ],
        raw_header="mx.corp-gateway.com; spf=pass; dkim=pass; dmarc=pass",
    )

    auth_result = AuthProtocolsResult(
        spf_status=local_spf,
        dkim_status=local_dkim,
        dmarc_status=local_dmarc,
        parsed_auth_results=[spoofed_header],
    )

    # 1. Local statuses must remain FAIL
    assert auth_result.spf_status == ProtocolStatus.FAIL
    assert auth_result.dkim_status == ProtocolStatus.FAIL
    assert auth_result.dmarc_status == ProtocolStatus.FAIL

    # 2. Trusted headers filter must exclude the untrusted header
    trusted_headers = auth_result.get_trusted_auth_results()
    assert len(trusted_headers) == 0

    # 3. Spoof detection telemetry flag must be True
    assert auth_result.has_untrusted_spoofed_auth_results() is True

    # 4. Raw header preserved for forensics/diagnostics
    assert auth_result.parsed_auth_results[0].raw_header == spoofed_header.raw_header


def test_analysis_completion_state_and_failed_evaluator_tracking():
    # 1. Normal absent evaluation: NOT_EVALUATED, but analysis_status is COMPLETED
    # and failed_evaluators is empty.
    absent_eval = AuthProtocolsResult(
        spf_status=ProtocolStatus.NOT_EVALUATED,
        analysis_status=AnalysisCompletionStatus.COMPLETED,
        failed_evaluators=[],
    )
    assert absent_eval.spf_status == ProtocolStatus.NOT_EVALUATED
    assert absent_eval.analysis_status == AnalysisCompletionStatus.COMPLETED
    assert len(absent_eval.failed_evaluators) == 0

    # 2. Evaluation failure: TEMPERROR, analysis_status is PARTIAL,
    # and evaluator is tracked in failed_evaluators with an AuthFinding.
    finding = AuthFinding(
        code="DKIM_WORKER_TIMEOUT",
        protocol="DKIM",
        severity="WARNING",
        message="DKIM verification timed out while waiting for worker thread",
        details={"timeout_seconds": 3.0, "active_workers": 8},
    )
    failed_eval = AuthProtocolsResult(
        spf_status=ProtocolStatus.PASS,
        dkim_status=ProtocolStatus.TEMPERROR,
        dmarc_status=ProtocolStatus.INDETERMINATE,
        analysis_status=AnalysisCompletionStatus.PARTIAL,
        failed_evaluators=["dkim"],
        findings=[finding],
    )
    assert failed_eval.analysis_status == AnalysisCompletionStatus.PARTIAL
    assert "dkim" in failed_eval.failed_evaluators
    assert len(failed_eval.findings) == 1
    assert failed_eval.findings[0].code == "DKIM_WORKER_TIMEOUT"


def test_contracts_import_from_auth_protocols_module():
    import app.modules.auth_protocols as ap

    assert hasattr(ap, "ProtocolStatus")
    assert hasattr(ap, "DMARCPolicy")
    assert hasattr(ap, "DMARCDisposition")
    assert hasattr(ap, "DMARCEnforcementDecision")
    assert hasattr(ap, "DMARCPolicyEnforcer")
    assert hasattr(ap, "PolicyOverrideType")
    assert hasattr(ap, "LocalPolicyOverrideRule")
    assert hasattr(ap, "OverrideRuleAction")
    assert hasattr(ap, "ForwarderTrustEvidence")
    assert hasattr(ap, "CorroboratingThreatSignals")
    assert hasattr(ap, "SMTPAdapterDecisionContract")
    assert hasattr(ap, "AnalysisCompletionStatus")
    assert hasattr(ap, "AlignmentMode")
    assert hasattr(ap, "TrustedSMTPMetadata")
    assert hasattr(ap, "DKIMSignatureResult")
    assert hasattr(ap, "SPFResult")
    assert hasattr(ap, "DMARCResult")
    assert hasattr(ap, "AuthResultsTrustProvenance")
    assert hasattr(ap, "ParsedAuthResultItem")
    assert hasattr(ap, "ParsedAuthResultsHeader")
    assert hasattr(ap, "AuthFinding")
    assert hasattr(ap, "AuthProtocolsResult")
    assert ap.ProtocolStatus.NOT_EVALUATED == "NOT_EVALUATED"
    assert ap.ProtocolStatus.INDETERMINATE == "INDETERMINATE"


def test_step373b_dmarc_enforcement_decision_contract_roundtrip():
    """Verify Step 3.7.3B Tier 1/2/3 contracts serialize cleanly and never emit INDETERMINATE rfc_status."""
    import app.modules.auth_protocols as ap

    assert hasattr(ap, "DNSOutcomeCategory")

    dmarc_res = DMARCResult(
        status=ProtocolStatus.INDETERMINATE,
        standard_status=None,
        internal_status=ProtocolStatus.INDETERMINATE,
        policy=DMARCPolicy.REJECT,
        record_p_policy=DMARCPolicy.NONE,
        non_existent_subdomain_policy=DMARCPolicy.REJECT,
        policy_discovery_source="org_domain",
        policy_domain="example.com",
        applicable_policy_tag="np",
        from_domain="ghost.example.com",
        org_domain="example.com",
        subdomain_existence_probe_enabled=True,
        subdomain_existence_status="confirmed_non_existent",
        test_mode=True,
    )
    enforcer = ap.DMARCPolicyEnforcer()
    decision = enforcer.enforce(dmarc_res)

    dumped = decision.model_dump(mode="json")
    restored = ap.DMARCEnforcementDecision.model_validate(dumped)
    assert restored.dmarc_status == ProtocolStatus.INDETERMINATE
    assert restored.dmarc_rfc_status is None
    assert restored.record_p_policy == DMARCPolicy.NONE
    assert restored.selected_applicable_policy == DMARCPolicy.REJECT
    assert restored.applicable_policy_tag == "np"
    assert restored.test_mode is True
    assert restored.test_mode_applied is False
    assert restored.local_override_applied is False
    assert restored.disposition == ap.DMARCDisposition.MANUAL_REVIEW_INCOMPLETE
    assert restored.smtp_contract is None


def test_step373b_remediation_m5_config_and_policy_serialization():
    """M5: Verify config rejects disabling §7.4 safeguard and contracts preserve p/sp/np/t=y/override distinctly."""
    from pydantic import ValidationError
    import app.modules.auth_protocols as ap

    assert hasattr(ap, "DKIMEvaluationState")

    # Default and True accepted
    cfg_default = ap.AuthProtocolsConfig()
    assert cfg_default.dmarc_enforce_strict_reject_only_with_corroboration is True
    assert cfg_default.dmarc_enable_subdomain_existence_probe is False
    assert ap.AuthProtocolsConfig(dmarc_enforce_strict_reject_only_with_corroboration=True)

    # False or invalid non-boolean rejected at validation boundary
    with pytest.raises(ValidationError):
        ap.AuthProtocolsConfig(dmarc_enforce_strict_reject_only_with_corroboration=False)
    with pytest.raises(ValidationError):
        ap.AuthProtocolsConfig(dmarc_enforce_strict_reject_only_with_corroboration="false")  # type: ignore[arg-type]

    # Contracts keep record_p_policy distinct from sp/np selected policy & effective t=y policy
    res_np = DMARCResult(
        status=ProtocolStatus.FAIL,
        standard_status="fail",
        policy=DMARCPolicy.REJECT,
        record_p_policy=DMARCPolicy.NONE,
        subdomain_policy=DMARCPolicy.QUARANTINE,
        non_existent_subdomain_policy=DMARCPolicy.REJECT,
        applicable_policy_tag="np",
        policy_discovery_source="org_domain",
        policy_domain="example.com",
        from_domain="ghost.example.com",
        org_domain="example.com",
        test_mode=True,
    )
    enforcer = ap.DMARCPolicyEnforcer()
    dec = enforcer.enforce(res_np)
    data = dec.model_dump(mode="json")
    assert data["record_p_policy"] == "none"
    assert data["selected_applicable_policy"] == "reject"
    assert data["effective_policy"] == "quarantine"
    assert data["test_mode_applied"] is True
    assert data["local_override_applied"] is False
    assert "published_policy" not in data


def test_step373b_remediation_l2_typed_dkim_state_contract_roundtrip():
    """L2: Verify DKIMEvaluationState & alignment provenance serialize cleanly across contracts."""
    import app.modules.auth_protocols as ap

    sig = ap.DKIMSignatureResult(
        index=0,
        status=ProtocolStatus.PERMERROR,
        evaluation_state=ap.DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES,
        reason_code="MISSING_RAW_MESSAGE_BYTES",
        alignment_source="uncomputed",
        alignment_is_authoritative=False,
    )
    auth_res = ap.AuthProtocolsResult(
        dkim_status=ProtocolStatus.PERMERROR,
        dkim_evaluation_state=ap.DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES,
        dkim_signatures=[sig],
    )
    dumped = auth_res.model_dump(mode="json")
    restored = ap.AuthProtocolsResult.model_validate(dumped)
    assert restored.dkim_evaluation_state == ap.DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES
    assert restored.dkim_signatures[0].reason_code == "MISSING_RAW_MESSAGE_BYTES"
    assert restored.dkim_signatures[0].alignment_is_authoritative is False

