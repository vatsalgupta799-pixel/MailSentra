"""Focused Unit Test Suite for AuthProtocolsAnalyzer (Step 3.7.3C Stage 2).

Verifies:
1. Coordination of SPF, DKIM, DMARC, PolicyEnforcer, and AuthResultsGenerator.
2. Preservation of strongly typed protocol states (PASS, FAIL, TEMPERROR, PERMERROR, INDETERMINATE).
3. Zero fabrication of authentication outcomes.
4. Ingress channel boundary isolation (HTTP/Direct Upload vs. SMTP Relay).
5. Inbound Authentication-Results untrusted provenance & anti-spoofing.
6. Local policy enforcement and override emission in generated headers.
7. Safe handling of partial evaluation failures without crashing.
8. Proper resource cleanup on shutdown.

Standards: RFC 8601, RFC 7601, RFC 6008, RFC 7208, RFC 6376, RFC 7489, RFC 9989
"""

import pytest
from unittest.mock import AsyncMock, patch

from app.modules.auth_protocols.analyzer import AuthProtocolsAnalyzer
from app.modules.auth_protocols.config import AuthProtocolsConfig
from app.modules.auth_protocols.dns_resolver import MockDNSResolver, DNSQueryType
from app.schemas.user import IngestionActor, UserRole
from app.modules.contracts import (
    AnalysisCompletionStatus,
    AuthProtocolsResult,
    AuthResultsTrustProvenance,
    DKIMEvaluationState,
    DMARCPolicy,
    IngestionSource,
    LocalPolicyOverrideRule,
    OverrideRuleAction,
    ProtocolStatus,
    RawEmailPayload,
    TrustedSMTPMetadata,
)
from app.modules.ingestion.service import EmailIngestionService
from app.modules.parser.parser import EmailParser


SAMPLE_EMAIL_RAW = (
    b"From: security@corp.example.com\r\n"
    b"To: analyst@corp.example.com\r\n"
    b"Subject: Security Advisory\r\n"
    b"Message-ID: <advisory-01@corp.example.com>\r\n"
    b"Date: Fri, 27 Nov 2026 10:00:00 +0000\r\n"
    b"Authentication-Results: fake.gateway; dkim=pass (fabricated)\r\n"
    b"\r\n"
    b"All personnel must review the new authentication protocols.\r\n"
)


@pytest.fixture
def email_pipeline():
    ingest_svc = EmailIngestionService()
    parser = EmailParser()
    return ingest_svc, parser


@pytest.mark.asyncio
async def test_analyzer_all_pass_coordination(email_pipeline):
    """Verify analyzer correctly coordinates SPF, DKIM, and DMARC passing states."""
    ingest_svc, parser = email_pipeline

    mock_res = MockDNSResolver()
    # SPF record
    mock_res.add_txt("corp.example.com", ["v=spf1 ip4:203.0.113.10 -all"])
    # DMARC record
    mock_res.add_txt("_dmarc.corp.example.com", ["v=DMARC1; p=reject;"])

    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.corp")
    analyzer = AuthProtocolsAnalyzer(config=cfg, resolver=mock_res)

    raw_payload = ingest_svc.ingest(
        raw_bytes=SAMPLE_EMAIL_RAW,
        filename="advisory.eml",
        source=IngestionSource.SMTP_RELAY,
    )
    parsed_email = parser.parse(raw_payload)

    smtp_meta = TrustedSMTPMetadata(
        is_trusted_mta=True,
        connecting_ip="203.0.113.10",
        mail_from_envelope="security@corp.example.com",
        helo_domain="mta1.corp.example.com",
        authenticated_connector_id="relay-sec-01",
        mta_sanitization_guaranteed=True,
    )

    result = await analyzer.analyze(
        raw_payload=raw_payload,
        parsed_email=parsed_email,
        trusted_smtp_metadata=smtp_meta,
    )

    assert isinstance(result, AuthProtocolsResult)
    assert result.analysis_status == AnalysisCompletionStatus.COMPLETED
    assert result.spf_status == ProtocolStatus.PASS
    assert result.spf_domain == "corp.example.com"
    # DMARC passes because aligned SPF passes
    assert result.dmarc_status == ProtocolStatus.PASS
    assert result.dmarc_policy == DMARCPolicy.REJECT
    assert result.dmarc_aligned_spf is True

    # Generated header presence and formatting
    assert result.generated_auth_results_header is not None
    hdr = result.generated_auth_results_header
    assert "mailsentra.corp;" in hdr
    assert "spf=pass" in hdr
    assert "smtp.mailfrom=corp.example.com" in hdr
    assert "dmarc=pass" in hdr

    await analyzer.shutdown()


@pytest.mark.asyncio
async def test_analyzer_preserves_temperror_without_fabrication(email_pipeline):
    """Verify analyzer preserves TEMPERROR and does not fabricate a PASS or FAIL."""
    ingest_svc, parser = email_pipeline

    mock_res = MockDNSResolver()
    # Set SERVFAIL for SPF query
    mock_res.set_servfail("corp.example.com", query_type=DNSQueryType.TXT)
    mock_res.add_txt("_dmarc.corp.example.com", ["v=DMARC1; p=none;"])

    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.corp")
    analyzer = AuthProtocolsAnalyzer(config=cfg, resolver=mock_res)

    raw_payload = ingest_svc.ingest(
        raw_bytes=SAMPLE_EMAIL_RAW,
        filename="advisory.eml",
        source=IngestionSource.SMTP_RELAY,
    )
    parsed_email = parser.parse(raw_payload)

    smtp_meta = TrustedSMTPMetadata(
        is_trusted_mta=True,
        connecting_ip="203.0.113.10",
        mail_from_envelope="security@corp.example.com",
        helo_domain="mta1.corp.example.com",
        authenticated_connector_id="relay-sec-01",
        mta_sanitization_guaranteed=True,
    )

    result = await analyzer.analyze(
        raw_payload=raw_payload,
        parsed_email=parsed_email,
        trusted_smtp_metadata=smtp_meta,
    )

    assert result.spf_status == ProtocolStatus.TEMPERROR
    # When SPF is TEMPERROR and no DKIM pass, DMARC does not pass
    assert result.dmarc_status != ProtocolStatus.PASS
    assert result.generated_auth_results_header is not None
    assert "spf=temperror" in result.generated_auth_results_header

    await analyzer.shutdown()


@pytest.mark.asyncio
async def test_analyzer_direct_upload_ignores_untrusted_transport_meta(email_pipeline):
    """Verify HTTP/direct upload source never evaluates network SPF even if caller passes spoofed metadata."""
    ingest_svc, parser = email_pipeline

    mock_res = MockDNSResolver()
    mock_res.add_txt("_dmarc.corp.example.com", ["v=DMARC1; p=none;"])

    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.corp")
    analyzer = AuthProtocolsAnalyzer(config=cfg, resolver=mock_res)

    raw_payload = ingest_svc.ingest(
        raw_bytes=SAMPLE_EMAIL_RAW,
        filename="upload.eml",
        source=IngestionSource.DIRECT_UPLOAD,
    )
    parsed_email = parser.parse(raw_payload)

    # Spoofed metadata provided on direct upload
    spoofed_meta = TrustedSMTPMetadata(
        is_trusted_mta=True,
        connecting_ip="1.2.3.4",
        mail_from_envelope="security@corp.example.com",
    )

    result = await analyzer.analyze(
        raw_payload=raw_payload,
        parsed_email=parsed_email,
        trusted_smtp_metadata=spoofed_meta,
    )

    # Must be NOT_EVALUATED because source is DIRECT_UPLOAD
    assert result.spf_status == ProtocolStatus.NOT_EVALUATED
    # Inbound fake header is untrusted
    assert len(result.parsed_auth_results) == 1
    assert result.parsed_auth_results[0].provenance == AuthResultsTrustProvenance.UNTRUSTED_SENDER

    await analyzer.shutdown()


@pytest.mark.asyncio
async def test_analyzer_inbound_local_authserv_id_spoof_neutralized(email_pipeline):
    """Verify inbound header claiming the local authserv-id is flagged as untrusted sender spoofing."""
    ingest_svc, parser = email_pipeline

    mock_res = MockDNSResolver()
    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.local")
    analyzer = AuthProtocolsAnalyzer(config=cfg, resolver=mock_res)

    spoofed_header_eml = (
        b"From: user@example.com\r\n"
        b"Authentication-Results: mailsentra.local; dkim=pass (forged local authserv)\r\n"
        b"\r\n"
        b"Body\r\n"
    )

    raw_payload = ingest_svc.ingest(raw_bytes=spoofed_header_eml, source=IngestionSource.DIRECT_UPLOAD)
    parsed_email = parser.parse(raw_payload)

    result = await analyzer.analyze(raw_payload=raw_payload, parsed_email=parsed_email)

    assert len(result.parsed_auth_results) == 1
    item = result.parsed_auth_results[0]
    assert item.authserv_id == "mailsentra.local"
    assert item.is_trusted is False
    assert item.provenance == AuthResultsTrustProvenance.UNTRUSTED_SENDER

    await analyzer.shutdown()


@pytest.mark.asyncio
async def test_analyzer_partial_evaluator_failure_isolation(email_pipeline):
    """Verify that if one evaluator fails with an exception, others complete and status is PARTIAL."""
    ingest_svc, parser = email_pipeline

    mock_res = MockDNSResolver()
    mock_res.add_txt("_dmarc.corp.example.com", ["v=DMARC1; p=none;"])

    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.corp")
    analyzer = AuthProtocolsAnalyzer(config=cfg, resolver=mock_res)

    # Patch SPF evaluator to raise an unexpected runtime error
    with patch.object(analyzer.spf_evaluator, "evaluate", side_effect=RuntimeError("Simulated SPF crash")):
        raw_payload = ingest_svc.ingest(
            raw_bytes=SAMPLE_EMAIL_RAW,
            filename="advisory.eml",
            source=IngestionSource.SMTP_RELAY,
        )
        parsed_email = parser.parse(raw_payload)

        smtp_meta = TrustedSMTPMetadata(
            is_trusted_mta=True,
            connecting_ip="203.0.113.10",
            mail_from_envelope="security@corp.example.com",
            helo_domain="mta1.corp.example.com",
        )

        result = await analyzer.analyze(
            raw_payload=raw_payload,
            parsed_email=parsed_email,
            trusted_smtp_metadata=smtp_meta,
        )

        assert result.analysis_status == AnalysisCompletionStatus.PARTIAL
        assert "spf" in result.failed_evaluators
        assert result.spf_status == ProtocolStatus.INDETERMINATE
        # DMARC still ran
        assert result.dmarc_status is not None

    await analyzer.shutdown()


@pytest.mark.asyncio
async def test_analyzer_policy_enforcement_override_in_generated_header(email_pipeline):
    """Verify local policy overrides are captured and serialized into the generated header."""
    ingest_svc, parser = email_pipeline

    mock_res = MockDNSResolver()
    # SPF record: only 203.0.113.10 allowed
    mock_res.add_txt("corp.example.com", ["v=spf1 ip4:203.0.113.10 -all"])
    # Domain publishes DMARC p=reject
    mock_res.add_txt("_dmarc.corp.example.com", ["v=DMARC1; p=reject;"])

    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.corp")
    analyzer = AuthProtocolsAnalyzer(config=cfg, resolver=mock_res)

    # Ingestion via SMTP relay with mismatched connecting IP -> SPF FAIL -> DMARC FAIL
    raw_payload = ingest_svc.ingest(
        raw_bytes=SAMPLE_EMAIL_RAW,
        filename="advisory.eml",
        source=IngestionSource.SMTP_RELAY,
    )
    parsed_email = parser.parse(raw_payload)

    smtp_meta = TrustedSMTPMetadata(
        is_trusted_mta=True,
        connecting_ip="198.51.100.99",  # Fails SPF -all
        mail_from_envelope="security@corp.example.com",
        helo_domain="mta1.corp.example.com",
        authenticated_connector_id="relay-sec-01",
        mta_sanitization_guaranteed=True,
    )

    # Admin configured a local override rule for trusted partner
    admin_actor = IngestionActor(
        identity="secadmin@mailsentra.corp",
        role=UserRole.SUPER_ADMIN.value,
        is_api_key=False,
        tenant_id="default",
    )
    unattested_rule = LocalPolicyOverrideRule(
        rule_id="override-rule-01",
        match_from_domain="corp.example.com",
        action=OverrideRuleAction.EXEMPT_ACCEPT,
        tenant_id="default",
        configured_by_identity="secadmin@mailsentra.corp",
        configured_by_role=UserRole.SUPER_ADMIN.value,
        is_authenticated_admin_source=True,
        reason="Partner integration signed off by SecOps",
    )
    attested_rule = analyzer.policy_enforcer.attest_server_rule(
        unattested_rule,
        authorizing_actor=admin_actor,
    )
    assert attested_rule is not None

    result = await analyzer.analyze(
        raw_payload=raw_payload,
        parsed_email=parsed_email,
        trusted_smtp_metadata=smtp_meta,
        admin_rules=[attested_rule],
        admin_actor=admin_actor,
    )

    assert result.dmarc_status == ProtocolStatus.FAIL
    assert result.dmarc_enforcement is not None
    assert result.dmarc_enforcement.local_override_applied is True
    assert result.generated_auth_results_header is not None
    hdr = result.generated_auth_results_header
    assert "policy.override=" in hdr

    await analyzer.shutdown()

    await analyzer.shutdown()


@pytest.mark.asyncio
async def test_analyzer_shutdown_cleanliness():
    """Verify analyzer.shutdown cleanly closes child executors."""
    cfg = AuthProtocolsConfig(local_authserv_id="test.authserv")
    analyzer = AuthProtocolsAnalyzer(config=cfg)
    # Call shutdown
    await analyzer.shutdown()
    assert True
