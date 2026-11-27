"""End-to-End Pipeline Integration Tests for Step 3.7.3C.

Verifies AuthProtocolsAnalyzer and its integration into ScanService.ingest_and_parse().
Standards: RFC 8601, RFC 7601, RFC 6008, RFC 5322, RFC 9989
"""

import pytest
from unittest.mock import AsyncMock, patch

from app.modules.auth_protocols.analyzer import AuthProtocolsAnalyzer
from app.modules.auth_protocols.config import AuthProtocolsConfig
from app.modules.auth_protocols.dns_resolver import MockDNSResolver, DNSResponse, DNSRecord
from app.modules.contracts import (
    AuthProtocolsResult,
    AuthResultsTrustProvenance,
    IngestionSource,
    ProtocolStatus,
    TrustedSMTPMetadata,
)
from app.services.scan_service import ScanService


SAMPLE_EML = (
    b"From: sender@example.com\r\n"
    b"To: recipient@example.com\r\n"
    b"Subject: Test Email for Pipeline\r\n"
    b"Message-ID: <pipeline-test-01@example.com>\r\n"
    b"Date: Fri, 27 Nov 2026 10:00:00 +0000\r\n"
    b"Authentication-Results: attacker.com; dkim=pass (forged); dmarc=pass\r\n"
    b"\r\n"
    b"Hello, this is a test email body for authentication pipeline verification.\r\n"
)

SAMPLE_EML_WITH_DKIM = (
    b"From: sender@example.com\r\n"
    b"To: recipient@example.com\r\n"
    b"Subject: Signed Test Email\r\n"
    b"Message-ID: <pipeline-test-02@example.com>\r\n"
    b"Date: Fri, 27 Nov 2026 10:00:00 +0000\r\n"
    b"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com;\r\n"
    b" s=s2026; h=from:to:subject:message-id:date; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;\r\n"
    b" b=dGVzdHNpZ25hdHVyZWJ5dGVzMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=\r\n"
    b"\r\n"
    b"Hello, this is a signed test email body.\r\n"
)


@pytest.mark.asyncio
async def test_analyzer_direct_upload_preserves_bytes_and_evaluates():
    """Verify AuthProtocolsAnalyzer evaluates direct upload with no transport metadata safely."""
    mock_resolver = MockDNSResolver()
    mock_resolver.add_txt(
        "_dmarc.example.com",
        ["v=DMARC1; p=none;"],
    )

    cfg = AuthProtocolsConfig(local_authserv_id="mailsentra.local")
    analyzer = AuthProtocolsAnalyzer(config=cfg, resolver=mock_resolver)

    from app.modules.ingestion.service import EmailIngestionService
    from app.modules.parser.parser import EmailParser

    ingest_svc = EmailIngestionService()
    parser = EmailParser()

    raw_payload = ingest_svc.ingest(
        raw_bytes=SAMPLE_EML,
        filename="test.eml",
        source=IngestionSource.DIRECT_UPLOAD,
    )
    parsed = parser.parse(raw_payload)

    result = await analyzer.analyze(
        raw_payload=raw_payload,
        parsed_email=parsed,
    )

    assert isinstance(result, AuthProtocolsResult)
    # Direct upload has no transport metadata -> SPF is NOT_EVALUATED
    assert result.spf_status == ProtocolStatus.NOT_EVALUATED
    # DKIM was evaluated, 0 signatures found -> overall NONE
    assert result.dkim_status == ProtocolStatus.NONE
    # DMARC evaluated against p=none
    assert result.dmarc_policy.value == "none"
    # Generated header exists in result
    assert result.generated_auth_results_header is not None
    assert "mailsentra.local;" in result.generated_auth_results_header

    # Inbound header from attacker.com was evaluated and untrusted
    assert len(result.parsed_auth_results) == 1
    inbound_ar = result.parsed_auth_results[0]
    assert inbound_ar.authserv_id == "attacker.com"
    assert inbound_ar.provenance == AuthResultsTrustProvenance.UNTRUSTED_SENDER
    assert inbound_ar.is_trusted is False

    await analyzer.shutdown()


@pytest.mark.asyncio
async def test_scan_service_ingest_and_parse_integration():
    """Verify ScanService.ingest_and_parse() attaches auth_protocols telemetry to ScanIncident."""
    scan_svc = ScanService()
    # Configure local_authserv_id on analyzer config
    scan_svc.auth_analyzer.config.local_authserv_id = "mailsentra.local"

    # Add mock DMARC record to analyzer's resolver
    if isinstance(scan_svc.auth_analyzer.resolver, MockDNSResolver):
        scan_svc.auth_analyzer.resolver.add_txt(
            "_dmarc.example.com",
            ["v=DMARC1; p=reject;"],
        )

    incident, parsed_email = await scan_svc.ingest_and_parse(
        raw_bytes=SAMPLE_EML,
        filename="sample.eml",
        source=IngestionSource.DIRECT_UPLOAD,
    )

    assert incident is not None
    assert parsed_email is not None

    # Telemetry must contain auth_protocols
    assert "auth_protocols" in incident.telemetry
    auth_data = incident.telemetry["auth_protocols"]
    assert "spf_status" in auth_data
    assert "dkim_status" in auth_data
    assert "dmarc_status" in auth_data
    assert "generated_auth_results_header" in auth_data
    assert auth_data["spf_status"] == "NOT_EVALUATED"

    # Generated header is accessible for preview
    gen_hdr = auth_data["generated_auth_results_header"]
    assert gen_hdr is not None
    assert "mailsentra.local;" in gen_hdr

    # Message parsing succeeded and preserved headers
    assert parsed_email.subject == "Test Email for Pipeline"


@pytest.mark.asyncio
async def test_scan_service_smtp_relay_with_trusted_metadata():
    """Verify that SMTP relay with TrustedSMTPMetadata evaluates SPF properly."""
    scan_svc = ScanService()
    scan_svc.auth_analyzer.config.local_authserv_id = "mailsentra.local"

    # Mock resolver responses for SPF and DMARC
    mock_res = MockDNSResolver()
    mock_res.add_txt("example.com", ["v=spf1 ip4:198.51.100.1 -all"])
    mock_res.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject;"])
    scan_svc.auth_analyzer.resolver = mock_res
    scan_svc.auth_analyzer.spf_evaluator.resolver = mock_res
    scan_svc.auth_analyzer.dmarc_evaluator.resolver = mock_res

    smtp_meta = TrustedSMTPMetadata(
        is_trusted_mta=True,
        connecting_ip="198.51.100.1",
        mail_from_envelope="sender@example.com",
        helo_domain="mail.example.com",
        authenticated_connector_id="conn-internal-01",
        mta_sanitization_guaranteed=True,
    )

    incident, parsed_email = await scan_svc.ingest_and_parse(
        raw_bytes=SAMPLE_EML,
        filename="smtp_message.eml",
        source=IngestionSource.SMTP_RELAY,
        trusted_smtp_metadata=smtp_meta,
    )

    assert incident is not None
    auth_data = incident.telemetry["auth_protocols"]
    # SPF evaluated successfully to PASS
    assert auth_data["spf_status"] == "PASS"
    assert auth_data["spf_domain"] == "example.com"
    # DMARC PASS due to aligned SPF PASS
    assert auth_data["dmarc_status"] == "PASS"

    gen_hdr = auth_data["generated_auth_results_header"]
    assert "spf=pass" in gen_hdr
    assert "smtp.mailfrom=example.com" in gen_hdr
    assert "dmarc=pass" in gen_hdr


@pytest.mark.asyncio
async def test_scan_service_auth_exception_resilience():
    """Verify that if auth analyzer encounters an unexpected error, ScanService handles it gracefully."""
    scan_svc = ScanService()

    # Patch analyzer to raise an unexpected runtime error
    with patch.object(scan_svc.auth_analyzer, "analyze", side_effect=RuntimeError("Simulated analyzer crash")):
        incident, parsed_email = await scan_svc.ingest_and_parse(
            raw_bytes=SAMPLE_EML,
            filename="crash_test.eml",
        )

        assert incident is not None
        assert "auth_protocols" in incident.telemetry
        auth_data = incident.telemetry["auth_protocols"]
        assert auth_data["analysis_status"] == "FAILED"
        assert "Simulated analyzer crash" in auth_data["error"]
        assert auth_data["spf_status"] == "NOT_EVALUATED"
        assert auth_data["failed_evaluators"] == ["auth_protocols_analyzer"]
