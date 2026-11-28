"""
Unit test suite for Phase C: Offline Authentication Mode in AuthProtocolsAnalyzer.

Verifies:
1. Analyzer in offline mode blocks outbound DNS lookups completely.
2. Protocols report NOT_EVALUATED when offline without claiming active authentication failures.
3. Historical Authentication-Results headers are strictly treated as untrusted forensic evidence.
4. OfflineBlockDNSResolver guarantees zero network sockets or I/O.
"""

import pytest
from app.modules.auth_protocols.analyzer import AuthProtocolsAnalyzer
from app.modules.auth_protocols.config import AuthProtocolsConfig
from app.modules.auth_protocols.dns_resolver import DNSQueryType, OfflineBlockDNSResolver
from app.modules.contracts import (
    IngestionSource,
    ParsedEmail,
    ProtocolStatus,
    RawEmailPayload,
)
from app.modules.parser.parser import EmailParser


@pytest.mark.asyncio
async def test_offline_block_dns_resolver_prevents_network():
    """Verifies that OfflineBlockDNSResolver blocks DNS resolution and records attempts without network calls."""
    resolver = OfflineBlockDNSResolver()
    resp = await resolver.resolve("example.com", DNSQueryType.TXT)
    assert resp.status.value == "ERROR"
    assert resp.error_type.value == "RESOLVER_ERROR"
    assert "DNS resolution disabled in offline evaluation mode" in resp.error_message
    assert len(resolver.attempted_queries) == 1
    assert resolver.attempted_queries[0] == ("example.com", DNSQueryType.TXT)
    await resolver.close()


@pytest.mark.asyncio
async def test_auth_analyzer_offline_mode_returns_not_evaluated():
    """Verifies that AuthProtocolsAnalyzer in offline mode reports NOT_EVALUATED and performs 0 DNS queries."""
    analyzer = AuthProtocolsAnalyzer(offline_mode=True)
    raw_eml = (
        b"From: sender@example.com\r\n"
        b"To: recipient@target.org\r\n"
        b"Subject: Test Offline Auth\r\n"
        b"Authentication-Results: mx.target.org; spf=pass (google.com: domain of sender@example.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=sender@example.com; dkim=pass header.i=@example.com\r\n"
        b"\r\n"
        b"Test body."
    )
    parser = EmailParser()
    raw_payload = RawEmailPayload(raw_bytes=raw_eml, source=IngestionSource.DIRECT_UPLOAD)
    parsed = parser.parse(raw_payload)

    result = await analyzer.analyze(raw_payload, parsed)
    try:
        # Check protocol statuses
        assert result.spf_status == ProtocolStatus.NOT_EVALUATED
        assert result.dkim_status == ProtocolStatus.NOT_EVALUATED
        assert result.dmarc_status == ProtocolStatus.NOT_EVALUATED

        # Historical headers must remain untrusted
        assert len(result.parsed_auth_results) == 1
        hist_header = result.parsed_auth_results[0]
        assert hist_header.is_trusted is False

        # Telemetry verification
        assert result.execution_telemetry.get("offline_mode") is True
        assert result.execution_telemetry.get("dns_queries_executed") == 0

        # Finding exists
        assert any(f.code == "OFFLINE_EVALUATION" for f in result.findings)
    finally:
        await analyzer.shutdown()


@pytest.mark.asyncio
async def test_analyze_method_offline_mode_flag_override():
    """Verifies that passing offline_mode=True to analyze() enforces offline isolation even on standard analyzer."""
    analyzer = AuthProtocolsAnalyzer()
    raw_eml = b"From: attacker@spoofed.com\r\nTo: victim@college.edu\r\nSubject: Hi\r\n\r\nBody"
    parser = EmailParser()
    raw_payload = RawEmailPayload(raw_bytes=raw_eml, source=IngestionSource.DIRECT_UPLOAD)
    parsed = parser.parse(raw_payload)

    result = await analyzer.analyze(raw_payload, parsed, offline_mode=True)
    try:
        assert result.spf_status == ProtocolStatus.NOT_EVALUATED
        assert result.dmarc_status == ProtocolStatus.NOT_EVALUATED
        assert result.execution_telemetry.get("offline_mode") is True
    finally:
        await analyzer.shutdown()
