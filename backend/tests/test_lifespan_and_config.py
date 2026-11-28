"""Automated test suite for Subsystem Operationalization & Application Lifespan Integration (Step 3.7.4).

Verifies:
1. Operational configuration loading and RFC 8601 syntax validation for LOCAL_AUTHSERV_ID.
2. DMARC_POLICY_ENFORCEMENT_ENABLED toggle behavior (isolation from evaluation).
3. AuthProtocolsAnalyzer resource lifecycle, worker termination, and DNS cache cleanup.
4. Idempotency of shutdown calls.
5. Exception resilience across subsystem shutdowns and FastAPI lifespan lifecycle.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.modules.auth_protocols.analyzer import AuthProtocolsAnalyzer
from app.modules.auth_protocols.config import AuthProtocolsConfig
from app.modules.auth_protocols.dns_resolver import AsyncDNSResolver, MockDNSResolver, DNSResponse, DNSResponseStatus
from app.modules.auth_protocols.executor import DKIMExecutor
from app.modules.contracts import (
    AnalysisCompletionStatus,
    DMARCDisposition,
    DMARCPolicy,
    DMARCResult,
    IngestionSource,
    ParsedEmail,
    ProtocolStatus,
    RawEmailPayload,
    SPFResult,
    TrustedSMTPMetadata,
)
from app.modules.parser.parser import EmailParser
from app.services.scan_service import ScanService


# =====================================================================
# 1. Configuration & Validation Tests
# =====================================================================

class TestOperationalConfiguration:
    """Verifies Settings validation for LOCAL_AUTHSERV_ID and DMARC_POLICY_ENFORCEMENT_ENABLED."""

    def test_default_configuration_values(self):
        s = Settings()
        assert s.LOCAL_AUTHSERV_ID is None
        assert s.DMARC_POLICY_ENFORCEMENT_ENABLED is True

    @pytest.mark.parametrize(
        "valid_id",
        [
            "mail.example.com",
            "mx1.corp.mailsentra.com",
            "authserv-1",
            "cluster-node_1.sec.net",
            "a.b.c.d",
            "edge-mta-42",
        ],
    )
    def test_local_authserv_id_valid_values(self, valid_id: str):
        s = Settings(LOCAL_AUTHSERV_ID=valid_id)
        assert s.LOCAL_AUTHSERV_ID == valid_id

    @pytest.mark.parametrize(
        "invalid_id",
        [
            "mail.example.com; rm -rf /",
            "mail.example.com\r\nX-Injected: evil",
            "mail.example.com\n",
            "auth serv.example.com",
            "server:25",
            "host/path",
            '"quoted"',
            "'single_quoted'",
            "<brackets>",
            "trailing.dot.",
            ".leading.dot",
            "double..dot",
            "null\x00byte",
            "x" * 256,  # exceeds 255 chars
        ],
    )
    def test_local_authserv_id_invalid_values_rejected(self, invalid_id: str):
        with pytest.raises(ValidationError):
            Settings(LOCAL_AUTHSERV_ID=invalid_id)

    def test_local_authserv_id_empty_and_whitespace_coerced_to_none(self):
        s1 = Settings(LOCAL_AUTHSERV_ID="")
        assert s1.LOCAL_AUTHSERV_ID is None

        s2 = Settings(LOCAL_AUTHSERV_ID="   ")
        assert s2.LOCAL_AUTHSERV_ID is None

    def test_dmarc_policy_enforcement_toggle(self):
        s_disabled = Settings(DMARC_POLICY_ENFORCEMENT_ENABLED=False)
        assert s_disabled.DMARC_POLICY_ENFORCEMENT_ENABLED is False

        s_enabled = Settings(DMARC_POLICY_ENFORCEMENT_ENABLED=True)
        assert s_enabled.DMARC_POLICY_ENFORCEMENT_ENABLED is True


# =====================================================================
# 2. Subsystem Wiring & Policy Enforcement Isolation Tests
# =====================================================================

class TestSubsystemConfigurationWiring:
    """Verifies Analyzer initializes with Settings values and respects policy toggles."""

    def test_analyzer_defaults_to_core_settings(self, monkeypatch):
        monkeypatch.setattr("app.core.config.settings.LOCAL_AUTHSERV_ID", "mta.local.corp")
        monkeypatch.setattr("app.core.config.settings.DMARC_POLICY_ENFORCEMENT_ENABLED", False)

        analyzer = AuthProtocolsAnalyzer()
        try:
            assert analyzer.config.local_authserv_id == "mta.local.corp"
            assert analyzer.config.dmarc_policy_enforcement_enabled is False
        finally:
            # Clean up default resolver and executor
            asyncio.run(analyzer.shutdown())

    @pytest.mark.asyncio
    async def test_dmarc_enforcement_disabled_preserves_evaluations(self):
        """When DMARC_POLICY_ENFORCEMENT_ENABLED is False, SPF/DKIM/DMARC evaluations

        must still execute fully, but receiver-local enforcement decisions must be skipped.
        """
        resolver = MockDNSResolver()
        resolver.add_txt("example.com", ["v=spf1 -all"])
        resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject;"])

        config = AuthProtocolsConfig(
            local_authserv_id="mx.mailsentra.local",
            dmarc_policy_enforcement_enabled=False,
        )
        analyzer = AuthProtocolsAnalyzer(config=config, resolver=resolver)

        try:
            raw_bytes = (
                b"From: sender@example.com\r\n"
                b"To: victim@mailsentra.local\r\n"
                b"Subject: Test Enforcement Toggle\r\n"
                b"Message-ID: <toggle-1@example.com>\r\n"
                b"\r\n"
                b"Hello World\r\n"
            )
            raw_payload = RawEmailPayload(
                raw_bytes=raw_bytes,
                sha256_hash="dummy",
                size_bytes=len(raw_bytes),
                source=IngestionSource.SMTP_RELAY,
            )
            parsed_email = EmailParser().parse(raw_payload)
            smtp_meta = TrustedSMTPMetadata(
                is_trusted_mta=True,
                connecting_ip="198.51.100.1",
                mail_from_envelope="sender@example.com",
                helo_domain="mta.example.com",
                authenticated_connector_id="relay-1",
            )

            result = await analyzer.analyze(
                raw_payload=raw_payload,
                parsed_email=parsed_email,
                trusted_smtp_metadata=smtp_meta,
            )

            # Protocol evaluations MUST still complete accurately
            assert result.spf_status == ProtocolStatus.FAIL
            assert result.dmarc_status == ProtocolStatus.FAIL
            assert result.dmarc_details is not None
            assert result.dmarc_details.policy == DMARCPolicy.REJECT

            # Enforcement decision must be skipped (None) and marked in telemetry
            assert result.dmarc_enforcement is None
            assert result.execution_telemetry.get("policy_enforcement") == "disabled"

            # Authentication-Results header still generates valid protocol outcomes
            assert result.generated_auth_results_header is not None
            assert "dmarc=fail" in result.generated_auth_results_header
            assert "spf=fail" in result.generated_auth_results_header
        finally:
            await analyzer.shutdown()

    @pytest.mark.asyncio
    async def test_dmarc_enforcement_enabled_generates_decision(self):
        """When DMARC_POLICY_ENFORCEMENT_ENABLED is True (default), policy enforcement

        evaluates receiver-local disposition.
        """
        resolver = MockDNSResolver()
        resolver.add_txt("example.com", ["v=spf1 -all"])
        resolver.add_txt("_dmarc.example.com", ["v=DMARC1; p=reject;"])

        config = AuthProtocolsConfig(
            local_authserv_id="mx.mailsentra.local",
            dmarc_policy_enforcement_enabled=True,
        )
        analyzer = AuthProtocolsAnalyzer(config=config, resolver=resolver)

        try:
            raw_bytes = (
                b"From: sender@example.com\r\n"
                b"To: victim@mailsentra.local\r\n"
                b"Subject: Test Enforcement Toggle\r\n"
                b"Message-ID: <toggle-2@example.com>\r\n"
                b"\r\n"
                b"Hello World\r\n"
            )
            raw_payload = RawEmailPayload(
                raw_bytes=raw_bytes,
                sha256_hash="dummy",
                size_bytes=len(raw_bytes),
                source=IngestionSource.SMTP_RELAY,
            )
            parsed_email = EmailParser().parse(raw_payload)
            smtp_meta = TrustedSMTPMetadata(
                is_trusted_mta=True,
                connecting_ip="198.51.100.1",
                mail_from_envelope="sender@example.com",
                helo_domain="mta.example.com",
                authenticated_connector_id="relay-1",
            )

            result = await analyzer.analyze(
                raw_payload=raw_payload,
                parsed_email=parsed_email,
                trusted_smtp_metadata=smtp_meta,
            )

            assert result.dmarc_enforcement is not None
            assert result.dmarc_enforcement.disposition in (DMARCDisposition.REJECT, DMARCDisposition.QUARANTINE)
            assert "policy_enforcement" not in result.execution_telemetry
        finally:
            await analyzer.shutdown()


# =====================================================================
# 3. Subsystem Shutdown & Resource Cleanup Tests
# =====================================================================

class TestSubsystemShutdownLifecycle:
    """Verifies clean shutdown, worker pool termination, DNS cache disposal, and idempotency."""

    @pytest.mark.asyncio
    async def test_analyzer_shutdown_terminates_workers_and_cleans_cache(self):
        from app.modules.auth_protocols.dns_resolver import DNSRecord, DNSQueryType
        resolver = AsyncDNSResolver()
        resolver.cache.put(
            "cached.domain.com",
            DNSQueryType.A,
            DNSResponse(
                domain="cached.domain.com",
                query_type=DNSQueryType.A,
                status=DNSResponseStatus.SUCCESS,
                records=[DNSRecord(record_type=DNSQueryType.A, value="1.2.3.4", ttl=300)],
                ttl=300,
            ),
        )
        assert resolver.cache.size == 1

        analyzer = AuthProtocolsAnalyzer(resolver=resolver)
        assert analyzer.dkim_executor is not None
        assert not analyzer.dkim_executor.is_shutdown

        await analyzer.shutdown()

        # DKIM executor worker threads terminated
        assert analyzer.dkim_executor.is_shutdown is True
        # DNS resolver cache cleared
        assert resolver.cache.size == 0

    @pytest.mark.asyncio
    async def test_repeated_shutdown_is_idempotent(self):
        resolver = AsyncDNSResolver()
        analyzer = AuthProtocolsAnalyzer(resolver=resolver)

        # Call shutdown 3 times consecutively
        await analyzer.shutdown()
        assert analyzer.dkim_executor.is_shutdown is True

        await analyzer.shutdown()
        assert analyzer.dkim_executor.is_shutdown is True

        await analyzer.shutdown()
        assert analyzer.dkim_executor.is_shutdown is True

    @pytest.mark.asyncio
    async def test_unowned_executor_not_shut_down_by_analyzer(self):
        shared_executor = DKIMExecutor()
        analyzer = AuthProtocolsAnalyzer(dkim_executor=shared_executor)
        assert analyzer._owns_executor is False

        try:
            await analyzer.shutdown()
            # Shared executor must NOT be shut down because analyzer does not own it
            assert shared_executor.is_shutdown is False
        finally:
            await shared_executor.shutdown()

    @pytest.mark.asyncio
    async def test_analyzer_shutdown_exception_resilience(self):
        """If one component raises an error during shutdown, remaining resources must still be cleaned up."""
        from app.modules.auth_protocols.dns_resolver import DNSRecord, DNSQueryType
        resolver = AsyncDNSResolver()
        resolver.cache.put(
            "cached.domain.com",
            DNSQueryType.A,
            DNSResponse(
                domain="cached.domain.com",
                query_type=DNSQueryType.A,
                status=DNSResponseStatus.SUCCESS,
                records=[DNSRecord(record_type=DNSQueryType.A, value="1.2.3.4", ttl=300)],
                ttl=300,
            ),
        )
        assert resolver.cache.size == 1

        analyzer = AuthProtocolsAnalyzer(resolver=resolver)

        # Mock executor to raise an unhandled exception on shutdown
        with patch.object(analyzer.dkim_executor, "shutdown", side_effect=RuntimeError("Simulated executor shutdown failure")):
            await analyzer.shutdown()

        # Resolver cache must still have been cleared despite executor failure
        assert resolver.cache.size == 0

    @pytest.mark.asyncio
    async def test_scan_service_shutdown_delegates_to_analyzer(self):
        service = ScanService()
        assert service.auth_analyzer is not None

        with patch.object(service.auth_analyzer, "shutdown", new_callable=AsyncMock) as mock_shut:
            await service.shutdown()
            mock_shut.assert_awaited_once()

        # Clean up actual analyzer
        await service.auth_analyzer.shutdown()


# =====================================================================
# 4. FastAPI Lifespan Integration Tests
# =====================================================================

class TestFastAPILifespanIntegration:
    """Verifies that the FastAPI application lifespan properly triggers startup checks

    and clean shutdown of the authentication subsystem.
    """

    @pytest.mark.asyncio
    async def test_lifespan_startup_and_shutdown_success(self):
        from backend.main import lifespan, app

        mock_scan_service = MagicMock()
        mock_scan_service.shutdown = AsyncMock()
        mock_scan_service.auth_analyzer = MagicMock()

        mock_engine = MagicMock()
        mock_engine.dispose = AsyncMock()
        mock_engine.begin = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.run_sync = AsyncMock()
        mock_engine.begin.return_value.__aenter__.return_value = mock_conn

        with patch("app.services.scan_service.scan_service", mock_scan_service), \
             patch("backend.main.async_engine", mock_engine):

            async with lifespan(app):
                # Application is running
                pass

            # Shutdown assertions
            mock_scan_service.shutdown.assert_awaited_once()
            mock_engine.dispose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_lifespan_shutdown_resilience_when_subsystem_fails(self):
        """Database disposal in lifespan finally block must execute even if subsystem shutdown fails."""
        from backend.main import lifespan, app

        mock_scan_service = MagicMock()
        mock_scan_service.shutdown = AsyncMock(side_effect=RuntimeError("Subsystem shutdown boom"))
        mock_scan_service.auth_analyzer = MagicMock()

        mock_engine = MagicMock()
        mock_engine.dispose = AsyncMock()
        mock_engine.begin = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.run_sync = AsyncMock()
        mock_engine.begin.return_value.__aenter__.return_value = mock_conn

        with patch("app.services.scan_service.scan_service", mock_scan_service), \
             patch("backend.main.async_engine", mock_engine):

            async with lifespan(app):
                pass

            # Scan service was attempted
            mock_scan_service.shutdown.assert_awaited_once()
            # Database engine disposal was guaranteed by finally block
            mock_engine.dispose.assert_awaited_once()
