"""Regression and security tests for Phase 2.1 Audit Remediation.

Covers:
1. Default admin user omitted in production environments (FIND-SEC-2026-01)
2. Insecure Docker Compose fallback secret rejected (FIND-SEC-2026-02)
3. Insufficient length SECRET_KEY rejected in production (FIND-SEC-2026-02)
4. Case-insensitive production environment check (FIND-SEC-2026-05)
5. Separation of duties: API key forbidden on scan read endpoints (FIND-SEC-2026-03)
6. Database persistence of audit trail & queryability via /api/v1/audit (FIND-SEC-2026-04)
7. Audit endpoint RBAC: restricted to SUPER_ADMIN and AUDITOR (FIND-SEC-2026-04)
8. Scan incident lookup by UUIDv4 (IDOR mitigation) (FIND-SEC-2026-07)
9. Rate limiting on /api/v1/auth/login (FIND-SEC-2026-06)
10. JWT Issuer and Audience claim validation (FIND-SEC-2026-09)
"""

import pytest
from jose import jwt
from sqlalchemy import select
from app.core.config import settings
from app.core.rate_limit import login_rate_limiter
from app.core.security import (
    JWT_AUDIENCE,
    JWT_ISSUER,
    create_access_token,
    decode_access_token,
    get_password_hash,
)
from app.models.audit import AuditRecord
from app.models.user import User, UserRole
from main import app, lifespan

SAMPLE_EML = b"""From: alerts@corp.security.com
To: analyst@mailsentra.com
Subject: Security Notice
Date: Mon, 24 Nov 2026 14:00:00 +0000
Message-ID: <audit_remediation_test_01@corp.security.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

This is a synthetic test email for audit remediation testing.
"""


# ============================================================================
# 1. Production Startup Security Checks & Case-Insensitive Guard
# ============================================================================

@pytest.mark.asyncio
async def test_default_admin_omitted_in_production(monkeypatch, db_session):
    """In production mode, the default development administrator must NOT be provisioned."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "SECRET_KEY", "secure_production_secret_key_at_least_32_bytes_entropy")
    monkeypatch.setattr(settings, "INGESTION_API_KEY", "ms_live_valid_key_for_production_testing")

    # Clear existing admin user if any
    stmt = select(User).where(User.email == "admin@mailsentra.local")
    result = await db_session.execute(stmt)
    existing = result.scalar_one_or_none()
    if existing:
        await db_session.delete(existing)
        await db_session.commit()

    async with lifespan(app):
        # Check that admin@mailsentra.local was NOT created
        stmt2 = select(User).where(User.email == "admin@mailsentra.local")
        result2 = await db_session.execute(stmt2)
        admin = result2.scalar_one_or_none()
        assert admin is None


@pytest.mark.asyncio
async def test_docker_compose_fallback_secret_rejected(monkeypatch):
    """Production startup must crash if Docker Compose default fallback secret is used."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "SECRET_KEY", "replace_with_a_secure_random_string_in_production_environment")
    monkeypatch.setattr(settings, "INGESTION_API_KEY", "ms_live_valid_key")

    with pytest.raises(RuntimeError) as exc_info:
        async with lifespan(app):
            pass
    assert "SECRET_KEY detected in production" in str(exc_info.value)


@pytest.mark.asyncio
async def test_insufficient_length_secret_key_rejected(monkeypatch):
    """Production startup must crash if SECRET_KEY has fewer than 32 characters."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "SECRET_KEY", "too_short_secret")
    monkeypatch.setattr(settings, "INGESTION_API_KEY", "ms_live_valid_key")

    with pytest.raises(RuntimeError) as exc_info:
        async with lifespan(app):
            pass
    assert "insufficient length SECRET_KEY" in str(exc_info.value)


@pytest.mark.asyncio
async def test_case_insensitive_production_checks(monkeypatch):
    """Capitalized 'Production' or 'PRODUCTION' must still enforce startup security checks."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "Production")
    monkeypatch.setattr(settings, "SECRET_KEY", "dev_secret_key_change_in_production_mailsentra_secops_platform")
    monkeypatch.setattr(settings, "INGESTION_API_KEY", "ms_live_valid_key")

    with pytest.raises(RuntimeError) as exc_info:
        async with lifespan(app):
            pass
    assert "SECRET_KEY detected in production" in str(exc_info.value)


# ============================================================================
# 2. JWT Issuer and Audience Claim Validation
# ============================================================================

def test_jwt_issuer_and_audience_enforced():
    """Validates that JWT tokens require exact issuer and audience matching."""
    # 1. Standard token with correct iss and aud decodes cleanly
    valid_token = create_access_token(subject="user@example.com", role="SOC_ANALYST")
    payload = decode_access_token(valid_token)
    assert payload["sub"] == "user@example.com"
    assert payload["iss"] == JWT_ISSUER
    assert payload["aud"] == JWT_AUDIENCE

    # 2. Token with wrong issuer is rejected
    wrong_iss_jwt = jwt.encode(
        {"sub": "user@example.com", "role": "SOC_ANALYST", "iss": "rogue-issuer", "aud": JWT_AUDIENCE},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    with pytest.raises(jwt.JWTError):
        decode_access_token(wrong_iss_jwt)

    # 3. Token with wrong audience is rejected
    wrong_aud_jwt = jwt.encode(
        {"sub": "user@example.com", "role": "SOC_ANALYST", "iss": JWT_ISSUER, "aud": "rogue-api"},
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM,
    )
    with pytest.raises(jwt.JWTError):
        decode_access_token(wrong_aud_jwt)


# ============================================================================
# 3. Database Audit Record Persistence & RBAC Verification
# ============================================================================

@pytest.mark.asyncio
async def test_audit_records_persisted_and_queryable(async_client, db_session, monkeypatch):
    """Uploading an email must persist an AuditRecord to the database, queryable via /api/v1/audit."""
    test_key = "ms_live_audit_test_secret_entropy_256bits"
    monkeypatch.setattr(settings, "REQUIRE_INGESTION_AUTH", True)
    monkeypatch.setattr(settings, "INGESTION_API_KEY", test_key)

    # 1. Ingest email with collector key
    files = {"file": ("audit_sample.eml", SAMPLE_EML, "message/rfc822")}
    up = await async_client.post("/api/v1/scans/upload", files=files, headers={"X-API-Key": test_key})
    assert up.status_code == 201

    # 2. Verify AuditRecord was inserted into SQLite database
    stmt = select(AuditRecord).where(AuditRecord.action == "EMAIL_INGESTED_AND_PARSED")
    result = await db_session.execute(stmt)
    records = result.scalars().all()
    assert len(records) >= 1
    latest_record = records[-1]
    assert latest_record.actor_id == "collector:api_key"
    assert latest_record.resource_type == "scan_incident"

    # 3. Create an Auditor user to query /api/v1/audit
    auditor_user = User(
        email="compliance_auditor@mailsentra.com",
        full_name="Compliance Auditor",
        hashed_password=get_password_hash("AuditorPassword2026!"),
        role=UserRole.AUDITOR,
        is_active=True,
    )
    db_session.add(auditor_user)
    await db_session.commit()

    token = create_access_token(subject=auditor_user.email, role=auditor_user.role.value)
    audit_res = await async_client.get(
        "/api/v1/audit",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert audit_res.status_code == 200
    audit_data = audit_res.json()
    assert len(audit_data) >= 1
    assert any(r["action"] == "EMAIL_INGESTED_AND_PARSED" for r in audit_data)


@pytest.mark.asyncio
async def test_audit_endpoint_role_restrictions(async_client, db_session, monkeypatch):
    """Normal SOC analysts or unauthenticated callers must be blocked from /api/v1/audit."""
    # 1. Unauthenticated request returns 401
    res_anon = await async_client.get("/api/v1/audit")
    assert res_anon.status_code == 401

    # 2. SOC Analyst receives 403 Forbidden
    analyst_user = User(
        email="soc_analyst_blocked@mailsentra.com",
        full_name="SOC Analyst Blocked",
        hashed_password=get_password_hash("AnalystPassword2026!"),
        role=UserRole.SOC_ANALYST,
        is_active=True,
    )
    db_session.add(analyst_user)
    await db_session.commit()

    analyst_token = create_access_token(subject=analyst_user.email, role=analyst_user.role.value)
    res_analyst = await async_client.get(
        "/api/v1/audit",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert res_analyst.status_code == 403


# ============================================================================
# 4. Login Rate Limiting (Abuse Resistance)
# ============================================================================

@pytest.mark.asyncio
async def test_login_rate_limiting_triggers_429(async_client):
    """Exceeding 10 rapid failed login attempts must trigger HTTP 429 Too Many Requests."""
    login_rate_limiter.reset()

    # 10 rapid invalid login requests
    for _ in range(10):
        res = await async_client.post(
            "/api/v1/auth/login",
            data={"username": "attacker@example.com", "password": "wrong_password"},
        )
        assert res.status_code == 401

    # 11th request must be throttled with 429
    res_blocked = await async_client.post(
        "/api/v1/auth/login",
        data={"username": "attacker@example.com", "password": "wrong_password"},
    )
    assert res_blocked.status_code == 429
    assert "Retry-After" in res_blocked.headers
    assert "Too many authentication attempts" in res_blocked.json()["detail"]

    login_rate_limiter.reset()


# ============================================================================
# 5. Object-Level Authorization & Cross-Tenant Access Defense (BOLA/IDOR)
# ============================================================================

@pytest.mark.asyncio
async def test_unauthorized_role_blocked_from_scans(async_client, db_session, monkeypatch):
    """Users with non-analyst roles (e.g. SYSTEM_AGENT) are forbidden from reading scans."""
    test_key = "ms_live_agent_test_key_secret_entropy_256"
    monkeypatch.setattr(settings, "REQUIRE_INGESTION_AUTH", True)
    monkeypatch.setattr(settings, "INGESTION_API_KEY", test_key)

    # 1. Ingest an email
    files = {"file": ("agent_test.eml", SAMPLE_EML, "message/rfc822")}
    up = await async_client.post("/api/v1/scans/upload", files=files, headers={"X-API-Key": test_key})
    scan_id = up.json()["scan_id"]

    # 2. Create SYSTEM_AGENT user
    agent_user = User(
        email="collector_agent@mailsentra.com",
        full_name="System Collector Agent",
        hashed_password=get_password_hash("AgentPassword2026!"),
        role=UserRole.SYSTEM_AGENT,
        is_active=True,
    )
    db_session.add(agent_user)
    await db_session.commit()

    agent_token = create_access_token(subject=agent_user.email, role=agent_user.role.value)
    headers = {"Authorization": f"Bearer {agent_token}"}

    # Attempt to list scans -> 403 Forbidden
    res_list = await async_client.get("/api/v1/scans", headers=headers)
    assert res_list.status_code == 403
    assert "not authorized" in res_list.json()["detail"]

    # Attempt to get scan details -> 403 Forbidden
    res_get = await async_client.get(f"/api/v1/scans/{scan_id}", headers=headers)
    assert res_get.status_code == 403
    assert "not authorized" in res_get.json()["detail"]


@pytest.mark.asyncio
async def test_cross_tenant_scan_access_forbidden(async_client, db_session, monkeypatch):
    """SOC Analyst from tenant_b cannot access scan incidents belonging to tenant_a."""
    from app.models.scan import ScanIncident, ScanStatus, RiskTier
    import uuid

    # Create scan incident belonging to tenant_a
    scan_tenant_a = ScanIncident(
        scan_uuid=str(uuid.uuid4()),
        sender="victim@tenant-a.com",
        recipient="user@tenant-a.com",
        subject="Confidential Tenant A Financials",
        status=ScanStatus.COMPLETED,
        tenant_id="tenant_a",
        risk_score=0.0,
        risk_tier=RiskTier.CLEAN,
        verdict_summary="Clean email",
        telemetry={},
    )
    db_session.add(scan_tenant_a)
    await db_session.commit()
    await db_session.refresh(scan_tenant_a)

    # Create SOC Analyst belonging to tenant_b
    analyst_b = User(
        email="analyst@tenant-b.com",
        full_name="Tenant B Analyst",
        hashed_password=get_password_hash("TenantBPassword2026!"),
        role=UserRole.SOC_ANALYST,
        is_active=True,
    )
    db_session.add(analyst_b)
    await db_session.commit()

    token_b = create_access_token(
        subject=analyst_b.email,
        role=analyst_b.role.value,
        extra_claims={"tenant_id": "tenant_b"},
    )
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # In deps.py, IngestionActor gets tenant_id from extra_claims or user
    # In list_scans, tenant_a scan should not be returned to tenant_b
    res_list = await async_client.get("/api/v1/scans", headers=headers_b)
    assert res_list.status_code == 200
    listed_ids = [s["id"] for s in res_list.json()]
    assert scan_tenant_a.id not in listed_ids

    # In get_scan, accessing tenant_a directly with tenant_b header must return 403 Forbidden
    # Mocking actor tenant_id to tenant_b
    from app.api.deps import get_scan_reader
    from app.schemas.user import IngestionActor, UserResponse

    app.dependency_overrides[get_scan_reader] = lambda: IngestionActor(
        identity=analyst_b.email,
        role=UserRole.SOC_ANALYST.value,
        is_api_key=False,
        tenant_id="tenant_b",
        user=UserResponse.model_validate(analyst_b),
    )

    try:
        res_get = await async_client.get(f"/api/v1/scans/{scan_tenant_a.id}")
        assert res_get.status_code == 403
        assert "Cross-tenant" in res_get.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_scan_reader, None)


# ============================================================================
# 6. Initial Administrator Provisioning & Password Defenses
# ============================================================================

@pytest.mark.asyncio
async def test_admin_cli_tool_provisioning():
    """Validates programmatic administrator provisioning via the CLI utility."""
    from app.cli import create_or_update_admin, KNOWN_INSECURE_PASSWORDS

    # 1. Provision new admin
    email = "cli_provisioned_admin@mailsentra.com"
    success = await create_or_update_admin(
        email=email,
        password="SecureAdminEntropyPassword2026!#",
        full_name="CLI Admin",
        role=UserRole.SUPER_ADMIN,
    )
    assert success is True

    # 2. Rejection of insecure password
    with pytest.raises(ValueError) as exc:
        await create_or_update_admin(
            email="fail_admin@mailsentra.com",
            password="MailSentraAdmin2026!",
        )
    assert "known insecure/default password" in str(exc.value)

    # 3. Rejection of short password
    with pytest.raises(ValueError) as exc2:
        await create_or_update_admin(
            email="fail_admin2@mailsentra.com",
            password="short",
        )
    assert "at least 12 characters" in str(exc2.value)


@pytest.mark.asyncio
async def test_production_known_default_password_blocked_in_login(async_client, monkeypatch):
    """In production, attempting to log in with known default password is hard-blocked."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")

    res = await async_client.post(
        "/api/v1/auth/login",
        data={"username": "admin@mailsentra.local", "password": "MailSentraAdmin2026!"},
    )
    assert res.status_code == 401
    assert "Incorrect email or password" in res.json()["detail"]


@pytest.mark.asyncio
async def test_production_bootstrap_admin_provisioning(monkeypatch):
    """Validates production bootstrap provisioning via INITIAL_ADMIN_EMAIL/PASSWORD."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "SECRET_KEY", "production_secret_key_entropy_32_characters_long")
    monkeypatch.setattr(settings, "INGESTION_API_KEY", "ms_live_production_key_test_12345")
    monkeypatch.setattr(settings, "INITIAL_ADMIN_EMAIL", "bootstrap_admin@company.com")
    monkeypatch.setattr(settings, "INITIAL_ADMIN_PASSWORD", "ProductionBootstrapPassword2026!#")

    from app.db.session import AsyncSessionLocal
    async with lifespan(app):
        pass

    async with AsyncSessionLocal() as session:
        stmt = select(User).where(User.email == "bootstrap_admin@company.com")
        result = await session.execute(stmt)
        user = result.scalar_one_or_none()
        assert user is not None
        assert user.role == UserRole.SUPER_ADMIN
        assert user.is_active is True

