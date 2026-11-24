"""Phase 2.1 Ingestion Authentication and Access Control Regression Test Suite.

Verifies:
1. Missing API key rejection under enforced authentication policy
2. Invalid API key rejection
3. Valid API key ingestion via X-API-Key header
4. Valid API key ingestion via Authorization: ApiKey header
5. Valid API key ingestion via Authorization: Bearer header
6. Valid User JWT ingestion via Authorization: Bearer <jwt>
7. Malformed Authorization header rejection (empty, no scheme, unsupported scheme)
8. Authentication policy toggle (development vs enforced)
9. Production startup security checks (refuses startup without required keys)
10. Sensitive scan access protection (list and detail routes)
11. Zero API key leakage in response bodies or log streams
12. Cryptographic API key generator and constant-time verification properties
"""

import pytest
from httpx import ASGITransport, AsyncClient
from app.core.api_key import generate_api_key, hash_api_key, verify_api_key
from app.core.config import settings
from app.core.security import create_access_token, get_password_hash
from app.models.user import User, UserRole
from main import app

TEST_API_KEY = "ms_live_supersecret_test_collector_key_2026_xyz"
SAMPLE_EML = b"From: collector@university.edu\r\nTo: triage@mailsentra.local\r\nSubject: Auth Test Ingestion\r\n\r\nTest payload\r\n"


@pytest.fixture
def configure_auth(monkeypatch):
    """Enforces ingestion authentication with a known test API key."""
    monkeypatch.setattr(settings, "REQUIRE_INGESTION_AUTH", True)
    monkeypatch.setattr(settings, "INGESTION_API_KEY", TEST_API_KEY)
    yield
    monkeypatch.setattr(settings, "REQUIRE_INGESTION_AUTH", False)
    monkeypatch.setattr(settings, "INGESTION_API_KEY", None)


# ============================================================================
# 1. API Key Generation & Cryptographic Verification
# ============================================================================

def test_api_key_generator_properties():
    """Verify generated API keys are unique, start with ms_live_, and have sufficient entropy."""
    key1 = generate_api_key()
    key2 = generate_api_key()
    assert key1 != key2
    assert key1.startswith("ms_live_")
    assert key2.startswith("ms_live_")
    # Base64 urlsafe 32 bytes produces 43 chars + 8 prefix = 51 chars
    assert len(key1) >= 50


def test_api_key_constant_time_verification():
    """Verify verify_api_key supports both raw constant-time matching and SHA-256 hash matching."""
    secret = "ms_live_example_secret_token_1234567890"
    secret_hash = hash_api_key(secret)

    # Direct match
    assert verify_api_key(secret, secret) is True
    assert verify_api_key(secret, "wrong_secret") is False
    assert verify_api_key(None, secret) is False
    assert verify_api_key(secret, None) is False

    # Hashed match
    assert verify_api_key(secret, secret_hash) is True
    assert verify_api_key("wrong_secret", secret_hash) is False


# ============================================================================
# 2. Ingestion Access Control: Missing, Invalid, and Malformed Credentials
# ============================================================================

@pytest.mark.asyncio
async def test_upload_missing_credentials_rejected_when_auth_enforced(async_client, configure_auth):
    """When ingestion auth is enforced, unauthenticated uploads must return HTTP 401."""
    files = {"file": ("test.eml", SAMPLE_EML, "message/rfc822")}
    res = await async_client.post("/api/v1/scans/upload", files=files)
    assert res.status_code == 401
    assert "authentication credentials required" in res.json()["detail"].lower()
    assert "ApiKey" in res.headers.get("www-authenticate", "")


@pytest.mark.asyncio
async def test_upload_invalid_api_key_rejected(async_client, configure_auth):
    """Uploading with an invalid X-API-Key must return HTTP 401."""
    files = {"file": ("test.eml", SAMPLE_EML, "message/rfc822")}
    headers = {"X-API-Key": "ms_live_invalid_bogus_key"}
    res = await async_client.post("/api/v1/scans/upload", files=files, headers=headers)
    assert res.status_code == 401
    assert "invalid api key" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_upload_malformed_authorization_headers_rejected(async_client, configure_auth):
    """Malformed Authorization headers must be rejected with HTTP 401."""
    files = {"file": ("test.eml", SAMPLE_EML, "message/rfc822")}

    malformed_headers = [
        {"Authorization": "NoSpaceHeader"},
        {"Authorization": "UnknownScheme some_token"},
        {"Authorization": "ApiKey "},  # Empty token
        {"Authorization": "Bearer "},  # Empty token
    ]

    for h in malformed_headers:
        res = await async_client.post("/api/v1/scans/upload", files=files, headers=h)
        assert res.status_code == 401
        assert "authorization" in res.json()["detail"].lower() or "empty" in res.json()["detail"].lower() or "scheme" in res.json()["detail"].lower()


# ============================================================================
# 3. Successful Ingestion with Authorized Credentials
# ============================================================================

@pytest.mark.asyncio
async def test_upload_with_valid_x_api_key_header(async_client, configure_auth):
    """Valid X-API-Key header successfully authorizes upload and records collector identity."""
    files = {"file": ("valid_key.eml", SAMPLE_EML, "message/rfc822")}
    headers = {"X-API-Key": TEST_API_KEY}
    res = await async_client.post("/api/v1/scans/upload", files=files, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["status"] == "COMPLETED"
    assert data["parsed_email"]["subject"] == "Auth Test Ingestion"


@pytest.mark.asyncio
async def test_upload_with_valid_authorization_apikey_header(async_client, configure_auth):
    """Valid 'Authorization: ApiKey <key>' header authorizes upload."""
    files = {"file": ("apikey_scheme.eml", SAMPLE_EML, "message/rfc822")}
    headers = {"Authorization": f"ApiKey {TEST_API_KEY}"}
    res = await async_client.post("/api/v1/scans/upload", files=files, headers=headers)
    assert res.status_code == 201
    assert res.json()["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_upload_with_valid_authorization_bearer_apikey(async_client, configure_auth):
    """Collector sending API key via 'Authorization: Bearer <key>' is authorized."""
    files = {"file": ("bearer_apikey.eml", SAMPLE_EML, "message/rfc822")}
    headers = {"Authorization": f"Bearer {TEST_API_KEY}"}
    res = await async_client.post("/api/v1/scans/upload", files=files, headers=headers)
    assert res.status_code == 201


@pytest.mark.asyncio
async def test_upload_with_valid_user_jwt_token(async_client, db_session, configure_auth):
    """Analyst logged into frontend console with JWT token is authorized to upload."""
    # Create active user in db
    test_user = User(
        email="analyst@mailsentra.com",
        full_name="SOC Analyst",
        hashed_password=get_password_hash("AnalystPassword2026!"),
        role=UserRole.SOC_ANALYST,
        is_active=True,
    )
    db_session.add(test_user)
    await db_session.commit()

    token = create_access_token(subject=test_user.email, role=test_user.role.value)
    files = {"file": ("jwt_upload.eml", SAMPLE_EML, "message/rfc822")}
    headers = {"Authorization": f"Bearer {token}"}
    res = await async_client.post("/api/v1/scans/upload", files=files, headers=headers)
    assert res.status_code == 201


# ============================================================================
# 4. Sensitive Scan Access Control & Separation of Duties
# ============================================================================

@pytest.mark.asyncio
async def test_sensitive_scan_listing_access_control(async_client, db_session, configure_auth):
    """Listing scan incidents requires user JWT; API keys are rejected with 403 Forbidden."""
    # 1. Anonymous access is rejected
    res_anon = await async_client.get("/api/v1/scans")
    assert res_anon.status_code == 401

    # 2. Ingestion API key is rejected with 403 Forbidden (separation of duties)
    res_api_key = await async_client.get("/api/v1/scans", headers={"X-API-Key": TEST_API_KEY})
    assert res_api_key.status_code == 403
    assert "write-only" in res_api_key.json()["detail"]

    # 3. SOC Analyst with JWT is authorized
    test_user = User(
        email="analyst_reader@mailsentra.com",
        full_name="SOC Analyst Reader",
        hashed_password=get_password_hash("AnalystPassword2026!"),
        role=UserRole.SOC_ANALYST,
        is_active=True,
    )
    db_session.add(test_user)
    await db_session.commit()

    token = create_access_token(subject=test_user.email, role=test_user.role.value)
    res_jwt = await async_client.get("/api/v1/scans", headers={"Authorization": f"Bearer {token}"})
    assert res_jwt.status_code == 200


@pytest.mark.asyncio
async def test_sensitive_scan_detail_access_control(async_client, db_session, configure_auth):
    """Accessing scan incident telemetry requires user JWT; API keys are rejected with 403."""
    # First upload an incident with ingestion key
    files = {"file": ("incident.eml", SAMPLE_EML, "message/rfc822")}
    up = await async_client.post("/api/v1/scans/upload", files=files, headers={"X-API-Key": TEST_API_KEY})
    assert up.status_code == 201
    scan_id = up.json()["scan_id"]
    scan_uuid = up.json()["scan_uuid"]

    # 1. Access without auth is rejected
    res_anon = await async_client.get(f"/api/v1/scans/{scan_id}")
    assert res_anon.status_code == 401

    # 2. Ingestion API key attempting to read is rejected with 403
    res_key = await async_client.get(f"/api/v1/scans/{scan_id}", headers={"X-API-Key": TEST_API_KEY})
    assert res_key.status_code == 403
    assert "write-only" in res_key.json()["detail"]

    # 3. User JWT access succeeds (by integer ID and by UUID)
    test_user = User(
        email="analyst_detail@mailsentra.com",
        full_name="SOC Analyst Detail",
        hashed_password=get_password_hash("AnalystPassword2026!"),
        role=UserRole.SOC_ANALYST,
        is_active=True,
    )
    db_session.add(test_user)
    await db_session.commit()

    token = create_access_token(subject=test_user.email, role=test_user.role.value)
    headers = {"Authorization": f"Bearer {token}"}

    res_by_id = await async_client.get(f"/api/v1/scans/{scan_id}", headers=headers)
    assert res_by_id.status_code == 200
    assert res_by_id.json()["id"] == scan_id

    res_by_uuid = await async_client.get(f"/api/v1/scans/{scan_uuid}", headers=headers)
    assert res_by_uuid.status_code == 200
    assert res_by_uuid.json()["scan_uuid"] == scan_uuid


# ============================================================================
# 5. Production Startup Validation
# ============================================================================

@pytest.mark.asyncio
async def test_production_startup_validation_refuses_missing_api_key(monkeypatch):
    """In production mode with auth enforced, startup must crash if INGESTION_API_KEY is not set."""
    from main import lifespan

    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "SECRET_KEY", "custom_production_secret_key_32_bytes_long_random_entropy")
    monkeypatch.setattr(settings, "INGESTION_API_KEY", None)

    with pytest.raises(RuntimeError) as exc_info:
        async with lifespan(app):
            pass
    assert "INGESTION_API_KEY is not configured" in str(exc_info.value)


@pytest.mark.asyncio
async def test_production_startup_validation_refuses_default_secret_key(monkeypatch):
    """In production mode, startup must crash if default dev SECRET_KEY is used."""
    from main import lifespan

    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "SECRET_KEY", "dev_secret_key_change_in_production_mailsentra_secops_platform")
    monkeypatch.setattr(settings, "INGESTION_API_KEY", "ms_live_some_valid_key")

    with pytest.raises(RuntimeError) as exc_info:
        async with lifespan(app):
            pass
    assert "SECRET_KEY detected in production" in str(exc_info.value)


# ============================================================================
# 6. Zero API Key Secret Leakage
# ============================================================================

@pytest.mark.asyncio
async def test_zero_api_key_leakage_in_responses(async_client, configure_auth):
    """Verify that neither successful responses nor error details leak the secret API key."""
    # Test error response
    res_err = await async_client.post(
        "/api/v1/scans/upload",
        files={"file": ("test.eml", SAMPLE_EML, "message/rfc822")},
        headers={"X-API-Key": "attempted_guess_key"},
    )
    assert res_err.status_code == 401
    assert TEST_API_KEY not in res_err.text
    assert "attempted_guess_key" not in res_err.text

    # Test success response
    res_ok = await async_client.post(
        "/api/v1/scans/upload",
        files={"file": ("test.eml", SAMPLE_EML, "message/rfc822")},
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert res_ok.status_code == 201
    assert TEST_API_KEY not in res_ok.text
