"""Tests for diagnostic health endpoint."""

import pytest


@pytest.mark.asyncio
async def test_health_check_endpoint(async_client):
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["HEALTHY", "DEGRADED"]
    assert "MailSentra" in data["service"]
    assert data["version"] == "1.0.0-phase2"
    assert data["database_connected"] is True
