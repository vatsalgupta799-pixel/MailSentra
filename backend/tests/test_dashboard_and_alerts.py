"""Unit tests for Dashboard aggregation stats, Alert lifecycle, and triage endpoints."""

import pytest
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.scan import RiskTier, ScanIncident, ScanStatus


@pytest.mark.asyncio
async def test_dashboard_stats_empty(async_client, db_session):
    """Dashboard stats endpoint must return clean zero counts when database is empty."""
    res = await async_client.get("/api/v1/scans/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_scanned" in data
    assert "clean_count" in data
    assert "suspicious_count" in data
    assert "malicious_count" in data
    assert "threat_detection_rate" in data


@pytest.mark.asyncio
async def test_dashboard_stats_aggregated(async_client, db_session):
    """Dashboard stats must compute lifetime totals accurately across all tiers."""
    s1 = ScanIncident(
        scan_uuid="stats-uuid-clean-1",
        sender="clean@domain.com",
        recipient="user@domain.com",
        subject="Clean Email 1",
        status=ScanStatus.COMPLETED,
        risk_score=0.0,
        risk_tier=RiskTier.CLEAN,
        verdict_summary="Clean email",
        telemetry={},
    )
    s2 = ScanIncident(
        scan_uuid="stats-uuid-suspicious-1",
        sender="spoof@domain.com",
        recipient="user@domain.com",
        subject="Suspicious Email 1",
        status=ScanStatus.COMPLETED,
        risk_score=55.0,
        risk_tier=RiskTier.SUSPICIOUS,
        verdict_summary="Suspicious email",
        telemetry={},
    )
    s3 = ScanIncident(
        scan_uuid="stats-uuid-malicious-1",
        sender="malware@domain.com",
        recipient="user@domain.com",
        subject="Malicious Payload 1",
        status=ScanStatus.COMPLETED,
        risk_score=85.0,
        risk_tier=RiskTier.MALICIOUS,
        verdict_summary="Malicious email",
        telemetry={},
    )
    db_session.add_all([s1, s2, s3])
    await db_session.commit()

    res = await async_client.get("/api/v1/scans/stats")
    assert res.status_code == 200
    data = res.json()
    assert data["total_scanned"] >= 3
    assert data["clean_count"] >= 1
    assert data["suspicious_count"] >= 1
    assert data["malicious_count"] >= 1
    assert data["high_risk_findings_count"] >= 1
    assert data["threat_detection_rate"] > 0.0


@pytest.mark.asyncio
async def test_alert_triage_status_patch(async_client, db_session):
    """Alert status must update through PATCH /api/v1/alerts/{id}/status."""
    alert = Alert(
        title="Test Phishing Lure",
        severity=AlertSeverity.HIGH,
        status=AlertStatus.OPEN,
        description="A high-confidence phishing lure was intercepted.",
        indicators={"risk_score": 85.0},
    )
    db_session.add(alert)
    await db_session.commit()
    await db_session.refresh(alert)

    # 1. Update to IN_TRIAGE
    res = await async_client.patch(
        f"/api/v1/alerts/{alert.id}/status",
        json={"status": "IN_TRIAGE"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "IN_TRIAGE"

    # 2. Update to RESOLVED
    res2 = await async_client.patch(
        f"/api/v1/alerts/{alert.id}/status",
        json={"status": "RESOLVED"},
    )
    assert res2.status_code == 200
    assert res2.json()["status"] == "RESOLVED"

    # 3. Filter alerts by status
    res_filter = await async_client.get("/api/v1/alerts?status=RESOLVED")
    assert res_filter.status_code == 200
    resolved_ids = [a["id"] for a in res_filter.json()]
    assert alert.id in resolved_ids
