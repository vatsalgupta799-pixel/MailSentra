"""Security Alert management endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_db, get_scan_reader
from app.models.alert import Alert, AlertStatus
from app.schemas.alert import AlertResponse, AlertUpdateStatusRequest
from app.schemas.user import IngestionActor

router = APIRouter()


@router.get("", response_model=List[AlertResponse], summary="List Security Alerts")
async def list_alerts(
    skip: int = Query(default=0, ge=0, description="Pagination offset"),
    limit: int = Query(default=50, ge=1, le=100, description="Items per page (max 100)"),
    status_filter: Optional[AlertStatus] = Query(default=None, alias="status", description="Filter by AlertStatus"),
    db: AsyncSession = Depends(get_db),
    actor: IngestionActor = Depends(get_scan_reader),
):
    """Retrieves paginated list of security threat alerts with optional status filtering."""
    stmt = select(Alert).order_by(Alert.id.desc())
    if status_filter:
        stmt = stmt.where(Alert.status == status_filter)
    stmt = stmt.offset(skip).limit(limit)

    result = await db.execute(stmt)
    alerts = result.scalars().all()
    return alerts


@router.patch("/{alert_id}/status", response_model=AlertResponse, summary="Update Alert Triage Status")
async def update_alert_status(
    payload: AlertUpdateStatusRequest,
    alert_id: int = Path(..., ge=1, description="Alert ID"),
    db: AsyncSession = Depends(get_db),
    actor: IngestionActor = Depends(get_scan_reader),
):
    """Updates the triage status of an alert (OPEN, IN_TRIAGE, RESOLVED, FALSE_POSITIVE)."""
    stmt = select(Alert).where(Alert.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert incident '{alert_id}' not found",
        )

    alert.status = payload.status
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    return alert
