"""Security Alert management endpoints."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user, get_db
from app.models.alert import Alert
from app.models.user import User
from app.schemas.alert import AlertResponse

router = APIRouter()


@router.get("", response_model=List[AlertResponse], summary="List Security Alerts")
async def list_alerts(
    skip: int = Query(default=0, ge=0, description="Pagination offset"),
    limit: int = Query(default=50, ge=1, le=100, description="Items per page (max 100)"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves paginated list of security threat alerts."""
    stmt = select(Alert).order_by(Alert.id.desc()).offset(skip).limit(limit)
    result = await db.execute(stmt)
    alerts = result.scalars().all()
    return alerts
