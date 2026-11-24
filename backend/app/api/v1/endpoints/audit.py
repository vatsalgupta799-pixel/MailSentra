"""Security Audit Log query endpoint."""

from typing import List
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import require_roles, get_db
from app.models.audit import AuditRecord
from app.models.user import User, UserRole

router = APIRouter()


@router.get(
    "",
    summary="List Security Audit Trail",
    dependencies=[Depends(require_roles([UserRole.SUPER_ADMIN, UserRole.AUDITOR]))],
)
async def list_audit_logs(
    skip: int = Query(default=0, ge=0, description="Pagination offset"),
    limit: int = Query(default=50, ge=1, le=100, description="Items per page (max 100)"),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves immutable audit records (Auditors and Admins only)."""
    stmt = select(AuditRecord).order_by(AuditRecord.id.desc()).offset(skip).limit(limit)
    result = await db.execute(stmt)
    records = result.scalars().all()
    return records
