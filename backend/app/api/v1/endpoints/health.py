"""Health check and platform diagnostic endpoint."""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.db.session import get_db
from app.schemas.common import HealthCheckResponse

router = APIRouter()


@router.get("/health", response_model=HealthCheckResponse, summary="System Health Check")
async def health_check(db: AsyncSession = Depends(get_db)):
    """Validates runtime health and database connectivity."""
    db_ok = False
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    is_dev = settings.ENVIRONMENT.lower().strip() == "development"
    return HealthCheckResponse(
        status="HEALTHY" if db_ok else "DEGRADED",
        service=settings.PROJECT_NAME,
        version="1.0.0-phase2",
        environment=settings.ENVIRONMENT if is_dev else "protected",
        database_connected=db_ok,
    )
