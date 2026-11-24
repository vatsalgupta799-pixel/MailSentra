"""Master v1 API router assembling all domain endpoint modules."""

from fastapi import APIRouter
from app.api.v1.endpoints import alerts, audit, auth, health, scans

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health & Diagnostics"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication & Identity"])
api_router.include_router(scans.router, prefix="/scans", tags=["Email Scans & Telemetry"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Threat Alerts"])
api_router.include_router(audit.router, prefix="/audit", tags=["Security Audit Trail"])
