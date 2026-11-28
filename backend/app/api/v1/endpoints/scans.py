"""Email scan and parsing management endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, File, HTTPException, Path, Query, Request, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user_optional, get_db, get_ingestion_actor, get_scan_reader
from app.core.config import settings
from app.models.scan import ScanIncident
from app.models.user import User, UserRole
from app.modules.contracts import IngestionSource
from app.modules.ingestion.exceptions import (
    EmailSizeExceededError,
    InvalidMimeTypeError,
    MalformedPayloadError,
)
from app.schemas.scan import (
    DashboardStatsResponse,
    EmailParseResponse,
    RawEmailParseRequest,
    ScanDetailResponse,
    ScanResponse,
)
from app.schemas.user import IngestionActor
from app.services.scan_service import scan_service

router = APIRouter()


@router.post(
    "/upload",
    response_model=EmailParseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and Parse EML File",
)
async def upload_and_parse_email(
    request: Request,
    file: UploadFile = File(..., description="Raw .eml or RFC 5322 email file to inspect"),
    db: AsyncSession = Depends(get_db),
    actor: IngestionActor = Depends(get_ingestion_actor),
):
    """Securely uploads an .eml file, normalizes its contents, extracts headers, body, URLs,

    and attachments, and stores the scan incident telemetry in the database.
    """
    client_ip = request.client.host if request.client else "unknown"

    try:
        # Stream read with bounded buffer to prevent memory exhaustion DoS
        max_bytes = settings.MAX_EMAIL_SIZE_BYTES
        chunks = []
        total_read = 0
        chunk_size = 64 * 1024  # 64KB

        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break
            total_read += len(chunk)
            if total_read > max_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail=f"Uploaded file exceeds maximum allowable size of {max_bytes} bytes."
                )
            chunks.append(chunk)

        raw_bytes = b"".join(chunks)

        incident, parsed_email = await scan_service.ingest_and_parse(
            raw_bytes=raw_bytes,
            filename=file.filename,
            source=IngestionSource.DIRECT_UPLOAD,
            source_ip=client_ip,
            db=db,
            actor=actor,
        )

        return EmailParseResponse(
            scan_id=incident.id,
            scan_uuid=incident.scan_uuid,
            status=incident.status,
            parsed_email=parsed_email,
            created_at=incident.created_at,
        )
    except HTTPException:
        raise
    except EmailSizeExceededError as e:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=str(e),
        )
    except (InvalidMimeTypeError, MalformedPayloadError) as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while parsing the email payload: {str(e)}",
        )


@router.post(
    "/parse-raw",
    response_model=EmailParseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Parse Raw RFC 5322 Email Text",
)
async def parse_raw_email(
    payload: RawEmailParseRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: IngestionActor = Depends(get_ingestion_actor),
):
    """Directly parses raw RFC 5322 string content without requiring multipart form-data."""
    client_ip = request.client.host if request.client else "unknown"
    raw_bytes = payload.raw_email.encode("utf-8")

    try:
        incident, parsed_email = await scan_service.ingest_and_parse(
            raw_bytes=raw_bytes,
            filename=payload.filename or "raw_email.eml",
            source=IngestionSource.RAW_PAYLOAD,
            source_ip=client_ip,
            db=db,
            actor=actor,
        )

        return EmailParseResponse(
            scan_id=incident.id,
            scan_uuid=incident.scan_uuid,
            status=incident.status,
            parsed_email=parsed_email,
            created_at=incident.created_at,
        )
    except HTTPException:
        raise
    except EmailSizeExceededError as e:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=str(e),
        )
    except (InvalidMimeTypeError, MalformedPayloadError) as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while parsing the raw payload: {str(e)}",
        )


def authorize_scan_incident_access(actor: IngestionActor, scan: ScanIncident) -> None:
    """Enforces object-level access control (BOLA / IDOR defense) on individual scan records."""
    # 1. API keys are strictly forbidden from reading scan objects
    if actor.is_api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API keys are restricted to write-only email ingestion. Accessing scan telemetry requires interactive analyst credentials.",
        )

    # 2. In unauthenticated development mode, permit local testing
    if actor.identity == "dev:unauthenticated":
        return

    # 3. Super Admins have global visibility
    if actor.role == UserRole.SUPER_ADMIN.value:
        return

    # 4. SOC Analysts and Auditors can view scans within their tenant
    if actor.role in [UserRole.SOC_ANALYST.value, UserRole.AUDITOR.value]:
        scan_tenant = getattr(scan, "tenant_id", "default") or "default"
        user_obj = getattr(actor, "user", None)
        user_tenant = getattr(user_obj, "tenant_id", "default") if user_obj else "default"
        if scan_tenant != user_tenant:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Cross-tenant scan telemetry access is prohibited.",
            )
        return

    # 5. Any other role is unauthorized
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"User role '{actor.role}' is not authorized to access scan incident telemetry.",
    )


@router.get("/stats", response_model=DashboardStatsResponse, summary="Get Aggregate SOC Dashboard Metrics")
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    actor: IngestionActor = Depends(get_scan_reader),
):
    """Computes accurate, tenant-scoped lifetime aggregate metrics across all stored scan incidents."""
    from sqlalchemy import func
    from app.models.alert import Alert, AlertStatus
    from app.models.scan import RiskTier

    tenant_filter = []
    if actor.role != UserRole.SUPER_ADMIN.value and actor.identity != "dev:unauthenticated":
        user_obj = getattr(actor, "user", None)
        user_tenant = getattr(user_obj, "tenant_id", "default") if user_obj else "default"
        tenant_filter.append(ScanIncident.tenant_id == user_tenant)

    # 1. Total counts by RiskTier across the complete database
    stmt = select(ScanIncident.risk_tier, func.count(ScanIncident.id)).where(*tenant_filter).group_by(ScanIncident.risk_tier)
    res = await db.execute(stmt)
    tier_counts = dict(res.all())

    clean = tier_counts.get(RiskTier.CLEAN, 0)
    suspicious = tier_counts.get(RiskTier.SUSPICIOUS, 0)
    malicious = tier_counts.get(RiskTier.MALICIOUS, 0)
    total = clean + suspicious + malicious

    # 2. High risk count (scans with risk_score >= 70.0)
    high_risk_stmt = select(func.count(ScanIncident.id)).where(ScanIncident.risk_score >= 70.0, *tenant_filter)
    high_risk_res = await db.execute(high_risk_stmt)
    high_risk_count = high_risk_res.scalar_one_or_none() or 0

    # 3. Active open alerts count
    alert_stmt = select(func.count(Alert.id)).where(Alert.status.in_([AlertStatus.OPEN, AlertStatus.IN_TRIAGE]))
    alert_res = await db.execute(alert_stmt)
    active_alerts = alert_res.scalar_one_or_none() or 0

    # 4. Threat detection rate = (suspicious + malicious) / total * 100
    detection_rate = round(((suspicious + malicious) / total * 100.0), 1) if total > 0 else 0.0

    return DashboardStatsResponse(
        total_scanned=total,
        clean_count=clean,
        suspicious_count=suspicious,
        malicious_count=malicious,
        high_risk_findings_count=high_risk_count,
        threat_detection_rate=detection_rate,
        active_alerts_count=active_alerts,
    )


@router.get("", response_model=List[ScanResponse], summary="List Scan Incidents")
async def list_scans(
    skip: int = Query(default=0, ge=0, description="Pagination offset"),
    limit: int = Query(default=50, ge=1, le=100, description="Items per page (max 100)"),
    db: AsyncSession = Depends(get_db),
    actor: IngestionActor = Depends(get_scan_reader),
):
    """Retrieves paginated list of email scan incidents with tenant authorization scoping."""
    if actor.role != UserRole.SUPER_ADMIN.value and actor.identity != "dev:unauthenticated":
        user_obj = getattr(actor, "user", None)
        user_tenant = getattr(user_obj, "tenant_id", "default") if user_obj else "default"
        stmt = select(ScanIncident).where(ScanIncident.tenant_id == user_tenant).order_by(ScanIncident.id.desc()).offset(skip).limit(limit)
    else:
        stmt = select(ScanIncident).order_by(ScanIncident.id.desc()).offset(skip).limit(limit)

    result = await db.execute(stmt)
    scans = result.scalars().all()
    return scans


@router.get("/{scan_id}", response_model=ScanDetailResponse, summary="Get Scan Details")
async def get_scan(
    scan_id: str = Path(..., min_length=1, description="Scan incident ID (integer ID or UUIDv4)"),
    db: AsyncSession = Depends(get_db),
    actor: IngestionActor = Depends(get_scan_reader),
):
    """Retrieves comprehensive threat telemetry for a specific scan incident by ID or UUID."""
    if scan_id.isdigit():
        stmt = select(ScanIncident).where(ScanIncident.id == int(scan_id))
    else:
        stmt = select(ScanIncident).where(ScanIncident.scan_uuid == scan_id)

    result = await db.execute(stmt)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan incident '{scan_id}' not found",
        )

    # Enforce object-level authorization
    authorize_scan_incident_access(actor, scan)

    return scan
