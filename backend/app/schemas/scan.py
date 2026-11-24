"""Scan schemas for ingest, request, and status reporting."""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.models.scan import RiskTier, ScanStatus
from app.modules.contracts import ParsedEmail


class ScanCreateRequest(BaseModel):
    source: str = "direct_upload"
    metadata: Optional[Dict[str, Any]] = None


class RawEmailParseRequest(BaseModel):
    raw_email: str = Field(..., min_length=1, max_length=15 * 1024 * 1024, description="RFC 5322 email string")
    filename: Optional[str] = Field(default="raw_email.eml", max_length=255)


class ScanResponse(BaseModel):
    id: int
    scan_uuid: str
    sender: Optional[str] = None
    recipient: Optional[str] = None
    subject: Optional[str] = None
    status: ScanStatus
    risk_score: float
    risk_tier: RiskTier
    verdict_summary: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanDetailResponse(ScanResponse):
    telemetry: Dict[str, Any]


class EmailParseResponse(BaseModel):
    scan_id: int
    scan_uuid: str
    status: ScanStatus
    parsed_email: ParsedEmail
    created_at: datetime
