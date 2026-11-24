"""Email scan incident and telemetry model."""

import enum
from typing import Optional
from sqlalchemy import Enum, Float, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base, TimestampMixin


class RiskTier(str, enum.Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    PENDING = "PENDING"


class ScanStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScanIncident(Base, TimestampMixin):
    __tablename__ = "scan_incidents"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    scan_uuid: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    sender: Mapped[str] = mapped_column(String(255), index=True, nullable=True)
    recipient: Mapped[str] = mapped_column(String(255), nullable=True)
    subject: Mapped[str] = mapped_column(String(500), nullable=True)
    message_id: Mapped[str] = mapped_column(String(255), index=True, nullable=True)
    
    # Execution State
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus),
        default=ScanStatus.QUEUED,
        nullable=False,
    )
    
    # Tenant & Ownership Scoping (Object-Level Authorization)
    tenant_id: Mapped[str] = mapped_column(String(64), default="default", index=True, nullable=False)
    created_by_user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    
    # Threat Intelligence & Scoring
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    risk_tier: Mapped[RiskTier] = mapped_column(
        Enum(RiskTier),
        default=RiskTier.PENDING,
        nullable=False,
    )
    
    # Detailed telemetry payload (JSON)
    verdict_summary: Mapped[str] = mapped_column(Text, nullable=True)
    telemetry: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
