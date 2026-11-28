"""Alert schemas."""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict
from app.models.alert import AlertSeverity, AlertStatus


class AlertResponse(BaseModel):
    id: int
    scan_id: Optional[int] = None
    title: str
    severity: AlertSeverity
    status: AlertStatus
    description: str
    indicators: Dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertUpdateStatusRequest(BaseModel):
    status: AlertStatus
