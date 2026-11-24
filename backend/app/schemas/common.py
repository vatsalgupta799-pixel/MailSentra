"""Common API response schemas."""

from typing import Any, Dict, Optional
from pydantic import BaseModel


class HealthCheckResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str
    database_connected: bool


class ErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
