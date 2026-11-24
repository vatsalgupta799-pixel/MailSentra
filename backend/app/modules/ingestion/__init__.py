"""Email Ingestion module exports."""

from app.modules.ingestion.exceptions import (
    EmailSizeExceededError,
    IngestionError,
    InvalidMimeTypeError,
    MalformedPayloadError,
)
from app.modules.ingestion.service import EmailIngestionService

__all__ = [
    "EmailIngestionService",
    "IngestionError",
    "EmailSizeExceededError",
    "InvalidMimeTypeError",
    "MalformedPayloadError",
]
