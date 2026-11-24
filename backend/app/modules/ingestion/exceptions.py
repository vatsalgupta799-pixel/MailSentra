"""Exceptions raised during email ingestion."""


class IngestionError(Exception):
    """Base exception for email ingestion errors."""
    pass


class EmailSizeExceededError(IngestionError):
    """Raised when uploaded email exceeds maximum allowed size."""
    pass


class InvalidMimeTypeError(IngestionError):
    """Raised when file extension or declared MIME is invalid for email payloads."""
    pass


class MalformedPayloadError(IngestionError):
    """Raised when payload is not a valid RFC 5322 email (e.g. raw executable binary)."""
    pass
