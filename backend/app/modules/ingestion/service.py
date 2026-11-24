"""Email Ingestion Service.

Responsible for receiving raw byte streams or uploaded .eml files, enforcing file size limits,
validating MIME structures, protecting against malicious non-email binaries, and packaging into
an immutable RawEmailPayload.
"""

import os
import re
from typing import Optional
from app.core.config import settings
from app.core.logging import logger
from app.modules.contracts import IngestionSource, RawEmailPayload
from app.modules.ingestion.exceptions import (
    EmailSizeExceededError,
    InvalidMimeTypeError,
    MalformedPayloadError,
)

# Known dangerous executable magic byte headers
EXECUTABLE_SIGNATURES = [
    (b"MZ", "Windows Portable Executable (PE)"),
    (b"\x7fELF", "Linux ELF Executable"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java Class"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit"),
]

ALLOWED_EXTENSIONS = {".eml", ".msg", ".txt", ".mime"}


class EmailIngestionService:
    """Validates and ingests raw email messages."""

    def __init__(self, max_size_bytes: Optional[int] = None):
        self.max_size_bytes = max_size_bytes or settings.MAX_EMAIL_SIZE_BYTES

    def ingest(
        self,
        raw_bytes: bytes,
        filename: Optional[str] = None,
        source: IngestionSource = IngestionSource.DIRECT_UPLOAD,
        source_ip: Optional[str] = None,
        tenant_id: str = "default",
    ) -> RawEmailPayload:
        """Validates raw email bytes and constructs a safe RawEmailPayload container."""
        # 1. Size constraint check
        payload_size = len(raw_bytes)
        if payload_size > self.max_size_bytes:
            logger.warning(
                f"Ingestion rejected: Email size {payload_size} bytes exceeds limit of {self.max_size_bytes} bytes"
            )
            raise EmailSizeExceededError(
                f"Email payload ({payload_size} bytes) exceeds maximum allowable limit of {self.max_size_bytes} bytes."
            )

        if payload_size == 0:
            raise MalformedPayloadError("Empty email payload received. Byte size is zero.")

        # 2. Filename validation and sanitization
        sanitized_filename = None
        if filename:
            # Strip null bytes and control characters
            clean_name = re.sub(r"[\x00-\x1f\x7f]", "", filename.strip())
            # Strip Windows drive letters (e.g. C:)
            clean_name = re.sub(r"^[a-zA-Z]:", "", clean_name)
            # Strip directory traversal patterns
            sanitized_filename = os.path.basename(clean_name.replace("\\", "/")).strip(". /\\")
            if not sanitized_filename:
                sanitized_filename = "unnamed_upload.eml"

            _, ext = os.path.splitext(sanitized_filename.lower())
            if ext and ext not in ALLOWED_EXTENSIONS:
                logger.warning(f"Ingestion rejected: Unsupported extension '{ext}' for filename '{sanitized_filename}'")
                raise InvalidMimeTypeError(
                    f"File extension '{ext}' is not supported for email ingestion. Expected one of: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
                )

        # 3. Executable binary / non-email content detection
        for sig, desc in EXECUTABLE_SIGNATURES:
            if raw_bytes.startswith(sig):
                logger.error(f"Malicious upload attempt: File begins with {desc} magic bytes.")
                raise MalformedPayloadError(f"Payload contains binary executable data ({desc}) instead of RFC 5322 email text.")

        # Block script files disguised as emails
        stripped_prefix = raw_bytes[:100].lstrip()
        if stripped_prefix.startswith((b"#!/bin/sh", b"#!/bin/bash", b"#!/usr/bin/env", b"@echo off", b"<script")):
            raise MalformedPayloadError("Payload contains script or markup execution tokens instead of RFC 5322 email text.")

        # 4. RFC 5322 Structure Sanity Check
        # Strip leading UTF-8 BOM if present
        clean_bytes = raw_bytes.lstrip(b"\xef\xbb\xbf").lstrip(b"\r\n \t")
        header_sample = clean_bytes[:4096].decode("ascii", errors="ignore")
        has_header_pattern = bool(
            re.search(r"^(From|Received|Return-Path|Subject|Date|To|Message-ID|MIME-Version|Content-Type):", 
                      header_sample, re.MULTILINE | re.IGNORECASE)
        )
        if not has_header_pattern:
            # Check if there is at least any valid 'Token: Value' pattern
            has_generic_header = bool(re.search(r"^[A-Za-z0-9\-]+:\s*.+", header_sample, re.MULTILINE))
            if not has_generic_header:
                raise MalformedPayloadError(
                    "Payload does not appear to contain valid RFC 5322 email headers or MIME delimiters."
                )

        logger.info(
            f"Successfully ingested email payload ({payload_size} bytes) from source '{source.value}', filename: '{sanitized_filename}'"
        )

        return RawEmailPayload(
            raw_bytes=raw_bytes,
            source=source,
            filename=sanitized_filename,
            source_ip=source_ip,
            tenant_id=tenant_id,
            size_bytes=payload_size,
        )
