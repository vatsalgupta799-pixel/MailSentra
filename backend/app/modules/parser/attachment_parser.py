"""Email Attachment Metadata Extraction Utilities.

Extracts attachment metadata safely without executing or executing file payloads.
Sanitizes filenames to prevent path traversal attacks.
"""

import email.message
import hashlib
import os
import re
from typing import List, Optional, Tuple
from app.modules.contracts import AttachmentMetadata
from app.modules.parser.header_parser import decode_rfc2047


def sanitize_filename(raw_filename: Optional[str]) -> Tuple[str, str]:
    """Sanitizes an attachment filename against path traversal, null bytes, and control characters.

    Returns:
        Tuple of (sanitized_filename, original_filename)
    """
    if not raw_filename or not raw_filename.strip():
        fallback = "unnamed_attachment.bin"
        return fallback, fallback

    original = decode_rfc2047(raw_filename.strip())

    # 1. Strip null bytes and control characters
    sanitized = re.sub(r"[\x00-\x1f\x7f]", "", original)

    # 2. Strip Windows drive letters (e.g. C:, D:)
    sanitized = re.sub(r"^[a-zA-Z]:", "", sanitized)

    # 3. Strip directory separators and traversal patterns (../ or ..\)
    sanitized = os.path.basename(sanitized.replace("\\", "/"))

    # 4. Remove any leading/trailing periods, spaces, or slashes
    sanitized = sanitized.strip(". /\\")

    if not sanitized:
        sanitized = "sanitized_attachment.bin"

    return sanitized, original


def extract_file_extension(filename: str) -> str:
    """Extracts extension, preserving multi-dot or single extension."""
    if not filename:
        return ""
    # Look for last extension
    _, ext = os.path.splitext(filename.lower())
    return ext


def extract_attachments_from_message(
    msg: email.message.Message,
    max_attachments: int = 50,
    max_payload_bytes: int = 10 * 1024 * 1024,
) -> Tuple[List[AttachmentMetadata], List[str]]:
    """Iterates through MIME message parts and extracts metadata for all attachments."""
    attachments: List[AttachmentMetadata] = []
    warnings: List[str] = []

    for part in msg.walk():
        if len(attachments) >= max_attachments:
            warnings.append(
                f"Maximum attachment extraction limit of {max_attachments} reached; remaining attachments skipped."
            )
            break

        # Skip multipart containers
        if part.is_multipart():
            continue

        content_disposition = part.get("Content-Disposition", "")
        content_type = part.get_content_type()
        filename_raw = part.get_filename()

        # Check if this part is an attachment or inline asset
        is_attachment = False
        is_inline = False
        disp_lower = content_disposition.lower()

        if "attachment" in disp_lower:
            is_attachment = True
        elif "inline" in disp_lower:
            is_inline = True
            # Inline parts with a filename are still treated as attachments (e.g. inline images/documents)
            if filename_raw:
                is_attachment = True
        elif filename_raw:
            is_attachment = True
        elif content_type.startswith(("application/", "audio/", "video/")) and content_type != "application/pkcs7-signature":
            # Binary payload without explicit disposition
            is_attachment = True

        if not is_attachment:
            continue

        # Extract payload bytes
        try:
            payload_bytes = part.get_payload(decode=True)
            if payload_bytes is None:
                payload_bytes = b""
        except Exception as e:
            warnings.append(f"Failed to decode attachment payload for part '{filename_raw}': {str(e)}")
            payload_bytes = b""

        # Filename sanitization
        sanitized_fn, orig_fn = sanitize_filename(filename_raw or f"attachment_{len(attachments)+1}.bin")
        if sanitized_fn != orig_fn:
            warnings.append(f"Attachment filename was sanitized from '{orig_fn}' to '{sanitized_fn}'")

        original_size = len(payload_bytes)
        original_sha256 = hashlib.sha256(payload_bytes).hexdigest()
        is_truncated = False

        # Bound attachment payload size to prevent memory exhaustion
        if original_size > max_payload_bytes:
            warnings.append(
                f"Attachment '{sanitized_fn}' payload ({original_size} bytes) exceeds max limit of {max_payload_bytes} bytes; payload bounded."
            )
            payload_bytes = payload_bytes[:max_payload_bytes]
            is_truncated = True

        # Executable MIME type warning
        suspect_executable_mimes = {
            "application/x-msdownload",
            "application/x-dosexec",
            "application/x-executable",
            "application/x-bat",
            "application/x-sh",
        }
        if content_type.lower() in suspect_executable_mimes:
            warnings.append(
                f"Suspicious executable MIME type '{content_type}' detected for attachment '{sanitized_fn}'"
            )

        # Double extension detection
        name_parts = sanitized_fn.split(".")
        is_double_ext = False
        if len(name_parts) > 2:
            suspect_secondaries = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "png", "txt", "zip", "csv"}
            if name_parts[-2].lower() in suspect_secondaries:
                is_double_ext = True
                warnings.append(
                    f"Suspicious double extension detected in attachment '{sanitized_fn}' (apparent '{name_parts[-2]}' masked as '{name_parts[-1]}')"
                )

        # Compute SHA-256 (retains full original_sha256)
        ext = extract_file_extension(sanitized_fn)

        content_id = part.get("Content-ID")
        if content_id:
            content_id = content_id.strip("<>")

        attachments.append(
            AttachmentMetadata(
                filename=sanitized_fn,
                original_filename=orig_fn,
                content_type=content_type,
                file_extension=ext,
                is_double_extension=is_double_ext,
                size_bytes=len(payload_bytes),
                sha256_hash=original_sha256,
                content_disposition="inline" if is_inline else "attachment",
                content_id=content_id,
                is_inline=is_inline,
                raw_payload=payload_bytes,
                is_truncated=is_truncated,
                actual_payload_size=original_size,
            )
        )

    return attachments, warnings
