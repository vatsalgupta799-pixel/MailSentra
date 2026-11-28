"""Attachment Forensic Analyzer (Module 6).

Implements comprehensive, safe static attachment forensic inspection conforming to BaseDetectionModule.
Never executes code, launches external processes, or contacts network endpoints.
"""

import hashlib
import logging
import os
import re
from typing import List, Optional, Tuple

from app.modules.base import BaseDetectionModule
from app.modules.contracts import (
    AttachmentAnalysisResult,
    AttachmentFinding,
    AttachmentMetadata,
    ParsedEmail,
    RawEmailPayload,
)
from app.modules.attachment_analysis.archive_analyzer import inspect_zip_archive
from app.modules.attachment_analysis.config import AttachmentAnalysisConfig
from app.modules.attachment_analysis.macro_detector import detect_document_active_content
from app.modules.attachment_analysis.magic_bytes import identify_format_and_mime

logger = logging.getLogger(__name__)


class AttachmentAnalyzer(BaseDetectionModule):
    """Module 6: Static Attachment Forensic Analysis Engine."""

    def __init__(self, config: Optional[AttachmentAnalysisConfig] = None):
        self.config = config or AttachmentAnalysisConfig()

    @property
    def module_name(self) -> str:
        return "attachment_analysis"

    @property
    def version(self) -> str:
        return "1.0.0"

    async def analyze(
        self,
        parsed_email: ParsedEmail,
        raw_payload: Optional[RawEmailPayload] = None,
        config: Optional[AttachmentAnalysisConfig] = None,
    ) -> AttachmentAnalysisResult:
        """Asynchronous analysis entrypoint for scan pipeline integration."""
        return self.analyze_sync(parsed_email, raw_payload=raw_payload, config=config)

    def analyze_sync(
        self,
        parsed_email: ParsedEmail,
        raw_payload: Optional[RawEmailPayload] = None,
        config: Optional[AttachmentAnalysisConfig] = None,
    ) -> AttachmentAnalysisResult:
        """Synchronously analyzes all attachments present in a ParsedEmail."""
        cfg = config or self.config
        attachments = parsed_email.attachments or []
        findings: List[AttachmentFinding] = []
        suspicious_count = 0
        malicious_count = 0
        highest_severity = "SAFE"

        for att in attachments:
            try:
                finding = self.analyze_single_attachment(att, config=cfg)
                findings.append(finding)
                if finding.severity == "MALICIOUS":
                    malicious_count += 1
                    highest_severity = "MALICIOUS"
                elif finding.severity == "SUSPICIOUS":
                    suspicious_count += 1
                    if highest_severity != "MALICIOUS":
                        highest_severity = "SUSPICIOUS"
            except Exception as e:
                logger.error(f"Error analyzing attachment '{att.filename}': {str(e)}", exc_info=True)
                # Failure isolation: return an error finding without crashing scan
                err_finding = AttachmentFinding(
                    filename=att.filename,
                    declared_type=att.content_type,
                    detected_mime="unknown",
                    sha256_hash=att.sha256_hash or "",
                    severity="SUSPICIOUS",
                    details=f"Analysis encountered an internal error: {str(e)}",
                    analysis_status="FAILED",
                    error_message=str(e),
                )
                findings.append(err_finding)
                suspicious_count += 1
                if highest_severity != "MALICIOUS":
                    highest_severity = "SUSPICIOUS"

        return AttachmentAnalysisResult(
            total_attachments=len(attachments),
            suspicious_count=suspicious_count,
            malicious_count=malicious_count,
            highest_severity=highest_severity,
            analysis_status="COMPLETED",
            findings=findings,
        )

    def analyze_single_attachment(
        self,
        att: AttachmentMetadata,
        config: Optional[AttachmentAnalysisConfig] = None,
    ) -> AttachmentFinding:
        """Analyzes a single AttachmentMetadata entity and its payload bytes."""
        cfg = config or self.config
        filename = att.filename or "unnamed_attachment.bin"
        declared_mime = att.content_type or "application/octet-stream"
        payload_bytes = getattr(att, "raw_payload", None) or b""

        # 1. SHA-256 Checksum Calculation & Verification
        actual_sha256 = hashlib.sha256(payload_bytes).hexdigest() if payload_bytes else att.sha256_hash

        finding = AttachmentFinding(
            filename=filename,
            declared_type=declared_mime,
            detected_mime="application/octet-stream",
            sha256_hash=actual_sha256 or "",
            severity="SAFE",
            details="",
            analysis_status="COMPLETED",
        )

        details_messages: List[str] = []

        # 2. Oversized Attachment Protection
        if att.size_bytes > cfg.max_attachment_size_bytes:
            details_messages.append(
                f"Attachment size ({att.size_bytes} bytes) exceeds analysis limit ({cfg.max_attachment_size_bytes} bytes)."
            )
            finding.severity = "SUSPICIOUS"
            finding.analysis_status = "SKIPPED_OVERSIZED"
            finding.details = "; ".join(details_messages)
            return finding

        # 3. Filename & Double Extension Analysis
        clean_fn = filename.strip()
        # Detect Right-to-Left Override (RTLO) character \u202E
        if "\u202e" in clean_fn:
            finding.severity = "MALICIOUS"
            details_messages.append("Evasive Unicode Right-to-Left Override (RTLO) detected in filename")

        name_parts = clean_fn.split(".")
        ext = name_parts[-1].lower() if len(name_parts) > 1 else ""

        # Check double extension
        if len(name_parts) > 2:
            second_last = name_parts[-2].lower().strip()
            if second_last in cfg.masked_document_extensions:
                finding.is_double_extension = True
                details_messages.append(f"Suspicious double extension: apparent '{second_last}' masked as '{ext}'")
                if ext in cfg.dangerous_executable_extensions or ext in cfg.dangerous_script_extensions:
                    finding.severity = "MALICIOUS"
                else:
                    if finding.severity != "MALICIOUS":
                        finding.severity = "SUSPICIOUS"

        # 4. Dangerous File Extension Identification
        if ext in cfg.dangerous_executable_extensions:
            finding.is_executable_or_script = True
            finding.severity = "MALICIOUS"
            details_messages.append(f"High-risk executable file extension '.{ext}' detected")
        elif ext in cfg.dangerous_script_extensions:
            finding.is_executable_or_script = True
            if finding.severity != "MALICIOUS":
                finding.severity = "SUSPICIOUS"
            details_messages.append(f"Script file extension '.{ext}' detected")
        elif ext in cfg.container_extensions:
            if finding.severity != "MALICIOUS":
                finding.severity = "SUSPICIOUS"
            details_messages.append(f"Disk image / shortcut extension '.{ext}' detected")
        elif ext in cfg.macro_enabled_extensions:
            finding.has_macros = True
            if finding.severity != "MALICIOUS":
                finding.severity = "SUSPICIOUS"
            details_messages.append(f"Macro-enabled document extension '.{ext}' detected")

        # 5. File Magic-Byte & Format Identification
        detected_mime, format_name, is_binary_exec = identify_format_and_mime(payload_bytes, filename=clean_fn)
        finding.detected_mime = detected_mime
        finding.detected_format = format_name

        if is_binary_exec:
            finding.is_executable_or_script = True
            finding.severity = "MALICIOUS"
            details_messages.append(f"Executable binary header identified: {format_name}")

        # 6. MIME Type vs Format Mismatch Detection
        decl_lower = declared_mime.lower().split(";")[0].strip()
        det_lower = detected_mime.lower().split(";")[0].strip()

        # Check for executable disguised as document or image
        if is_binary_exec and not ("executable" in decl_lower or "dosexec" in decl_lower or "octet-stream" in decl_lower):
            finding.magic_byte_mismatch = True
            finding.severity = "MALICIOUS"
            details_messages.append(
                f"Severe MIME mismatch: declared as '{declared_mime}' but actual binary format is '{format_name}'"
            )
        elif decl_lower != det_lower and det_lower != "application/octet-stream" and decl_lower != "application/octet-stream":
            # Significant divergence (e.g. declared application/pdf but actual image/jpeg)
            if not (decl_lower.startswith("text/") and det_lower.startswith("text/")):
                finding.magic_byte_mismatch = True
                details_messages.append(f"MIME mismatch: declared '{declared_mime}' differs from detected '{detected_mime}'")
                if finding.severity == "SAFE":
                    finding.severity = "SUSPICIOUS"

        # 7. Document Active Content & Macro Scanning
        has_macros, macro_details, macro_severity = detect_document_active_content(payload_bytes, filename=clean_fn)
        if has_macros:
            finding.has_macros = True
            details_messages.extend(macro_details)
            if macro_severity == "MALICIOUS":
                finding.severity = "MALICIOUS"
            elif finding.severity != "MALICIOUS":
                finding.severity = "SUSPICIOUS"

        # 8. Archive Inspection (ZIP / Containers)
        if payload_bytes.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")) and ext not in {"docx", "xlsx", "pptx"}:
            finding.is_archive = True
            archive_res = inspect_zip_archive(payload_bytes, config=cfg)
            finding.extracted_archive_names = archive_res.entry_names
            finding.is_encrypted_archive = archive_res.is_encrypted
            finding.archive_has_traversal = archive_res.has_traversal

            if archive_res.has_traversal:
                finding.severity = "MALICIOUS"
            elif archive_res.is_decompression_bomb:
                finding.severity = "MALICIOUS"
            elif archive_res.dangerous_entries:
                if any(e.lower().endswith(tuple(cfg.dangerous_executable_extensions)) for e in archive_res.dangerous_entries):
                    finding.severity = "MALICIOUS"
                elif finding.severity != "MALICIOUS":
                    finding.severity = "SUSPICIOUS"
            elif archive_res.is_encrypted:
                if finding.severity != "MALICIOUS":
                    finding.severity = "SUSPICIOUS"
            elif archive_res.severity != "SAFE":
                if finding.severity != "MALICIOUS":
                    finding.severity = archive_res.severity

            if archive_res.findings:
                details_messages.extend(archive_res.findings)
            if archive_res.error:
                details_messages.append(archive_res.error)
                if finding.severity == "SAFE":
                    finding.severity = "SUSPICIOUS"

        finding.details = "; ".join(details_messages) if details_messages else "Clean attachment; no structural anomalies detected."
        return finding
