"""Module 6: Attachment Forensic Analysis Subsystem."""

from app.modules.attachment_analysis.analyzer import AttachmentAnalyzer
from app.modules.attachment_analysis.config import AttachmentAnalysisConfig
from app.modules.attachment_analysis.magic_bytes import identify_format_and_mime
from app.modules.attachment_analysis.archive_analyzer import inspect_zip_archive
from app.modules.attachment_analysis.macro_detector import detect_document_active_content

__all__ = [
    "AttachmentAnalyzer",
    "AttachmentAnalysisConfig",
    "identify_format_and_mime",
    "inspect_zip_archive",
    "detect_document_active_content",
]
