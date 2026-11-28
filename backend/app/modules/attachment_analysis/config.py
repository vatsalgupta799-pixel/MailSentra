"""Configuration for Module 6: Attachment Forensic Analysis."""

from typing import Set
from pydantic import BaseModel, Field


class AttachmentAnalysisConfig(BaseModel):
    """Configurable security boundaries and heuristics for attachment analysis."""

    # Resource bounds
    max_attachment_size_bytes: int = 25 * 1024 * 1024  # 25 MB
    max_archive_entries: int = 100
    max_archive_depth: int = 2
    max_decompression_ratio: float = 100.0  # Alert if uncompressed / compressed > 100
    max_uncompressed_bytes: int = 50 * 1024 * 1024  # 50 MB total uncompressed

    # Dangerous executables and binaries
    dangerous_executable_extensions: Set[str] = Field(
        default_factory=lambda: {
            "exe", "scr", "pif", "com", "bat", "cmd", "msi", "dll", "sys", "cpl",
            "gadget", "hta", "csh", "ksh", "bin",
        }
    )

    # Script extensions
    dangerous_script_extensions: Set[str] = Field(
        default_factory=lambda: {
            "vbs", "vbe", "js", "jse", "wsf", "wsh", "ps1", "ps1xml", "ps2",
            "ps2xml", "psc1", "psc2", "sh", "bash", "py", "rb", "pl", "php",
        }
    )

    # Container & Link extensions
    container_extensions: Set[str] = Field(
        default_factory=lambda: {
            "lnk", "inf", "reg", "iso", "img", "vhd", "vhdx",
        }
    )

    # Macro-enabled Office extensions
    macro_enabled_extensions: Set[str] = Field(
        default_factory=lambda: {
            "docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm",
        }
    )

    # Standard archive extensions
    archive_extensions: Set[str] = Field(
        default_factory=lambda: {
            "zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar",
        }
    )

    # Secondary extensions commonly used in double-extension masking
    masked_document_extensions: Set[str] = Field(
        default_factory=lambda: {
            "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg",
            "png", "gif", "txt", "csv", "mp3", "mp4",
        }
    )
