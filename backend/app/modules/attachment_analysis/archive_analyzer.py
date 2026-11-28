"""In-Memory Safe Archive Inspection Engine.

Performs deterministic inspection of ZIP archives without filesystem extraction.
Detects path traversal, encryption, decompression bombs, dangerous payloads, and nested archives.
"""

import io
import os
import zipfile
from typing import List, Optional, Set, Tuple
from app.modules.attachment_analysis.config import AttachmentAnalysisConfig


class ArchiveInspectionResult:
    def __init__(self):
        self.is_valid_archive: bool = False
        self.entry_names: List[str] = []
        self.total_entries: int = 0
        self.is_encrypted: bool = False
        self.has_traversal: bool = False
        self.is_decompression_bomb: bool = False
        self.has_nested_archive: bool = False
        self.max_depth_reached: int = 0
        self.dangerous_entries: List[str] = []
        self.findings: List[str] = []
        self.severity: str = "SAFE"
        self.error: Optional[str] = None


def inspect_zip_archive(
    data: bytes,
    config: Optional[AttachmentAnalysisConfig] = None,
    current_depth: int = 1,
) -> ArchiveInspectionResult:
    """Safely inspects a ZIP archive in memory without extracting files to disk."""
    cfg = config or AttachmentAnalysisConfig()
    result = ArchiveInspectionResult()
    result.max_depth_reached = current_depth

    if not data or not data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        result.error = "Not a recognized ZIP archive format."
        return result

    try:
        with zipfile.ZipFile(io.BytesIO(data), mode="r") as zf:
            result.is_valid_archive = True
            infolist = zf.infolist()
            result.total_entries = len(infolist)

            # 1. Excessive Entry Count Check
            if result.total_entries > cfg.max_archive_entries:
                result.findings.append(
                    f"Excessive archive entry count: {result.total_entries} exceeds maximum allowed ({cfg.max_archive_entries})."
                )
                if result.severity != "MALICIOUS":
                    result.severity = "SUSPICIOUS"

            total_compressed = 0
            total_uncompressed = 0

            # Inspect up to max_archive_entries
            bounded_infolist = infolist[: cfg.max_archive_entries]
            for info in bounded_infolist:
                name = info.filename
                result.entry_names.append(name)
                total_compressed += info.compress_size
                total_uncompressed += info.file_size

                # 2. Encrypted Archive Check
                if info.flag_bits & 0x1:
                    result.is_encrypted = True
                    result.findings.append(f"Encrypted archive entry detected: '{name}'")
                    if result.severity != "MALICIOUS":
                        result.severity = "SUSPICIOUS"

                # 3. Path Traversal & Absolute Path Check
                normalized_name = name.replace("\\", "/")
                if (
                    "../" in normalized_name
                    or normalized_name.startswith("/")
                    or (len(normalized_name) > 2 and normalized_name[1] == ":")
                    or "\x00" in name
                ):
                    result.has_traversal = True
                    result.severity = "MALICIOUS"
                    result.findings.append(f"Path traversal or absolute path detected in archive entry: '{name}'")

                # 4. Dangerous File Extensions inside Archive
                name_parts = name.split(".")
                if len(name_parts) > 1:
                    ext = name_parts[-1].lower()
                    if ext in cfg.dangerous_executable_extensions:
                        result.dangerous_entries.append(name)
                        result.severity = "MALICIOUS"
                        result.findings.append(f"Executable binary inside archive: '{name}' (extension '.{ext}')")
                    elif ext in cfg.dangerous_script_extensions:
                        result.dangerous_entries.append(name)
                        if result.severity != "MALICIOUS":
                            result.severity = "SUSPICIOUS"
                        result.findings.append(f"Script file inside archive: '{name}' (extension '.{ext}')")
                    elif ext in cfg.container_extensions:
                        result.dangerous_entries.append(name)
                        if result.severity != "MALICIOUS":
                            result.severity = "SUSPICIOUS"
                        result.findings.append(f"Container/shortcut inside archive: '{name}' (extension '.{ext}')")
                    elif ext in cfg.macro_enabled_extensions:
                        result.dangerous_entries.append(name)
                        if result.severity != "MALICIOUS":
                            result.severity = "SUSPICIOUS"
                        result.findings.append(f"Macro-enabled document inside archive: '{name}'")

                # 5. Nested Archive Inspection
                if name.lower().endswith(".zip"):
                    result.has_nested_archive = True
                    if current_depth >= cfg.max_archive_depth:
                        result.findings.append(
                            f"Nested archive depth limit exceeded at entry '{name}' (depth {current_depth} >= {cfg.max_archive_depth})"
                        )
                        if result.severity != "MALICIOUS":
                            result.severity = "SUSPICIOUS"
                    else:
                        # Safely read inner zip bytes if reasonably bounded
                        if info.file_size <= cfg.max_attachment_size_bytes and not (info.flag_bits & 0x1):
                            try:
                                inner_bytes = zf.read(info)
                                inner_res = inspect_zip_archive(
                                    inner_bytes, config=cfg, current_depth=current_depth + 1
                                )
                                result.max_depth_reached = max(result.max_depth_reached, inner_res.max_depth_reached)
                                if inner_res.has_traversal:
                                    result.has_traversal = True
                                    result.severity = "MALICIOUS"
                                if inner_res.is_encrypted:
                                    result.is_encrypted = True
                                    if result.severity != "MALICIOUS":
                                        result.severity = "SUSPICIOUS"
                                for inner_finding in inner_res.findings:
                                    result.findings.append(f"[Nested {name}] {inner_finding}")
                            except Exception as inner_e:
                                result.findings.append(f"Failed to inspect inner archive '{name}': {str(inner_e)}")

            # 6. Decompression Bomb Check
            if total_compressed > 0:
                ratio = total_uncompressed / total_compressed
                if ratio > cfg.max_decompression_ratio or total_uncompressed > cfg.max_uncompressed_bytes:
                    result.is_decompression_bomb = True
                    result.severity = "MALICIOUS"
                    result.findings.append(
                        f"Decompression bomb indicator: compression ratio {ratio:.1f}:1 (uncompressed {total_uncompressed} bytes, limit {cfg.max_uncompressed_bytes} bytes)."
                    )
            elif total_uncompressed > cfg.max_uncompressed_bytes:
                result.is_decompression_bomb = True
                result.severity = "MALICIOUS"
                result.findings.append(
                    f"Excessive uncompressed size: {total_uncompressed} bytes exceeds limit of {cfg.max_uncompressed_bytes} bytes."
                )

    except zipfile.BadZipFile as bzf:
        result.error = f"Corrupted or malformed ZIP archive: {str(bzf)}"
    except Exception as e:
        result.error = f"Error inspecting ZIP archive: {str(e)}"

    return result
