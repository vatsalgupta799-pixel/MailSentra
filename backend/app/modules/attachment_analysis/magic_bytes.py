"""Pure-Python File Magic-Byte & Format Identification.

Identifies actual file format from leading header bytes without external binaries or network calls.
"""

from typing import Optional, Tuple


def identify_format_and_mime(data: bytes, filename: str = "") -> Tuple[str, str, bool]:
    """Inspects header bytes and returns (detected_mime, format_name, is_executable_binary).

    Returns:
        (detected_mime, format_name, is_executable_binary)
    """
    if not data:
        return "application/octet-stream", "Empty Data", False

    # 1. PE Windows Executable (MZ header)
    if data.startswith(b"MZ"):
        # Check if e_lfanew points to PE signature (offset 0x3C has 4-byte little-endian offset)
        is_pe = False
        if len(data) >= 0x40:
            pe_offset = int.from_bytes(data[0x3C:0x40], byteorder="little")
            if 0 < pe_offset < len(data) - 4 and data[pe_offset:pe_offset+4] == b"PE\x00\x00":
                is_pe = True
        format_name = "Windows PE Executable" if is_pe else "DOS/MZ Binary"
        return "application/x-dosexec", format_name, True

    # 2. Linux ELF Executable
    if data.startswith(b"\x7fELF"):
        return "application/x-executable", "ELF Executable", True

    # 3. macOS Mach-O Executable
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "application/x-mach-binary", "Mach-O Executable", True

    # 4. Windows Shortcut (LNK)
    if data.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00"):
        return "application/x-ms-shortcut", "Windows LNK Shortcut", True

    # 5. PDF Document
    if data.startswith(b"%PDF-"):
        return "application/pdf", "PDF Document", False

    # 6. ZIP Archive / OpenXML
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        # Could be standard ZIP or Office OpenXML (.docx, .xlsx, .pptx, etc.)
        fn_lower = filename.lower()
        if fn_lower.endswith((".docx", ".dotx")):
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "Word OpenXML", False
        elif fn_lower.endswith((".xlsx", ".xltx")):
            return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Excel OpenXML", False
        elif fn_lower.endswith((".pptx", ".potx")):
            return "application/vnd.openxmlformats-officedocument.presentationml.presentation", "PowerPoint OpenXML", False
        elif fn_lower.endswith(".docm"):
            return "application/vnd.ms-word.document.macroEnabled.12", "Word Macro-Enabled", False
        elif fn_lower.endswith(".xlsm"):
            return "application/vnd.ms-excel.sheet.macroEnabled.12", "Excel Macro-Enabled", False
        elif fn_lower.endswith(".pptm"):
            return "application/vnd.ms-powerpoint.presentation.macroEnabled.12", "PowerPoint Macro-Enabled", False
        return "application/zip", "ZIP Archive", False

    # 7. GZIP Archive
    if data.startswith(b"\x1f\x8b"):
        return "application/gzip", "GZIP Archive", False

    # 8. 7-Zip Archive
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "application/x-7z-compressed", "7-Zip Archive", False

    # 9. RAR Archive
    if data.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        return "application/x-rar-compressed", "RAR Archive", False

    # 10. OLE2 Compound Document (Legacy MS Office .doc, .xls, .ppt)
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "application/x-ole-storage", "Microsoft OLE2 Compound Document", False

    # 11. Rich Text Format (RTF)
    if data.startswith(b"{\\rtf"):
        return "application/rtf", "Rich Text Format", False

    # 12. Images
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", "JPEG Image", False
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", "PNG Image", False
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif", "GIF Image", False
    if data.startswith(b"BM"):
        return "image/bmp", "BMP Image", False

    # 13. HTML / XML / SVG
    leading_1k = data[:1024].lstrip().lower()
    if leading_1k.startswith((b"<!doctype html", b"<html", b"<head", b"<body")):
        return "text/html", "HTML Document", False
    if b"<svg" in leading_1k:
        return "image/svg+xml", "SVG Vector Image", False
    if leading_1k.startswith(b"<?xml"):
        return "application/xml", "XML Document", False

    # 14. Text / Plain / Scripts
    # Check if printable ASCII/UTF-8 text
    if not (b"\x00" in data[:1024]):
        try:
            sample_str = data[:1024].decode("utf-8", errors="strict")
            fn_lower = filename.lower()
            if fn_lower.endswith((".ps1", ".psm1", ".psd1")):
                return "text/x-powershell", "PowerShell Script", True
            elif fn_lower.endswith((".vbs", ".vbe")):
                return "text/x-vbs", "VBScript", True
            elif fn_lower.endswith((".js", ".jse")):
                return "application/javascript", "JavaScript Script", True
            elif fn_lower.endswith((".bat", ".cmd")):
                return "application/x-bat", "Batch Script", True
            elif fn_lower.endswith((".sh", ".bash")):
                return "application/x-sh", "Shell Script", True
            elif fn_lower.endswith((".py", ".pyw")):
                return "text/x-python", "Python Script", True
            return "text/plain", "Plain Text", False
        except UnicodeDecodeError:
            pass

    return "application/octet-stream", "Binary Data", False
