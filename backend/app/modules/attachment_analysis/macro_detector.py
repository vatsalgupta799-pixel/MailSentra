"""Macro & Active Content Detection in Documents.

Statically detects embedded VBA macros in Office OpenXML / OLE2 files and active scripts in PDFs.
Never executes or runs code.
"""

import io
import zipfile
from typing import List, Tuple


def detect_document_active_content(data: bytes, filename: str) -> Tuple[bool, List[str], str]:
    """Inspects document bytes for active macro code or PDF execution triggers.

    Returns:
        (has_active_content, details_list, severity)
    """
    if not data:
        return False, [], "SAFE"

    details: List[str] = []
    fn_lower = filename.lower()

    # 1. OpenXML VBA Macro Detection (.docm, .xlsm, .pptm, .docx, .xlsx, .pptx)
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        try:
            with zipfile.ZipFile(io.BytesIO(data), mode="r") as zf:
                names = [n.lower() for n in zf.namelist()]
                vba_indicators = [
                    "vbaproject.bin",
                    "word/vbaproject.bin",
                    "xl/vbaproject.bin",
                    "ppt/vbaproject.bin",
                    "word/vba/vbaproject.bin",
                    "xl/vba/vbaproject.bin",
                ]
                found_vba = [ind for ind in vba_indicators if ind in names]
                if found_vba:
                    details.append(f"VBA Macro stream detected: {', '.join(found_vba)}")
                    # If file has non-macro extension (e.g. .docx or .xlsx) but embeds macros, that is highly suspicious
                    if fn_lower.endswith((".docx", ".xlsx", ".pptx")):
                        details.append("Stealth macro detected in standard document format (.docx/.xlsx/.pptx)")
                        return True, details, "MALICIOUS"
                    return True, details, "SUSPICIOUS"
        except Exception:
            pass

    # 2. OLE2 Legacy Office Document Macro Detection (.doc, .xls, .ppt)
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        ole_macro_signatures = [
            b"_VBA_PROJECT",
            b"VBA",
            b"Macros",
            b"\x00dir\x00",
            b"Attribut\x00e\x00 \x00V\x00B\x00_\x00N\x00a\x00m\x00e",
        ]
        found_ole_macros = [sig for sig in ole_macro_signatures if sig in data]
        if found_ole_macros:
            details.append("Legacy OLE2 VBA macro streams detected in compound document.")
            return True, details, "SUSPICIOUS"

    # 3. PDF Active Code & Exploit Vectors (/JavaScript, /Launch, /OpenAction)
    if data.startswith(b"%PDF-"):
        # Check PDF structural markers
        pdf_threat_markers = [
            (b"/JavaScript", "Embedded JavaScript in PDF"),
            (b"/JS", "Embedded JS action in PDF"),
            (b"/Launch", "Automatic application launch action (/Launch) in PDF"),
            (b"/EmbeddedFiles", "Embedded file attachment inside PDF"),
        ]
        found_pdf_threats = []
        for marker, desc in pdf_threat_markers:
            if marker in data:
                found_pdf_threats.append(desc)

        if found_pdf_threats:
            details.extend(found_pdf_threats)
            # /Launch is practically always malicious in email attachments
            if b"/Launch" in data:
                return True, details, "MALICIOUS"
            return True, details, "SUSPICIOUS"

    return False, [], "SAFE"
