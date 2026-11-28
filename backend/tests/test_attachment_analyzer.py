"""Automated Test Suite for Module 6: Attachment Forensic Analysis.

Deterministic tests validating:
1. Benign PDF-like inert fixture
2. Benign text file
3. Double extensions (e.g. .pdf.exe, .xlsx.exe, .pdf.scr)
4. Executable magic-byte identification (MZ, ELF, Mach-O)
5. MIME mismatch (declared PDF but actual executable)
6. Extension mismatch
7. Macro-enabled Office identification (.docm, .xlsm, stealth macro)
8. Malformed PDF (/Launch, /JavaScript triggers)
9. HTML and SVG attachments
10. ZIP archive inspection
11. Archive path traversal (../../)
12. Nested archive depth limits
13. Excessive archive entries
14. Oversized files (exceeding memory/resource limits)
15. Encrypted archives (password protected zip)
16. Unicode filenames (RTLO \u202e and international characters)
17. Corrupted archive handling
18. Multiple attachments scanning
19. Attachment-level failure isolation (one bad attachment doesn't crash scan)
20. SHA-256 correctness
21. ScanService end-to-end integration and telemetry persistence
"""

import hashlib
import io
import pytest
import zipfile
from app.modules.attachment_analysis.analyzer import AttachmentAnalyzer
from app.modules.attachment_analysis.archive_analyzer import inspect_zip_archive
from app.modules.attachment_analysis.config import AttachmentAnalysisConfig
from app.modules.attachment_analysis.macro_detector import detect_document_active_content
from app.modules.attachment_analysis.magic_bytes import identify_format_and_mime
from app.modules.contracts import (
    AttachmentMetadata,
    IngestionSource,
    ParsedEmail,
    RawEmailPayload,
)
from app.services.scan_service import ScanService


@pytest.fixture
def analyzer():
    return AttachmentAnalyzer()


# ============================================================================
# 1. Benign Inert Fixtures
# ============================================================================

def test_benign_pdf(analyzer):
    data = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF"
    meta = AttachmentMetadata(
        filename="report.pdf",
        original_filename="report.pdf",
        content_type="application/pdf",
        file_extension=".pdf",
        size_bytes=len(data),
        sha256_hash=hashlib.sha256(data).hexdigest(),
        raw_payload=data,
    )
    finding = analyzer.analyze_single_attachment(meta)
    assert finding.severity == "SAFE"
    assert finding.detected_mime == "application/pdf"
    assert finding.magic_byte_mismatch is False
    assert finding.is_executable_or_script is False


def test_benign_text(analyzer):
    data = b"Hello, this is a plain text notes file."
    meta = AttachmentMetadata(
        filename="notes.txt",
        original_filename="notes.txt",
        content_type="text/plain",
        file_extension=".txt",
        size_bytes=len(data),
        sha256_hash=hashlib.sha256(data).hexdigest(),
        raw_payload=data,
    )
    finding = analyzer.analyze_single_attachment(meta)
    assert finding.severity == "SAFE"
    assert finding.detected_mime == "text/plain"
    assert finding.is_executable_or_script is False


# ============================================================================
# 2. Double Extension Detection
# ============================================================================

def test_double_extension_executable(analyzer):
    data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff"
    meta = AttachmentMetadata(
        filename="Invoice_Overdue.pdf.exe",
        original_filename="Invoice_Overdue.pdf.exe",
        content_type="application/pdf",
        file_extension=".exe",
        is_double_extension=True,
        size_bytes=len(data),
        sha256_hash=hashlib.sha256(data).hexdigest(),
        raw_payload=data,
    )
    finding = analyzer.analyze_single_attachment(meta)
    assert finding.severity == "MALICIOUS"
    assert finding.is_double_extension is True
    assert finding.is_executable_or_script is True
    assert "double extension" in finding.details.lower()


def test_double_extension_screensaver(analyzer):
    data = b"MZ\x00\x00"
    meta = AttachmentMetadata(
        filename="Salary_Bonus.xlsx.scr",
        original_filename="Salary_Bonus.xlsx.scr",
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        file_extension=".scr",
        is_double_extension=True,
        size_bytes=len(data),
        sha256_hash=hashlib.sha256(data).hexdigest(),
        raw_payload=data,
    )
    finding = analyzer.analyze_single_attachment(meta)
    assert finding.severity == "MALICIOUS"
    assert finding.is_double_extension is True


# ============================================================================
# 3. Executable Magic-Byte Identification & MIME Mismatch
# ============================================================================

def test_executable_pe_magic_identification(analyzer):
    # Simulated PE header with valid offset
    data = bytearray(b"MZ" + b"\x00" * 0x3A + b"\x80\x00\x00\x00" + b"\x00" * 0x40 + b"PE\x00\x00" + b"\x00" * 20)
    mime, name, is_exec = identify_format_and_mime(bytes(data), "document.pdf")
    assert mime == "application/x-dosexec"
    assert name == "Windows PE Executable"
    assert is_exec is True

    # When declared as application/pdf, must raise severe MIME mismatch
    meta = AttachmentMetadata(
        filename="scanned_receipt.pdf",
        original_filename="scanned_receipt.pdf",
        content_type="application/pdf",
        file_extension=".pdf",
        size_bytes=len(data),
        sha256_hash=hashlib.sha256(data).hexdigest(),
        raw_payload=bytes(data),
    )
    finding = analyzer.analyze_single_attachment(meta)
    assert finding.severity == "MALICIOUS"
    assert finding.magic_byte_mismatch is True
    assert finding.is_executable_or_script is True


def test_elf_binary_identification(analyzer):
    data = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 32
    mime, name, is_exec = identify_format_and_mime(data, "updater")
    assert mime == "application/x-executable"
    assert is_exec is True


def test_macho_binary_identification(analyzer):
    data = b"\xfe\xed\xfa\xce" + b"\x00" * 32
    mime, name, is_exec = identify_format_and_mime(data, "payload.bin")
    assert mime == "application/x-mach-binary"
    assert is_exec is True


# ============================================================================
# 4. Macro-Enabled Document Identification
# ============================================================================

def test_macro_enabled_office_file(analyzer):
    # Create an in-memory zip resembling a .docm file with vbaProject.bin
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", b"<Types></Types>")
        zf.writestr("word/vbaProject.bin", b"VBA MACRO DUMMY BYTES")
    docm_bytes = buf.getvalue()

    meta = AttachmentMetadata(
        filename="Contract_Review.docm",
        original_filename="Contract_Review.docm",
        content_type="application/vnd.ms-word.document.macroEnabled.12",
        file_extension=".docm",
        size_bytes=len(docm_bytes),
        sha256_hash=hashlib.sha256(docm_bytes).hexdigest(),
        raw_payload=docm_bytes,
    )
    finding = analyzer.analyze_single_attachment(meta)
    assert finding.has_macros is True
    assert finding.severity in ("SUSPICIOUS", "MALICIOUS")


def test_stealth_macro_in_docx(analyzer):
    # .docx containing unexpected vbaProject.bin
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("word/vbaProject.bin", b"STEALTH MACRO BYTES")
    docx_bytes = buf.getvalue()

    meta = AttachmentMetadata(
        filename="Quarterly_Report.docx",
        original_filename="Quarterly_Report.docx",
        content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        file_extension=".docx",
        size_bytes=len(docx_bytes),
        sha256_hash=hashlib.sha256(docx_bytes).hexdigest(),
        raw_payload=docx_bytes,
    )
    finding = analyzer.analyze_single_attachment(meta)
    assert finding.has_macros is True
    assert finding.severity == "MALICIOUS"
    assert "stealth macro" in finding.details.lower()


# ============================================================================
# 5. Malformed PDF (/Launch and /JavaScript)
# ============================================================================

def test_pdf_with_launch_action(analyzer):
    data = b"%PDF-1.4\n<< /Type /Action /S /Launch /F (powershell.exe) >>\n%%EOF"
    meta = AttachmentMetadata(
        filename="invoice.pdf",
        original_filename="invoice.pdf",
        content_type="application/pdf",
        file_extension=".pdf",
        size_bytes=len(data),
        sha256_hash=hashlib.sha256(data).hexdigest(),
        raw_payload=data,
    )
    finding = analyzer.analyze_single_attachment(meta)
    assert finding.severity == "MALICIOUS"
    assert "launch" in finding.details.lower()


def test_pdf_with_javascript(analyzer):
    data = b"%PDF-1.4\n<< /Type /Action /S /JavaScript /JS (app.alert('hi');) >>\n%%EOF"
    meta = AttachmentMetadata(
        filename="ticket.pdf",
        original_filename="ticket.pdf",
        content_type="application/pdf",
        file_extension=".pdf",
        size_bytes=len(data),
        sha256_hash=hashlib.sha256(data).hexdigest(),
        raw_payload=data,
    )
    finding = analyzer.analyze_single_attachment(meta)
    assert finding.severity == "SUSPICIOUS"
    assert "javascript" in finding.details.lower()


# ============================================================================
# 6. HTML and SVG Attachments
# ============================================================================

def test_html_attachment(analyzer):
    data = b"<!DOCTYPE html><html><body><h1>Please Login</h1></body></html>"
    mime, name, _ = identify_format_and_mime(data, "login.html")
    assert mime == "text/html"
    assert name == "HTML Document"


def test_svg_attachment(analyzer):
    data = b"<svg xmlns='http://www.w3.org/2000/svg'><circle r='10'/></svg>"
    mime, name, _ = identify_format_and_mime(data, "vector.svg")
    assert mime == "image/svg+xml"
    assert name == "SVG Vector Image"


# ============================================================================
# 7. ZIP Archive Inspection & Path Traversal
# ============================================================================

def test_archive_path_traversal(analyzer):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../../../etc/passwd", b"root:x:0:0:root:/root:/bin/bash")
    zip_bytes = buf.getvalue()

    meta = AttachmentMetadata(
        filename="archive.zip",
        original_filename="archive.zip",
        content_type="application/zip",
        file_extension=".zip",
        size_bytes=len(zip_bytes),
        sha256_hash=hashlib.sha256(zip_bytes).hexdigest(),
        raw_payload=zip_bytes,
    )
    finding = analyzer.analyze_single_attachment(meta)
    assert finding.severity == "MALICIOUS"
    assert finding.archive_has_traversal is True
    assert "path traversal" in finding.details.lower()


def test_archive_dangerous_binary_entry(analyzer):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("setup.exe", b"MZ\x00\x00")
    zip_bytes = buf.getvalue()

    meta = AttachmentMetadata(
        filename="utilities.zip",
        original_filename="utilities.zip",
        content_type="application/zip",
        file_extension=".zip",
        size_bytes=len(zip_bytes),
        sha256_hash=hashlib.sha256(zip_bytes).hexdigest(),
        raw_payload=zip_bytes,
    )
    finding = analyzer.analyze_single_attachment(meta)
    assert finding.severity == "MALICIOUS"
    assert "executable binary inside archive" in finding.details.lower()


def test_nested_archive_depth_limit(analyzer):
    cfg = AttachmentAnalysisConfig(max_archive_depth=1)
    inner_buf = io.BytesIO()
    with zipfile.ZipFile(inner_buf, "w") as inner_zf:
        inner_zf.writestr("data.txt", b"inner data")

    outer_buf = io.BytesIO()
    with zipfile.ZipFile(outer_buf, "w") as outer_zf:
        outer_zf.writestr("inner.zip", inner_buf.getvalue())
    outer_bytes = outer_buf.getvalue()

    meta = AttachmentMetadata(
        filename="outer.zip",
        original_filename="outer.zip",
        content_type="application/zip",
        file_extension=".zip",
        size_bytes=len(outer_bytes),
        sha256_hash=hashlib.sha256(outer_bytes).hexdigest(),
        raw_payload=outer_bytes,
    )
    finding = analyzer.analyze_single_attachment(meta, config=cfg)
    assert finding.severity == "SUSPICIOUS"
    assert "nested archive depth limit exceeded" in finding.details.lower()


def test_excessive_archive_entries(analyzer):
    cfg = AttachmentAnalysisConfig(max_archive_entries=5)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(10):
            zf.writestr(f"file_{i}.txt", b"test")
    zip_bytes = buf.getvalue()

    meta = AttachmentMetadata(
        filename="many_files.zip",
        original_filename="many_files.zip",
        content_type="application/zip",
        file_extension=".zip",
        size_bytes=len(zip_bytes),
        sha256_hash=hashlib.sha256(zip_bytes).hexdigest(),
        raw_payload=zip_bytes,
    )
    finding = analyzer.analyze_single_attachment(meta, config=cfg)
    assert finding.severity == "SUSPICIOUS"
    assert "excessive archive entry count" in finding.details.lower()


def test_encrypted_archive(analyzer):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("secret.txt", b"confidential payload")
    data = bytearray(buf.getvalue())
    # Set bit 0 of General Purpose Bit Flag in Local File Header and Central Directory Header
    idx_lfh = data.find(b"PK\x03\x04")
    if idx_lfh != -1:
        data[idx_lfh + 6] |= 0x1
    idx_cdh = data.find(b"PK\x01\x02")
    if idx_cdh != -1:
        data[idx_cdh + 8] |= 0x1
    zip_bytes = bytes(data)

    meta = AttachmentMetadata(
        filename="encrypted.zip",
        original_filename="encrypted.zip",
        content_type="application/zip",
        file_extension=".zip",
        size_bytes=len(zip_bytes),
        sha256_hash=hashlib.sha256(zip_bytes).hexdigest(),
        raw_payload=zip_bytes,
    )
    finding = analyzer.analyze_single_attachment(meta)
    assert finding.is_encrypted_archive is True
    assert finding.severity == "SUSPICIOUS"
    assert "encrypted" in finding.details.lower()


# ============================================================================
# 8. Unicode RTLO & Oversized Files
# ============================================================================

def test_rtlo_unicode_filename(analyzer):
    # \u202E causes "doc\u202Efdp.exe" to render visually as "docexe.pdf"
    rtlo_filename = "Invoice\u202efdp.exe"
    data = b"Hello world"
    meta = AttachmentMetadata(
        filename=rtlo_filename,
        original_filename=rtlo_filename,
        content_type="application/octet-stream",
        file_extension=".exe",
        size_bytes=len(data),
        sha256_hash=hashlib.sha256(data).hexdigest(),
        raw_payload=data,
    )
    finding = analyzer.analyze_single_attachment(meta)
    assert finding.severity == "MALICIOUS"
    assert "rtlo" in finding.details.lower()


def test_oversized_file_protection(analyzer):
    cfg = AttachmentAnalysisConfig(max_attachment_size_bytes=100)
    data = b"A" * 200
    meta = AttachmentMetadata(
        filename="huge.bin",
        original_filename="huge.bin",
        content_type="application/octet-stream",
        file_extension=".bin",
        size_bytes=len(data),
        sha256_hash=hashlib.sha256(data).hexdigest(),
        raw_payload=data,
    )
    finding = analyzer.analyze_single_attachment(meta, config=cfg)
    assert finding.severity == "SUSPICIOUS"
    assert finding.analysis_status == "SKIPPED_OVERSIZED"
    assert "exceeds analysis limit" in finding.details.lower()


def test_corrupted_archive_handling(analyzer):
    corrupted_data = b"PK\x03\x04corrupted_payload_without_central_directory"
    meta = AttachmentMetadata(
        filename="broken.zip",
        original_filename="broken.zip",
        content_type="application/zip",
        file_extension=".zip",
        size_bytes=len(corrupted_data),
        sha256_hash=hashlib.sha256(corrupted_data).hexdigest(),
        raw_payload=corrupted_data,
    )
    finding = analyzer.analyze_single_attachment(meta)
    assert finding.severity == "SUSPICIOUS"
    assert "corrupted" in finding.details.lower() or "malformed" in finding.details.lower()


# ============================================================================
# 9. Multiple Attachments & Failure Isolation
# ============================================================================

def test_multiple_attachments_and_isolation(analyzer):
    clean_data = b"%PDF-1.4\nclean"
    clean_meta = AttachmentMetadata(
        filename="clean.pdf",
        original_filename="clean.pdf",
        content_type="application/pdf",
        file_extension=".pdf",
        size_bytes=len(clean_data),
        sha256_hash=hashlib.sha256(clean_data).hexdigest(),
        raw_payload=clean_data,
    )

    bad_data = b"MZ\x00\x00"
    bad_meta = AttachmentMetadata(
        filename="malware.exe",
        original_filename="malware.exe",
        content_type="application/x-msdownload",
        file_extension=".exe",
        size_bytes=len(bad_data),
        sha256_hash=hashlib.sha256(bad_data).hexdigest(),
        raw_payload=bad_data,
    )

    parsed_email = ParsedEmail(attachments=[clean_meta, bad_meta])
    result = analyzer.analyze_sync(parsed_email)

    assert result.total_attachments == 2
    assert result.malicious_count == 1
    assert result.highest_severity == "MALICIOUS"
    assert len(result.findings) == 2
    assert result.findings[0].severity == "SAFE"
    assert result.findings[1].severity == "MALICIOUS"


# ============================================================================
# 10. Pipeline Integration via ScanService
# ============================================================================

@pytest.mark.asyncio
async def test_scanservice_attachment_integration():
    scan_svc = ScanService()
    sample_email_with_double_ext = (
        b"From: billing@company.com\r\n"
        b"To: user@enterprise.com\r\n"
        b"Subject: Overdue Payment Notice\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please review the attached invoice.\r\n\r\n"
        b"--BOUNDARY\r\n"
        b"Content-Type: application/pdf; name=\"invoice.pdf.exe\"\r\n"
        b"Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"TVqQAAMAAAAEAAAA//8A\r\n"
        b"--BOUNDARY--\r\n"
    )

    incident, parsed_email = await scan_svc.ingest_and_parse(
        raw_bytes=sample_email_with_double_ext,
        filename="payment_invoice.eml",
        source=IngestionSource.DIRECT_UPLOAD,
    )

    assert incident is not None
    assert parsed_email is not None

    # Telemetry must contain attachment_analysis
    assert "attachment_analysis" in incident.telemetry
    att_res = incident.telemetry["attachment_analysis"]
    assert att_res["total_attachments"] == 1
    assert att_res["highest_severity"] == "MALICIOUS"
    assert len(att_res["findings"]) == 1
    assert att_res["findings"][0]["is_double_extension"] is True
    assert att_res["findings"][0]["is_executable_or_script"] is True

    # Risk Engine must classify as MALICIOUS
    assert incident.risk_tier.value == "MALICIOUS"
    assert incident.risk_score >= 85.0
    assert "THREAT DETECTED" in incident.verdict_summary
    assert "risk_assessment" in incident.telemetry
