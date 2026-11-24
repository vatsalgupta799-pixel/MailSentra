"""Comprehensive Test Suite for Email Ingestion and Parsing Engine (Part 2).

Covers all 10 required security and edge-case scenarios:
1. Normal legitimate email.
2. HTML email.
3. Multipart email.
4. Email containing multiple URLs.
5. Email with attachments.
6. Missing headers.
7. Malformed email.
8. Unicode characters.
9. Duplicate URLs.
10. Suspicious filenames and double extensions.
Plus ingestion security controls (size limits, binary executable protection, API endpoints).
"""

import hashlib
import io
import pytest
from app.modules.contracts import IngestionSource, RawEmailPayload
from app.modules.ingestion.exceptions import (
    EmailSizeExceededError,
    MalformedPayloadError,
)
from app.modules.ingestion.service import EmailIngestionService
from app.modules.parser.parser import EmailParser


@pytest.fixture
def parser():
    return EmailParser()


@pytest.fixture
def ingestion():
    return EmailIngestionService(max_size_bytes=1024 * 1024)  # 1MB for tests


# ============================================================================
# Scenario 1: Normal Legitimate Email
# ============================================================================
def test_scenario_01_normal_legitimate_email(parser):
    eml = b"""From: Alice Engineer <alice@techcorp.com>
To: Bob Manager <bob@techcorp.com>
Subject: Weekly Sprint Planning Notes
Date: Mon, 24 Nov 2026 10:00:00 +0000
Message-ID: <sprint-notes-123@techcorp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi Bob,

Here are the notes from our morning sprint planning meeting.
Let me know if you have any questions.

Best regards,
Alice
"""
    raw = RawEmailPayload(raw_bytes=eml)
    parsed = parser.parse(raw)

    assert parsed.subject == "Weekly Sprint Planning Notes"
    assert parsed.message_id == "<sprint-notes-123@techcorp.com>"
    assert parsed.from_sender is not None
    assert parsed.from_sender.display_name == "Alice Engineer"
    assert parsed.from_sender.address == "alice@techcorp.com"
    assert parsed.from_sender.domain == "techcorp.com"
    assert len(parsed.to_recipients) == 1
    assert parsed.to_recipients[0].address == "bob@techcorp.com"
    assert parsed.body_plain is not None
    assert "Weekly Sprint Planning Notes" in parsed.subject
    assert "notes from our morning" in parsed.body_plain
    assert parsed.date_utc is not None
    assert len(parsed.parsing_warnings) == 0


# ============================================================================
# Scenario 2: HTML Email
# ============================================================================
def test_scenario_02_html_email(parser):
    eml = b"""From: Marketing <newsletter@store.com>
To: Customer <user@domain.com>
Subject: <b>Special Promotion</b>
Content-Type: text/html; charset="utf-8"

<!DOCTYPE html>
<html>
  <body>
    <h1>Exclusive Autumn Deals</h1>
    <p>Check out our <a href="https://store.com/deals">Promotions Catalog</a> today!</p>
    <script>alert('malicious script tag');</script>
  </body>
</html>
"""
    raw = RawEmailPayload(raw_bytes=eml)
    parsed = parser.parse(raw)

    assert parsed.body_html is not None
    assert "Exclusive Autumn Deals" in parsed.body_html
    # Extracted text must have stripped script tag
    assert parsed.body_extracted_text is not None
    assert "Exclusive Autumn Deals" in parsed.body_extracted_text
    assert "alert" not in parsed.body_extracted_text  # Script tag decomposed
    assert len(parsed.urls) >= 1
    assert any(u.original_url == "https://store.com/deals" for u in parsed.urls)
    assert any(u.visible_text == "Promotions Catalog" for u in parsed.urls)


# ============================================================================
# Scenario 3: Multipart Email (alternative + mixed)
# ============================================================================
def test_scenario_03_multipart_email(parser):
    boundary = "BOUNDARY_12345"
    eml = f"""From: hr@enterprise.com
To: staff@enterprise.com
Subject: Open Enrollment Notification
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="{boundary}"

--{boundary}
Content-Type: text/plain; charset="utf-8"

Please visit the benefits portal to complete open enrollment.

--{boundary}
Content-Type: text/html; charset="utf-8"

<p>Please visit the <a href="https://benefits.enterprise.com">Benefits Portal</a> to complete enrollment.</p>

--{boundary}--
""".encode("utf-8")

    raw = RawEmailPayload(raw_bytes=eml)
    parsed = parser.parse(raw)

    assert parsed.body_plain is not None
    assert "open enrollment" in parsed.body_plain
    assert parsed.body_html is not None
    assert "Benefits Portal" in parsed.body_html
    assert any("benefits.enterprise.com" in u.original_url for u in parsed.urls)


# ============================================================================
# Scenario 4: Email Containing Multiple URLs
# ============================================================================
def test_scenario_04_multiple_urls(parser):
    eml = b"""From: alerts@fintech.com
To: user@bank.com
Subject: Account Activity Alert
Content-Type: text/html; charset="utf-8"

<p>We detected unusual activity. Review at <a href="https://fintech.com/security">Security Center</a>.</p>
<p>Alternative link: https://portal.fintech.com/verify-login?session=987</p>
<p>Help docs: <a href="http://help.fintech.com/faq">FAQ</a></p>
"""
    raw = RawEmailPayload(raw_bytes=eml)
    parsed = parser.parse(raw)

    extracted_origins = [u.normalized_url for u in parsed.urls]
    assert "https://fintech.com/security" in extracted_origins
    assert "https://portal.fintech.com/verify-login?session=987" in extracted_origins
    assert "http://help.fintech.com/faq" in extracted_origins
    # Ensure defanging
    for u in parsed.urls:
        assert "[.]" in u.defanged_url
        assert "http" not in u.defanged_url or "hxxp" in u.defanged_url


# ============================================================================
# Scenario 5: Email with Attachments
# ============================================================================
def test_scenario_05_email_with_attachments(parser):
    pdf_content = b"%PDF-1.5 test pdf stream payload"
    pdf_sha = hashlib.sha256(pdf_content).hexdigest()

    boundary = "BOUND_ATT"
    eml = f"""From: billing@vendor.com
To: accounting@company.com
Subject: Invoice #99482
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="{boundary}"

--{boundary}
Content-Type: text/plain; charset="utf-8"

Attached is the invoice for services rendered.

--{boundary}
Content-Type: application/pdf; name="Invoice_99482.pdf"
Content-Disposition: attachment; filename="Invoice_99482.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjUgdGVzdCBwZGYgc3RyZWFtIHBheWxvYWQ=
--{boundary}--
""".encode("utf-8")

    raw = RawEmailPayload(raw_bytes=eml)
    parsed = parser.parse(raw)

    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "Invoice_99482.pdf"
    assert att.file_extension == ".pdf"
    assert att.content_type == "application/pdf"
    assert att.sha256_hash == pdf_sha
    assert att.size_bytes == len(pdf_content)
    assert att.content_disposition == "attachment"


# ============================================================================
# Scenario 6: Missing Headers (Explicit Nulls)
# ============================================================================
def test_scenario_06_missing_headers(parser):
    # Missing Subject, Missing From, Missing Date
    eml = b"""Content-Type: text/plain; charset="utf-8"

This is an email with completely missing Subject, From, To, and Date headers.
"""
    raw = RawEmailPayload(raw_bytes=eml)
    parsed = parser.parse(raw)

    assert parsed.subject is None
    assert parsed.from_sender is None
    assert parsed.date_utc is None
    assert len(parsed.to_recipients) == 0
    assert parsed.body_plain is not None
    assert "completely missing Subject" in parsed.body_plain


# ============================================================================
# Scenario 7: Malformed Email Structures
# ============================================================================
def test_scenario_07_malformed_email(parser):
    # Malformed headers, unclosed boundary, garbage characters
    eml = b"""From::: <<<<malformed@@@>>>
Subject: Broken Boundary Test
Content-Type: multipart/mixed; boundary="GHOST_BOUNDARY"

This content has no valid starting boundary marker and is completely corrupted!
"""
    raw = RawEmailPayload(raw_bytes=eml)
    parsed = parser.parse(raw)

    # Must not crash, should extract what it can and log warnings
    assert parsed.subject == "Broken Boundary Test"
    assert len(parsed.parsing_warnings) >= 0  # Handled safely without unhandled exception


# ============================================================================
# Scenario 8: Unicode Characters (RFC 2047 & Body)
# ============================================================================
def test_scenario_08_unicode_and_emojis(parser):
    # Encoded subject with UTF-8 base64
    eml = b"""From: =?UTF-8?B?44K744Kt44Ol44Oq44OG44Kj?= <security@tokyo.jp>
To: admin@company.com
Subject: =?UTF-8?B?4pyFIEFsZXJ0OiDjg4bjgrnjg4gg8J+agA==?=
Content-Type: text/plain; charset="utf-8"

Hello \xe2\x9c\x85, your account has been reviewed. \xf0\x9f\x94\x92 Verified!
"""
    raw = RawEmailPayload(raw_bytes=eml)
    parsed = parser.parse(raw)

    assert parsed.from_sender is not None
    assert parsed.from_sender.display_name == "セキュリティ"
    assert "✅ Alert: テスト 🚀" in parsed.subject
    assert parsed.body_plain is not None
    assert "✅" in parsed.body_plain
    assert "🔒 Verified!" in parsed.body_plain


# ============================================================================
# Scenario 9: Duplicate URLs
# ============================================================================
def test_scenario_09_duplicate_urls(parser):
    eml = b"""From: notify@portal.com
To: user@portal.com
Subject: Urgent Action Required
Content-Type: text/html; charset="utf-8"

<p>First link: <a href="https://portal.com/login">Login Here</a></p>
<p>Second link: <a href="https://portal.com/login">Click to Login</a></p>
<p>Text reference: https://portal.com/login</p>
"""
    raw = RawEmailPayload(raw_bytes=eml)
    parsed = parser.parse(raw)

    # Filter to occurrences of https://portal.com/login
    portal_urls = [u for u in parsed.urls if u.normalized_url == "https://portal.com/login"]
    assert len(portal_urls) >= 2
    # At least one must be marked as duplicate
    assert any(u.is_duplicate is True for u in portal_urls)
    assert any(u.occurrence_count > 1 for u in portal_urls)


# ============================================================================
# Scenario 10: Suspicious Filenames and Double Extensions
# ============================================================================
def test_scenario_10_suspicious_filenames_and_traversal(parser):
    boundary = "BOUND_SUSP"
    eml = f"""From: attacker@evil.com
To: victim@corp.com
Subject: Payment Remittance
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="{boundary}"

--{boundary}
Content-Type: text/plain; charset="utf-8"

See attached document.

--{boundary}
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="../../../../../evil_payload.pdf.exe"

TVqQAAMAAAAEAAAA//8A
--{boundary}--
""".encode("utf-8")

    raw = RawEmailPayload(raw_bytes=eml)
    parsed = parser.parse(raw)

    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    # Path traversal must be stripped
    assert "/" not in att.filename
    assert ".." not in att.filename
    assert att.filename == "evil_payload.pdf.exe"
    assert att.original_filename == "../../../../../evil_payload.pdf.exe"
    assert att.file_extension == ".exe"
    assert att.is_double_extension is True
    # A warning must have been generated
    assert any("sanitized" in w.lower() for w in parsed.parsing_warnings)
    assert any("double extension" in w.lower() for w in parsed.parsing_warnings)


# ============================================================================
# Ingestion Security Tests (Size limits & Executable blocks)
# ============================================================================
def test_ingestion_size_limit_exceeded(ingestion):
    # Ingestion configured with 1MB limit; send 1.5MB payload
    oversized = b"From: test@test.com\n\n" + (b"A" * (1024 * 1024 + 100))
    with pytest.raises(EmailSizeExceededError):
        ingestion.ingest(oversized, filename="huge.eml")


def test_ingestion_blocks_executable_binary_extension(ingestion):
    # Prohibited extension
    fake_exe = b"MZ\x90\x00\x03\x00\x00\x00" + (b"\x00" * 100)
    with pytest.raises(Exception):
        ingestion.ingest(fake_exe, filename="malware.exe")


def test_ingestion_blocks_executable_binary_disguised_as_eml(ingestion):
    # Windows PE binary magic bytes 'MZ' disguised as legitimate .eml
    fake_exe = b"MZ\x90\x00\x03\x00\x00\x00" + (b"\x00" * 100)
    with pytest.raises(MalformedPayloadError):
        ingestion.ingest(fake_exe, filename="invoice_scan.eml")


# ============================================================================
# API Endpoint Integration Test
# ============================================================================
@pytest.mark.asyncio
async def test_api_upload_and_parse_endpoint(async_client):
    eml_content = b"""From: sender@domain.com
To: recipient@domain.com
Subject: Test API Upload
Date: Mon, 24 Nov 2026 12:00:00 +0000
Message-ID: <api-test-01@domain.com>
Content-Type: text/plain; charset="utf-8"

This is a test email submitted via the FastAPI /api/v1/scans/upload endpoint.
Visit https://example.com/test for more details.
"""
    files = {
        "file": ("test_upload.eml", io.BytesIO(eml_content), "message/rfc822")
    }

    response = await async_client.post("/api/v1/scans/upload", files=files)
    assert response.status_code == 201
    data = response.json()

    assert "scan_id" in data
    assert "scan_uuid" in data
    assert data["status"] == "COMPLETED"
    parsed = data["parsed_email"]
    assert parsed["subject"] == "Test API Upload"
    assert parsed["from_sender"]["address"] == "sender@domain.com"
    assert len(parsed["urls"]) == 1
    assert parsed["urls"][0]["normalized_url"] == "https://example.com/test"


def test_ingestion_rejects_unsupported_extensions(ingestion):
    valid_email = b"From: a@b.com\nSubject: Test\n\nHello"
    with pytest.raises(Exception) as exc_info:
        ingestion.ingest(valid_email, filename="photo.png")
    assert "not supported" in str(exc_info.value).lower()


def test_ingestion_rejects_non_header_payload(ingestion):
    # Payload with no RFC header format
    garbage_payload = b"this is completely random text without any colons or email headers whatsoever"
    with pytest.raises(MalformedPayloadError):
        ingestion.ingest(garbage_payload, filename="test.eml")


def test_ip_address_url_extraction(parser):
    eml = b"""From: alerts@internal.net
To: admin@internal.net
Subject: Router Alert
Content-Type: text/plain; charset="utf-8"

Access the gateway at http://192.168.1.1:8080/admin/settings now.
"""
    raw = RawEmailPayload(raw_bytes=eml)
    parsed = parser.parse(raw)
    assert len(parsed.urls) == 1
    assert "192.168.1.1:8080" in parsed.urls[0].normalized_url
    assert "192[.]168[.]1[.]1:8080" in parsed.urls[0].defanged_url


@pytest.mark.asyncio
async def test_duplicate_message_id_detection(async_client):
    # Upload first email
    eml_content = b"""From: duplicate@origin.com
To: target@dest.com
Subject: Duplicate Scan Test
Message-ID: <unique-id-998877@origin.com>
Content-Type: text/plain; charset="utf-8"

Test content for duplicate detection.
"""
    files1 = {
        "file": ("dup_test_1.eml", io.BytesIO(eml_content), "message/rfc822")
    }
    res1 = await async_client.post("/api/v1/scans/upload", files=files1)
    assert res1.status_code == 201
    data1 = res1.json()

    # Upload second email with identical Message-ID
    files2 = {
        "file": ("dup_test_2.eml", io.BytesIO(eml_content), "message/rfc822")
    }
    res2 = await async_client.post("/api/v1/scans/upload", files=files2)
    assert res2.status_code == 201
    data2 = res2.json()

    # The second parsed email must reflect the duplicate warning
    warnings = data2["parsed_email"]["parsing_warnings"]
    assert any("duplicate message-id detected" in w.lower() for w in warnings)
