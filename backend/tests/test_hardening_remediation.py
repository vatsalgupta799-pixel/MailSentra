"""Complete Security Remediation and Hardening Verification Test Suite.

Verifies:
1. Security HTTP response headers (nosniff, DENY, XSS protection, Referrer-Policy)
2. Shebang / script file upload rejection
3. UTF-8 BOM resilience during RFC 5322 parsing
4. Recipient address count bounding (MAX_RECIPIENT_ADDRESSES)
5. Received hops count bounding (MAX_RECEIVED_HOPS)
6. Single attachment payload size bounding (MAX_ATTACHMENT_SIZE_BYTES)
7. Suspicious executable MIME type detection in attachments
8. API pagination boundary enforcement (Query ge=0, le=100)
9. Database string length resilience (oversized subject and Message-ID)
10. Trailing quote, angle bracket, and punctuation stripping in URLs
"""

import base64
import pytest
from app.core.config import settings
from app.modules.contracts import IngestionSource, RawEmailPayload
from app.modules.ingestion.exceptions import (
    InvalidMimeTypeError,
    MalformedPayloadError,
)
from app.modules.ingestion.service import EmailIngestionService
from app.modules.parser.parser import EmailParser
from app.services.scan_service import scan_service


@pytest.fixture
def parser():
    return EmailParser()


@pytest.fixture
def ingestion():
    return EmailIngestionService()


# ============================================================================
# 1. Security HTTP Headers
# ============================================================================

@pytest.mark.asyncio
async def test_security_http_headers_present(async_client):
    """Verify that every HTTP response enforces defensive security headers."""
    response = await async_client.get("/api/v1/health")
    assert response.status_code == 200
    headers = response.headers

    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert "1; mode=block" in headers.get("x-xss-protection", "")
    assert headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert "geolocation=()" in headers.get("permissions-policy", "")


# ============================================================================
# 2. Ingestion Hardening: Shebang, BOM, and Script Disguises
# ============================================================================

def test_ingestion_rejects_disguised_shebang_scripts(ingestion):
    """Disguised shell and batch scripts with .eml extensions must be rejected."""
    bad_payloads = [
        (b"#!/bin/bash\nrm -rf /tmp/data\n", "malicious_script.eml"),
        (b"#!/bin/sh\necho 'pwnd'\n", "script.eml"),
        (b"@echo off\ndel C:\\Windows\\temp\n", "cleanup.eml"),
        (b"<script>alert(1)</script>", "markup.eml"),
    ]

    for payload, filename in bad_payloads:
        with pytest.raises(MalformedPayloadError) as exc_info:
            ingestion.ingest(payload, filename=filename)
        assert "script or markup" in str(exc_info.value).lower() or "not appear" in str(exc_info.value).lower()


def test_ingestion_accepts_utf8_bom_emails(ingestion, parser):
    """Emails prepended with a UTF-8 Byte Order Mark (\\xef\\xbb\\xbf) must be parsed cleanly."""
    bom_eml = b"\xef\xbb\xbfFrom: test@domain.org\r\nSubject: BOM Email\r\nTo: user@domain.org\r\n\r\nHello with BOM\r\n"
    raw_payload = ingestion.ingest(bom_eml, filename="bom_test.eml")
    assert raw_payload is not None

    parsed = parser.parse(raw_payload)
    assert parsed.subject == "BOM Email"
    assert parsed.from_sender is not None
    assert parsed.from_sender.address == "test@domain.org"


# ============================================================================
# 3. Parser Bounds: Recipient Addresses & Received Hops
# ============================================================================

def test_recipient_addresses_bounded(parser):
    """Challenge: Verify recipient addresses are bounded at MAX_RECIPIENT_ADDRESSES (100)."""
    many_recipients = ", ".join([f"user_{i}@corp.org" for i in range(150)])
    eml = f"From: hr@corp.org\r\nTo: {many_recipients}\r\nSubject: Address Flood\r\n\r\nNotice\r\n".encode("utf-8")

    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    assert len(parsed.to_recipients) == settings.MAX_RECIPIENT_ADDRESSES
    assert len(parsed.to_recipients) == 100


def test_received_hops_bounded(parser):
    """Challenge: Verify Received headers list is bounded at MAX_RECEIVED_HOPS (100)."""
    hops_headers = [f"Received: from relay{i}.isp.com by mail.corp.com; Tue, 24 Nov 2026 12:00:{i%60:02d} +0000" for i in range(130)]
    eml = "\r\n".join(hops_headers) + "\r\nFrom: sender@isp.com\r\nSubject: Hops Flood\r\n\r\nBody\r\n"
    raw = RawEmailPayload(raw_bytes=eml.encode("utf-8"))

    parsed = parser.parse(raw)
    assert len(parsed.received_hops) <= settings.MAX_RECEIVED_HOPS
    assert len(parsed.received_hops) == 100


# ============================================================================
# 4. Attachment Security: Max Payload Size & Suspicious Executable MIME
# ============================================================================

def test_attachment_max_payload_size_bounded(parser):
    """Attachments exceeding MAX_ATTACHMENT_SIZE_BYTES must have payload bounded and emit a warning."""
    # 11MB raw payload
    oversized_size = 11 * 1024 * 1024
    payload_data = b"B" * oversized_size
    b64_data = base64.b64encode(payload_data).decode("ascii")

    eml = f"""From: sender@corp.org
Subject: Huge Attachment
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND_HUGE"

--BOUND_HUGE
Content-Type: text/plain

Body

--BOUND_HUGE
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="large_asset.dat"
Content-Transfer-Encoding: base64

{b64_data}
--BOUND_HUGE--
""".encode("utf-8")

    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    # Bound payload length
    assert att.size_bytes <= settings.MAX_ATTACHMENT_SIZE_BYTES
    warning_present = any("exceeds max limit" in w for w in parsed.parsing_warnings)
    assert warning_present


def test_suspicious_executable_mime_type_warning(parser):
    """Attachments with application/x-msdownload or application/x-dosexec must trigger warning."""
    eml = b"""From: attacker@evil.org
Subject: Resume
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND_MIME_WARN"

--BOUND_MIME_WARN
Content-Type: text/plain

Resume attached.

--BOUND_MIME_WARN
Content-Type: application/x-msdownload
Content-Disposition: attachment; filename="document.pdf"

FAKEDATA
--BOUND_MIME_WARN--
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    assert len(parsed.attachments) == 1
    warning_present = any("executable MIME type" in w for w in parsed.parsing_warnings)
    assert warning_present


# ============================================================================
# 5. URL Trailing Punctuation & Scheme Sanitization
# ============================================================================

def test_url_trailing_punctuation_and_quotes_cleaned(parser):
    """URLs enclosed in quotes, angle brackets, or trailing punctuation must normalize cleanly."""
    eml = b"""From: alerts@corp.org
Subject: URL Sanitation
Content-Type: text/plain

Please check 'https://security.corp.org/verify'.
Also check "https://portal.corp.org/login".
And reference <https://wiki.corp.org/entry>.
Or visit https://service.corp.org/status,
"""
    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    extracted = [u.normalized_url for u in parsed.urls]

    assert "https://security.corp.org/verify" in extracted
    assert "https://portal.corp.org/login" in extracted
    assert "https://wiki.corp.org/entry" in extracted
    assert "https://service.corp.org/status" in extracted


# ============================================================================
# 6. API Validation & Pagination Constraints
# ============================================================================

@pytest.mark.asyncio
async def test_pagination_bounds_enforced_in_api(async_client):
    """Passing invalid limit or skip parameters must return HTTP 422 validation error."""
    # Negative skip
    res1 = await async_client.get("/api/v1/scans?skip=-5")
    assert res1.status_code == 422

    # Excessive limit (>100)
    res2 = await async_client.get("/api/v1/scans?limit=500")
    assert res2.status_code == 422

    # Zero limit (<1)
    res3 = await async_client.get("/api/v1/scans?limit=0")
    assert res3.status_code == 422

    # Valid pagination
    res4 = await async_client.get("/api/v1/scans?skip=0&limit=10")
    assert res4.status_code == 200


@pytest.mark.asyncio
async def test_raw_email_request_empty_rejected(async_client):
    """Empty raw_email string must fail with HTTP 422 at Pydantic schema validation."""
    response = await async_client.post("/api/v1/scans/parse-raw", json={"raw_email": ""})
    assert response.status_code == 422


# ============================================================================
# 7. Database String Length Resilience
# ============================================================================

@pytest.mark.asyncio
async def test_database_oversized_string_columns_no_error(db_session):
    """Email with 1,000-char Subject and 500-char Message-ID must persist without DB error."""
    huge_subject = "A" * 1000
    huge_msg_id = "<" + ("M" * 400) + "@domain.org>"
    huge_sender = "S" * 300 + "@longdomain.org"

    eml = f"""From: {huge_sender}
To: victim@target.org
Subject: {huge_subject}
Message-ID: {huge_msg_id}

Body content
""".encode("utf-8")

    incident, parsed = await scan_service.ingest_and_parse(
        raw_bytes=eml,
        filename="oversized_fields.eml",
        source=IngestionSource.DIRECT_UPLOAD,
        db=db_session,
    )

    assert incident.id is not None
    assert len(incident.subject) <= 500
    assert len(incident.message_id) <= 255
    assert len(incident.sender) <= 255
    # Full untruncated values preserved in telemetry JSON
    assert parsed.subject == huge_subject
    assert parsed.message_id == huge_msg_id
