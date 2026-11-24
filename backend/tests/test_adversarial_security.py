"""Adversarial File Upload, Attachment Security, URL Safety, and API Robustness Tests.

Covers:
- Section B: Adversarial file uploads & malformed payloads
- Section D: Attachment forensics & path traversal prevention
- Section E: URL extraction safety & zero outbound network calls
- Section F: API boundary validation & HTTP error responses
"""

import hashlib
import io
import os
import socket
import urllib.request
import pytest
from app.modules.contracts import IngestionSource, RawEmailPayload
from app.modules.ingestion.exceptions import (
    EmailSizeExceededError,
    InvalidMimeTypeError,
    MalformedPayloadError,
)
from app.modules.ingestion.service import EmailIngestionService
from app.modules.parser.parser import EmailParser


@pytest.fixture
def parser():
    return EmailParser()


@pytest.fixture
def ingestion():
    return EmailIngestionService()


# ============================================================================
# Section B: Adversarial Upload & Evasion Tests
# ============================================================================
def test_adversarial_prohibited_extensions(ingestion):
    prohibited = ["malware.exe", "script.bat", "run.ps1", "lib.dll", "trojan.scr", "hack.vbs", "app.cmd"]
    payload = b"From: attacker@evil.com\nSubject: Test\n\nContent"

    for fn in prohibited:
        with pytest.raises(InvalidMimeTypeError) as exc:
            ingestion.ingest(payload, filename=fn)
        assert "not supported" in str(exc.value).lower() or "prohibited" in str(exc.value).lower()


def test_adversarial_empty_file_rejected(ingestion):
    with pytest.raises(MalformedPayloadError) as exc:
        ingestion.ingest(b"", filename="empty.eml")
    assert "empty" in str(exc.value).lower() or "zero" in str(exc.value).lower()


def test_adversarial_extremely_long_filename(parser):
    # 500-character filename
    long_name = "A" * 500 + ".pdf"
    eml = f"""From: sender@domain.com
Subject: Long Filename Attachment
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND_LONG"

--BOUND_LONG
Content-Type: text/plain

Body

--BOUND_LONG
Content-Type: application/pdf
Content-Disposition: attachment; filename="{long_name}"

JVBERi0xLjUK
--BOUND_LONG--
""".encode("utf-8")

    raw = RawEmailPayload(raw_bytes=eml)
    parsed = parser.parse(raw)

    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename.endswith(".pdf")
    assert len(parsed.attachments[0].filename) > 0


def test_adversarial_path_traversal_filenames(parser):
    traversal_filenames = [
        "../../../../Windows/System32/calc.exe",
        "..\\..\\..\\boot.ini",
        "/etc/shadow",
        "C:\\Windows\\cmd.exe",
        "....//....//payload.bin",
    ]

    for trav in traversal_filenames:
        eml = f"""From: attacker@evil.com
Subject: Traversal Test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND_TRAV"

--BOUND_TRAV
Content-Type: text/plain

Hello

--BOUND_TRAV
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="{trav}"

PAYLOAD_BYTES
--BOUND_TRAV--
""".encode("utf-8")

        raw = RawEmailPayload(raw_bytes=eml)
        parsed = parser.parse(raw)

        assert len(parsed.attachments) == 1
        att = parsed.attachments[0]
        # Must not contain directory traversal slashes or path references
        assert ".." not in att.filename
        assert "/" not in att.filename
        assert "\\" not in att.filename
        assert ":" not in att.filename


def test_adversarial_deeply_nested_multiparts(parser):
    # Construct 10 layers of nested multipart MIME containers
    nested_eml = b"From: nest@domain.com\nSubject: Deeply Nested\nMIME-Version: 1.0\n"
    depth = 8
    boundaries = [f"BOUND_LEVEL_{i}" for i in range(depth)]

    # Outermost header
    nested_eml += f'Content-Type: multipart/mixed; boundary="{boundaries[0]}"\n\n'.encode()

    for i in range(depth - 1):
        nested_eml += f"--{boundaries[i]}\n".encode()
        nested_eml += f'Content-Type: multipart/mixed; boundary="{boundaries[i+1]}"\n\n'.encode()

    # Innermost part
    nested_eml += f"--{boundaries[-1]}\n".encode()
    nested_eml += b"Content-Type: text/plain\n\nInnermost Secret Payload\n"
    nested_eml += f"--{boundaries[-1]}--\n".encode()

    for i in range(depth - 2, -1, -1):
        nested_eml += f"--{boundaries[i]}--\n".encode()

    raw = RawEmailPayload(raw_bytes=nested_eml)
    parsed = parser.parse(raw)

    assert parsed.body_plain is not None
    assert "Innermost Secret Payload" in parsed.body_plain


# ============================================================================
# Section D: Attachment Security & Cryptographic Verifications
# ============================================================================
def test_attachment_sha256_independent_verification(parser):
    dummy_payload = b"Sample verification data for attachment hash matching 1234567890"
    expected_sha256 = hashlib.sha256(dummy_payload).hexdigest()

    eml = f"""From: verification@sec.com
Subject: Hash Match Test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND_HASH"

--BOUND_HASH
Content-Type: text/plain

Verification

--BOUND_HASH
Content-Type: text/plain
Content-Disposition: attachment; filename="audit_data.txt"
Content-Transfer-Encoding: 7bit

{dummy_payload.decode('ascii')}
--BOUND_HASH--
""".encode("utf-8")

    raw = RawEmailPayload(raw_bytes=eml)
    parsed = parser.parse(raw)

    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.sha256_hash == expected_sha256
    assert att.size_bytes == len(dummy_payload)


# ============================================================================
# Section E: URL Extraction Safety (Zero Network Calls Guaranteed)
# ============================================================================
def test_url_extraction_triggers_zero_network_calls(monkeypatch, parser):
    # Monkeypatch network sockets to guarantee no outbound connections occur
    def fail_on_connect(*args, **kwargs):
        raise AssertionError("SECURITY VIOLATION: Network connection attempted during email parsing!")

    monkeypatch.setattr(socket, "getaddrinfo", fail_on_connect)
    monkeypatch.setattr(socket.socket, "connect", fail_on_connect)

    eml = b"""From: test@domain.com
Subject: External URL Test
Content-Type: text/html; charset="utf-8"

<p>Click <a href="https://externally-hosted-malware-server.com/payload">Here</a></p>
<p>Also check http://198.51.100.44:9999/listen</p>
"""
    raw = RawEmailPayload(raw_bytes=eml)
    # Parsing must succeed without invoking socket.connect or getaddrinfo
    parsed = parser.parse(raw)

    assert len(parsed.urls) == 2
    assert any("externally-hosted-malware-server.com" in u.normalized_url for u in parsed.urls)
    assert any("198.51.100.44:9999" in u.normalized_url for u in parsed.urls)


def test_url_anchor_text_distinction(parser):
    eml = b"""From: security@notice.com
Subject: Link Cloaking Test
Content-Type: text/html; charset="utf-8"

<p>Visit <a href="https://actual-malicious-server.net/login">https://my-legitimate-bank.com/portal</a> to authenticate.</p>
"""
    raw = RawEmailPayload(raw_bytes=eml)
    parsed = parser.parse(raw)

    href_urls = [u for u in parsed.urls if u.source_location == "html_href"]
    assert len(href_urls) == 1
    assert "actual-malicious-server.net" in href_urls[0].normalized_url
    assert href_urls[0].visible_text == "https://my-legitimate-bank.com/portal"


# ============================================================================
# Section F: API Security & Boundary Tests
# ============================================================================
@pytest.mark.asyncio
async def test_api_rejects_missing_file_payload(async_client):
    # POST with no file param
    response = await async_client.post("/api/v1/scans/upload", data={})
    assert response.status_code == 422  # Unprocessable Entity (FastAPI validation)


@pytest.mark.asyncio
async def test_api_rejects_empty_file_upload(async_client):
    files = {
        "file": ("empty.eml", io.BytesIO(b""), "message/rfc822")
    }
    response = await async_client.post("/api/v1/scans/upload", files=files)
    assert response.status_code == 422
    data = response.json()
    assert "empty" in data["detail"].lower() or "zero" in data["detail"].lower()


@pytest.mark.asyncio
async def test_api_rejects_executable_disguised_upload(async_client):
    fake_exe = b"MZ\x90\x00\x03\x00" + b"\x00" * 200
    files = {
        "file": ("invoice.eml", io.BytesIO(fake_exe), "message/rfc822")
    }
    response = await async_client.post("/api/v1/scans/upload", files=files)
    assert response.status_code == 422
    data = response.json()
    assert "executable" in data["detail"].lower()


@pytest.mark.asyncio
async def test_api_parse_raw_invalid_json(async_client):
    # Invalid JSON body structure (missing raw_email)
    response = await async_client.post(
        "/api/v1/scans/parse-raw",
        json={"wrong_field": "some data"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_api_get_nonexistent_scan_returns_404(async_client):
    response = await async_client.get("/api/v1/scans/9999999")
    assert response.status_code == 404
    data = response.json()
    assert "not found" in data["detail"].lower()
