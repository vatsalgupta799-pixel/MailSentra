"""Second-Stage Independent Security Challenge and Verification Suite.

Challenging:
1. MIME bomb / high part count bounding
2. Excessive URL extraction bounding
3. Excessive attachment count bounding
4. Settings-driven upload size limit enforcement
5. Rigorous zero-outbound-network & zero-DNS assertion during parsing
6. Attachment path traversal neutralization
7. SHA-256 byte-level hash accuracy on decoded payloads
8. Authentication and Authorization state truthfulness
"""

import hashlib
import http.client
import io
import socket
import urllib.request
import pytest
from httpx import ASGITransport, AsyncClient
from app.core.config import settings
from app.modules.contracts import IngestionSource, RawEmailPayload
from app.modules.ingestion.service import EmailIngestionService
from app.modules.parser.parser import EmailParser
from main import app


@pytest.fixture
def parser():
    return EmailParser()


@pytest.fixture
def ingestion():
    return EmailIngestionService()


# ============================================================================
# 1. Resource Exhaustion & DoS Boundaries
# ============================================================================

def test_mime_bomb_excessive_parts_capped(parser):
    """Challenge: Verify that an email with >250 MIME parts does not cause unbounded traversal."""
    boundary = "BOUND_MIME_BOMB"
    parts = [
        f"From: attacker@evil.com",
        f"Subject: MIME Part Exhaustion Challenge",
        f"MIME-Version: 1.0",
        f'Content-Type: multipart/mixed; boundary="{boundary}"',
        "",
        f"--{boundary}",
        "Content-Type: text/plain",
        "",
        "Initial text part",
    ]
    # Add 280 distinct sub-parts
    for i in range(280):
        parts.extend([
            f"--{boundary}",
            f"Content-Type: text/plain",
            "",
            f"MIME Part Number {i}",
        ])
    parts.append(f"--{boundary}--")
    raw_email = "\n".join(parts).encode("utf-8")

    parsed = parser.parse(RawEmailPayload(raw_bytes=raw_email))
    assert parsed is not None
    # Verify warning generated
    warning_present = any("MIME part count limit" in w for w in parsed.parsing_warnings)
    assert warning_present, f"Expected MIME part limit warning, got warnings: {parsed.parsing_warnings}"


def test_excessive_url_extraction_capped(parser):
    """Challenge: Verify that an email with 600 URLs does not create unbounded memory allocations."""
    html_links = "".join([f'<a href="https://attack-{i}.domain.org/landing">Link {i}</a><br>' for i in range(600)])
    raw_email = f"""From: phishing@adversary.org
Subject: URL Flood Challenge
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>{html_links}</body></html>""".encode("utf-8")

    parsed = parser.parse(RawEmailPayload(raw_bytes=raw_email))
    assert len(parsed.urls) <= settings.MAX_EXTRACTED_URLS
    assert len(parsed.urls) == settings.MAX_EXTRACTED_URLS


def test_excessive_attachment_count_capped(parser):
    """Challenge: Verify that an email with >50 attachments is bounded at MAX_ATTACHMENTS."""
    boundary = "BOUND_ATT_FLOOD"
    parts = [
        "From: attacker@evil.com",
        "Subject: Attachment Flood",
        "MIME-Version: 1.0",
        f'Content-Type: multipart/mixed; boundary="{boundary}"',
        "",
        f"--{boundary}",
        "Content-Type: text/plain",
        "",
        "Container message",
    ]
    for i in range(70):
        parts.extend([
            f"--{boundary}",
            f"Content-Type: application/octet-stream",
            f'Content-Disposition: attachment; filename="sample_{i}.dat"',
            "",
            f"DATA_{i}",
        ])
    parts.append(f"--{boundary}--")
    raw_email = "\n".join(parts).encode("utf-8")

    parsed = parser.parse(RawEmailPayload(raw_bytes=raw_email))
    assert len(parsed.attachments) <= settings.MAX_ATTACHMENTS
    warning_present = any("Maximum attachment extraction limit" in w for w in parsed.parsing_warnings)
    assert warning_present, f"Expected attachment limit warning, got: {parsed.parsing_warnings}"


# ============================================================================
# 2. Upload Endpoint Size Limit Enforcement
# ============================================================================

@pytest.mark.asyncio
async def test_dynamic_max_email_size_enforced_in_upload_api(async_client):
    """Challenge: Stream upload slightly exceeding MAX_EMAIL_SIZE_BYTES returns HTTP 413."""
    oversized_len = settings.MAX_EMAIL_SIZE_BYTES + 1024
    header = b"From: attacker@evil.com\r\nSubject: Oversized Payload\r\n\r\n"
    oversized_bytes = header + (b"X" * (oversized_len - len(header)))

    files = {"file": ("oversized.eml", oversized_bytes, "message/rfc822")}
    response = await async_client.post("/api/v1/scans/upload", files=files)
    assert response.status_code == 413
    data = response.json()
    assert "exceeds maximum allowable size" in data["detail"].lower()


# ============================================================================
# 3. Network Isolation & SSRF Immunity
# ============================================================================

def test_zero_dns_and_socket_calls_during_ingestion_and_parsing(monkeypatch, parser, ingestion):
    """Challenge: Prove that neither ingestion nor parsing makes any outbound DNS/socket connections."""
    def block_getaddrinfo(*args, **kwargs):
        pytest.fail(f"SECURITY VIOLATION: DNS lookup attempted on {args}")

    def block_connect(*args, **kwargs):
        pytest.fail(f"SECURITY VIOLATION: Socket connect attempted on {args}")

    monkeypatch.setattr(socket, "getaddrinfo", block_getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", block_connect)

    malicious_eml = b"""From: attacker@adversary.com
To: victim@company.com
Subject: SSRF Attempt via External Resource
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html>
<body>
    <img src="http://169.254.169.254/latest/meta-data/" />
    <link rel="stylesheet" href="https://evil.corp/stylesheet.css" />
    <a href="http://internal.vault.corp/secret">Click Here</a>
    <p>Check out http://10.0.0.1/admin console</p>
</body>
</html>"""

    # Ingestion check
    raw_payload = ingestion.ingest(malicious_eml, filename="ssrf_test.eml")
    assert raw_payload is not None

    # Parsing check
    parsed = parser.parse(raw_payload)
    assert parsed is not None
    assert len(parsed.urls) >= 1
    # Check that URLs are defanged properly
    defanged_urls = [u.defanged_url for u in parsed.urls]
    assert any("hxxp" in u for u in defanged_urls)


# ============================================================================
# 4. Attachment Security & Hash Integrity
# ============================================================================

def test_path_traversal_attachment_names_strictly_sanitized(parser):
    """Challenge: Attachment filenames with directory traversal tokens must be neutralized."""
    from app.modules.parser.attachment_parser import sanitize_filename

    # Direct unit verification of sanitize_filename
    direct_cases = [
        ("..\\..\\..\\Windows\\System32\\cmd.exe", "cmd.exe"),
        ("/etc/passwd", "passwd"),
        ("..//..//secret.bin", "secret.bin"),
        ("C:\\Users\\Admin\\AppData\\script.vbs", "script.vbs"),
        ("...../////test.pdf", "test.pdf"),
    ]
    for raw_fn, expected_clean in direct_cases:
        sanitized, _ = sanitize_filename(raw_fn)
        assert sanitized == expected_clean

    # MIME parser integration verification
    traversal_filenames = [
        "../../../../Windows/System32/calc.exe",
        "..\\..\\..\\boot.ini",
        "/etc/shadow",
        "C:\\Windows\\cmd.exe",
        "....//....//payload.bin",
    ]

    for raw_fn in traversal_filenames:
        eml = f"""From: attacker@evil.com
Subject: Traversal Test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND_TRAV"

--BOUND_TRAV
Content-Type: text/plain

Payload

--BOUND_TRAV
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="{raw_fn}"

RAWDATA
--BOUND_TRAV--
""".encode("utf-8")

        parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
        assert len(parsed.attachments) == 1
        sanitized = parsed.attachments[0].filename
        assert "/" not in sanitized
        assert "\\" not in sanitized
        assert ".." not in sanitized
        assert ":" not in sanitized


def test_decoded_attachment_sha256_matches_raw_bytes(parser):
    """Challenge: Verify SHA-256 is strictly computed on decoded bytes, not on base64 stream."""
    import base64
    original_secret = b"This is the unencoded binary secret payload 1234567890."
    expected_sha256 = hashlib.sha256(original_secret).hexdigest()
    b64_encoded = base64.b64encode(original_secret).decode("ascii")

    eml = f"""From: trusted@sender.org
Subject: Hash Accuracy Test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND_HASH"

--BOUND_HASH
Content-Type: text/plain

Content

--BOUND_HASH
Content-Type: application/pdf
Content-Disposition: attachment; filename="document.pdf"
Content-Transfer-Encoding: base64

{b64_encoded}
--BOUND_HASH--
""".encode("utf-8")

    parsed = parser.parse(RawEmailPayload(raw_bytes=eml))
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.sha256_hash == expected_sha256
    assert att.size_bytes == len(original_secret)


# ============================================================================
# 5. Authentication & Authorization Reality Check
# ============================================================================

@pytest.mark.asyncio
async def test_auth_status_truthfulness(async_client):
    """Challenge: Verify actual endpoint auth behavior.

    - POST /scans/upload permits unauthenticated callers (ingestion collector mode)
    - POST /auth/login fails gracefully on invalid credentials
    """
    # Invalid credentials return 401 via OAuth2PasswordRequestForm (form-encoded data)
    login_res = await async_client.post(
        "/api/v1/auth/login",
        data={"username": "nonexistent@example.com", "password": "WrongPassword123!"},
    )
    assert login_res.status_code == 401
    assert "incorrect email or password" in login_res.json()["detail"].lower()

    # Ingestion upload does not mandate Bearer token
    sample_eml = b"From: collector@company.com\r\nSubject: Test Ingestion\r\n\r\nBody\r\n"
    files = {"file": ("collector.eml", sample_eml, "message/rfc822")}
    upload_res = await async_client.post("/api/v1/scans/upload", files=files)
    assert upload_res.status_code == 201
