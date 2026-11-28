"""
Regression tests for safe MIME header reconstruction in DatasetEvaluator.

Verifies remediation of the RFC 5322 header reconstruction defect:
- Linefeed (\n) and CRLF (\r\n) normalization to safe whitespace
- CRLF injection prevention across all reconstructed headers
- Missing, null, non-string, and oversized header values
- Original raw-byte path preservation
- Record immutability and downstream parser compatibility
"""

import email
import pytest
from app.datasets.evaluator import (
    DatasetEvaluator,
    _sanitize_reconstructed_header,
    MAX_RECONSTRUCTED_HEADER_LENGTH,
)
from app.modules.contracts import RawEmailPayload, IngestionSource
from app.modules.parser.parser import EmailParser


@pytest.fixture
def evaluator():
    return DatasetEvaluator(offline_auth=True, fixture_mode=False)


@pytest.fixture
def parser():
    return EmailParser()


def test_subject_containing_newline(evaluator, parser):
    """Test 1: Subject containing unescaped \\n does not crash and normalizes to space."""
    rec = {
        "from": "legit@sender.com",
        "to": "user@example.com",
        "subject": "Urgent Security Alert\nAction Required Immediately",
        "body_plain": "Please click the link.",
    }
    payload_bytes = evaluator._prepare_email_payload(rec)
    assert isinstance(payload_bytes, bytes)

    # Downstream EmailParser must parse cleanly without ValueError
    parsed = parser.parse(RawEmailPayload(raw_bytes=payload_bytes, source=IngestionSource.RAW_PAYLOAD))
    assert "Urgent Security Alert Action Required Immediately" in parsed.subject
    assert "\n" not in parsed.subject
    assert "\r" not in parsed.subject


def test_subject_containing_crlf(evaluator, parser):
    """Test 2: Subject containing unescaped \\r\\n does not crash and normalizes to space."""
    rec = {
        "from": "alert@banking.com",
        "to": "victim@example.com",
        "subject": "Account Suspended\r\nVerify Your Identity Now",
        "body_plain": "Verification required.",
    }
    payload_bytes = evaluator._prepare_email_payload(rec)
    assert isinstance(payload_bytes, bytes)

    parsed = parser.parse(RawEmailPayload(raw_bytes=payload_bytes, source=IngestionSource.RAW_PAYLOAD))
    assert "Account Suspended Verify Your Identity Now" in parsed.subject
    assert "\r" not in parsed.subject
    assert "\n" not in parsed.subject


def test_from_containing_crlf_injection_attempt(evaluator, parser):
    """Test 3: From header containing CRLF injection does not introduce new headers."""
    rec = {
        "from": "attacker@evil.com\r\nBcc: secret_victim@target.com\r\nX-Injected: MaliciousHeader",
        "to": "victim@example.com",
        "subject": "Normal Subject",
        "body_plain": "Payload body.",
    }
    payload_bytes = evaluator._prepare_email_payload(rec)
    assert isinstance(payload_bytes, bytes)

    msg = email.message_from_bytes(payload_bytes)
    # The injected headers must NOT exist as independent RFC headers
    assert "Bcc" not in msg
    assert "X-Injected" not in msg
    assert "secret_victim@target.com" not in msg.get_all("Bcc", [])

    parsed = parser.parse(RawEmailPayload(raw_bytes=payload_bytes, source=IngestionSource.RAW_PAYLOAD))
    assert "Bcc" not in parsed.headers
    assert "X-Injected" not in parsed.headers


def test_to_containing_crlf_injection_attempt(evaluator, parser):
    """Test 4: To header containing CRLF injection does not introduce new headers."""
    rec = {
        "from": "sender@example.com",
        "to": "intended@example.com\r\nCc: spy@adversary.com\r\nSubject: Overridden Subject",
        "subject": "Original Subject",
        "body_plain": "Test body.",
    }
    payload_bytes = evaluator._prepare_email_payload(rec)
    assert isinstance(payload_bytes, bytes)

    msg = email.message_from_bytes(payload_bytes)
    assert "Cc" not in msg
    assert len(msg.get_all("Subject", [])) == 1
    assert "Original Subject" in msg["Subject"]

    parsed = parser.parse(RawEmailPayload(raw_bytes=payload_bytes, source=IngestionSource.RAW_PAYLOAD))
    assert "Cc" not in parsed.headers
    assert parsed.subject == "Original Subject"


def test_missing_and_null_header_fields(evaluator, parser):
    """Test 5: Reconstructing records with missing or null headers uses safe defaults."""
    rec = {
        "from": None,
        "to": None,
        "subject": None,
        "message_id": None,
        "date": None,
        "return_path": None,
        "body_plain": "Body only.",
    }
    payload_bytes = evaluator._prepare_email_payload(rec)
    assert isinstance(payload_bytes, bytes)

    parsed = parser.parse(RawEmailPayload(raw_bytes=payload_bytes, source=IngestionSource.RAW_PAYLOAD))
    assert parsed.from_sender is not None
    assert "unknown" in parsed.from_sender.address
    assert parsed.subject == ""
    assert "Body only." in parsed.body_plain


def test_non_string_header_values(evaluator, parser):
    """Test 6: Non-string header fields (int, bool, float, list) are safely coerced."""
    rec = {
        "from": 12345,
        "to": ["user1@test.com", "user2@test.com"],
        "subject": 999.888,
        "message_id": True,
        "date": 20261128,
        "body_plain": 42,
    }
    payload_bytes = evaluator._prepare_email_payload(rec)
    assert isinstance(payload_bytes, bytes)

    parsed = parser.parse(RawEmailPayload(raw_bytes=payload_bytes, source=IngestionSource.RAW_PAYLOAD))
    assert "999.888" in parsed.subject
    assert "42" in parsed.body_plain


def test_very_long_header_values(evaluator, parser):
    """Test 7: Oversized headers are bounded and do not cause parser exhaustion."""
    long_subject = "A" * 50000
    long_from = "attacker@" + ("x" * 20000) + ".com"
    rec = {
        "from": long_from,
        "to": "recipient@example.com",
        "subject": long_subject,
        "body_plain": "Short body.",
    }
    payload_bytes = evaluator._prepare_email_payload(rec)
    assert isinstance(payload_bytes, bytes)

    parsed = parser.parse(RawEmailPayload(raw_bytes=payload_bytes, source=IngestionSource.RAW_PAYLOAD))
    assert len(parsed.subject) <= MAX_RECONSTRUCTED_HEADER_LENGTH
    assert len(parsed.subject) > 0


def test_normal_legitimate_email(evaluator, parser):
    """Test 8: Normal legitimate email reconstructs cleanly with exact values."""
    rec = {
        "from": "alice@corp.com",
        "to": "bob@corp.com",
        "subject": "Quarterly Planning Sync",
        "message_id": "<planning.2026@corp.com>",
        "date": "Sat, 28 Nov 2026 12:00:00 +0000",
        "return_path": "<alice@corp.com>",
        "body_plain": "Let us meet at 2pm.",
        "body_html": "<p>Let us meet at 2pm.</p>",
    }
    payload_bytes = evaluator._prepare_email_payload(rec)
    assert isinstance(payload_bytes, bytes)

    parsed = parser.parse(RawEmailPayload(raw_bytes=payload_bytes, source=IngestionSource.RAW_PAYLOAD))
    assert parsed.subject == "Quarterly Planning Sync"
    assert parsed.from_sender is not None
    assert parsed.from_sender.address == "alice@corp.com"
    assert "bob@corp.com" in [r.address for r in parsed.to_recipients]
    assert "Let us meet at 2pm." in parsed.body_plain
    assert "<p>Let us meet at 2pm.</p>" in parsed.body_html


def test_record_with_original_raw_email_bytes_preserved(evaluator):
    """Test 9: Raw bytes path remains untouched and returns exact byte sequence."""
    original_raw = (
        b"From: original@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Subject: Raw Unmodified Email\r\n"
        b"X-Custom-Header: True\r\n\r\n"
        b"Exact raw content."
    )
    rec = {
        "raw_bytes": original_raw,
        "from": "different@reconstructed.com",
        "subject": "Different Subject",
    }
    payload_bytes = evaluator._prepare_email_payload(rec)
    assert payload_bytes == original_raw


def test_original_dataset_record_is_not_mutated(evaluator):
    """Verify record immutability: the original record dictionary is unchanged."""
    rec = {
        "from": "sender@test.com\r\nBadHeader: 1",
        "to": "user@test.com",
        "subject": "Line 1\nLine 2\r\nLine 3",
        "body_plain": "Hello",
    }
    rec_copy = dict(rec)
    evaluator._prepare_email_payload(rec)
    assert rec == rec_copy
    assert rec["subject"] == "Line 1\nLine 2\r\nLine 3"
    assert rec["from"] == "sender@test.com\r\nBadHeader: 1"


def test_nazario_adversarial_records_reconstruct_without_error(evaluator, parser):
    """Verifies that actual adversarial samples like those in Nazario reconstruct safely."""
    adversarial_samples = [
        {"subject": "W2 Form\nUrgent", "from": "hr@fake.com\n", "to": "victim@work.com"},
        {"subject": "PayPal Alert\r\nAction Needed", "from": "service@paypa1.com\r\n", "to": "user@mail.com"},
        {"subject": "Overfolded Header\r\n\tContinuation\n\tMore", "from": "spoofed@domain.com", "to": "target@domain.com"},
    ]
    for sample in adversarial_samples:
        payload_bytes = evaluator._prepare_email_payload(sample)
        assert isinstance(payload_bytes, bytes)
        parsed = parser.parse(RawEmailPayload(raw_bytes=payload_bytes, source=IngestionSource.RAW_PAYLOAD))
        assert parsed.subject is not None
        assert "\r" not in parsed.subject
        assert "\n" not in parsed.subject
