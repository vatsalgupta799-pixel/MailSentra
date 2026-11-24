"""Automated Verification Suite for the 20 Realistic Email Scenarios.

Executes and verifies exact normalized output for every sample in the test corpus:
tests/fixtures/real_world_emails/
"""

import hashlib
import os
import pytest
from app.modules.contracts import IngestionSource, RawEmailPayload
from app.modules.ingestion.service import EmailIngestionService
from app.modules.parser.parser import EmailParser

CORPUS_ROOT = os.path.join(os.path.dirname(__file__), "fixtures", "real_world_emails")


def read_fixture(subfolder: str, filename: str) -> bytes:
    filepath = os.path.join(CORPUS_ROOT, subfolder, filename)
    with open(filepath, "rb") as f:
        return f.read()


@pytest.fixture
def parser():
    return EmailParser()


@pytest.fixture
def ingestion():
    return EmailIngestionService()


# ============================================================================
# Scenario 01: Normal University Announcement
# ============================================================================
def test_scenario_01_university_announcement(ingestion, parser):
    raw_bytes = read_fixture("normal", "01_university_announcement.eml")
    payload = ingestion.ingest(raw_bytes, "01_university_announcement.eml")
    parsed = parser.parse(payload)

    assert parsed.subject == "Autumn Quarter 2026 Final Examination Schedule"
    assert parsed.from_sender is not None
    assert parsed.from_sender.display_name == "University Registrar"
    assert parsed.from_sender.address == "registrar@stanford.edu"
    assert parsed.from_sender.domain == "stanford.edu"
    assert parsed.reply_to is not None
    assert parsed.reply_to.address == "registrar@stanford.edu"
    assert parsed.body_plain is not None
    assert parsed.body_html is not None
    assert len(parsed.urls) >= 1
    assert any("registrar.stanford.edu/exams/autumn-2026" in u.normalized_url for u in parsed.urls)
    assert len(parsed.parsing_warnings) == 0


# ============================================================================
# Scenario 02: Genuine Password Reset Notification
# ============================================================================
def test_scenario_02_genuine_password_reset(ingestion, parser):
    raw_bytes = read_fixture("normal", "02_genuine_password_reset.eml")
    payload = ingestion.ingest(raw_bytes, "02_genuine_password_reset.eml")
    parsed = parser.parse(payload)

    assert parsed.subject == "[GitHub] Please reset your password"
    assert parsed.from_sender is not None
    assert parsed.from_sender.address == "noreply@github.com"
    assert len(parsed.authentication_results) >= 1
    assert "dkim=pass" in parsed.authentication_results[0].lower()
    assert len(parsed.dkim_signatures) >= 1
    assert "v=1;" in parsed.dkim_signatures[0]
    assert any("github.com/password_reset" in u.normalized_url for u in parsed.urls)


# ============================================================================
# Scenario 03: Fake University Administrator Email
# ============================================================================
def test_scenario_03_fake_admin_email(ingestion, parser):
    raw_bytes = read_fixture("suspicious", "03_fake_admin.eml")
    payload = ingestion.ingest(raw_bytes, "03_fake_admin.eml")
    parsed = parser.parse(payload)

    # Ingestion/parsing should accurately extract the display name and actual domain
    assert parsed.from_sender is not None
    assert parsed.from_sender.display_name == "Office of the Dean"
    assert parsed.from_sender.domain == "university-secure-login.xyz"
    assert any("university-secure-login.xyz/portal/verify" in u.normalized_url for u in parsed.urls)


# ============================================================================
# Scenario 04: Display Name Spoofing
# ============================================================================
def test_scenario_04_display_name_spoofing(ingestion, parser):
    raw_bytes = read_fixture("suspicious", "04_display_name_spoofing.eml")
    payload = ingestion.ingest(raw_bytes, "04_display_name_spoofing.eml")
    parsed = parser.parse(payload)

    assert parsed.from_sender is not None
    assert "Marc Tessier-Lavigne" in parsed.from_sender.display_name
    # Address domain does not match university
    assert parsed.from_sender.address == "executive-office-temp@fast-free-mail.org"
    assert parsed.from_sender.domain == "fast-free-mail.org"
    assert "wire transfer" in parsed.body_plain.lower()


# ============================================================================
# Scenario 05: Mismatched From and Reply-To Addresses
# ============================================================================
def test_scenario_05_mismatched_from_and_replyto(ingestion, parser):
    raw_bytes = read_fixture("suspicious", "05_mismatched_from_replyto.eml")
    payload = ingestion.ingest(raw_bytes, "05_mismatched_from_replyto.eml")
    parsed = parser.parse(payload)

    assert parsed.from_sender is not None
    assert parsed.from_sender.address == "no-reply@chase.com"
    assert parsed.from_sender.domain == "chase.com"

    assert parsed.reply_to is not None
    assert parsed.reply_to.address == "chase-fraud-prevention@secure-resolve-tickets.net"
    assert parsed.reply_to.domain == "secure-resolve-tickets.net"
    assert parsed.from_sender.domain != parsed.reply_to.domain


# ============================================================================
# Scenario 06: Multiple Received Headers (4 Hops)
# ============================================================================
def test_scenario_06_multiple_received_hops(ingestion, parser):
    raw_bytes = read_fixture("edge_cases", "06_multiple_received_hops.eml")
    payload = ingestion.ingest(raw_bytes, "06_multiple_received_hops.eml")
    parsed = parser.parse(payload)

    assert len(parsed.received_hops) == 4
    # Check that hops are ordered and IPs extracted
    ips_found = [h.ip for h in parsed.received_hops if h.ip]
    assert len(ips_found) >= 3
    assert "10.0.1.50" in ips_found
    assert "192.0.2.10" in ips_found
    assert "198.51.100.99" in ips_found


# ============================================================================
# Scenario 07: Missing Message-ID (Never Fabricated)
# ============================================================================
def test_scenario_07_missing_message_id(ingestion, parser):
    raw_bytes = read_fixture("edge_cases", "07_missing_message_id.eml")
    payload = ingestion.ingest(raw_bytes, "07_missing_message_id.eml")
    parsed = parser.parse(payload)

    assert parsed.message_id is None
    assert parsed.subject == "Ambient Temperature Reading Normal"


# ============================================================================
# Scenario 08: Missing Date Header (Never Fabricated)
# ============================================================================
def test_scenario_08_missing_date_header(ingestion, parser):
    raw_bytes = read_fixture("edge_cases", "08_missing_date_header.eml")
    payload = ingestion.ingest(raw_bytes, "08_missing_date_header.eml")
    parsed = parser.parse(payload)

    assert parsed.date_raw is None
    assert parsed.date_utc is None
    assert parsed.subject == "Disk Cleanup Executed"


# ============================================================================
# Scenario 09: Invalid Sender Address
# ============================================================================
def test_scenario_09_invalid_sender_address(ingestion, parser):
    raw_bytes = read_fixture("edge_cases", "09_invalid_sender_address.eml")
    payload = ingestion.ingest(raw_bytes, "09_invalid_sender_address.eml")
    parsed = parser.parse(payload)

    # Should not crash, and captures the raw value
    assert parsed.from_sender is not None
    assert parsed.from_sender.raw != ""


# ============================================================================
# Scenario 10: HTML-Only Email
# ============================================================================
def test_scenario_10_html_only_email(ingestion, parser):
    raw_bytes = read_fixture("multipart", "10_html_only.eml")
    payload = ingestion.ingest(raw_bytes, "10_html_only.eml")
    parsed = parser.parse(payload)

    assert parsed.body_html is not None
    assert parsed.body_plain is None
    assert parsed.body_extracted_text is not None
    assert "Top 10 Interface Trends" in parsed.body_extracted_text
    assert any("design-weekly.com/issue-89" in u.normalized_url for u in parsed.urls)


# ============================================================================
# Scenario 11: Plain-Text Email
# ============================================================================
def test_scenario_11_plain_text_email(ingestion, parser):
    raw_bytes = read_fixture("normal", "11_plain_text.eml")
    payload = ingestion.ingest(raw_bytes, "11_plain_text.eml")
    parsed = parser.parse(payload)

    assert parsed.body_plain is not None
    assert parsed.body_html is None
    assert "BACKUP TASK: FULL DATABASE EXPORT" in parsed.body_plain
    assert len(parsed.urls) == 0


# ============================================================================
# Scenario 12: Multipart Mixed & Alternative Email
# ============================================================================
def test_scenario_12_multipart_mixed_alt(ingestion, parser):
    raw_bytes = read_fixture("multipart", "12_multipart_mixed_alt.eml")
    payload = ingestion.ingest(raw_bytes, "12_multipart_mixed_alt.eml")
    parsed = parser.parse(payload)

    assert parsed.body_plain is not None
    assert parsed.body_html is not None
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "run_metrics.csv"
    assert att.file_extension == ".csv"
    assert att.size_bytes > 0


# ============================================================================
# Scenario 13: Several URLs (IPs, Ports, Shorteners, Mismatched Anchors)
# ============================================================================
def test_scenario_13_several_urls_extraction(ingestion, parser):
    raw_bytes = read_fixture("edge_cases", "13_several_urls.eml")
    payload = ingestion.ingest(raw_bytes, "13_several_urls.eml")
    parsed = parser.parse(payload)

    assert len(parsed.urls) >= 7
    normalized_list = [u.normalized_url for u in parsed.urls]
    # Check IP host with port
    assert any("192.168.1.100:8443/management" in u for u in normalized_list)
    # Check shortener
    assert any("bit.ly/3xyfaketoken" in u.lower() for u in normalized_list)
    # Check query params
    assert any("token=abc" in u for u in normalized_list)
    # Check mismatched anchor text
    mismatched = [u for u in parsed.urls if u.visible_text and "trusted-bank.com" in u.visible_text]
    assert len(mismatched) >= 1
    assert "actual-malicious-site.com" in mismatched[0].normalized_url


# ============================================================================
# Scenario 14: Unicode and International Characters
# ============================================================================
def test_scenario_14_unicode_international(ingestion, parser):
    raw_bytes = read_fixture("edge_cases", "14_unicode_international.eml")
    payload = ingestion.ingest(raw_bytes, "14_unicode_international.eml")
    parsed = parser.parse(payload)

    assert parsed.from_sender is not None
    # Arabic display name decoded
    assert "المركز" in parsed.from_sender.display_name
    # Subject contains emojis and Chinese
    assert "🚀" in parsed.subject
    assert "报告" in parsed.subject
    # Body contains Cyrillic and Arabic
    assert "مرحبا" in parsed.body_plain
    assert "Проверка" in parsed.body_plain


# ============================================================================
# Scenario 15: Multiple Attachments with SHA-256 Verification
# ============================================================================
def test_scenario_15_multiple_attachments(ingestion, parser):
    raw_bytes = read_fixture("attachments", "15_multiple_attachments.eml")
    payload = ingestion.ingest(raw_bytes, "15_multiple_attachments.eml")
    parsed = parser.parse(payload)

    assert len(parsed.attachments) == 3
    filenames = [a.filename for a in parsed.attachments]
    assert "Formal_Summary.pdf" in filenames
    assert "integrity_notes.txt" in filenames
    assert "harmless_archive.zip" in filenames

    # Verify SHA-256 length and formatting
    for att in parsed.attachments:
        assert len(att.sha256_hash) == 64
        assert att.size_bytes > 0


# ============================================================================
# Scenario 16: Suspicious Attachment Filenames & Double Extensions
# ============================================================================
def test_scenario_16_suspicious_attachment_filename(ingestion, parser):
    raw_bytes = read_fixture("suspicious", "16_suspicious_attachment_filename.eml")
    payload = ingestion.ingest(raw_bytes, "16_suspicious_attachment_filename.eml")
    parsed = parser.parse(payload)

    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    assert att.filename == "Q4_Salary_Adjustments.xlsx.exe"
    assert att.file_extension == ".exe"
    assert att.is_double_extension is True
    assert any("double extension" in w.lower() for w in parsed.parsing_warnings)


# ============================================================================
# Scenario 17: Unusually Long and Folded Headers
# ============================================================================
def test_scenario_17_unusually_long_folded_headers(ingestion, parser):
    raw_bytes = read_fixture("edge_cases", "17_unusually_long_headers.eml")
    payload = ingestion.ingest(raw_bytes, "17_unusually_long_headers.eml")
    parsed = parser.parse(payload)

    assert parsed.subject is not None
    assert "Unusually Long Header Test Case" in parsed.subject
    assert "Without Breaking The Normalization Pipeline" in parsed.subject
    # Unfolded: should not contain raw tabs or carriage breaks inside subject string
    assert "\t" not in parsed.subject


# ============================================================================
# Scenario 18: Malformed MIME Boundaries
# ============================================================================
def test_scenario_18_malformed_mime_boundaries(ingestion, parser):
    raw_bytes = read_fixture("malformed", "18_malformed_mime_boundaries.eml")
    payload = ingestion.ingest(raw_bytes, "18_malformed_mime_boundaries.eml")
    parsed = parser.parse(payload)

    # Must survive without raising an unhandled exception
    assert parsed.subject == "Malformed Boundary Test Case"
    assert parsed.body_plain is not None


# ============================================================================
# Scenario 19: Encoded Subjects (ISO-8859-1 Quoted-Printable)
# ============================================================================
def test_scenario_19_encoded_subjects(ingestion, parser):
    raw_bytes = read_fixture("edge_cases", "19_encoded_subjects.eml")
    payload = ingestion.ingest(raw_bytes, "19_encoded_subjects.eml")
    parsed = parser.parse(payload)

    assert parsed.subject == "Conférence sur la sécurité numérique 2026"


# ============================================================================
# Scenario 20: Misleading MIME Metadata
# ============================================================================
def test_scenario_20_misleading_mime_metadata(ingestion, parser):
    raw_bytes = read_fixture("multipart", "20_misleading_mime_metadata.eml")
    payload = ingestion.ingest(raw_bytes, "20_misleading_mime_metadata.eml")
    parsed = parser.parse(payload)

    assert parsed.subject == "Server Diagnostic Report"
    # Even though declared as text/plain, raw content preserved safely
    assert parsed.body_plain is not None
    assert "<h1>Notice</h1>" in parsed.body_plain
    # URLs inside raw HTML in text/plain are extracted safely
    assert any("hidden-portal.com/login" in u.normalized_url for u in parsed.urls)
