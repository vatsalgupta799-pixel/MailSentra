"""End-to-End Comprehensive Pipeline Validation Suite.

Executes the unified email scanning pipeline across all 15 required threat and benign scenarios:
1. Legitimate university email
2. Legitimate password reset
3. Phishing email (credential harvesting)
4. Sender impersonation (VIP display name spoofing)
5. From/Reply-To address mismatch
6. SPF/DKIM/DMARC protocol analysis
7. Suspicious URL (private IP / shortener / redirect)
8. Homoglyph / Punycode URL
9. Double-extension attachment (.xlsx.exe / .pdf.scr)
10. MIME mismatch (declared PDF, actual executable)
11. Inert executable-format attachment (ELF / PE)
12. Malformed attachment (corrupted archive)
13. Multiple attachments (mixed clean and malicious)
14. Malformed email (boundary / syntax resilience)
15. Benign email containing normal attachments (.pdf, .txt, .csv)
"""

import hashlib
import io
import pytest
import zipfile
from app.models.scan import RiskTier
from app.modules.contracts import IngestionSource, ProtocolStatus
from app.services.scan_service import ScanService


@pytest.fixture
def scan_service():
    return ScanService()


# 1. Legitimate University Email
@pytest.mark.asyncio
async def test_scenario_01_legitimate_university_email(scan_service):
    raw = (
        b"From: University Registrar <registrar@stanford.edu>\r\n"
        b"To: student@stanford.edu\r\n"
        b"Subject: Autumn Final Exam Schedule\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please review your exam timetable at https://registrar.stanford.edu/exams\r\n"
    )
    incident, parsed = await scan_service.ingest_and_parse(raw, filename="exam_schedule.eml")
    assert incident.risk_tier == RiskTier.CLEAN
    assert incident.risk_score == 0.0
    assert "CLEAN" in incident.verdict_summary
    assert parsed.from_sender.domain == "stanford.edu"
    assert "url_analysis" in incident.telemetry
    assert "attachment_analysis" in incident.telemetry


# 2. Legitimate Password Reset
@pytest.mark.asyncio
async def test_scenario_02_legitimate_password_reset(scan_service):
    raw = (
        b"From: GitHub Support <noreply@github.com>\r\n"
        b"To: developer@enterprise.com\r\n"
        b"Subject: Reset your password\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Follow this link to reset password: https://github.com/password_reset\r\n"
    )
    incident, parsed = await scan_service.ingest_and_parse(raw, filename="pwd_reset.eml")
    assert incident.risk_tier == RiskTier.CLEAN
    assert incident.risk_score == 0.0


# 3. Phishing Email (Credential Harvesting on .xyz domain)
@pytest.mark.asyncio
async def test_scenario_03_phishing_email(scan_service):
    raw = (
        b"From: IT Helpdesk <helpdesk@service-security-portal.xyz>\r\n"
        b"To: victim@enterprise.com\r\n"
        b"Subject: Immediate Password Verification Required\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Verify now: http://service-security-portal.xyz/verify-login\r\n"
    )
    incident, parsed = await scan_service.ingest_and_parse(raw, filename="phish.eml")
    assert incident.risk_tier in (RiskTier.SUSPICIOUS, RiskTier.MALICIOUS)
    assert incident.risk_score >= 40.0
    assert "url_analysis" in incident.telemetry
    assert len(incident.telemetry["url_analysis"]["findings"]) >= 1


# 4. Sender Impersonation (VIP Display Name Spoofing)
@pytest.mark.asyncio
async def test_scenario_04_sender_impersonation(scan_service):
    from app.modules.identity.config import VIPIdentity
    scan_service.identity_analyzer.default_config.vip_identities = [
        VIPIdentity(name="Marc Tessier-Lavigne", allowed_domains=["stanford.edu"])
    ]
    raw = (
        b"From: \"Marc Tessier-Lavigne, President\" <executive-temp@free-mail.org>\r\n"
        b"To: finance@stanford.edu\r\n"
        b"Subject: Urgent Wire Transfer Request\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please execute confidential wire transfer immediately.\r\n"
    )
    incident, parsed = await scan_service.ingest_and_parse(raw, filename="bec_spoof.eml")
    assert incident.risk_tier == RiskTier.MALICIOUS
    assert incident.risk_score >= 80.0
    assert "IDENTITY-IMPERSONATION" in incident.verdict_summary


# 5. From / Reply-To Mismatch
@pytest.mark.asyncio
async def test_scenario_05_mismatched_from_replyto(scan_service):
    raw = (
        b"From: Customer Support <support@chase.com>\r\n"
        b"Reply-To: security-team@chase-fraud-prevention-tickets.net\r\n"
        b"To: customer@chase.com\r\n"
        b"Subject: Suspicious Activity Detected On Your Account\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please reply with your account verification details.\r\n"
    )
    incident, parsed = await scan_service.ingest_and_parse(raw, filename="mismatch.eml")
    assert incident.risk_tier in (RiskTier.SUSPICIOUS, RiskTier.MALICIOUS)
    assert incident.risk_score >= 50.0


# 6. SPF / DKIM / DMARC Protocol Analysis
@pytest.mark.asyncio
async def test_scenario_06_auth_protocols_analysis(scan_service):
    raw = (
        b"From: admin@example.com\r\n"
        b"To: user@example.com\r\n"
        b"Subject: System Notice\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Routine notification.\r\n"
    )
    incident, parsed = await scan_service.ingest_and_parse(raw, filename="auth_test.eml")
    assert "auth_protocols" in incident.telemetry
    auth = incident.telemetry["auth_protocols"]
    assert "spf_status" in auth
    assert "dkim_status" in auth
    assert "dmarc_status" in auth


# 7. Suspicious URL (Private IP & Open Redirect)
@pytest.mark.asyncio
async def test_scenario_07_suspicious_url(scan_service):
    raw = (
        b"From: alert@enterprise.com\r\n"
        b"To: user@enterprise.com\r\n"
        b"Subject: Infrastructure Alert\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Access internal console: http://192.168.1.100:8443/management?redirect=http://malicious.org\r\n"
    )
    incident, parsed = await scan_service.ingest_and_parse(raw, filename="ip_url.eml")
    assert incident.risk_tier == RiskTier.MALICIOUS
    assert incident.risk_score >= 85.0
    assert "URL-MALICIOUS" in incident.verdict_summary


# 8. Homoglyph / Punycode URL
@pytest.mark.asyncio
async def test_scenario_08_homoglyph_url(scan_service):
    raw = (
        b"From: Security <security@service.com>\r\n"
        b"To: user@enterprise.com\r\n"
        b"Subject: Security Update\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Login here: https://xn--pple-43d.com/login\r\n"
    )
    incident, parsed = await scan_service.ingest_and_parse(raw, filename="punycode.eml")
    assert incident.risk_tier in (RiskTier.SUSPICIOUS, RiskTier.MALICIOUS)
    assert len(incident.telemetry["url_analysis"]["findings"]) >= 1


# 9. Double-Extension Attachment
@pytest.mark.asyncio
async def test_scenario_09_double_extension_attachment(scan_service):
    raw = (
        b"From: vendor@supply.com\r\n"
        b"To: accounts@enterprise.com\r\n"
        b"Subject: Overdue Invoice\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BND\"\r\n\r\n"
        b"--BND\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Invoice attached.\r\n\r\n"
        b"--BND\r\n"
        b"Content-Type: application/pdf; name=\"Invoice_2026.pdf.exe\"\r\n"
        b"Content-Disposition: attachment; filename=\"Invoice_2026.pdf.exe\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"TVqQAAMAAAAEAAAA//8A\r\n"
        b"--BND--\r\n"
    )
    incident, parsed = await scan_service.ingest_and_parse(raw, filename="double_ext.eml")
    assert incident.risk_tier == RiskTier.MALICIOUS
    assert incident.risk_score >= 85.0
    assert "ATTACHMENT-MALICIOUS" in incident.verdict_summary


# 10. MIME Mismatch (Declared PDF, Actual Executable)
@pytest.mark.asyncio
async def test_scenario_10_mime_mismatch_attachment(scan_service):
    raw = (
        b"From: sender@domain.com\r\n"
        b"To: user@enterprise.com\r\n"
        b"Subject: Document\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BND\"\r\n\r\n"
        b"--BND\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Document.\r\n\r\n"
        b"--BND\r\n"
        b"Content-Type: application/pdf; name=\"document.pdf\"\r\n"
        b"Content-Disposition: attachment; filename=\"document.pdf\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"TVqQAAMAAAAEAAAA//8A\r\n"
        b"--BND--\r\n"
    )
    incident, parsed = await scan_service.ingest_and_parse(raw, filename="mime_mismatch.eml")
    assert incident.risk_tier == RiskTier.MALICIOUS
    att_finding = incident.telemetry["attachment_analysis"]["findings"][0]
    assert att_finding["magic_byte_mismatch"] is True


# 11. Inert Executable-Format Attachment (ELF binary)
@pytest.mark.asyncio
async def test_scenario_11_inert_executable_attachment(scan_service):
    # ELF binary header base64: f0VMRgEBAQAAAAAAAAAAAA==
    raw = (
        b"From: devops@enterprise.com\r\n"
        b"To: engineer@enterprise.com\r\n"
        b"Subject: Compiled binary\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BND\"\r\n\r\n"
        b"--BND\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Binary.\r\n\r\n"
        b"--BND\r\n"
        b"Content-Type: application/octet-stream; name=\"service_daemon\"\r\n"
        b"Content-Disposition: attachment; filename=\"service_daemon\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"f0VMRgEBAQAAAAAAAAAAAA==\r\n"
        b"--BND--\r\n"
    )
    incident, parsed = await scan_service.ingest_and_parse(raw, filename="elf_att.eml")
    assert incident.risk_tier == RiskTier.MALICIOUS
    att_finding = incident.telemetry["attachment_analysis"]["findings"][0]
    assert att_finding["is_executable_or_script"] is True
    assert "ELF" in att_finding["detected_format"]


# 12. Malformed Attachment (Corrupted ZIP header)
@pytest.mark.asyncio
async def test_scenario_12_malformed_attachment(scan_service):
    # PK\x03\x04 followed by broken bytes
    raw = (
        b"From: sender@domain.com\r\n"
        b"To: user@enterprise.com\r\n"
        b"Subject: Broken archive\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BND\"\r\n\r\n"
        b"--BND\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Broken.\r\n\r\n"
        b"--BND\r\n"
        b"Content-Type: application/zip; name=\"archive.zip\"\r\n"
        b"Content-Disposition: attachment; filename=\"archive.zip\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"UEsDBAoAAAAAAIC1\r\n"
        b"--BND--\r\n"
    )
    incident, parsed = await scan_service.ingest_and_parse(raw, filename="corrupt_zip.eml")
    assert incident is not None
    # Must not raise unhandled exception, records findings safely
    assert len(incident.telemetry["attachment_analysis"]["findings"]) == 1


# 13. Multiple Attachments (Clean PDF + Malicious Binary)
@pytest.mark.asyncio
async def test_scenario_13_multiple_attachments(scan_service):
    raw = (
        b"From: hr@enterprise.com\r\n"
        b"To: employee@enterprise.com\r\n"
        b"Subject: Benefits Package\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BND\"\r\n\r\n"
        b"--BND\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please review benefits.\r\n\r\n"
        b"--BND\r\n"
        b"Content-Type: application/pdf; name=\"guide.pdf\"\r\n"
        b"Content-Disposition: attachment; filename=\"guide.pdf\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"JVBERi0xLjQKMSAwIG9iajw8L1R5cGUvQ2F0YWxvZz4+ZW5kb2JqCnRyYWlsZXI8PC9Sb290IDEgMCBSPj4lJUVPRg==\r\n\r\n"
        b"--BND\r\n"
        b"Content-Type: application/octet-stream; name=\"setup.exe\"\r\n"
        b"Content-Disposition: attachment; filename=\"setup.exe\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"TVqQAAMAAAAEAAAA//8A\r\n"
        b"--BND--\r\n"
    )
    incident, parsed = await scan_service.ingest_and_parse(raw, filename="multi_att.eml")
    assert incident.risk_tier == RiskTier.MALICIOUS
    att_findings = incident.telemetry["attachment_analysis"]["findings"]
    assert len(att_findings) == 2
    assert att_findings[0]["severity"] == "SAFE"
    assert att_findings[1]["severity"] == "MALICIOUS"


# 14. Malformed Email (Survives Broken MIME Boundaries)
@pytest.mark.asyncio
async def test_scenario_14_malformed_email(scan_service):
    raw = (
        b"From: system@enterprise.com\r\n"
        b"Subject: Truncated Boundary Test\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BROKEN_BOUNDARY\"\r\n\r\n"
        b"--BROKEN_BOUNDARY\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Incomplete body without closing boundary."
    )
    incident, parsed = await scan_service.ingest_and_parse(raw, filename="malformed_boundary.eml")
    assert incident is not None
    assert incident.status.value == "COMPLETED"


# 15. Benign Email Containing Normal Attachments
@pytest.mark.asyncio
async def test_scenario_15_benign_email_with_normal_attachments(scan_service):
    raw = (
        b"From: colleague@enterprise.com\r\n"
        b"To: teammate@enterprise.com\r\n"
        b"Subject: Q4 Sprint Review\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BND\"\r\n\r\n"
        b"--BND\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Attached are the sprint metrics.\r\n\r\n"
        b"--BND\r\n"
        b"Content-Type: text/csv; name=\"sprint_metrics.csv\"\r\n"
        b"Content-Disposition: attachment; filename=\"sprint_metrics.csv\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"ZGF0ZSx0YXNrLHN0YXR1cwoyMDI2LTExLTI3LEZpbmFsIFNwcmludCxDb21wbGV0ZWQK\r\n"
        b"--BND--\r\n"
    )
    incident, parsed = await scan_service.ingest_and_parse(raw, filename="sprint_review.eml")
    assert incident.risk_tier == RiskTier.CLEAN
    assert incident.risk_score == 0.0
    assert len(incident.telemetry["attachment_analysis"]["findings"]) == 1
    assert incident.telemetry["attachment_analysis"]["findings"][0]["severity"] == "SAFE"
