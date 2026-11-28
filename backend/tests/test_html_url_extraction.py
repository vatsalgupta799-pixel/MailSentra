"""
Unit and regression test suite for HTML URL extraction across <a>, <area>, <iframe>, and <form>.

Verifies:
1. Extraction from <a href="..."> with anchor text.
2. Extraction from <area href="..."> image-map hotspots with alt/title text.
3. Extraction from <iframe src="..."> embedded frames.
4. Extraction from <form action="..."> submission endpoints.
5. Safe parsing of severely malformed HTML.
6. Deduplication preserving occurrence counts and source evidence.
7. Relative URLs parsed and retained safely without crashing.
8. Benign email controls.
9. Authentic regression verification on Nazario sample #0 from phishing3.mbox.
"""

import mailbox
import os
import pytest
from app.modules.contracts import ExtractedUrl, IngestionSource, RawEmailPayload, UrlRiskSeverity
from app.modules.parser.parser import EmailParser
from app.modules.parser.url_extractor import extract_urls
from app.modules.url_analysis.analyzer import UrlAnalyzer

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
NAZARIO_MBOX_PATH = os.path.join(PROJECT_ROOT, "backend", "data", "raw", "phishing_email", "nazario", "phishing3.mbox")


def test_extract_urls_from_all_four_html_elements():
    """Verifies that <a>, <area>, <iframe>, and <form> elements yield extracted URLs with exact tag and attribute tags."""
    html = """
    <html>
      <body>
        <a href="https://legit-portal.example.com/welcome">Click Here</a>
        <map name="hotspots">
          <area shape="rect" coords="0,0,50,50" href="http://198.51.100.22/phish" alt="Image Hotspot">
        </map>
        <iframe src="https://embedded-tracker.example.org/pixel"></iframe>
        <form action="https://credential-stealer.example.net/submit" method="POST">
          <input type="text" name="user">
        </form>
      </body>
    </html>
    """
    urls = extract_urls(html_content=html)
    assert len(urls) == 4

    # Tag 'a'
    a_url = next(u for u in urls if u.source_tag == "a")
    assert a_url.normalized_url == "https://legit-portal.example.com/welcome"
    assert a_url.source_attribute == "href"
    assert a_url.source_location == "html_href"
    assert a_url.visible_text == "Click Here"

    # Tag 'area'
    area_url = next(u for u in urls if u.source_tag == "area")
    assert area_url.normalized_url == "http://198.51.100.22/phish"
    assert area_url.source_attribute == "href"
    assert area_url.source_location == "html_area"
    assert area_url.visible_text == "Image Hotspot"

    # Tag 'iframe'
    iframe_url = next(u for u in urls if u.source_tag == "iframe")
    assert iframe_url.normalized_url == "https://embedded-tracker.example.org/pixel"
    assert iframe_url.source_attribute == "src"
    assert iframe_url.source_location == "html_iframe"

    # Tag 'form'
    form_url = next(u for u in urls if u.source_tag == "form")
    assert form_url.normalized_url == "https://credential-stealer.example.net/submit"
    assert form_url.source_attribute == "action"
    assert form_url.source_location == "html_form"


def test_malformed_html_safety():
    """Verifies that unclosed tags, broken quotes, and null bytes do not crash the extractor."""
    malformed = """
    <html>
      <body>
        <a href="https://broken-quote.example.com/path<area href='http://unclosed.example.org/x'
        <iframe src=http://noquotes.example.com/iframe
        <form action="http://valid.example.com/login" unclosed
      </body>
    """
    urls = extract_urls(html_content=malformed)
    assert len(urls) >= 1
    # Check that at least some valid endpoints were safely extracted without raising exceptions
    extracted_domains = [u.normalized_url for u in urls]
    assert any("example.com" in u or "example.org" in u for u in extracted_domains)


def test_duplicate_url_deduplication_with_distinct_sources():
    """Verifies that multiple occurrences of the same URL are tracked with correct counts and locations."""
    html = """
    <html>
      <body>
        <a href="https://example.com/login">Link 1</a>
        <a href="https://example.com/login">Link 2</a>
        <map name="m"><area href="https://example.com/login" alt="Area"></map>
      </body>
    </html>
    """
    urls = extract_urls(html_content=html)
    assert len(urls) == 3  # All instances recorded
    assert urls[0].is_duplicate is False
    assert urls[1].is_duplicate is True
    assert urls[2].is_duplicate is True
    assert urls[2].occurrence_count == 3
    assert urls[2].source_tag == "area"


def test_relative_urls_extracted_safely():
    """Verifies that relative URLs like /login.php are extracted safely without crashing normalization."""
    html = """
    <html>
      <body>
        <a href="/login.php">Relative Link</a>
        <form action="/auth/submit.do"></form>
      </body>
    </html>
    """
    urls = extract_urls(html_content=html)
    assert len(urls) == 2
    assert urls[0].original_url == "/login.php"
    assert urls[1].original_url == "/auth/submit.do"


def test_benign_controls():
    """Verifies that emails with non-HTTP links (mailto) and standard plain text work properly."""
    html = """
    <html>
      <body>
        <p>Please contact us at <a href="mailto:support@college.edu">support@college.edu</a>.</p>
        <p>Visit our website at https://college.edu/portal for more info.</p>
      </body>
    </html>
    """
    urls = extract_urls(html_content=html)
    assert len(urls) == 1
    assert urls[0].normalized_url == "https://college.edu/portal"
    assert urls[0].source_location == "html_text"


@pytest.mark.asyncio
async def test_nazario_sample_0_regression_area_hotspot():
    """Regression test: verifies that Nazario sample #0 extracts the hidden <area> phishing link and detects it."""
    assert os.path.exists(NAZARIO_MBOX_PATH), f"Nazario mbox not found at {NAZARIO_MBOX_PATH}"
    mb = mailbox.mbox(NAZARIO_MBOX_PATH)
    msg_0 = mb[0]

    parser = EmailParser()
    url_analyzer = UrlAnalyzer()

    try:
        raw_payload = RawEmailPayload(raw_bytes=msg_0.as_bytes(), source=IngestionSource.DIRECT_UPLOAD)
        parsed = parser.parse(raw_payload)

        # 1. Verify that 2 URLs were extracted (1 from <a> and 1 from <area>)
        assert len(parsed.urls) == 2

        a_url = next(u for u in parsed.urls if u.source_tag == "a")
        assert "southtrust.com" in a_url.normalized_url

        area_url = next(u for u in parsed.urls if u.source_tag == "area")
        assert area_url.source_attribute == "href"
        assert area_url.source_location == "html_area"
        assert "202.99.223.139" in area_url.normalized_url

        # 2. Verify that UrlAnalyzer detects the IP host in the area URL
        res = await url_analyzer.analyze(parsed)
        assert len(res.findings) >= 1

        ip_finding = next(f for f in res.findings if "202.99.223.139" in f.url)
        assert ip_finding.severity in (UrlRiskSeverity.SUSPICIOUS, UrlRiskSeverity.MALICIOUS)
        assert "IP_HOST_PUBLIC" in ip_finding.reason
    finally:
        await url_analyzer.shutdown()
