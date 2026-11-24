"""Email Body Parsing and Text Extraction Utilities."""

import re
from typing import Optional, Tuple
from bs4 import BeautifulSoup, Comment


def decode_payload_bytes(payload_bytes: bytes, declared_charset: Optional[str]) -> str:
    """Decodes raw message payload bytes using declared charset with robust fallback chain."""
    encodings_to_try = []
    if declared_charset:
        encodings_to_try.append(declared_charset.strip().lower().strip('"').strip("'"))
    encodings_to_try.extend(["utf-8", "windows-1252", "iso-8859-1", "ascii"])

    for enc in encodings_to_try:
        try:
            return payload_bytes.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue

    # Final fallback with character replacement to ensure parsing never crashes
    return payload_bytes.decode("utf-8", errors="replace")


def extract_clean_text_from_html(html_content: str, max_html_bytes: int = 2 * 1024 * 1024) -> str:
    """Safely extracts clean plain-text from HTML without executing scripts or styles."""
    if not html_content or not html_content.strip():
        return ""

    # Bound HTML input size to prevent parser CPU starvation
    bounded_html = html_content[:max_html_bytes] if len(html_content) > max_html_bytes else html_content

    try:
        soup = BeautifulSoup(bounded_html, "html.parser")

        # Strip dangerous tags, script tags, style tags, comments, and form elements
        for tag in soup(["script", "style", "noscript", "iframe", "object", "embed", "svg", "form", "meta", "link", "applet"]):
            tag.decompose()

        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()

        # Extract text separated by whitespace
        text = soup.get_text(separator=" ", strip=True)
        # Normalize excessive whitespace
        text = re.sub(r"\s+", " ", text).strip()
        return text
    except Exception:
        # Fallback regex strip if HTML parser fails on malformed markup
        stripped = re.sub(r"<[^>]+>", " ", html_content)
        return re.sub(r"\s+", " ", stripped).strip()
