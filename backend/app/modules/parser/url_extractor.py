"""URL Extraction and Defanging Utilities.

Extracts URLs from plain-text bodies, HTML href attributes, and HTML-visible link text.
Does NOT visit, fetch, or request extracted URLs.
"""

import re
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple
from bs4 import BeautifulSoup
from app.modules.contracts import ExtractedUrl

# Regex matching standard http and https URLs
URL_PATTERN = re.compile(
    r"""(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))""",
    re.IGNORECASE,
)


def defang_url(url: str) -> str:
    """Defangs a URL so it cannot be inadvertently clicked or resolved in security consoles.

    Example:
    'https://evil.com/login' -> 'hxxps[://]evil[.]com/login'
    """
    if not url:
        return ""
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Defang domain dots
    # Replace dots in host portion if possible, or all dots
    defanged = defanged.replace(".", "[.]")
    defanged = defanged.replace("://", "[://]")
    return defanged


def normalize_url(url: str) -> str:
    """Safely normalizes a URL by trimming trailing punctuation, lowering scheme/host, and unquoting safe chars."""
    if not url:
        return ""

    url = url.strip()
    # Strip common trailing punctuation and closing quotes/brackets attached via regex capture
    url = re.sub(r"[.,;:!?)>\"'\]]+$", "", url)

    # Prefix with http:// if bare domain matched
    if url.lower().startswith("www."):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query
        fragment = parsed.fragment
        normalized = urllib.parse.urlunsplit((scheme, netloc, path, query, fragment))
        return normalized
    except Exception:
        return url


def extract_urls(
    plain_text: Optional[str] = None,
    html_content: Optional[str] = None,
    max_urls: int = 500,
) -> List[ExtractedUrl]:
    """Extracts all unique and duplicate URLs from plain-text and HTML content up to max_urls."""
    extracted_urls: List[ExtractedUrl] = []
    seen_urls: Dict[str, ExtractedUrl] = {}

    def add_url(
        raw_url: str,
        location: str,
        visible_text: Optional[str] = None,
        source_tag: Optional[str] = None,
        source_attribute: Optional[str] = None,
    ):
        if len(extracted_urls) >= max_urls:
            return
        if not raw_url:
            return
        cleaned_raw = raw_url.strip()
        # Ignore mailto:, javascript:, tel:, data:, file:, vbscript:, blob: schemes
        if cleaned_raw.lower().startswith(("javascript:", "mailto:", "tel:", "data:", "file:", "vbscript:", "blob:", "#")):
            return

        norm = normalize_url(cleaned_raw)
        if not norm or len(norm) < 4:
            return

        defanged = defang_url(norm)

        if norm in seen_urls:
            # Increment occurrence count on the first instance
            existing = seen_urls[norm]
            existing.occurrence_count += 1
            # Also record this instance as a duplicate occurrence with its specific source tag/attribute
            extracted_urls.append(
                ExtractedUrl(
                    original_url=cleaned_raw,
                    normalized_url=norm,
                    defanged_url=defanged,
                    visible_text=visible_text,
                    source_location=location,
                    source_tag=source_tag,
                    source_attribute=source_attribute,
                    is_duplicate=True,
                    occurrence_count=existing.occurrence_count,
                )
            )
        else:
            new_item = ExtractedUrl(
                original_url=cleaned_raw,
                normalized_url=norm,
                defanged_url=defanged,
                visible_text=visible_text,
                source_location=location,
                source_tag=source_tag,
                source_attribute=source_attribute,
                is_duplicate=False,
                occurrence_count=1,
            )
            seen_urls[norm] = new_item
            extracted_urls.append(new_item)

    # 1. Extract from plain-text body
    if plain_text and len(extracted_urls) < max_urls:
        matches = URL_PATTERN.findall(plain_text)
        for match in matches:
            if len(extracted_urls) >= max_urls:
                break
            url_str = match[0] if isinstance(match, tuple) else match
            add_url(url_str, location="plain_text", visible_text=None, source_tag="text", source_attribute=None)

    # 2. Extract from HTML content
    if html_content and len(extracted_urls) < max_urls:
        try:
            soup = BeautifulSoup(html_content, "html.parser")

            # Extract from <a href="..."> tags (href and anchor text)
            for a_tag in soup.find_all("a", href=True):
                if len(extracted_urls) >= max_urls:
                    break
                href = a_tag["href"]
                anchor_text = a_tag.get_text(strip=True) or None
                add_url(href, location="html_href", visible_text=anchor_text, source_tag="a", source_attribute="href")

            # Extract from <area href="..."> image-map tags (href and alt/title text)
            for area_tag in soup.find_all("area", href=True):
                if len(extracted_urls) >= max_urls:
                    break
                href = area_tag["href"]
                alt_text = area_tag.get("alt") or area_tag.get("title") or None
                add_url(href, location="html_area", visible_text=alt_text, source_tag="area", source_attribute="href")

            # Extract from <iframe src="..."> embedded frame tags
            for iframe_tag in soup.find_all("iframe", src=True):
                if len(extracted_urls) >= max_urls:
                    break
                src = iframe_tag["src"]
                add_url(src, location="html_iframe", visible_text=None, source_tag="iframe", source_attribute="src")

            # Extract from <form action="..."> submission targets
            for form_tag in soup.find_all("form", action=True):
                if len(extracted_urls) >= max_urls:
                    break
                action = form_tag["action"]
                add_url(action, location="html_form", visible_text=None, source_tag="form", source_attribute="action")

            # Extract visible URLs written in text inside HTML (after decomposing scripts/styles)
            if len(extracted_urls) < max_urls:
                for tag in soup(["script", "style", "noscript", "iframe"]):
                    tag.decompose()
                body_text = soup.get_text(separator=" ")
                matches = URL_PATTERN.findall(body_text)
                for match in matches:
                    if len(extracted_urls) >= max_urls:
                        break
                    url_str = match[0] if isinstance(match, tuple) else match
                    add_url(url_str, location="html_text", visible_text=None, source_tag="text", source_attribute=None)
        except Exception:
            # Fallback regex if HTML parsing fails
            if len(extracted_urls) < max_urls:
                matches = URL_PATTERN.findall(html_content)
                for match in matches:
                    if len(extracted_urls) >= max_urls:
                        break
                    url_str = match[0] if isinstance(match, tuple) else match
                    add_url(url_str, location="html_text", visible_text=None, source_tag="text", source_attribute=None)

    return extracted_urls
