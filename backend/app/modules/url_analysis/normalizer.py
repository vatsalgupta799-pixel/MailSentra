"""URL parsing and normalization utilities."""

import re
import urllib.parse
from dataclasses import dataclass
from typing import Optional


@dataclass
class UrlParseResult:
    """Structured representation of parsed URL components."""
    original: str
    scheme: str
    host: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    userinfo: Optional[str]
    is_valid: bool
    parse_error: Optional[str]
    host_stripped: str


class UrlNormalizer:
    """Safe URL normalizer and component parser."""

    def parse(self, url: str, max_url_length: int = 2000) -> UrlParseResult:
        """Parses a URL string safely without external network calls or regex vulnerabilities."""
        if not url or not isinstance(url, str) or not url.strip():
            return UrlParseResult(
                original=url or "",
                scheme="",
                host="",
                port=None,
                path="",
                query="",
                fragment="",
                userinfo=None,
                is_valid=False,
                parse_error="Empty or whitespace URL",
                host_stripped="",
            )

        trimmed = url.strip()
        parse_error: Optional[str] = None

        if len(trimmed) > max_url_length:
            parse_error = f"URL length ({len(trimmed)}) exceeds limit ({max_url_length})"

        # Attempt standard splitting
        try:
            split_target = trimmed
            # Check for standard URI scheme pattern: scheme:path
            has_scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", split_target)
            if not has_scheme_match:
                if split_target.startswith("//"):
                    split_target = "http:" + split_target
                else:
                    split_target = "http://" + split_target

            split_res = urllib.parse.urlsplit(split_target)
        except Exception as e:
            return UrlParseResult(
                original=trimmed,
                scheme="",
                host="",
                port=None,
                path="",
                query="",
                fragment="",
                userinfo=None,
                is_valid=False,
                parse_error=f"Malformed URL split: {str(e)}",
                host_stripped="",
            )

        scheme = split_res.scheme.lower()
        netloc = split_res.netloc
        path = split_res.path
        query = split_res.query
        fragment = split_res.fragment

        userinfo: Optional[str] = None
        host_str = netloc
        port: Optional[int] = None

        if "@" in netloc:
            parts = netloc.split("@", 1)
            userinfo = parts[0]
            host_str = parts[1]

        # Extract IPv6 brackets vs port
        if host_str.startswith("["):
            bracket_close = host_str.find("]")
            if bracket_close != -1:
                ipv6_host = host_str[1:bracket_close]
                remainder = host_str[bracket_close + 1:]
                if remainder.startswith(":"):
                    try:
                        port = int(remainder[1:])
                    except ValueError:
                        parse_error = "Invalid port in IPv6 URL"
                host_stripped = ipv6_host.lower()
                host_norm = f"[{host_stripped}]"
            else:
                host_stripped = host_str.lstrip("[").rstrip("]").lower()
                host_norm = host_str.lower()
                parse_error = "Unclosed IPv6 bracket in hostname"
        else:
            if ":" in host_str:
                host_parts = host_str.split(":", 1)
                host_norm = host_parts[0].lower()
                try:
                    port = int(host_parts[1])
                except ValueError:
                    parse_error = "Invalid port in URL"
                host_stripped = host_norm
            else:
                host_norm = host_str.lower()
                host_stripped = host_norm

        # A URL is valid if it has a host (for network schemes) or is a valid non-network scheme
        is_valid = (bool(host_stripped) or scheme in {"javascript", "data", "file", "mailto", "tel"}) and parse_error is None

        return UrlParseResult(
            original=trimmed,
            scheme=scheme,
            host=host_norm,
            port=port,
            path=path,
            query=query,
            fragment=fragment,
            userinfo=userinfo,
            is_valid=is_valid,
            parse_error=parse_error,
            host_stripped=host_stripped,
        )

    def defang(self, url: str) -> str:
        """Defangs a URL safely for reporting (e.g. hxxps://domain[.]com)."""
        if not url:
            return ""
        defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
        try:
            parts = urllib.parse.urlsplit(defanged)
            if parts.netloc:
                defanged_netloc = parts.netloc.replace(".", "[.]")
                return urllib.parse.urlunsplit(
                    (parts.scheme, defanged_netloc, parts.path, parts.query, parts.fragment)
                )
        except Exception:
            pass
        return defanged.replace(".", "[.]")
