"""Domain utilities for safe normalization, edit distance, and Unicode analysis.

Pure-Python implementation with zero outbound network requests and zero DNS lookups.
Uses offline tldextract snapshot when available for public suffix resolution.
"""

import re
import unicodedata
from typing import List, Optional, Set, Tuple
import idna
import tldextract

# Offline extractor initialized once with suffix_list_urls=None (guarantees zero network calls)
_OFFLINE_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)

# Bounded regex for email address extraction (avoids catastrophic backtracking)
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9_.+-]{1,64}@[a-zA-Z0-9-]{1,255}(?:\.[a-zA-Z0-9-]{1,63})+")

# Suspicious Unicode categories & directional control characters
SUSPICIOUS_UNICODE_CODEPOINTS = {
    # Directional overrides & embeddings
    0x202A: "LEFT-TO-RIGHT EMBEDDING",
    0x202B: "RIGHT-TO-LEFT EMBEDDING",
    0x202C: "POP DIRECTIONAL FORMATTING",
    0x202D: "LEFT-TO-RIGHT OVERRIDE",
    0x202E: "RIGHT-TO-LEFT OVERRIDE",
    0x2066: "LEFT-TO-RIGHT ISOLATE",
    0x2067: "RIGHT-TO-LEFT ISOLATE",
    0x2068: "FIRST STRONG ISOLATE",
    0x2069: "POP DIRECTIONAL ISOLATE",
    # Zero-width / invisible characters
    0x200B: "ZERO WIDTH SPACE",
    0x200C: "ZERO WIDTH NON-JOINER",
    0x200D: "ZERO WIDTH JOINER",
    0x200E: "LEFT-TO-RIGHT MARK",
    0x200F: "RIGHT-TO-LEFT MARK",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
    0x00AD: "SOFT HYPHEN",
}


def normalize_domain(domain_str: Optional[str], max_len: int = 255) -> str:
    """Safely normalizes a domain string: stripped, lowercased, brackets removed, length bounded."""
    if not domain_str:
        return ""
    val = str(domain_str).strip()
    val = val.strip("<>\"' \t\r\n").rstrip(".")
    if not val:
        return ""
    # Bounded length to prevent excessive computation
    val = val[:max_len]
    return val.lower()


def is_subdomain_of(subdomain: str, parent_domain: str) -> bool:
    """Checks if subdomain is equal to parent_domain or is a strict subdomain of parent_domain."""
    sub = normalize_domain(subdomain)
    parent = normalize_domain(parent_domain)
    if not sub or not parent:
        return False
    if sub == parent:
        return True
    return sub.endswith("." + parent)


def get_registered_domain_offline(domain_str: str) -> str:
    """Extracts top domain under public suffix using offline bundled snapshot."""
    norm = normalize_domain(domain_str)
    if not norm:
        return ""
    try:
        extracted = _OFFLINE_EXTRACTOR(norm)
        top = getattr(extracted, "top_domain_under_public_suffix", None) or getattr(extracted, "registered_domain", None)
        return top.lower() if top else norm
    except Exception:
        return norm


def extract_email_from_text(text: Optional[str], max_len: int = 255) -> Optional[str]:
    """Safely searches for an embedded email address in a bounded text string."""
    if not text:
        return None
    bounded = str(text)[:max_len]
    match = EMAIL_PATTERN.search(bounded)
    if match:
        return match.group(0).lower()
    return None


def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    """Computes the Damerau-Levenshtein distance (insertions, deletions, substitutions, transpositions).

    Pure Python, deterministic, $O(M \\times N)$ time and $O(N)$ space.
    """
    len1, len2 = len(s1), len(s2)
    if len1 == 0:
        return len2
    if len2 == 0:
        return len1

    # Distance matrix
    d = [[0] * (len2 + 2) for _ in range(len1 + 2)]
    max_dist = len1 + len2
    d[0][0] = max_dist

    da = {}
    for i in range(len1 + 1):
        d[i + 1][0] = max_dist
        d[i + 1][1] = i
    for j in range(len2 + 1):
        d[0][j + 1] = max_dist
        d[1][j + 1] = j

    for i in range(1, len1 + 1):
        db = 0
        for j in range(1, len2 + 1):
            k = da.get(s2[j - 1], 0)
            l = db
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            if cost == 0:
                db = j

            d[i + 1][j + 1] = min(
                d[i][j + 1] + 1,  # deletion
                d[i + 1][j] + 1,  # insertion
                d[i][j] + cost,   # substitution
                d[k][l] + (i - k - 1) + 1 + (j - l - 1),  # transposition
            )
        da[s1[i - 1]] = i

    return d[len1 + 1][len2 + 1]


def calculate_domain_similarity(domain: str, target: str) -> float:
    """Calculates normalized string similarity score in [0.0, 1.0] based on Damerau-Levenshtein distance."""
    d1 = normalize_domain(domain)
    d2 = normalize_domain(target)
    if d1 == d2:
        return 1.0
    max_len = max(len(d1), len(d2))
    if max_len == 0:
        return 0.0
    dist = damerau_levenshtein_distance(d1, d2)
    similarity = max(0.0, 1.0 - (dist / max_len))
    return round(similarity, 3)


def decode_idna_safely(domain_str: str) -> Tuple[bool, str]:
    """Checks for Punycode label ('xn--') and safely decodes via idna library.

    Returns:
        (has_punycode, decoded_domain)
    """
    norm = normalize_domain(domain_str)
    labels = norm.split(".")
    has_punycode = any(lbl.startswith("xn--") for lbl in labels)
    if not has_punycode:
        return False, norm

    try:
        decoded = idna.decode(norm)
        return True, decoded
    except Exception:
        # Fallback to normalized ASCII string if IDNA decoding fails
        return True, norm


def detect_mixed_scripts(domain_or_text: str) -> Tuple[bool, List[str]]:
    """Detects mixed Unicode scripts within individual labels of a domain.

    Returns:
        (is_mixed, script_names_found)
    """
    norm = normalize_domain(domain_or_text)
    labels = norm.split(".")
    for label in labels:
        if not label:
            continue
        scripts_found: Set[str] = set()
        for ch in label:
            if ch.isalnum():
                try:
                    char_name = unicodedata.name(ch, "")
                    first_word = char_name.split()[0] if char_name else "UNKNOWN"
                    if first_word in {
                        "LATIN",
                        "CYRILLIC",
                        "GREEK",
                        "HEBREW",
                        "ARABIC",
                        "DEVANAGARI",
                        "BENGALI",
                        "CJK",
                        "HIRAGANA",
                        "KATAKANA",
                    }:
                        scripts_found.add(first_word)
                except ValueError:
                    continue
        if len(scripts_found) > 1:
            return True, sorted(list(scripts_found))

    return False, []


def detect_suspicious_unicode(text: Optional[str]) -> Tuple[bool, List[str]]:
    """Detects directional override characters and zero-width/invisible codepoints."""
    if not text:
        return False, []

    detected_names: List[str] = []
    for ch in text:
        cp = ord(ch)
        if cp in SUSPICIOUS_UNICODE_CODEPOINTS:
            name = SUSPICIOUS_UNICODE_CODEPOINTS[cp]
            if name not in detected_names:
                detected_names.append(name)

    return len(detected_names) > 0, detected_names
