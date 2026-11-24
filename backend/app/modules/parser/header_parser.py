"""Email Header Parsing and Decoding Utilities."""

import email.header
import email.utils
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from app.modules.contracts import EmailAddress, EmailHeader, ReceivedHop


def decode_rfc2047(header_value: Optional[str]) -> str:
    """Decodes RFC 2047 MIME encoded-word header values and unfolds RFC 5322 folded whitespace."""
    if not header_value:
        return ""

    # Unfold RFC 5322 multi-line folded whitespace (CRLF / LF followed by WSP, or tabs)
    raw_val_str = str(header_value)
    unfolded = re.sub(r"[\r\n]+[ \t]+", " ", raw_val_str)
    unfolded = re.sub(r"[\t\r\n]+", " ", unfolded).strip()

    try:
        decoded_chunks = email.header.decode_header(unfolded)
        decoded_parts = []
        for chunk, charset in decoded_chunks:
            if isinstance(chunk, bytes):
                # Try declared charset, then common fallbacks
                encodings_to_try = [charset, "utf-8", "windows-1252", "iso-8859-1"]
                decoded_str = None
                for enc in encodings_to_try:
                    if not enc:
                        continue
                    try:
                        decoded_str = chunk.decode(enc)
                        break
                    except (UnicodeDecodeError, LookupError):
                        continue
                if decoded_str is None:
                    decoded_str = chunk.decode("utf-8", errors="replace")
                decoded_parts.append(decoded_str)
            else:
                decoded_parts.append(str(chunk))
        res = "".join(decoded_parts)
        return re.sub(r"[ \t]+", " ", res).strip()
    except Exception:
        # Fallback to unfolded string
        return re.sub(r"[ \t]+", " ", unfolded).strip()


def parse_email_address(raw_address: Optional[str]) -> Optional[EmailAddress]:
    """Parses a single email address into display name, address, and domain."""
    if not raw_address or not raw_address.strip():
        return None

    decoded_raw = decode_rfc2047(raw_address.strip())
    name, addr = email.utils.parseaddr(decoded_raw)

    addr = addr.strip().lower()
    if not addr or "@" not in addr:
        # Might be malformed or bare display name
        return EmailAddress(
            raw=decoded_raw,
            display_name=name.strip() if name else decoded_raw,
            address=addr,
            domain=addr.split("@")[-1] if "@" in addr else "",
        )

    domain = addr.split("@")[-1].strip().lower()
    return EmailAddress(
        raw=decoded_raw,
        display_name=name.strip() if name else None,
        address=addr,
        domain=domain,
    )


def parse_address_list(
    raw_header_value: Optional[str],
    max_addresses: int = 100,
) -> List[EmailAddress]:
    """Parses a comma-separated list of addresses (To, CC, BCC) up to max_addresses."""
    if not raw_header_value:
        return []

    decoded_header = decode_rfc2047(raw_header_value)
    addresses: List[EmailAddress] = []

    parsed_pairs = email.utils.getaddresses([decoded_header])
    for name, addr in parsed_pairs:
        if len(addresses) >= max_addresses:
            break
        addr = addr.strip().lower()
        if not addr:
            continue
        domain = addr.split("@")[-1].strip().lower() if "@" in addr else ""
        addresses.append(
            EmailAddress(
                raw=f"{name} <{addr}>" if name else addr,
                display_name=name.strip() if name else None,
                address=addr,
                domain=domain,
            )
        )
    return addresses


def parse_date_header(raw_date: Optional[str]) -> Tuple[Optional[str], Optional[datetime]]:
    """Parses a Date header into raw string and normalized UTC datetime."""
    if not raw_date:
        return None, None

    decoded_date = decode_rfc2047(raw_date).strip()
    try:
        dt = email.utils.parsedate_to_datetime(decoded_date)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return decoded_date, dt
    except Exception:
        return decoded_date, None


def parse_received_hops(
    received_headers: List[str],
    max_hops: int = 100,
) -> List[ReceivedHop]:
    """Parses raw Received header lines into structured hops with IP and host extraction up to max_hops."""
    hops: List[ReceivedHop] = []
    ip_pattern = re.compile(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]|\[([a-fA-F0-9:]+)\]")
    from_pattern = re.compile(r"from\s+([^\s;]+)", re.IGNORECASE)
    by_pattern = re.compile(r"by\s+([^\s;]+)", re.IGNORECASE)

    for idx, raw_val in enumerate(received_headers[:max_hops], start=1):
        clean_raw = " ".join(raw_val.split())
        ip_match = ip_pattern.search(clean_raw)
        from_match = from_pattern.search(clean_raw)
        by_match = by_pattern.search(clean_raw)

        extracted_ip = None
        if ip_match:
            extracted_ip = ip_match.group(1) or ip_match.group(2)

        hops.append(
            ReceivedHop(
                hop_number=idx,
                raw=clean_raw,
                from_host=from_match.group(1) if from_match else None,
                by=by_match.group(1) if by_match else None,
                ip=extracted_ip,
                date=clean_raw.split(";")[-1].strip() if ";" in clean_raw else None,
            )
        )
    return hops
