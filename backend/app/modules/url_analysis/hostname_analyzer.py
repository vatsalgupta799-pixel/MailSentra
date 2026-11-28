"""Hostname, IDN, Punycode, and IP analysis for static URL security evaluation."""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional

from app.modules.identity.domain_utils import (
    calculate_domain_similarity,
    damerau_levenshtein_distance,
    decode_idna_safely,
    detect_mixed_scripts,
    detect_suspicious_unicode,
    get_registered_domain_offline,
    normalize_domain,
)
from app.modules.url_analysis.config import UrlAnalysisConfig


@dataclass
class HostAnalysisResult:
    """Detailed structural and security analysis of a URL host."""
    host: str
    is_ip_host: bool = False
    ip_version: Optional[int] = None
    resolved_ip: Optional[str] = None
    ip_is_private: bool = False
    ip_is_loopback: bool = False
    ip_is_link_local: bool = False
    ip_is_reserved: bool = False
    ip_is_unspecified: bool = False
    ip_is_multicast: bool = False
    is_encoded_ip: bool = False
    is_punycode: bool = False
    decoded_hostname: str = ""
    has_mixed_script: bool = False
    mixed_scripts: List[str] = field(default_factory=list)
    has_suspicious_unicode: bool = False
    suspicious_unicode_chars: List[str] = field(default_factory=list)
    registered_domain: str = ""
    subdomain_labels: int = 0
    is_shortener: bool = False
    typosquat_target: Optional[str] = None
    typosquat_similarity: float = 0.0


def _try_parse_ip(host_stripped: str) -> Optional[tuple[ipaddress._BaseAddress, bool]]:
    """Attempts to parse standard, hex, octal, or integer encoded IP literals.

    Returns (ip_object, is_encoded).
    """
    cleaned = host_stripped.strip().lower()
    if not cleaned:
        return None

    # 1. Standard IPv4 / IPv6
    try:
        ip = ipaddress.ip_address(cleaned)
        return ip, False
    except ValueError:
        pass

    # 2. Single 32-bit integer (e.g. 2130706433 or 0x7f000001)
    if re.fullmatch(r"0x[0-9a-fA-F]{1,8}", cleaned):
        try:
            val = int(cleaned, 16)
            return ipaddress.IPv4Address(val), True
        except (ValueError, OverflowError):
            pass

    if re.fullmatch(r"\d+", cleaned):
        try:
            val = int(cleaned, 10)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val), True
        except (ValueError, OverflowError):
            pass

    # 3. Dotted IPv4 with hex/octal parts (e.g. 0177.0.0.1 or 0x7f.0.0.1 or 0300.0250.01.01)
    parts = cleaned.split(".")
    if len(parts) == 4 and all(p for p in parts):
        num_parts = []
        is_encoded = False
        for p in parts:
            try:
                if p.startswith("0x") or p.startswith("0X"):
                    num = int(p, 16)
                    is_encoded = True
                elif len(p) > 1 and p.startswith("0") and all(c in "01234567" for c in p):
                    num = int(p, 8)
                    is_encoded = True
                elif p.isdigit():
                    num = int(p, 10)
                else:
                    return None
                if not (0 <= num <= 255):
                    return None
                num_parts.append(str(num))
            except Exception:
                return None

        if len(num_parts) == 4:
            try:
                ip_str = ".".join(num_parts)
                return ipaddress.IPv4Address(ip_str), is_encoded
            except Exception:
                pass

    return None


class HostnameAnalyzer:
    """Analyzes hostname characteristics including IP literal detection, IDN, and typosquatting."""

    def analyze(self, host_stripped: str, config: UrlAnalysisConfig) -> HostAnalysisResult:
        res = HostAnalysisResult(host=host_stripped)
        if not host_stripped:
            return res

        # 1. IP Literal Analysis
        ip_parsed = _try_parse_ip(host_stripped)
        if ip_parsed is not None:
            ip_obj, is_encoded = ip_parsed
            res.is_ip_host = True
            res.ip_version = ip_obj.version
            res.resolved_ip = str(ip_obj)
            res.is_encoded_ip = is_encoded
            res.ip_is_private = ip_obj.is_private
            res.ip_is_loopback = ip_obj.is_loopback
            res.ip_is_link_local = ip_obj.is_link_local
            res.ip_is_reserved = ip_obj.is_reserved
            res.ip_is_unspecified = ip_obj.is_unspecified
            res.ip_is_multicast = ip_obj.is_multicast
            return res

        # 2. Hostname / Domain Analysis
        norm_host = normalize_domain(host_stripped)
        res.decoded_hostname = norm_host

        # Punycode / IDNA
        has_punycode, decoded_domain = decode_idna_safely(norm_host)
        res.is_punycode = has_punycode
        res.decoded_hostname = decoded_domain

        # Mixed scripts
        is_mixed, scripts_found = detect_mixed_scripts(decoded_domain)
        res.has_mixed_script = is_mixed
        res.mixed_scripts = scripts_found

        # Suspicious Unicode characters in raw host
        has_susp, susp_chars = detect_suspicious_unicode(host_stripped)
        res.has_suspicious_unicode = has_susp
        res.suspicious_unicode_chars = susp_chars

        # Registered Domain & Subdomains via offline PSL
        reg_domain = get_registered_domain_offline(norm_host)
        res.registered_domain = reg_domain

        labels = [lbl for lbl in norm_host.split(".") if lbl]
        reg_labels = [lbl for lbl in reg_domain.split(".") if lbl] if reg_domain else []
        res.subdomain_labels = max(0, len(labels) - len(reg_labels))

        # Known shortener check
        check_domain = reg_domain if reg_domain else norm_host
        if check_domain in config.shortener_domains or norm_host in config.shortener_domains:
            res.is_shortener = True

        # Typosquatting check against protected domains
        if config.protected_domains and reg_domain:
            for prot in config.protected_domains:
                norm_prot = normalize_domain(prot)
                if not norm_prot or norm_prot == reg_domain or norm_host == norm_prot:
                    continue
                reg_prot = get_registered_domain_offline(norm_prot)
                if reg_prot == reg_domain:
                    continue

                comp_host = reg_domain
                comp_prot = reg_prot if reg_prot else norm_prot

                if (
                    len(comp_host) >= config.typosquatting_min_domain_length
                    and len(comp_prot) >= config.typosquatting_min_domain_length
                ):
                    dist = damerau_levenshtein_distance(comp_host, comp_prot)
                    sim = calculate_domain_similarity(comp_host, comp_prot)
                    if (
                        dist <= config.typosquatting_max_distance
                        and sim >= config.typosquatting_min_similarity
                    ):
                        res.typosquat_target = norm_prot
                        res.typosquat_similarity = sim
                        break

        return res
