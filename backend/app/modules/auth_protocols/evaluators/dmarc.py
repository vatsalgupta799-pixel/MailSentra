"""DMARC Record Discovery and Bounded DNS Tree Walking.

Architecture reference: MS-ARCH-SEC-2026-AUTH-PROTOCOLS-REV13
Standards: RFC 9989 (DMARCbis), RFC 9091
"""

from __future__ import annotations

import asyncio
from enum import Enum
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.parse
import idna

from pydantic import BaseModel, Field

from app.modules.auth_protocols.config import AuthProtocolsConfig
from app.modules.auth_protocols.dns_resolver import BaseDNSResolver, DNSQueryType, DNSResponseStatus
from app.modules.contracts import (
    AlignmentMode,
    AuthProtocolsResult,
    DKIMEvaluationState,
    DKIMSignatureResult,
    DMARCPolicy,
    DMARCResult,
    ProtocolStatus,
    SPFResult,
)
from app.modules.identity.domain_utils import normalize_domain

logger = logging.getLogger(__name__)


# RFC 9989 Section 4.7: Recognized DMARC tags registered in the IANA DMARC registry.
# Unknown or obsolete tags (such as historical 'pct') MUST be ignored.
RECOGNIZED_DMARC_TAGS = {
    "v",
    "p",
    "sp",
    "np",
    "psd",
    "adkim",
    "aspf",
    "fo",
    "rua",
    "ruf",
    "t",
}


def is_dmarc_version1_record(raw: str) -> bool:
    """Checks if a TXT record identifies the current DMARC version (v=DMARC1) per RFC 9989 Section 4.7.
    
    The first tag MUST be 'v' and its value MUST be case-sensitive 'DMARC1'.
    Records not meeting this requirement MUST be ignored.
    """
    s = raw.strip()
    if not s:
        return False
    parts = s.split(";", 1)
    first_tag = parts[0].strip()
    if "=" not in first_tag:
        return False
    k, v = first_tag.split("=", 1)
    return k.strip().lower() == "v" and v.strip() == "DMARC1"


class DMARCDiscoveryStatus(str, Enum):
    """Discovery outcome status for DMARC policy discovery."""
    FOUND = "FOUND"
    ABSENT = "ABSENT"
    INVALID = "INVALID"
    TEMPERROR = "TEMPERROR"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    INDETERMINATE = "INDETERMINATE"


class DMARCDiscoveryResult(BaseModel):
    """Structured result of DMARC policy discovery and tree walking per RFC 9989."""
    status: DMARCDiscoveryStatus
    protocol_status: ProtocolStatus
    domain: str
    discovered_domain: Optional[str] = None
    org_domain: Optional[str] = None
    raw_record: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    tree_walk_queries: int = 0
    psd_type: Optional[str] = None  # "y", "n", "u", or None
    is_psd: bool = False
    policy_discovery_source: Optional[str] = None  # "author_domain", "org_domain", "psd", "none", "temperror", "indeterminate", "permerror"
    p_defaulted_from_missing: bool = False
    policy_fallback_from_rua: bool = False
    traversed_domains: List[str] = Field(default_factory=list)
    error_reason: Optional[str] = None

    def to_dmarc_result(self) -> DMARCResult:
        """Converts discovery result to typed DMARCResult contract."""
        effective_org_domain = self.org_domain or self.discovered_domain
        if self.status == DMARCDiscoveryStatus.FOUND:
            p_val = self.tags.get("p", "none").lower()
            policy_enum = (
                DMARCPolicy(p_val)
                if p_val in ("none", "quarantine", "reject")
                else DMARCPolicy.NONE
            )
            sp_val = self.tags.get("sp", "").lower()
            sub_policy = (
                DMARCPolicy(sp_val)
                if sp_val in ("none", "quarantine", "reject")
                else None
            )
            np_val = self.tags.get("np", "").lower()
            np_policy = (
                DMARCPolicy(np_val)
                if np_val in ("none", "quarantine", "reject")
                else None
            )
            disc_dom = (self.discovered_domain or self.domain or "").lower()
            norm_dom = (self.domain or "").lower()
            is_sub = bool(disc_dom and norm_dom != disc_dom and norm_dom.endswith("." + disc_dom))
            source = self.policy_discovery_source or (
                "author_domain" if not is_sub else ("psd" if self.is_psd else "org_domain")
            )
            tag_used = (
                "p_rua_fallback"
                if self.policy_fallback_from_rua
                else ("p_default_missing" if self.p_defaulted_from_missing else "p")
            )
            return DMARCResult(
                status=ProtocolStatus.PASS,
                standard_status="pass",
                internal_status=ProtocolStatus.PASS,
                policy=policy_enum,
                record_p_policy=policy_enum,
                subdomain_policy=sub_policy,
                non_existent_subdomain_policy=np_policy,
                applicable_policy_tag=tag_used,
                policy_discovery_source=source,
                policy_domain=self.discovered_domain,
                is_psd_policy=self.is_psd,
                is_subdomain=is_sub,
                test_mode=(self.tags.get("t", "n").lower() == "y"),
                org_domain=effective_org_domain,
                from_domain=self.domain,
                evaluated_record=self.raw_record,
                raw_tags=dict(self.tags),
                tree_walk_queries=self.tree_walk_queries,
                psd_type=self.psd_type,
            )
        elif self.status == DMARCDiscoveryStatus.ABSENT:
            return DMARCResult(
                status=ProtocolStatus.NONE,
                standard_status="none",
                internal_status=ProtocolStatus.NONE,
                policy=DMARCPolicy.NOT_CONFIGURED,
                policy_discovery_source=self.policy_discovery_source or "none",
                policy_domain=self.discovered_domain,
                is_psd_policy=self.is_psd,
                org_domain=effective_org_domain,
                from_domain=self.domain,
                tree_walk_queries=self.tree_walk_queries,
                psd_type=self.psd_type,
                error_reason=self.error_reason,
            )
        elif self.status == DMARCDiscoveryStatus.TEMPERROR:
            return DMARCResult(
                status=ProtocolStatus.TEMPERROR,
                standard_status="temperror",
                internal_status=ProtocolStatus.TEMPERROR,
                policy=DMARCPolicy.NOT_CONFIGURED,
                policy_discovery_source=self.policy_discovery_source or "temperror",
                policy_domain=self.discovered_domain,
                is_psd_policy=self.is_psd,
                org_domain=effective_org_domain,
                from_domain=self.domain,
                tree_walk_queries=self.tree_walk_queries,
                psd_type=self.psd_type,
                error_reason=self.error_reason,
            )
        elif self.status in (DMARCDiscoveryStatus.LIMIT_EXCEEDED, DMARCDiscoveryStatus.INDETERMINATE):
            return DMARCResult(
                status=ProtocolStatus.INDETERMINATE,
                standard_status=None,
                internal_status=ProtocolStatus.INDETERMINATE,
                policy=DMARCPolicy.NOT_CONFIGURED,
                policy_discovery_source=self.policy_discovery_source or "indeterminate",
                policy_domain=self.discovered_domain,
                is_psd_policy=self.is_psd,
                org_domain=effective_org_domain,
                from_domain=self.domain,
                tree_walk_queries=self.tree_walk_queries,
                psd_type=self.psd_type,
                error_reason=self.error_reason,
            )
        else:  # INVALID or other
            return DMARCResult(
                status=ProtocolStatus.PERMERROR,
                standard_status="permerror",
                internal_status=ProtocolStatus.PERMERROR,
                policy=DMARCPolicy.NOT_CONFIGURED,
                policy_discovery_source=self.policy_discovery_source or "permerror",
                policy_domain=self.discovered_domain,
                is_psd_policy=self.is_psd,
                org_domain=effective_org_domain,
                from_domain=self.domain,
                tree_walk_queries=self.tree_walk_queries,
                psd_type=self.psd_type,
                error_reason=self.error_reason,
            )


def is_valid_dmarc_uri(uri_str: str) -> bool:
    """Validates a single DMARC reporting URI per RFC 9989 Section 4.6/4.8 and RFC 3986.
    
    Supports optional obsolete report size modifier (e.g. !10m per obs-dmarc-report-size).
    """
    s = uri_str.strip()
    if not s:
        return False
    if "!" in s:
        base, sep, size_mod = s.rpartition("!")
        if re.match(r"^\d+[kmgtKMGT]?$", size_mod):
            s = base.strip()
    try:
        parsed = urllib.parse.urlsplit(s)
        # RFC 3986: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
        if not parsed.scheme or not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*$", parsed.scheme):
            return False
        # Must have non-empty scheme-specific part (path, netloc, or query)
        if not (parsed.netloc or parsed.path or parsed.query):
            return False
        return True
    except Exception:
        return False


def has_valid_reporting_uri(rua_val: Optional[str]) -> bool:
    """Checks if a 'rua' tag value contains at least one syntactically valid reporting URI.
    
    RFC 9989 Section 4.10.1 requires at least one syntactically valid reporting URI
    for the record to fallback to p=none when policy tags (p, sp, np) are invalid.
    """
    if not rua_val:
        return False
    candidates = [u.strip() for u in rua_val.split(",") if u.strip()]
    return any(is_valid_dmarc_uri(u) for u in candidates)


def parse_dmarc_tags_with_metadata(
    record_str: str,
) -> Tuple[Optional[Dict[str, str]], Optional[str], Dict[str, Any]]:
    """Parses and validates a DMARC Policy Record string per RFC 9989 Sections 4.7, 4.8, and 4.10.1.

    Returns (tags_dict, error_reason, metadata_dict).
    """
    meta: Dict[str, Any] = {
        "p_defaulted_from_missing": False,
        "policy_fallback_from_rua": False,
    }
    raw = record_str.strip()
    if not raw:
        return None, "Empty DMARC record", meta

    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts:
        return None, "DMARC record contains no tag-value pairs", meta

    # RFC 9989 Section 4.7: First tag MUST be 'v=DMARC1' (case-sensitive)
    first_part = parts[0]
    if "=" not in first_part:
        return None, f"First tag '{first_part}' is not a valid key-value pair", meta

    v_key, v_val = first_part.split("=", 1)
    if v_key.strip().lower() != "v":
        return None, f"The 'v' tag must be the first tag in the DMARC record (found '{v_key.strip()}')", meta

    if v_val.strip() != "DMARC1":
        return None, f"Invalid DMARC version '{v_val.strip()}'; must be 'DMARC1'", meta

    tags: Dict[str, str] = {"v": "DMARC1"}
    seen_tags: Set[str] = {"v"}

    for part in parts[1:]:
        if "=" not in part:
            return None, f"Malformed tag-value pair '{part}'", meta
        k, v = part.split("=", 1)
        tag_name = k.strip().lower()
        tag_val = v.strip()

        if not tag_name:
            return None, f"Malformed tag-value pair '{part}'", meta

        if tag_name in seen_tags:
            return None, f"Duplicate tag '{tag_name}' in DMARC record", meta
        seen_tags.add(tag_name)

        # RFC 9989 Section 4.7: Only registered tags are processed; unknown tags MUST be ignored.
        # Historical 'pct' tag was removed from RFC 9989 and is treated as an unknown tag (ignored).
        if tag_name not in RECOGNIZED_DMARC_TAGS:
            continue

        tags[tag_name] = tag_val

    # Policy tags: p=, sp=, np= (RFC 9989 Section 4.7 & 4.10.1)
    raw_p = tags.get("p")
    p_invalid = False
    if raw_p is not None:
        p_val = raw_p.strip().lower()
        if p_val in ("none", "quarantine", "reject"):
            tags["p"] = p_val
        else:
            p_invalid = True
    else:
        # RFC 9989 Section 4.7: p is RECOMMENDED. If absent in an otherwise
        # syntactically valid record, default is p=none.
        tags["p"] = "none"
        meta["p_defaulted_from_missing"] = True

    raw_sp = tags.get("sp")
    sp_invalid = False
    if raw_sp is not None:
        sp_val = raw_sp.strip().lower()
        if sp_val in ("none", "quarantine", "reject"):
            tags["sp"] = sp_val
        else:
            sp_invalid = True

    raw_np = tags.get("np")
    np_invalid = False
    if raw_np is not None:
        np_val = raw_np.strip().lower()
        if np_val in ("none", "quarantine", "reject"):
            tags["np"] = np_val
        else:
            np_invalid = True

    if p_invalid or sp_invalid or np_invalid:
        # RFC 9989 Section 4.10.1:
        # Invalid policy tag with >=1 valid 'rua' URI -> treat as if p=none was retrieved.
        # Otherwise apply no DMARC processing.
        if has_valid_reporting_uri(tags.get("rua")):
            logger.info(
                "Policy syntax error detected (p_invalid=%s, sp_invalid=%s, np_invalid=%s) "
                "with valid 'rua'; acting as if record containing 'p=none' was retrieved (RFC 9989 §4.10.1)",
                p_invalid,
                sp_invalid,
                np_invalid,
            )
            tags["p"] = "none"
            tags.pop("sp", None)
            tags.pop("np", None)
            meta["policy_fallback_from_rua"] = True
            meta["p_defaulted_from_missing"] = False
        else:
            err_parts = []
            if p_invalid:
                err_parts.append(f"invalid 'p' tag value '{raw_p}'")
            if sp_invalid:
                err_parts.append(f"invalid 'sp' tag value '{raw_sp}'")
            if np_invalid:
                err_parts.append(f"invalid 'np' tag value '{raw_np}'")
            return None, f"Invalid policy tag ({'; '.join(err_parts)}) without valid rua fallback (RFC 9989 Section 4.10.1)", meta

    # Identifier alignment: adkim= and aspf= (RFC 9989 Section 4.7 & 4.8: "r" or "s", default "r")
    adkim_raw = tags.get("adkim")
    if adkim_raw is not None:
        adkim_val = adkim_raw.strip().lower()
        if adkim_val in ("r", "s"):
            tags["adkim"] = adkim_val
        else:
            logger.debug("Invalid 'adkim' value '%s'; falling back to default 'r' per RFC 9989 §4.7/4.8", adkim_raw)
            tags["adkim"] = "r"
    else:
        tags["adkim"] = "r"

    aspf_raw = tags.get("aspf")
    if aspf_raw is not None:
        aspf_val = aspf_raw.strip().lower()
        if aspf_val in ("r", "s"):
            tags["aspf"] = aspf_val
        else:
            logger.debug("Invalid 'aspf' value '%s'; falling back to default 'r' per RFC 9989 §4.7/4.8", aspf_raw)
            tags["aspf"] = "r"
    else:
        tags["aspf"] = "r"

    # Test mode: t= (RFC 9989 Section 4.7 & 4.8: "y" or "n", default "n")
    t_raw = tags.get("t")
    if t_raw is not None:
        t_val = t_raw.strip().lower()
        if t_val in ("y", "n"):
            tags["t"] = t_val
        else:
            logger.debug("Invalid 't' value '%s'; falling back to default 'n' per RFC 9989 §4.7/4.8", t_raw)
            tags["t"] = "n"
    else:
        tags["t"] = "n"

    # Public Suffix Domain flag: psd= (RFC 9989 Section 4.7 & 4.8: "y", "n", or "u", default "u")
    psd_raw = tags.get("psd")
    if psd_raw is not None:
        psd_val = psd_raw.strip().lower()
        if psd_val in ("y", "n", "u"):
            tags["psd"] = psd_val
        else:
            logger.debug("Invalid 'psd' value '%s'; falling back to default 'u' per RFC 9989 §4.7/4.8", psd_raw)
            tags["psd"] = "u"
    else:
        tags["psd"] = "u"

    return tags, None, meta


def parse_dmarc_tags(record_str: str) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    """Parses and validates a DMARC Policy Record string per RFC 9989 Section 4.7 & 4.8.

    Returns (tags_dict, error_reason). If invalid, tags_dict is None.
    Unknown or obsolete tags (e.g. historical 'pct') MUST be ignored.
    Syntax errors in tag values with defined defaults fall back to defaults per Section 4.8.
    Invalid policy tags (p, sp, np) fall back to p=none if a valid rua URI is present per Section 4.10.1.
    """
    tags, err, _ = parse_dmarc_tags_with_metadata(record_str)
    return tags, err


class DMARCRecordDiscovery:
    """Asynchronous DMARC policy discovery and bounded DNS tree walker.
    
    Standards: RFC 9989 (DMARCbis), RFC 9091
    Architecture: MS-ARCH-SEC-2026-AUTH-PROTOCOLS-REV13
    
    Invariants:
    1. Bounded Tree Walking: Strictest cap of max 8 DNS queries per discovery operation.
    2. Zero Public DNS in Tests: Exclusively relies on injected BaseDNSResolver.
    3. Multi-Record vs Multi-String Distinction: Discards non-DMARC1 TXT records;
       concatenates multi-string single TXT records; discards all if multiple DMARC records.
    4. PSD Semantics: Implements RFC 9989 Sections 4.7, 4.10.1, and 4.10.2 psd=y, psd=n,
       and psd=u handling; permits PSD operator policies while distinguishing Org Domains.
    5. No Infinite Traversal or Duplicate Queries: Strict cycle and repeated domain prevention.
    """

    def __init__(
        self,
        resolver: BaseDNSResolver,
        config: Optional[AuthProtocolsConfig] = None,
    ) -> None:
        self._resolver = resolver
        self._config = config or AuthProtocolsConfig()
        self._max_queries = max(1, self._config.dmarc_tree_walk_max_queries)

    @property
    def max_queries(self) -> int:
        return self._max_queries

    async def discover(self, domain: Optional[str]) -> DMARCDiscoveryResult:
        """Discovers the applicable DMARC policy record for a domain via bounded tree walking.
        
        Args:
            domain: The domain name being evaluated (e.g. RFC 5322 From domain).
            
        Returns:
            DMARCDiscoveryResult detailing discovery status, policy domain, org domain,
            parsed tags, and query accounting.
        """
        if not domain or not isinstance(domain, str) or not domain.strip():
            return DMARCDiscoveryResult(
                status=DMARCDiscoveryStatus.INVALID,
                protocol_status=ProtocolStatus.PERMERROR,
                domain="",
                error_reason="Domain name cannot be empty",
            )

        norm_domain = domain.strip().lower().rstrip(".")
        if not norm_domain:
            return DMARCDiscoveryResult(
                status=DMARCDiscoveryStatus.INVALID,
                protocol_status=ProtocolStatus.PERMERROR,
                domain="",
                error_reason="Domain name cannot be empty",
            )

        labels = norm_domain.split(".")
        if any(not lbl for lbl in labels):
            return DMARCDiscoveryResult(
                status=DMARCDiscoveryStatus.INVALID,
                protocol_status=ProtocolStatus.PERMERROR,
                domain=norm_domain,
                error_reason="Domain contains empty labels",
            )

        # RFC 9989 Section 4.10: Tree walk starts at Author Domain.
        # If no valid record is found and domain has >= 8 labels, it is shortened to 7 labels.
        queries_count = 0
        visited_domains: Set[str] = set()
        traversed_domains: List[str] = []
        current: Optional[str] = norm_domain

        # Retain candidate organizational records discovered with psd=u / default
        # Tuple of: (domain, tags, raw_record, tag_meta)
        candidate_records: List[Tuple[str, Dict[str, str], str, Dict[str, Any]]] = []

        try:
            while current:
                # Enforce strict maximum query budget
                if queries_count >= self._max_queries:
                    return DMARCDiscoveryResult(
                        status=DMARCDiscoveryStatus.LIMIT_EXCEEDED,
                        protocol_status=ProtocolStatus.INDETERMINATE,
                        domain=norm_domain,
                        org_domain=norm_domain,
                        policy_discovery_source="indeterminate",
                        tree_walk_queries=queries_count,
                        traversed_domains=traversed_domains,
                        error_reason=(
                            f"DMARC tree-walk query limit ({self._max_queries}) reached; "
                            f"attempted query {queries_count + 1} blocked"
                        ),
                    )

                # Avoid repeated queries and infinite loops
                if current in visited_domains:
                    break

                visited_domains.add(current)
                traversed_domains.append(current)

                query_name = f"_dmarc.{current}"
                queries_count += 1
                dns_res = await self._resolver.resolve(query_name, DNSQueryType.TXT)

                # Classify DNS infrastructure vs invalid-query failures BEFORE absence checks (H3)
                if dns_res.is_transient_error or dns_res.is_malformed_response:
                    err_msg = dns_res.error_message or dns_res.status.value
                    return DMARCDiscoveryResult(
                        status=DMARCDiscoveryStatus.TEMPERROR,
                        protocol_status=ProtocolStatus.TEMPERROR,
                        domain=norm_domain,
                        discovered_domain=current,
                        org_domain=current,
                        policy_discovery_source="temperror",
                        tree_walk_queries=queries_count,
                        traversed_domains=traversed_domains,
                        error_reason=f"DNS temporary error querying {query_name}: {err_msg}",
                    )
                if dns_res.is_invalid_query or dns_res.is_internal_error or dns_res.status == DNSResponseStatus.ERROR:
                    err_msg = dns_res.error_message or dns_res.status.value
                    return DMARCDiscoveryResult(
                        status=DMARCDiscoveryStatus.INDETERMINATE,
                        protocol_status=ProtocolStatus.INDETERMINATE,
                        domain=norm_domain,
                        discovered_domain=current,
                        org_domain=current,
                        policy_discovery_source="indeterminate",
                        tree_walk_queries=queries_count,
                        traversed_domains=traversed_domains,
                        error_reason=f"DNS invalid query or internal error querying {query_name}: {err_msg}",
                    )

                txt_values = dns_res.txt_values()

                # Authoritative absence (NXDOMAIN/NODATA) or valid TXT response with no DMARC records
                if dns_res.is_authoritative_absence or not txt_values:
                    current = self._get_next_domain(current, norm_domain, labels)
                    continue

                # RFC 9989 Section 4.10 Generic Steps 2 & 6:
                # Filter TXT records that identify current DMARC version (v=DMARC1).
                # Unrelated TXT records (non-DMARC) are discarded.
                dmarc_candidates = [t for t in txt_values if is_dmarc_version1_record(t)]

                if not dmarc_candidates:
                    # No DMARC Policy Record at this target; discard non-DMARC records and continue
                    current = self._get_next_domain(current, norm_domain, labels)
                    continue

                # RFC 9989 Section 4.10 Generic Steps 2 & 6:
                # If multiple DMARC Policy Records are returned for a single target, they are all discarded.
                if len(dmarc_candidates) > 1:
                    current = self._get_next_domain(current, norm_domain, labels)
                    continue

                # Exactly one DMARC policy record candidate
                raw_record = dmarc_candidates[0]
                tags, err, tag_meta = parse_dmarc_tags_with_metadata(raw_record)
                if err is not None:
                    # Malformed DMARC record syntax
                    return DMARCDiscoveryResult(
                        status=DMARCDiscoveryStatus.INVALID,
                        protocol_status=ProtocolStatus.PERMERROR,
                        domain=norm_domain,
                        discovered_domain=current,
                        org_domain=current,
                        raw_record=raw_record,
                        policy_discovery_source="permerror",
                        tree_walk_queries=queries_count,
                        traversed_domains=traversed_domains,
                        error_reason=f"Malformed DMARC record at {query_name}: {err}",
                    )

                assert tags is not None
                psd_tag = tags.get("psd", "u").lower()
                is_psd = (psd_tag == "y")

                # Case A: Found directly at Author Domain (exact domain match)
                if current == norm_domain:
                    return DMARCDiscoveryResult(
                        status=DMARCDiscoveryStatus.FOUND,
                        protocol_status=ProtocolStatus.PASS,
                        domain=norm_domain,
                        discovered_domain=current,
                        org_domain=norm_domain,
                        raw_record=raw_record,
                        tags=tags,
                        tree_walk_queries=queries_count,
                        psd_type=psd_tag,
                        is_psd=is_psd,
                        policy_discovery_source="author_domain",
                        p_defaulted_from_missing=bool(tag_meta.get("p_defaulted_from_missing")),
                        policy_fallback_from_rua=bool(tag_meta.get("policy_fallback_from_rua")),
                        traversed_domains=traversed_domains,
                    )

                # Case B: Found at parent domain - evaluate PSD rules (RFC 9989 Sections 4.7, 4.10.1, 4.10.2)
                if psd_tag == "y":
                    child_org_domain = self._get_domain_below_psd(norm_domain, current)
                    # L1 / RFC 9989 §§4.10.1 & 4.10.2: Only the exact Organizational Domain
                    # one label below the PSD may act as org_domain policy; an unrelated intermediate
                    # psd=u subdomain below child_org_domain MUST NOT shadow the PSD policy.
                    matching_org_candidates = [
                        c for c in candidate_records if c[0] == child_org_domain
                    ]
                    if matching_org_candidates:
                        cand_domain, cand_tags, cand_raw, cand_meta = matching_org_candidates[0]
                        return DMARCDiscoveryResult(
                            status=DMARCDiscoveryStatus.FOUND,
                            protocol_status=ProtocolStatus.PASS,
                            domain=norm_domain,
                            discovered_domain=cand_domain,
                            org_domain=child_org_domain,
                            raw_record=cand_raw,
                            tags=cand_tags,
                            tree_walk_queries=queries_count,
                            psd_type=cand_tags.get("psd", "u").lower(),
                            is_psd=False,
                            policy_discovery_source="org_domain",
                            p_defaulted_from_missing=bool(cand_meta.get("p_defaulted_from_missing")),
                            policy_fallback_from_rua=bool(cand_meta.get("policy_fallback_from_rua")),
                            traversed_domains=traversed_domains,
                        )

                    # RFC 9989 Section 4.10.1: Child Organizational Domain published no policy -> PSD policy APPLIES
                    return DMARCDiscoveryResult(
                        status=DMARCDiscoveryStatus.FOUND,
                        protocol_status=ProtocolStatus.PASS,
                        domain=norm_domain,
                        discovered_domain=current,
                        org_domain=child_org_domain,
                        raw_record=raw_record,
                        tags=tags,
                        tree_walk_queries=queries_count,
                        psd_type="y",
                        is_psd=True,
                        policy_discovery_source="psd",
                        p_defaulted_from_missing=bool(tag_meta.get("p_defaulted_from_missing")),
                        policy_fallback_from_rua=bool(tag_meta.get("policy_fallback_from_rua")),
                        traversed_domains=traversed_domains,
                    )

                if psd_tag == "n":
                    # RFC 9989 Section 4.10 Step 2/6: If record contains psd=n, stop tree walk
                    return DMARCDiscoveryResult(
                        status=DMARCDiscoveryStatus.FOUND,
                        protocol_status=ProtocolStatus.PASS,
                        domain=norm_domain,
                        discovered_domain=current,
                        org_domain=current,
                        raw_record=raw_record,
                        tags=tags,
                        tree_walk_queries=queries_count,
                        psd_type="n",
                        is_psd=False,
                        policy_discovery_source="org_domain",
                        p_defaulted_from_missing=bool(tag_meta.get("p_defaulted_from_missing")),
                        policy_fallback_from_rua=bool(tag_meta.get("policy_fallback_from_rua")),
                        traversed_domains=traversed_domains,
                    )

                # psd=u or omitted at parent domain: store candidate and continue upward
                candidate_records.append((current, tags, raw_record, tag_meta))
                current = self._get_next_domain(current, norm_domain, labels)

            # Post-traversal evaluation of candidates (RFC 9989 Section 4.10.2 rule 3)
            if candidate_records:
                cand_domain, cand_tags, cand_raw, cand_meta = min(
                    candidate_records, key=lambda c: len(c[0].split("."))
                )
                return DMARCDiscoveryResult(
                    status=DMARCDiscoveryStatus.FOUND,
                    protocol_status=ProtocolStatus.PASS,
                    domain=norm_domain,
                    discovered_domain=cand_domain,
                    org_domain=cand_domain,
                    raw_record=cand_raw,
                    tags=cand_tags,
                    tree_walk_queries=queries_count,
                    psd_type=cand_tags.get("psd", "u").lower(),
                    is_psd=False,
                    policy_discovery_source="org_domain",
                    p_defaulted_from_missing=bool(cand_meta.get("p_defaulted_from_missing")),
                    policy_fallback_from_rua=bool(cand_meta.get("policy_fallback_from_rua")),
                    traversed_domains=traversed_domains,
                )

            if queries_count >= self._max_queries:
                return DMARCDiscoveryResult(
                    status=DMARCDiscoveryStatus.LIMIT_EXCEEDED,
                    protocol_status=ProtocolStatus.INDETERMINATE,
                    domain=norm_domain,
                    org_domain=norm_domain,
                    policy_discovery_source="indeterminate",
                    tree_walk_queries=queries_count,
                    traversed_domains=traversed_domains,
                    error_reason=(
                        f"DMARC tree-walk query limit ({self._max_queries}) reached without finding policy"
                    ),
                )

            # No record found across traversed tree (RFC 9989 Section 4.10.1 & 4.10.2)
            return DMARCDiscoveryResult(
                status=DMARCDiscoveryStatus.ABSENT,
                protocol_status=ProtocolStatus.NONE,
                domain=norm_domain,
                org_domain=norm_domain,
                policy_discovery_source="none",
                tree_walk_queries=queries_count,
                traversed_domains=traversed_domains,
                error_reason="No DMARC policy record found across traversed domain tree",
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return DMARCDiscoveryResult(
                status=DMARCDiscoveryStatus.INDETERMINATE,
                protocol_status=ProtocolStatus.INDETERMINATE,
                domain=norm_domain,
                org_domain=norm_domain,
                policy_discovery_source="indeterminate",
                tree_walk_queries=queries_count,
                traversed_domains=traversed_domains,
                error_reason=f"DMARC internal discovery error ({type(exc).__name__})",
            )

    @classmethod
    def _get_next_domain(cls, current: str, norm_domain: str, labels: List[str]) -> Optional[str]:
        """Returns the next domain to query per RFC 9989 Section 4.10.
        
        If departing from the author domain and it has 8 or more labels,
        the domain is shortened to 7 labels. Otherwise, leftmost label is stripped.
        """
        if current == norm_domain and len(labels) >= 8:
            return ".".join(labels[-7:])
        return cls._get_parent_domain(current)

    @staticmethod
    def _get_parent_domain(domain_str: str) -> Optional[str]:
        """Returns parent domain by stripping leftmost label, or None if at top-level."""
        if "." not in domain_str:
            return None
        parent = domain_str.split(".", 1)[1].strip(".")
        return parent if parent else None

    @staticmethod
    def _get_domain_below_psd(child_domain: str, psd_domain: str) -> str:
        """Returns the domain one label below psd_domain in child_domain's hierarchy per RFC 9989 Section 4.10.2."""
        child_labels = child_domain.split(".")
        psd_labels = psd_domain.split(".")
        target_len = len(psd_labels) + 1
        if len(child_labels) >= target_len:
            return ".".join(child_labels[-target_len:])
        return child_domain

    async def determine_org_domain(
        self, domain: Optional[str]
    ) -> Tuple[str, DMARCDiscoveryStatus, int]:
        """Determines the RFC 9989 Section 4.10.2 Organizational Domain for a domain name.

        Standards: RFC 9989 Section 4.10.2 (Identifier Alignment Org Domain Determination).
        This process is authoritative for relaxed identifier alignment checks and distinct
        from Section 4.10.1 (Policy Discovery).

        Rules:
        1. If a DMARC Policy Record is found that contains "psd=n", the query process
           is complete, and this domain is the Organizational Domain.
        2. If a DMARC Policy Record is found that contains "psd=y", the query process
           is complete, and the domain one label below this PSD in the DNS hierarchy
           is the Organizational Domain.
        3. If candidate records were retrieved with psd=u (or omitted), select the
           candidate record found at the name with the fewest number of labels.
           This is the Organizational Domain.
        4. If no records were retrieved across the tree, the initial target domain
           is the Organizational Domain.
        """
        if not domain or not isinstance(domain, str) or not domain.strip():
            return "", DMARCDiscoveryStatus.INVALID, 0

        norm_domain = domain.strip().lower().rstrip(".")
        if not norm_domain:
            return "", DMARCDiscoveryStatus.INVALID, 0

        labels = norm_domain.split(".")
        if any(not lbl for lbl in labels):
            return norm_domain, DMARCDiscoveryStatus.INVALID, 0

        queries_count = 0
        visited_domains: Set[str] = set()
        current: Optional[str] = norm_domain
        candidate_records: List[str] = []

        try:
            while current:
                if queries_count >= self._max_queries:
                    return norm_domain, DMARCDiscoveryStatus.LIMIT_EXCEEDED, queries_count

                if current in visited_domains:
                    break
                visited_domains.add(current)

                query_name = f"_dmarc.{current}"
                queries_count += 1
                dns_res = await self._resolver.resolve(query_name, DNSQueryType.TXT)

                if dns_res.is_transient_error or dns_res.is_malformed_response:
                    return current, DMARCDiscoveryStatus.TEMPERROR, queries_count
                if dns_res.is_invalid_query or dns_res.is_internal_error or dns_res.status == DNSResponseStatus.ERROR:
                    return current, DMARCDiscoveryStatus.INDETERMINATE, queries_count

                txt_values = dns_res.txt_values()
                if dns_res.is_authoritative_absence or not txt_values:
                    current = self._get_next_domain(current, norm_domain, labels)
                    continue

                dmarc_candidates = [t for t in txt_values if is_dmarc_version1_record(t)]
                if not dmarc_candidates or len(dmarc_candidates) > 1:
                    # Discard non-DMARC or multiple DMARC records per RFC 9989 §4.10
                    current = self._get_next_domain(current, norm_domain, labels)
                    continue

                raw_record = dmarc_candidates[0]
                tags, err = parse_dmarc_tags(raw_record)
                if err is not None:
                    # Discard malformed record per RFC 9989 §4.10
                    current = self._get_next_domain(current, norm_domain, labels)
                    continue

                assert tags is not None
                psd_tag = tags.get("psd", "u").lower()

                # Rule 1: psd=n marks the Organizational Domain boundary
                if psd_tag == "n":
                    return current, DMARCDiscoveryStatus.FOUND, queries_count

                # Rule 2: psd=y marks a PSD; the domain one label below is the Org Domain.
                # RFC 9989 §4.10.2: Rule 2 only applies to records found other than at the starting domain of the walk.
                if psd_tag == "y" and current != norm_domain:
                    child_org = self._get_domain_below_psd(norm_domain, current)
                    return child_org, DMARCDiscoveryStatus.FOUND, queries_count

                # Rule 3: psd=u (or omitted, or psd=y at starting domain) -> candidate organizational record
                candidate_records.append(current)
                current = self._get_next_domain(current, norm_domain, labels)

            # Rule 3: select candidate record with fewest labels
            if candidate_records:
                best_org = min(candidate_records, key=lambda d: len(d.split(".")))
                return best_org, DMARCDiscoveryStatus.FOUND, queries_count

            if queries_count >= self._max_queries:
                return norm_domain, DMARCDiscoveryStatus.LIMIT_EXCEEDED, queries_count

            # Rule 4: If no records retrieved, initial target domain is Org Domain
            return norm_domain, DMARCDiscoveryStatus.ABSENT, queries_count
        except asyncio.CancelledError:
            raise
        except Exception:
            return norm_domain, DMARCDiscoveryStatus.INDETERMINATE, queries_count


class AlignmentOutcome:
    """Outcome of identifier alignment evaluation per RFC 9989 Section 4.4 and Section 4.10.2."""

    def __init__(
        self,
        is_aligned: bool,
        aligned_strict: bool,
        aligned_relaxed: bool,
        discovery_status: Optional[DMARCDiscoveryStatus] = None,
        auth_org_domain: Optional[str] = None,
        from_org_domain: Optional[str] = None,
    ) -> None:
        self.is_aligned = is_aligned
        self.aligned_strict = aligned_strict
        self.aligned_relaxed = aligned_relaxed
        self.discovery_status = discovery_status
        self.auth_org_domain = auth_org_domain
        self.from_org_domain = from_org_domain

    def __iter__(self):
        yield self.is_aligned
        yield self.aligned_strict
        yield self.aligned_relaxed

    def __getitem__(self, index: int):
        return (self.is_aligned, self.aligned_strict, self.aligned_relaxed)[index]

    def __len__(self) -> int:
        return 3

    def __repr__(self) -> str:
        return (
            f"AlignmentOutcome(is_aligned={self.is_aligned}, aligned_strict={self.aligned_strict}, "
            f"aligned_relaxed={self.aligned_relaxed}, discovery_status={self.discovery_status}, "
            f"auth_org={self.auth_org_domain}, from_org={self.from_org_domain})"
        )


async def _resolve_org_domain_with_cache(
    domain_norm: str,
    disc_runner: DMARCRecordDiscovery,
    org_domain_cache: Optional[Dict[str, Any]],
) -> Tuple[Optional[str], DMARCDiscoveryStatus]:
    """Resolves Organizational Domain via cache or bounded RFC 9989 Tree Walk safely."""
    if org_domain_cache is not None and domain_norm in org_domain_cache:
        cached = org_domain_cache[domain_norm]
        if isinstance(cached, tuple):
            return cached[0], cached[1]
        if isinstance(cached, DMARCDiscoveryResult):
            if cached.psd_type == "n" and cached.discovered_domain:
                return cached.discovered_domain, cached.status
            if cached.status in (
                DMARCDiscoveryStatus.TEMPERROR,
                DMARCDiscoveryStatus.LIMIT_EXCEEDED,
                DMARCDiscoveryStatus.INDETERMINATE,
                DMARCDiscoveryStatus.INVALID,
            ):
                return cached.org_domain or domain_norm, cached.status
        else:
            return str(cached), DMARCDiscoveryStatus.FOUND

    try:
        org_dom, status, _ = await disc_runner.determine_org_domain(domain_norm)
    except asyncio.CancelledError:
        raise
    except Exception:
        org_dom, status = domain_norm, DMARCDiscoveryStatus.INDETERMINATE

    if org_domain_cache is not None:
        org_domain_cache[domain_norm] = (org_dom, status)
    return org_dom, status


async def check_domain_alignment(
    auth_domain: Optional[str],
    from_domain: Optional[str],
    mode: AlignmentMode = AlignmentMode.RELAXED,
    org_domain_hint: Optional[str] = None,
    org_domain_from: Optional[str] = None,
    discovery: Optional[DMARCRecordDiscovery] = None,
    resolver: Optional[BaseDNSResolver] = None,
    org_domain_cache: Optional[Dict[str, Any]] = None,
) -> AlignmentOutcome:
    """Evaluates identifier alignment between an authenticated domain and RFC 5322 From domain.

    Standards: RFC 9989 Section 4.4, Section 4.10.2, RFC 4343 (case-insensitivity).

    Requirements (RFC 9989 §4.10.2):
    1. If auth_domain and from_domain match exactly (case-insensitive normalized),
       both strict and relaxed alignment are satisfied when domain determinations succeed.
    2. Strict alignment requires exact match.
    3. Relaxed alignment requires that both domains share the same RFC 9989 Section 4.10.2
       Organizational Domain determined via authoritative DNS Tree Walk (NOT PSL heuristics).
    4. Internal/limit/transient failures (INDETERMINATE, TEMPERROR, LIMIT_EXCEEDED) are
       propagated explicitly and never masked by another path's FOUND result.
    """
    if not auth_domain or not from_domain:
        return AlignmentOutcome(
            is_aligned=False,
            aligned_strict=False,
            aligned_relaxed=False,
            discovery_status=DMARCDiscoveryStatus.INVALID,
        )

    a_norm = normalize_domain(auth_domain)
    f_norm = normalize_domain(from_domain)
    if not a_norm or not f_norm:
        return AlignmentOutcome(
            is_aligned=False,
            aligned_strict=False,
            aligned_relaxed=False,
            discovery_status=DMARCDiscoveryStatus.INVALID,
        )

    try:
        a_norm = idna.encode(a_norm, uts46=True, transitional=False).decode("ascii").lower()
    except Exception:
        pass
    try:
        f_norm = idna.encode(f_norm, uts46=True, transitional=False).decode("ascii").lower()
    except Exception:
        pass

    aligned_strict = (a_norm == f_norm)

    disc_runner = discovery
    if disc_runner is None and resolver is not None:
        disc_runner = DMARCRecordDiscovery(resolver=resolver)

    if disc_runner is None:
        effective_from = org_domain_from or org_domain_hint
        if effective_from:
            from_org_norm = normalize_domain(effective_from)
            try:
                from_org_norm = idna.encode(from_org_norm, uts46=True, transitional=False).decode("ascii").lower()
            except Exception:
                pass
            aligned_relaxed = aligned_strict or (a_norm == from_org_norm and f_norm == from_org_norm)
            is_aligned = aligned_strict if mode == AlignmentMode.STRICT else aligned_relaxed
            return AlignmentOutcome(
                is_aligned=is_aligned,
                aligned_strict=aligned_strict,
                aligned_relaxed=aligned_relaxed,
                discovery_status=DMARCDiscoveryStatus.FOUND if aligned_strict else DMARCDiscoveryStatus.INDETERMINATE,
                auth_org_domain=from_org_norm if aligned_strict else None,
                from_org_domain=from_org_norm,
            )

        if aligned_strict:
            return AlignmentOutcome(
                is_aligned=True,
                aligned_strict=True,
                aligned_relaxed=True,
                discovery_status=DMARCDiscoveryStatus.FOUND,
                auth_org_domain=f_norm,
                from_org_domain=f_norm,
            )

        return AlignmentOutcome(
            is_aligned=False,
            aligned_strict=aligned_strict,
            aligned_relaxed=False,
            discovery_status=DMARCDiscoveryStatus.INDETERMINATE,
        )

    # 1. Determine Author Domain's Organizational Domain per RFC 9989 Section 4.10.2
    from_org, f_status = await _resolve_org_domain_with_cache(f_norm, disc_runner, org_domain_cache)

    if f_status in (
        DMARCDiscoveryStatus.TEMPERROR,
        DMARCDiscoveryStatus.LIMIT_EXCEEDED,
        DMARCDiscoveryStatus.INDETERMINATE,
        DMARCDiscoveryStatus.INVALID,
    ):
        return AlignmentOutcome(
            is_aligned=False,
            aligned_strict=aligned_strict,
            aligned_relaxed=False,
            discovery_status=f_status,
            from_org_domain=from_org,
        )

    if aligned_strict:
        return AlignmentOutcome(
            is_aligned=True,
            aligned_strict=True,
            aligned_relaxed=True,
            discovery_status=DMARCDiscoveryStatus.FOUND,
            auth_org_domain=from_org,
            from_org_domain=from_org,
        )

    # 2. Determine Authenticated Identifier's Organizational Domain per RFC 9989 Section 4.10.2
    auth_org, a_status = await _resolve_org_domain_with_cache(a_norm, disc_runner, org_domain_cache)

    if a_status in (
        DMARCDiscoveryStatus.TEMPERROR,
        DMARCDiscoveryStatus.LIMIT_EXCEEDED,
        DMARCDiscoveryStatus.INDETERMINATE,
        DMARCDiscoveryStatus.INVALID,
    ):
        return AlignmentOutcome(
            is_aligned=False,
            aligned_strict=aligned_strict,
            aligned_relaxed=False,
            discovery_status=a_status,
            auth_org_domain=auth_org,
            from_org_domain=from_org,
        )

    # 3. Compare Organizational Domains per RFC 9989 Section 4.4 and Section 4.10.2
    aligned_relaxed = bool(from_org and auth_org and auth_org.lower() == from_org.lower())
    is_aligned = aligned_strict if mode == AlignmentMode.STRICT else aligned_relaxed
    final_status = (
        DMARCDiscoveryStatus.FOUND
        if (a_status == DMARCDiscoveryStatus.FOUND or f_status == DMARCDiscoveryStatus.FOUND)
        else DMARCDiscoveryStatus.ABSENT
    )

    return AlignmentOutcome(
        is_aligned=is_aligned,
        aligned_strict=aligned_strict,
        aligned_relaxed=aligned_relaxed,
        discovery_status=final_status,
        auth_org_domain=auth_org,
        from_org_domain=from_org,
    )


class DMARCEvaluator:
    """Asynchronous DMARC Identifier Alignment Engine and Authentication Evaluator per RFC 9989.
    
    Standards: RFC 9989 (DMARCbis), RFC 5322, RFC 7208, RFC 6376
    Architecture: MS-ARCH-SEC-2026-AUTH-PROTOCOLS-REV13
    """

    def __init__(
        self,
        resolver: Optional[BaseDNSResolver] = None,
        discovery: Optional[DMARCRecordDiscovery] = None,
        config: Optional[AuthProtocolsConfig] = None,
    ) -> None:
        self._config = config or AuthProtocolsConfig()
        if discovery is not None:
            self._discovery = discovery
        elif resolver is not None:
            self._discovery = DMARCRecordDiscovery(resolver=resolver, config=self._config)
        else:
            raise ValueError("Either 'resolver' or 'discovery' must be provided to DMARCEvaluator")

    @property
    def discovery(self) -> DMARCRecordDiscovery:
        return self._discovery

    async def evaluate(
        self,
        from_domain: Optional[str],
        spf_result: Optional[SPFResult] = None,
        dkim_results: Optional[List[DKIMSignatureResult]] = None,
        discovery_result: Optional[DMARCDiscoveryResult] = None,
        is_subdomain_non_existent: Optional[bool] = None,
        all_from_domains: Optional[List[str]] = None,
        dkim_evaluated: bool = True,
        check_subdomain_existence: Optional[bool] = None,
        dkim_evaluation_state: Optional[DKIMEvaluationState] = None,
    ) -> DMARCResult:
        """Evaluates DMARC authentication for an email message.

        The core DMARC evaluation rule (RFC 9989 Section 5.3.5):
        DMARC PASS = (SPF PASS and SPF aligned) OR (DKIM PASS and at least one DKIM signature aligned).
        Preserves RFC 9989 §5.3.6 / §9.2 error semantics and MailSentra incomplete-evaluation safety.
        """
        try:
            # 1. Validate RFC 5322 From Domain(s) (RFC 9989 Section 5.3.1 & Section 11.5)
            if all_from_domains is not None:
                normalized_multi: List[str] = []
                for item in all_from_domains:
                    raw_item = (item or "").strip()
                    if "@" in raw_item:
                        raw_item = raw_item.split("@")[-1].strip().rstrip(">")
                    norm_item = normalize_domain(raw_item)
                    if norm_item:
                        try:
                            norm_item = idna.encode(norm_item, uts46=True, transitional=False).decode("ascii").lower()
                        except Exception:
                            pass
                        if norm_item not in normalized_multi:
                            normalized_multi.append(norm_item)

                if len(normalized_multi) == 0:
                    return DMARCResult(
                        status=ProtocolStatus.PERMERROR,
                        standard_status="permerror",
                        internal_status=ProtocolStatus.PERMERROR,
                        policy=DMARCPolicy.NOT_CONFIGURED,
                        policy_discovery_source="permerror",
                        error_reason="Missing RFC 5322 From domain",
                        diagnostics={"classification_origin": "rfc9989_5_3_1_missing_from"},
                    )
                if len(normalized_multi) > 1:
                    return DMARCResult(
                        status=ProtocolStatus.PERMERROR,
                        standard_status="permerror",
                        internal_status=ProtocolStatus.PERMERROR,
                        policy=DMARCPolicy.NOT_CONFIGURED,
                        from_domain=normalized_multi[0],
                        policy_discovery_source="permerror",
                        error_reason=(
                            "Multiple distinct RFC 5322 From domains present; DMARC validation not possible "
                            "(RFC 9989 Sections 5.3.1 & 11.5)"
                        ),
                        diagnostics={
                            "classification_origin": "rfc9989_5_3_1_multiple_from",
                            "from_domains_checked": normalized_multi,
                        },
                    )
                if not from_domain:
                    from_domain = normalized_multi[0]

            if not from_domain or not isinstance(from_domain, str) or not from_domain.strip():
                return DMARCResult(
                    status=ProtocolStatus.PERMERROR,
                    standard_status="permerror",
                    internal_status=ProtocolStatus.PERMERROR,
                    policy=DMARCPolicy.NOT_CONFIGURED,
                    policy_discovery_source="permerror",
                    error_reason="Missing or empty RFC 5322 From domain",
                    diagnostics={"classification_origin": "rfc9989_5_3_1_missing_from"},
                )

            raw_from = from_domain.strip()
            if "@" in raw_from:
                raw_from = raw_from.split("@")[-1].strip().rstrip(">")

            norm_from = normalize_domain(raw_from)
            if not norm_from or "." not in norm_from:
                return DMARCResult(
                    status=ProtocolStatus.PERMERROR,
                    standard_status="permerror",
                    internal_status=ProtocolStatus.PERMERROR,
                    policy=DMARCPolicy.NOT_CONFIGURED,
                    from_domain=norm_from or raw_from,
                    policy_discovery_source="permerror",
                    error_reason=f"Malformed RFC 5322 From domain '{from_domain}'",
                    diagnostics={"classification_origin": "rfc9989_5_3_1_malformed_from"},
                )

            try:
                norm_from = idna.encode(norm_from, uts46=True, transitional=False).decode("ascii").lower()
            except Exception:
                pass

            # 2. Policy Discovery (RFC 9989 Section 4.10.1 & Section 5.3.2)
            if discovery_result is None:
                discovery_result = await self._discovery.discover(norm_from)

            effective_org_domain = discovery_result.org_domain or discovery_result.discovered_domain or norm_from

            if discovery_result.status == DMARCDiscoveryStatus.ABSENT:
                return DMARCResult(
                    status=ProtocolStatus.NONE,
                    standard_status="none",
                    internal_status=ProtocolStatus.NONE,
                    policy=DMARCPolicy.NOT_CONFIGURED,
                    policy_discovery_source="none",
                    from_domain=norm_from,
                    org_domain=effective_org_domain,
                    tree_walk_queries=discovery_result.tree_walk_queries,
                    psd_type=discovery_result.psd_type,
                    error_reason=discovery_result.error_reason or "No DMARC policy record found",
                    diagnostics={"classification_origin": "rfc9989_4_10_1_no_policy"},
                )

            if discovery_result.status == DMARCDiscoveryStatus.TEMPERROR:
                return DMARCResult(
                    status=ProtocolStatus.TEMPERROR,
                    standard_status="temperror",
                    internal_status=ProtocolStatus.TEMPERROR,
                    policy=DMARCPolicy.NOT_CONFIGURED,
                    policy_discovery_source="temperror",
                    policy_domain=discovery_result.discovered_domain,
                    from_domain=norm_from,
                    org_domain=effective_org_domain,
                    tree_walk_queries=discovery_result.tree_walk_queries,
                    psd_type=discovery_result.psd_type,
                    error_reason=discovery_result.error_reason or "DNS transient error during DMARC policy discovery",
                    diagnostics={"classification_origin": "rfc9989_5_3_6_discovery_temperror"},
                )

            if discovery_result.status in (DMARCDiscoveryStatus.LIMIT_EXCEEDED, DMARCDiscoveryStatus.INDETERMINATE):
                origin = (
                    "rfc9989_4_10_query_limit_exceeded"
                    if discovery_result.status == DMARCDiscoveryStatus.LIMIT_EXCEEDED
                    else "internal_discovery_error"
                )
                return DMARCResult(
                    status=ProtocolStatus.INDETERMINATE,
                    standard_status=None,
                    internal_status=ProtocolStatus.INDETERMINATE,
                    policy=DMARCPolicy.NOT_CONFIGURED,
                    policy_discovery_source="indeterminate",
                    from_domain=norm_from,
                    org_domain=effective_org_domain,
                    tree_walk_queries=discovery_result.tree_walk_queries,
                    psd_type=discovery_result.psd_type,
                    error_reason=discovery_result.error_reason or "DMARC discovery did not complete",
                    diagnostics={"classification_origin": origin},
                )

            if discovery_result.status != DMARCDiscoveryStatus.FOUND:
                return DMARCResult(
                    status=ProtocolStatus.PERMERROR,
                    standard_status="permerror",
                    internal_status=ProtocolStatus.PERMERROR,
                    policy=DMARCPolicy.NOT_CONFIGURED,
                    policy_discovery_source="permerror",
                    policy_domain=discovery_result.discovered_domain,
                    from_domain=norm_from,
                    org_domain=effective_org_domain,
                    tree_walk_queries=discovery_result.tree_walk_queries,
                    psd_type=discovery_result.psd_type,
                    error_reason=discovery_result.error_reason or f"DMARC discovery failure: {discovery_result.status.value}",
                    diagnostics={"classification_origin": "rfc9989_4_10_1_permerror"},
                )

            # 3. Applicable Policy Selection (RFC 9989 Section 4.10.1)
            tags = discovery_result.tags
            discovered_domain = (discovery_result.discovered_domain or norm_from).lower()
            raw_record = discovery_result.raw_record

            p_val = tags.get("p", "none").lower()
            policy_enum = DMARCPolicy(p_val) if p_val in ("none", "quarantine", "reject") else DMARCPolicy.NONE

            sp_val = tags.get("sp", "").lower()
            sub_policy = DMARCPolicy(sp_val) if sp_val in ("none", "quarantine", "reject") else None

            np_val = tags.get("np", "").lower()
            non_existent_policy = DMARCPolicy(np_val) if np_val in ("none", "quarantine", "reject") else None

            t_val = tags.get("t", "n").lower()
            test_mode = (t_val == "y")

            # Author domain is a strict subdomain of the discovered policy domain
            is_subdomain = (norm_from != discovered_domain and norm_from.endswith("." + discovered_domain))
            policy_discovery_source = (
                "author_domain"
                if not is_subdomain
                else ("psd" if discovery_result.is_psd else "org_domain")
            )

            probe_enabled = (
                self._config.dmarc_enable_subdomain_existence_probe
                if check_subdomain_existence is None
                else bool(check_subdomain_existence)
            )
            subdomain_existence_temperror = False
            subdomain_existence_indeterminate = False
            subdomain_existence_status: Optional[str] = None
            np_evaluation_skipped_reason: Optional[str] = None
            recorded_non_existent_flag: Optional[bool] = is_subdomain_non_existent

            if not is_subdomain:
                effective_is_non_existent = False
                subdomain_existence_status = "not_subdomain"
            elif is_subdomain_non_existent is not None:
                effective_is_non_existent = bool(is_subdomain_non_existent)
                recorded_non_existent_flag = effective_is_non_existent
                subdomain_existence_status = (
                    "confirmed_non_existent" if effective_is_non_existent else "confirmed_existing"
                )
            elif probe_enabled:
                if non_existent_policy is None:
                    effective_is_non_existent = False
                    recorded_non_existent_flag = None
                    subdomain_existence_status = "probe_skipped_no_np_tag"
                elif discovery_result.tree_walk_queries >= self._config.max_total_dns_queries_per_scan:
                    subdomain_existence_indeterminate = True
                    effective_is_non_existent = False
                    recorded_non_existent_flag = None
                    subdomain_existence_status = "unknown_budget_exhausted"
                    np_evaluation_skipped_reason = "dns_query_budget_exhausted"
                else:
                    # RFC 9989 Appendix A.4: NXDOMAIN means non-existent; NODATA or record means existing.
                    probe_res = await self._discovery._resolver.resolve(norm_from, DNSQueryType.A)
                    if probe_res.is_transient_error or probe_res.is_malformed_response:
                        subdomain_existence_temperror = True
                        effective_is_non_existent = False
                        recorded_non_existent_flag = None
                        subdomain_existence_status = "unknown_dns_temperror"
                        np_evaluation_skipped_reason = "subdomain_existence_probe_temperror"
                    elif probe_res.is_invalid_query or probe_res.is_internal_error or probe_res.status == DNSResponseStatus.ERROR:
                        subdomain_existence_indeterminate = True
                        effective_is_non_existent = False
                        recorded_non_existent_flag = None
                        subdomain_existence_status = "unknown_dns_error"
                        np_evaluation_skipped_reason = "subdomain_existence_probe_error"
                    elif probe_res.is_nxdomain:
                        effective_is_non_existent = True
                        recorded_non_existent_flag = True
                        subdomain_existence_status = "confirmed_non_existent"
                    else:
                        effective_is_non_existent = False
                        recorded_non_existent_flag = False
                        subdomain_existence_status = "confirmed_existing"
            else:
                effective_is_non_existent = False
                recorded_non_existent_flag = None
                if non_existent_policy is not None:
                    subdomain_existence_status = "unknown_probe_disabled"
                    np_evaluation_skipped_reason = "subdomain_existence_probe_disabled"
                else:
                    subdomain_existence_status = "not_probed_no_np_tag"

            p_base_tag = (
                "p_rua_fallback"
                if discovery_result.policy_fallback_from_rua
                else ("p_default_missing" if discovery_result.p_defaulted_from_missing else "p")
            )

            # RFC 9989 §4.10.1 strictly (NOT naive np > sp > p):
            # - Author Domain record: ONLY p applies (sp/np ignored).
            # - Org Domain / PSD record + non-existent subdomain: np -> sp -> p.
            # - Org Domain / PSD record + existing subdomain: sp -> p (np MUST NOT apply).
            if not is_subdomain:
                applicable_policy = policy_enum
                applicable_policy_tag = p_base_tag
                policy_selection_reason = f"Author Domain record at '{discovered_domain}' uses p={policy_enum.value}"
            elif effective_is_non_existent:
                if non_existent_policy is not None:
                    applicable_policy = non_existent_policy
                    applicable_policy_tag = "np"
                    policy_selection_reason = (
                        f"Non-existent subdomain under {policy_discovery_source} '{discovered_domain}' uses np={non_existent_policy.value}"
                    )
                elif sub_policy is not None:
                    applicable_policy = sub_policy
                    applicable_policy_tag = "sp"
                    policy_selection_reason = (
                        f"Non-existent subdomain under {policy_discovery_source} '{discovered_domain}' falls back to sp={sub_policy.value} (np absent)"
                    )
                else:
                    applicable_policy = policy_enum
                    applicable_policy_tag = p_base_tag
                    policy_selection_reason = (
                        f"Non-existent subdomain under {policy_discovery_source} '{discovered_domain}' falls back to p={policy_enum.value} (np/sp absent)"
                    )
            else:
                if sub_policy is not None:
                    applicable_policy = sub_policy
                    applicable_policy_tag = "sp"
                    policy_selection_reason = (
                        f"Existing subdomain under {policy_discovery_source} '{discovered_domain}' uses sp={sub_policy.value}"
                    )
                else:
                    applicable_policy = policy_enum
                    applicable_policy_tag = p_base_tag
                    policy_selection_reason = (
                        f"Existing subdomain under {policy_discovery_source} '{discovered_domain}' falls back to p={policy_enum.value} (sp absent; np inapplicable)"
                    )

            # Alignment modes (RFC 9989 Section 4.7: defaults to "r")
            aspf_tag = tags.get("aspf", "r").lower()
            aspf_mode = AlignmentMode.STRICT if aspf_tag == "s" else AlignmentMode.RELAXED

            adkim_tag = tags.get("adkim", "r").lower()
            adkim_mode = AlignmentMode.STRICT if adkim_tag == "s" else AlignmentMode.RELAXED

            org_domain_cache: Dict[str, Any] = {norm_from: discovery_result}
            identifier_transient_error = False
            identifier_limit_exceeded = False
            identifier_internal_error = False
            internal_error_messages: List[str] = []

            # 4. SPF Identifier Alignment (RFC 9989 Section 4.4.2 & Section 5.3.3)
            spf_aligned = False
            spf_aligned_strict = False
            spf_aligned_relaxed = False

            is_synthesized_bounce = (
                spf_result is not None
                and bool(spf_result.is_null_reverse_path)
                and bool(spf_result.is_synthesized_mfrom)
                and not bool(spf_result.is_standalone_helo)
            )
            is_normal_mfrom = (
                spf_result is not None
                and (spf_result.scope or "").lower() == "mfrom"
                and not bool(spf_result.is_null_reverse_path)
                and not bool(spf_result.is_standalone_helo)
                and not bool(spf_result.is_synthesized_mfrom)
            )
            is_valid_dmarc_spf_identity = is_normal_mfrom or is_synthesized_bounce
            spf_standalone_helo_ignored = (
                spf_result is not None
                and not is_valid_dmarc_spf_identity
                and (
                    spf_result.is_standalone_helo
                    or (spf_result.scope or "").lower() == "helo"
                )
            )

            if is_valid_dmarc_spf_identity and spf_result.status == ProtocolStatus.PASS and spf_result.domain:
                spf_auth_domain = normalize_domain(spf_result.domain)
                if spf_auth_domain:
                    try:
                        outcome = await check_domain_alignment(
                            auth_domain=spf_auth_domain,
                            from_domain=norm_from,
                            mode=aspf_mode,
                            discovery=self._discovery,
                            org_domain_cache=org_domain_cache,
                        )
                        spf_aligned = outcome.is_aligned
                        spf_aligned_strict = outcome.aligned_strict
                        spf_aligned_relaxed = outcome.aligned_relaxed
                        if outcome.from_org_domain:
                            effective_org_domain = outcome.from_org_domain
                        if outcome.discovery_status == DMARCDiscoveryStatus.TEMPERROR:
                            identifier_transient_error = True
                        elif outcome.discovery_status == DMARCDiscoveryStatus.LIMIT_EXCEEDED:
                            identifier_limit_exceeded = True
                        elif outcome.discovery_status == DMARCDiscoveryStatus.INDETERMINATE:
                            identifier_internal_error = True
                            internal_error_messages.append("spf_alignment_org_domain_indeterminate")
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        identifier_internal_error = True
                        internal_error_messages.append(f"SPF alignment error ({type(exc).__name__})")

            # 5. DKIM Identifier Alignment (RFC 9989 Section 4.4.1 & Section 5.3.3)
            # Authoritative RFC 9989 §4.10.2 Org Domain Tree Walk always supersedes any standalone PSL hint.
            dkim_aligned = False
            dkim_aligned_strict = False
            dkim_aligned_relaxed = False

            if dkim_results:
                for sig in dkim_results:
                    if sig.standalone_psl_aligned_relaxed is None and sig.alignment_source == "standalone_psl_diagnostic_only":
                        sig.standalone_psl_aligned_relaxed = sig.aligned_relaxed

                    if sig.status == ProtocolStatus.PASS and sig.domain:
                        sig_domain = normalize_domain(sig.domain)
                        if sig_domain:
                            try:
                                outcome = await check_domain_alignment(
                                    auth_domain=sig_domain,
                                    from_domain=norm_from,
                                    mode=adkim_mode,
                                    discovery=self._discovery,
                                    org_domain_cache=org_domain_cache,
                                )
                                sig.is_aligned_with_from = outcome.is_aligned
                                sig.aligned_strict = outcome.aligned_strict
                                sig.aligned_relaxed = outcome.aligned_relaxed
                                align_completed = outcome.discovery_status in (
                                    DMARCDiscoveryStatus.FOUND,
                                    DMARCDiscoveryStatus.ABSENT,
                                )
                                sig.alignment_source = (
                                    "dmarc_tree_walk_authoritative"
                                    if align_completed
                                    else "dmarc_tree_walk_incomplete"
                                )
                                sig.alignment_is_authoritative = align_completed
                                if outcome.from_org_domain:
                                    effective_org_domain = outcome.from_org_domain
                                if outcome.aligned_strict:
                                    dkim_aligned_strict = True
                                if outcome.aligned_relaxed:
                                    dkim_aligned_relaxed = True
                                if outcome.is_aligned:
                                    dkim_aligned = True
                                if outcome.discovery_status == DMARCDiscoveryStatus.TEMPERROR:
                                    identifier_transient_error = True
                                elif outcome.discovery_status == DMARCDiscoveryStatus.LIMIT_EXCEEDED:
                                    identifier_limit_exceeded = True
                                elif outcome.discovery_status == DMARCDiscoveryStatus.INDETERMINATE:
                                    identifier_internal_error = True
                                    internal_error_messages.append("dkim_alignment_org_domain_indeterminate")
                            except asyncio.CancelledError:
                                raise
                            except Exception as exc:
                                sig.is_aligned_with_from = False
                                sig.aligned_strict = False
                                sig.aligned_relaxed = False
                                sig.alignment_source = "dmarc_tree_walk_incomplete"
                                sig.alignment_is_authoritative = False
                                identifier_internal_error = True
                                internal_error_messages.append(f"DKIM alignment error ({type(exc).__name__})")
                    else:
                        sig.is_aligned_with_from = False
                        sig.aligned_strict = False
                        sig.aligned_relaxed = False
                        sig.alignment_source = "dmarc_tree_walk_authoritative"
                        sig.alignment_is_authoritative = True

            # Classify input mechanism completion & error states via structured types (no prose substring matching)
            spf_is_incomplete = (
                spf_result is None
                or spf_result.status in (ProtocolStatus.NOT_EVALUATED, ProtocolStatus.INDETERMINATE)
            )
            spf_is_temperror = (
                spf_result is not None and spf_result.status == ProtocolStatus.TEMPERROR
            )
            dkim_missing_bytes = (
                dkim_evaluation_state == DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES
                or (
                    bool(dkim_results)
                    and all(
                        s.evaluation_state == DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES
                        or s.reason_code == "MISSING_RAW_MESSAGE_BYTES"
                        or s.status == ProtocolStatus.NOT_EVALUATED
                        for s in dkim_results
                    )
                )
            )
            dkim_has_incomplete_status = (
                dkim_evaluation_state == DKIMEvaluationState.INCOMPLETE_INTERNAL_ERROR
                or (
                    bool(dkim_results)
                    and any(
                        s.evaluation_state == DKIMEvaluationState.INCOMPLETE_INTERNAL_ERROR
                        or s.status in (ProtocolStatus.INDETERMINATE, ProtocolStatus.NOT_EVALUATED)
                        for s in dkim_results
                    )
                )
            )
            dkim_has_temperror = (
                dkim_evaluation_state == DKIMEvaluationState.INCOMPLETE_TRANSIENT_ERROR
                or (
                    bool(dkim_results)
                    and any(
                        s.evaluation_state == DKIMEvaluationState.INCOMPLETE_TRANSIENT_ERROR
                        or s.status == ProtocolStatus.TEMPERROR
                        for s in dkim_results
                    )
                )
            )
            dkim_is_incomplete = (
                (not dkim_evaluated)
                or dkim_missing_bytes
                or dkim_has_incomplete_status
            )

            if (not dkim_evaluated) or dkim_missing_bytes:
                effective_dkim_eval_state = DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES
            elif dkim_has_temperror:
                effective_dkim_eval_state = DKIMEvaluationState.INCOMPLETE_TRANSIENT_ERROR
            elif dkim_has_incomplete_status:
                effective_dkim_eval_state = DKIMEvaluationState.INCOMPLETE_INTERNAL_ERROR
            elif not dkim_results or dkim_evaluation_state == DKIMEvaluationState.EVALUATED_NO_SIGNATURES:
                effective_dkim_eval_state = DKIMEvaluationState.EVALUATED_NO_SIGNATURES
            else:
                effective_dkim_eval_state = DKIMEvaluationState.EVALUATED_COMPLETED

            incomplete_reasons: List[str] = []
            if spf_result is None:
                incomplete_reasons.append("spf_not_provided_or_not_evaluated")
            elif spf_result.status in (ProtocolStatus.NOT_EVALUATED, ProtocolStatus.INDETERMINATE):
                incomplete_reasons.append(f"spf_{spf_result.status.value.lower()}")
            if not dkim_evaluated:
                incomplete_reasons.append("dkim_not_evaluated")
            if dkim_missing_bytes:
                incomplete_reasons.append("dkim_missing_raw_message_bytes")
            if dkim_has_incomplete_status:
                incomplete_reasons.append("dkim_internal_incomplete_or_error")
            if subdomain_existence_indeterminate:
                identifier_internal_error = True
                incomplete_reasons.append(np_evaluation_skipped_reason or "subdomain_existence_probe_error")
            if identifier_limit_exceeded:
                incomplete_reasons.append("tree_walk_query_limit_exceeded")
            if identifier_internal_error:
                incomplete_reasons.extend(internal_error_messages)

            transient_sources: List[str] = []
            if identifier_transient_error:
                transient_sources.append("alignment_tree_walk_dns_temperror")
            if spf_is_temperror:
                transient_sources.append("spf_temperror")
            if dkim_has_temperror:
                transient_sources.append("dkim_temperror")
            if subdomain_existence_temperror:
                transient_sources.append("subdomain_existence_probe_temperror")

            # 6. Final DMARC Authentication Decision (RFC 9989 §§5.3.5, 5.3.6, 9.2 + MailSentra Safety Model)
            dmarc_pass = (spf_aligned or dkim_aligned)
            if dmarc_pass:
                auth_status = ProtocolStatus.PASS
                std_status = "pass"
                internal_status = ProtocolStatus.PASS
                classification_origin = "rfc9989_5_3_5_pass"
            elif transient_sources:
                # RFC 9989 §5.3.6 & §9.2: transient DNS error preventing validation yields temperror, never FAIL
                auth_status = ProtocolStatus.TEMPERROR
                std_status = "temperror"
                internal_status = ProtocolStatus.TEMPERROR
                classification_origin = "rfc9989_5_3_6_temperror"
            elif identifier_limit_exceeded or identifier_internal_error or spf_is_incomplete or dkim_is_incomplete:
                # MailSentra Safety Model: incomplete evaluations / local software errors NEVER claim FAIL;
                # RFC 9989 §9.2 does not standardize INDETERMINATE so rfc_status/standard_status MUST be None.
                auth_status = ProtocolStatus.INDETERMINATE
                std_status = None
                internal_status = ProtocolStatus.INDETERMINATE
                classification_origin = (
                    "internal_evaluator_error"
                    if identifier_internal_error
                    else "mailsentra_channel_safety_incomplete"
                )
            else:
                auth_status = ProtocolStatus.FAIL
                std_status = "fail"
                internal_status = ProtocolStatus.FAIL
                classification_origin = "rfc9989_5_3_5_fail"

            # Diagnostic explanation
            diag_parts: List[str] = []
            if spf_aligned:
                diag_parts.append(f"SPF PASS aligned ({aspf_mode.value}) with '{spf_result.domain}'")
            elif spf_standalone_helo_ignored:
                diag_parts.append("SPF standalone HELO check ignored for DMARC (RFC 9989 §4.4.2)")
            elif spf_result and spf_result.status == ProtocolStatus.PASS:
                diag_parts.append(f"SPF PASS unaligned ({aspf_mode.value}) with '{spf_result.domain}'")
            elif spf_result:
                diag_parts.append(f"SPF {spf_result.status.value}")
            else:
                diag_parts.append("SPF not evaluated")

            if dkim_aligned:
                aligned_sigs = [s.domain for s in (dkim_results or []) if s.is_aligned_with_from and s.domain]
                diag_parts.append(f"DKIM PASS aligned ({adkim_mode.value}) with {aligned_sigs}")
            elif dkim_results and any(s.status == ProtocolStatus.PASS for s in dkim_results):
                passed_sigs = [s.domain for s in dkim_results if s.status == ProtocolStatus.PASS and s.domain]
                diag_parts.append(f"DKIM PASS unaligned ({adkim_mode.value}) with {passed_sigs}")
            elif not dkim_evaluated or dkim_missing_bytes:
                diag_parts.append("DKIM unavailable / not evaluated")
            elif dkim_has_incomplete_status:
                diag_parts.append("DKIM evaluation incomplete / internal error")
            elif dkim_has_temperror:
                diag_parts.append("DKIM verification encountered transient DNS/worker error")
            elif dkim_results:
                diag_parts.append("DKIM signatures failed verification")
            else:
                diag_parts.append("No DKIM signatures evaluated")

            if transient_sources and not dmarc_pass:
                diag_parts.append(f"Transient error sources: {', '.join(transient_sources)}")
            elif incomplete_reasons and not dmarc_pass:
                diag_parts.append(f"Incomplete evaluation reasons: {', '.join(incomplete_reasons)}")

            summary_reason = f"DMARC {auth_status.value}: {'; '.join(diag_parts)}"
            diagnostics: Dict[str, Any] = {
                "classification_origin": classification_origin,
                "policy_selection_reason": policy_selection_reason,
                "policy_discovery_source": policy_discovery_source,
                "policy_domain": discovered_domain,
                "applicable_policy_tag": applicable_policy_tag,
                "record_p_policy": policy_enum.value,
                "selected_applicable_policy": applicable_policy.value,
                "subdomain_existence_probe_enabled": probe_enabled,
                "subdomain_existence_status": subdomain_existence_status,
                "np_evaluation_skipped_reason": np_evaluation_skipped_reason,
                "test_mode": test_mode,
                "spf_input_status": spf_result.status.value if spf_result else ProtocolStatus.NOT_EVALUATED.value,
                "dkim_input_statuses": [s.status.value for s in (dkim_results or [])],
                "dkim_evaluated": dkim_evaluated,
                "dkim_evaluation_state": effective_dkim_eval_state.value,
                "dkim_alignment_source": "dmarc_tree_walk_authoritative",
                "dkim_alignment_authoritative": True,
                "incomplete_reasons": incomplete_reasons,
                "transient_error_sources": transient_sources,
            }

            return DMARCResult(
                status=auth_status,
                standard_status=std_status,
                internal_status=internal_status,
                policy=applicable_policy,
                record_p_policy=policy_enum,
                subdomain_policy=sub_policy,
                non_existent_subdomain_policy=non_existent_policy,
                applicable_policy_tag=applicable_policy_tag,
                policy_discovery_source=policy_discovery_source,
                policy_domain=discovered_domain,
                is_psd_policy=discovery_result.is_psd,
                is_subdomain=is_subdomain,
                is_subdomain_non_existent=recorded_non_existent_flag,
                subdomain_existence_probe_enabled=probe_enabled,
                subdomain_existence_status=subdomain_existence_status,
                np_evaluation_skipped_reason=np_evaluation_skipped_reason,
                test_mode=test_mode,
                org_domain=effective_org_domain,
                from_domain=norm_from,
                evaluated_record=raw_record,
                raw_tags=dict(tags),
                tree_walk_queries=discovery_result.tree_walk_queries,
                psd_type=discovery_result.psd_type,
                spf_aligned=spf_aligned,
                dkim_aligned=dkim_aligned,
                spf_alignment_mode=aspf_mode,
                dkim_alignment_mode=adkim_mode,
                spf_aligned_relaxed=spf_aligned_relaxed,
                spf_aligned_strict=spf_aligned_strict,
                dkim_aligned_relaxed=dkim_aligned_relaxed,
                dkim_aligned_strict=dkim_aligned_strict,
                error_reason=summary_reason if auth_status != ProtocolStatus.PASS else None,
                diagnostics=diagnostics,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Unexpected exception during DMARC evaluation: %s", exc)
            return DMARCResult(
                status=ProtocolStatus.INDETERMINATE,
                standard_status=None,
                internal_status=ProtocolStatus.INDETERMINATE,
                policy=DMARCPolicy.NOT_CONFIGURED,
                policy_discovery_source="indeterminate",
                from_domain=from_domain,
                error_reason=f"DMARC internal evaluator exception ({type(exc).__name__})",
                diagnostics={
                    "classification_origin": "internal_evaluator_error",
                    "exception_type": type(exc).__name__,
                },
            )

    async def evaluate_auth_protocols(
        self,
        from_domain: Optional[str],
        auth_result: AuthProtocolsResult,
        discovery_result: Optional[DMARCDiscoveryResult] = None,
        is_subdomain_non_existent: Optional[bool] = None,
        all_from_domains: Optional[List[str]] = None,
        dkim_evaluated: Optional[bool] = None,
        check_subdomain_existence: Optional[bool] = None,
    ) -> DMARCResult:
        """Evaluates DMARC directly using an existing AuthProtocolsResult container."""
        effective_dkim_eval = (
            dkim_evaluated
            if dkim_evaluated is not None
            else (
                auth_result.dkim_evaluation_state != DKIMEvaluationState.NOT_EVALUATED_MISSING_RAW_BYTES
                and (
                    auth_result.dkim_status != ProtocolStatus.NOT_EVALUATED
                    or len(auth_result.dkim_signatures) > 0
                )
            )
        )
        dmarc_res = await self.evaluate(
            from_domain=from_domain,
            spf_result=auth_result.spf_details,
            dkim_results=auth_result.dkim_signatures,
            discovery_result=discovery_result,
            is_subdomain_non_existent=is_subdomain_non_existent,
            all_from_domains=all_from_domains,
            dkim_evaluated=effective_dkim_eval,
            check_subdomain_existence=check_subdomain_existence,
            dkim_evaluation_state=auth_result.dkim_evaluation_state,
        )
        diag_dkim_state = (dmarc_res.diagnostics or {}).get("dkim_evaluation_state")
        if diag_dkim_state:
            auth_result.dkim_evaluation_state = DKIMEvaluationState(diag_dkim_state)
        auth_result.execution_telemetry = {
            **(auth_result.execution_telemetry or {}),
            "dkim_evaluation_state": diag_dkim_state,
            "dkim_alignment_source": "dmarc_tree_walk_authoritative",
            "dkim_alignment_authoritative": True,
        }
        auth_result.dmarc_status = dmarc_res.status
        auth_result.dmarc_policy = dmarc_res.policy
        auth_result.dmarc_aligned_spf = dmarc_res.spf_aligned
        auth_result.dmarc_aligned_dkim = dmarc_res.dkim_aligned
        auth_result.spf_alignment_mode = dmarc_res.spf_alignment_mode
        auth_result.dkim_alignment_mode = dmarc_res.dkim_alignment_mode
        auth_result.spf_aligned_relaxed = dmarc_res.spf_aligned_relaxed
        auth_result.spf_aligned_strict = dmarc_res.spf_aligned_strict
        auth_result.dkim_aligned_relaxed = dmarc_res.dkim_aligned_relaxed
        auth_result.dkim_aligned_strict = dmarc_res.dkim_aligned_strict
        auth_result.dmarc_test_mode = dmarc_res.test_mode
        auth_result.dmarc_details = dmarc_res
        return dmarc_res


