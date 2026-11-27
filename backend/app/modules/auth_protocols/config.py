"""Configuration settings for Module 4 (Authentication Protocols)."""

import re
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator

AUTHSERV_ID_PATTERN = re.compile(
    r"^(?=.{1,255}$)[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*$"
)


class AuthProtocolsConfig(BaseModel):
    """Configuration and resource budgets for SPF, DKIM, DMARC, and DNS resolution."""

    # DNS Resolver Transport & Limits
    nameservers: Optional[List[str]] = None  # None: system default resolv.conf / OS adapters
    dns_port: int = 53
    dns_query_timeout: float = 2.0  # seconds per query
    dns_total_lifetime: float = 5.0  # seconds maximum overall query lifetime
    max_concurrent_dns_queries: int = 16  # bounded concurrency semaphore
    dns_cache_max_entries: int = 1000  # bounded LRU cache size
    dns_cache_max_ttl: int = 3600  # seconds maximum cache TTL clamp (authoritative TTL is never extended)
    cache_negative_responses: bool = True  # RFC 2308 negative response caching
    max_negative_cache_ttl: int = 3600  # seconds maximum negative cache TTL clamp (RFC 2308 Section 3)

    # Security & Standards Budgets
    max_total_dns_queries_per_scan: int = 15  # Strict MailSentra product budget
    spf_global_dns_term_limit: int = 10  # RFC 7208 Section 4.6.4 global limit
    spf_subordinate_address_limit: int = 10  # RFC 7208 per-MX / per-PTR address records
    spf_max_void_lookups: int = 2  # Product security void-lookup budget (RFC 7208 Section 4.6.4)
    dmarc_tree_walk_max_queries: int = 8  # RFC 9989 Section 4.10 tree walk query limit

    # DMARC Subdomain Existence Probe (RFC 9989 §4.10.1 & Appendix A.4)
    # Disabled by default to prevent extra DNS queries when offline/static or when budget is tight;
    # when False and `np=` is present, DMARCResult records skipped provenance explicitly.
    dmarc_enable_subdomain_existence_probe: bool = False

    # DKIM Verification Concurrency
    dkim_worker_threads: int = 8  # Bounded ThreadPoolExecutor workers
    dkim_queue_capacity: int = 24  # Maximum queued verification jobs
    dkim_verification_timeout: float = 3.0  # seconds per verification attempt

    # Authentication-Results Trusted Boundaries
    local_authserv_id: Optional[str] = None
    trusted_authserv_ids: List[str] = Field(default_factory=list)

    @field_validator("local_authserv_id", mode="before")
    @classmethod
    def _validate_local_authserv_id(cls, value: Any) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("local_authserv_id must be a string or None.")
        clean_val = value.strip()
        if not clean_val:
            return None
        if len(clean_val) > 255:
            raise ValueError(
                f"local_authserv_id exceeds maximum RFC 8601 length of 255 characters (length={len(clean_val)})."
            )
        # Disallow control characters, whitespace, semicolons, quotes, colons, slashes
        if any(ord(c) < 33 or ord(c) > 126 or c in ';:"\'/\\[]()<>' for c in clean_val):
            raise ValueError(
                f"local_authserv_id contains disallowed whitespace, control characters, or delimiters: '{clean_val}'"
            )
        if not AUTHSERV_ID_PATTERN.match(clean_val):
            raise ValueError(
                f"local_authserv_id must conform to RFC 8601 Section 2.5 FQDN/atom syntax: '{clean_val}'"
            )
        return clean_val

    @field_validator("trusted_authserv_ids", mode="before")
    @classmethod
    def _validate_trusted_authserv_ids(cls, value: Any) -> List[str]:
        if value is None:
            return []
        if not isinstance(value, (list, tuple, set)):
            raise ValueError("trusted_authserv_ids must be a sequence of strings.")
        validated: List[str] = []
        for item in value:
            if not isinstance(item, str):
                raise ValueError("All elements in trusted_authserv_ids must be strings.")
            clean_item = item.strip()
            if not clean_item:
                continue
            if len(clean_item) > 255 or any(ord(c) < 33 or ord(c) > 126 or c in ';:"\'/\\[]()<>' for c in clean_item):
                raise ValueError(
                    f"trusted_authserv_id item contains disallowed characters or exceeds 255 chars: '{clean_item}'"
                )
            if not AUTHSERV_ID_PATTERN.match(clean_item):
                raise ValueError(
                    f"trusted_authserv_id item must conform to RFC 8601 Section 2.5 syntax: '{clean_item}'"
                )
            validated.append(clean_item)
        return validated

    # DMARC Receiver-Local Disposition & Enforcement Policy (Step 3.7.3B)
    dmarc_temperror_smtp_action: Literal["defer", "accept"] = "defer"
    # Deprecated mandatory RFC 9989 §7.4 safeguard: rejecting solely on p=reject without
    # corroborating analysis is disallowed; setting this to False raises a ValidationError.
    dmarc_enforce_strict_reject_only_with_corroboration: bool = True
    trusted_forwarder_connector_ids: List[str] = Field(default_factory=list)
    trusted_forwarder_ips: List[str] = Field(default_factory=list)
    trusted_forwarder_bindings: Dict[str, List[str]] = Field(default_factory=dict)
    local_override_rules: List[Any] = Field(default_factory=list)

    @field_validator("dmarc_enforce_strict_reject_only_with_corroboration", mode="before")
    @classmethod
    def _validate_rfc9989_7_4_safeguard(cls, value: Any) -> bool:
        if not isinstance(value, bool):
            raise ValueError(
                "dmarc_enforce_strict_reject_only_with_corroboration must be boolean True "
                "(strict RFC 9989 Section 7.4 safeguard cannot be bypassed)."
            )
        if value is not True:
            raise ValueError(
                "RFC 9989 Section 7.4 prohibits rejecting incoming mail solely on published p=reject "
                "without corroborating knowledge and analysis; "
                "dmarc_enforce_strict_reject_only_with_corroboration cannot be False."
            )
        return True
