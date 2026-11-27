"""Bounded asynchronous DNS resolver and deterministic mock framework for MailSentra.

Provides:
- Strongly typed DNS response models and error taxonomies.
- TTL-aware LRU memory cache with clock injection.
- Production AsyncDNSResolver wrapping dnspython with bounded concurrency and timeouts.
- Deterministic MockDNSResolver for offline, zero-network unit testing.
"""

from abc import ABC, abstractmethod
import asyncio
from collections import OrderedDict
from datetime import datetime, timezone
from enum import Enum
import ipaddress
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import dns.asyncresolver
import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver
import dns.reversename
from pydantic import BaseModel, ConfigDict, Field

from app.modules.auth_protocols.config import AuthProtocolsConfig


class DNSQueryType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    MX = "MX"
    TXT = "TXT"
    PTR = "PTR"


class DNSErrorType(str, Enum):
    NXDOMAIN = "NXDOMAIN"
    NODATA = "NODATA"
    TIMEOUT = "TIMEOUT"
    SERVFAIL = "SERVFAIL"
    REFUSED = "REFUSED"
    FORMERR = "FORMERR"
    INVALID_QUERY = "INVALID_QUERY"
    RESOLVER_ERROR = "RESOLVER_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class DNSResponseStatus(str, Enum):
    SUCCESS = "SUCCESS"
    NXDOMAIN = "NXDOMAIN"
    NODATA = "NODATA"
    TIMEOUT = "TIMEOUT"
    SERVFAIL = "SERVFAIL"
    ERROR = "ERROR"


class DNSOutcomeCategory(str, Enum):
    """Explicit classification of DNS outcomes separating authoritative absence from resolver failures."""

    VALID_RECORDS = "VALID_RECORDS"
    AUTHORITATIVE_NXDOMAIN = "AUTHORITATIVE_NXDOMAIN"
    NODATA = "NODATA"
    TRANSIENT_FAILURE = "TRANSIENT_FAILURE"
    RESOLVER_FAILURE = "RESOLVER_FAILURE"
    INVALID_QUERY = "INVALID_QUERY"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


_TRANSIENT_ERROR_TYPES = {
    DNSErrorType.TIMEOUT,
    DNSErrorType.SERVFAIL,
    DNSErrorType.REFUSED,
    DNSErrorType.RESOLVER_ERROR,
}


class DNSRecord(BaseModel):
    record_type: DNSQueryType
    value: str
    ttl: int = 300
    preference: Optional[int] = None  # Populated for MX records


class DNSError(Exception):
    """Raised when a DNS query fails and raise_on_error is True."""

    def __init__(
        self,
        error_type: DNSErrorType,
        domain: str,
        query_type: DNSQueryType,
        message: str,
    ):
        super().__init__(f"DNS query failed [{error_type.value}] for {domain} ({query_type.value}): {message}")
        self.error_type = error_type
        self.domain = domain
        self.query_type = query_type
        self.message = message


class DNSResponse(BaseModel):
    domain: str
    query_type: DNSQueryType
    status: DNSResponseStatus = DNSResponseStatus.SUCCESS
    records: List[DNSRecord] = Field(default_factory=list)
    ttl: int = 0
    is_cached: bool = False
    error_type: Optional[DNSErrorType] = None
    error_message: Optional[str] = None
    resolved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def outcome_category(self) -> DNSOutcomeCategory:
        if self.status == DNSResponseStatus.NXDOMAIN:
            return DNSOutcomeCategory.AUTHORITATIVE_NXDOMAIN
        if self.status == DNSResponseStatus.NODATA:
            return DNSOutcomeCategory.NODATA
        if self.status in (DNSResponseStatus.TIMEOUT, DNSResponseStatus.SERVFAIL):
            return DNSOutcomeCategory.TRANSIENT_FAILURE
        if self.status == DNSResponseStatus.ERROR:
            if self.error_type == DNSErrorType.INVALID_QUERY:
                return DNSOutcomeCategory.INVALID_QUERY
            if self.error_type == DNSErrorType.INTERNAL_ERROR:
                return DNSOutcomeCategory.INTERNAL_ERROR
            if self.error_type == DNSErrorType.FORMERR:
                return DNSOutcomeCategory.MALFORMED_RESPONSE
            if self.error_type in _TRANSIENT_ERROR_TYPES:
                return DNSOutcomeCategory.TRANSIENT_FAILURE
            return DNSOutcomeCategory.RESOLVER_FAILURE
        if self.status == DNSResponseStatus.SUCCESS and len(self.records) > 0:
            return DNSOutcomeCategory.VALID_RECORDS
        return DNSOutcomeCategory.MALFORMED_RESPONSE

    @property
    def is_success(self) -> bool:
        return self.status == DNSResponseStatus.SUCCESS and len(self.records) > 0

    @property
    def is_nxdomain(self) -> bool:
        return self.status == DNSResponseStatus.NXDOMAIN

    @property
    def is_nodata(self) -> bool:
        return self.status == DNSResponseStatus.NODATA

    @property
    def is_void(self) -> bool:
        """Authoritative absence only (NXDOMAIN or NOERROR/NODATA); never returns True on errors."""
        return self.status in (DNSResponseStatus.NXDOMAIN, DNSResponseStatus.NODATA)

    @property
    def is_authoritative_absence(self) -> bool:
        return self.status in (DNSResponseStatus.NXDOMAIN, DNSResponseStatus.NODATA)

    @property
    def is_transient_error(self) -> bool:
        return self.outcome_category in (
            DNSOutcomeCategory.TRANSIENT_FAILURE,
            DNSOutcomeCategory.RESOLVER_FAILURE,
        )

    @property
    def is_invalid_query(self) -> bool:
        return self.outcome_category == DNSOutcomeCategory.INVALID_QUERY

    @property
    def is_internal_error(self) -> bool:
        return self.outcome_category == DNSOutcomeCategory.INTERNAL_ERROR

    @property
    def is_malformed_response(self) -> bool:
        return self.outcome_category == DNSOutcomeCategory.MALFORMED_RESPONSE

    @property
    def is_resolver_failure(self) -> bool:
        return self.status in (
            DNSResponseStatus.TIMEOUT,
            DNSResponseStatus.SERVFAIL,
            DNSResponseStatus.ERROR,
        )

    @property
    def has_error(self) -> bool:
        return self.status != DNSResponseStatus.SUCCESS or len(self.records) == 0

    def raise_for_status(self) -> None:
        if self.has_error:
            raise DNSError(
                error_type=self.error_type or DNSErrorType.RESOLVER_ERROR,
                domain=self.domain,
                query_type=self.query_type,
                message=self.error_message or f"DNS resolution resulted in {self.status.value}",
            )

    def txt_values(self) -> List[str]:
        return [r.value for r in self.records if r.record_type == DNSQueryType.TXT]

    def a_values(self) -> List[str]:
        return [r.value for r in self.records if r.record_type == DNSQueryType.A]

    def aaaa_values(self) -> List[str]:
        return [r.value for r in self.records if r.record_type == DNSQueryType.AAAA]

    def mx_values(self) -> List[Tuple[int, str]]:
        """Returns MX records sorted by preference ascending."""
        mxs = [
            (r.preference if r.preference is not None else 0, r.value)
            for r in self.records
            if r.record_type == DNSQueryType.MX
        ]
        return sorted(mxs, key=lambda x: x[0])

    def ptr_values(self) -> List[str]:
        return [r.value for r in self.records if r.record_type == DNSQueryType.PTR]


class _CacheEntry:
    __slots__ = ("response", "expires_at")

    def __init__(self, response: DNSResponse, expires_at: float):
        self.response = response
        self.expires_at = expires_at


class DNSCache:
    """Bounded, TTL-aware LRU cache for DNS query results."""

    def __init__(
        self,
        max_entries: int = 1000,
        max_ttl: int = 3600,
        cache_negative: bool = True,
        max_negative_ttl: int = 3600,
        clock: Optional[Callable[[], float]] = None,
    ):
        self.max_entries = max_entries
        self.max_ttl = max_ttl
        self.cache_negative = cache_negative
        self.max_negative_ttl = max_negative_ttl
        self._clock = clock or time.monotonic
        self._cache: OrderedDict[Tuple[str, DNSQueryType], _CacheEntry] = OrderedDict()

    def get(self, domain: str, query_type: DNSQueryType) -> Optional[DNSResponse]:
        key = (domain.lower().rstrip("."), query_type)
        entry = self._cache.get(key)
        if entry is None:
            return None

        # Check TTL expiration
        now = self._clock()
        if now >= entry.expires_at:
            del self._cache[key]
            return None

        # Move to most-recently-used position (LRU maintenance)
        self._cache.move_to_end(key)
        cached_resp = entry.response.model_copy(update={"is_cached": True})
        return cached_resp

    def put(self, domain: str, query_type: DNSQueryType, response: DNSResponse) -> None:
        # Never cache transient, internal, or resolver errors (TIMEOUT, SERVFAIL, REFUSED, ERROR)
        if response.is_transient_error or response.is_internal_error or response.status == DNSResponseStatus.ERROR:
            return

        now = self._clock()
        if response.is_void:
            if not self.cache_negative:
                return
            # RFC 2308: negative TTL derived strictly from SOA (min(SOA.ttl, SOA.minimum))
            # If SOA was missing, invalid, or response.ttl <= 0: DO NOT CACHE
            if response.ttl <= 0:
                return
            effective_ttl = min(self.max_negative_ttl, response.ttl)
        else:
            # Positive response: evaluate records
            if not response.records:
                return
            # Shortest TTL among all records in the response
            min_record_ttl = min(r.ttl for r in response.records)
            # Never cache zero-TTL records
            if min_record_ttl <= 0:
                return
            # Cap by max_ttl; authoritative TTL is NEVER extended by any minimum TTL!
            effective_ttl = min(self.max_ttl, min_record_ttl)

        if effective_ttl <= 0:
            return

        key = (domain.lower().rstrip("."), query_type)
        expires_at = now + effective_ttl

        # Evict oldest entry if at capacity
        if key not in self._cache and len(self._cache) >= self.max_entries:
            self._cache.popitem(last=False)

        self._cache[key] = _CacheEntry(response=response, expires_at=expires_at)
        self._cache.move_to_end(key)

    def clear(self) -> None:
        self._cache.clear()

    @property
    def size(self) -> int:
        return len(self._cache)


class BaseDNSResolver(ABC):
    """Abstract interface for asynchronous DNS resolution."""

    def __init__(self):
        self._total_queries: int = 0
        self._cache_hits: int = 0
        self._cache_misses: int = 0
        self._void_lookups: int = 0
        self._transient_errors: int = 0

    @property
    def total_queries(self) -> int:
        return self._total_queries

    @property
    def cache_hits(self) -> int:
        return self._cache_hits

    @property
    def cache_misses(self) -> int:
        return self._cache_misses

    @property
    def void_lookups(self) -> int:
        return self._void_lookups

    @property
    def transient_errors(self) -> int:
        return self._transient_errors

    def reset_telemetry(self) -> None:
        self._total_queries = 0
        self._cache_hits = 0
        self._cache_misses = 0
        self._void_lookups = 0
        self._transient_errors = 0

    @abstractmethod
    async def resolve(
        self,
        domain: str,
        query_type: Union[DNSQueryType, str],
        raise_on_error: bool = False,
    ) -> DNSResponse:
        """Resolve a DNS query for domain and query_type."""
        pass

    async def resolve_txt(self, domain: str) -> List[str]:
        resp = await self.resolve(domain, DNSQueryType.TXT)
        return resp.txt_values()

    async def resolve_a(self, domain: str) -> List[str]:
        resp = await self.resolve(domain, DNSQueryType.A)
        return resp.a_values()

    async def resolve_aaaa(self, domain: str) -> List[str]:
        resp = await self.resolve(domain, DNSQueryType.AAAA)
        return resp.aaaa_values()

    async def resolve_mx(self, domain: str) -> List[Tuple[int, str]]:
        resp = await self.resolve(domain, DNSQueryType.MX)
        return resp.mx_values()

    async def resolve_ptr(self, ip_address: str) -> List[str]:
        resp = await self.resolve(ip_address, DNSQueryType.PTR)
        return resp.ptr_values()


class AsyncDNSResolver(BaseDNSResolver):
    """Production asynchronous DNS resolver wrapping dnspython with bounded concurrency and timeouts."""

    def __init__(
        self,
        config: Optional[AuthProtocolsConfig] = None,
        clock: Optional[Callable[[], float]] = None,
    ):
        super().__init__()
        self.config = config or AuthProtocolsConfig()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent_dns_queries)
        self.cache = DNSCache(
            max_entries=self.config.dns_cache_max_entries,
            max_ttl=self.config.dns_cache_max_ttl,
            cache_negative=self.config.cache_negative_responses,
            max_negative_ttl=self.config.max_negative_cache_ttl,
            clock=clock,
        )

        # Initialize underlying dnspython async resolver
        self._resolver = dns.asyncresolver.Resolver()
        if self.config.nameservers:
            self._resolver.nameservers = list(self.config.nameservers)
        self._resolver.port = self.config.dns_port
        self._resolver.timeout = self.config.dns_query_timeout
        self._resolver.lifetime = self.config.dns_total_lifetime

    def _extract_soa_negative_ttl(
        self, exc: Union[dns.resolver.NXDOMAIN, dns.resolver.NoAnswer]
    ) -> Optional[int]:
        """Derives RFC 2308 negative cache TTL: min(SOA.ttl, SOA.minimum).

        Returns None if SOA record is absent or unusable.
        """
        response = getattr(exc, "response", None)
        if response is None:
            return None

        for rrset in getattr(response, "authority", []):
            if rrset.rdtype == dns.rdatatype.SOA:
                try:
                    soa_ttl = int(rrset.ttl)
                    soa_minimum = int(rrset[0].minimum)
                    if soa_ttl > 0 and soa_minimum > 0:
                        return min(soa_ttl, soa_minimum)
                except (AttributeError, IndexError, ValueError):
                    continue
        return None

    def _normalize_query(self, domain: str, qtype: Union[DNSQueryType, str]) -> Tuple[str, DNSQueryType]:
        if isinstance(qtype, str):
            try:
                qtype_enum = DNSQueryType(qtype.upper())
            except ValueError:
                raise DNSError(
                    error_type=DNSErrorType.INVALID_QUERY,
                    domain=domain,
                    query_type=DNSQueryType.A,
                    message=f"Unsupported DNS record type: {qtype}",
                )
        else:
            qtype_enum = qtype

        cleaned_domain = domain.strip().rstrip(".")
        if not cleaned_domain:
            raise DNSError(
                error_type=DNSErrorType.INVALID_QUERY,
                domain=domain,
                query_type=qtype_enum,
                message="DNS query domain cannot be empty",
            )

        return cleaned_domain, qtype_enum

    def _get_lookup_name(self, domain: str, qtype: DNSQueryType) -> str:
        """Translates IP addresses to in-addr.arpa or ip6.arpa for PTR queries."""
        if qtype == DNSQueryType.PTR:
            try:
                rev_name = dns.reversename.from_address(domain)
                return rev_name.to_text()
            except Exception as e:
                raise DNSError(
                    error_type=DNSErrorType.INVALID_QUERY,
                    domain=domain,
                    query_type=qtype,
                    message=f"Invalid IP address for PTR reverse lookup: {e}",
                )
        return domain

    async def resolve(
        self,
        domain: str,
        query_type: Union[DNSQueryType, str],
        raise_on_error: bool = False,
    ) -> DNSResponse:
        self._total_queries += 1

        try:
            cleaned_domain, qtype = self._normalize_query(domain, query_type)
        except DNSError as err:
            self._transient_errors += 1
            resp = DNSResponse(
                domain=domain,
                query_type=err.query_type,
                status=DNSResponseStatus.ERROR,
                error_type=err.error_type,
                error_message=err.message,
            )
            if raise_on_error:
                resp.raise_for_status()
            return resp

        try:
            # Check Cache
            cached_resp = self.cache.get(cleaned_domain, qtype)
            if cached_resp is not None:
                self._cache_hits += 1
                if cached_resp.is_void:
                    self._void_lookups += 1
                if raise_on_error:
                    cached_resp.raise_for_status()
                return cached_resp

            self._cache_misses += 1

            # Resolve via dnspython under concurrency semaphore
            try:
                lookup_name = self._get_lookup_name(cleaned_domain, qtype)
            except DNSError as err:
                self._transient_errors += 1
                resp = DNSResponse(
                    domain=cleaned_domain,
                    query_type=qtype,
                    status=DNSResponseStatus.ERROR,
                    error_type=err.error_type,
                    error_message=err.message,
                )
                if raise_on_error:
                    resp.raise_for_status()
                return resp

            # Semaphore guarantees bounded concurrent network queries
            # Safe against cancellation: async with automatically releases permit on CancelledError
            async with self._semaphore:
                try:
                    answer = await self._resolver.resolve(lookup_name, qtype.value)
                    records: List[DNSRecord] = []
                    rrset_ttl = answer.rrset.ttl if answer.rrset else 0

                    for rdata in answer:
                        if qtype == DNSQueryType.TXT:
                            # RFC 7208 Section 3.3: multi-segment strings concatenated without spaces
                            txt_str = b"".join(rdata.strings).decode("utf-8", errors="replace")
                            records.append(DNSRecord(record_type=qtype, value=txt_str, ttl=rrset_ttl))
                        elif qtype in (DNSQueryType.A, DNSQueryType.AAAA):
                            records.append(DNSRecord(record_type=qtype, value=rdata.address, ttl=rrset_ttl))
                        elif qtype == DNSQueryType.MX:
                            exchange = rdata.exchange.to_text().rstrip(".")
                            records.append(
                                DNSRecord(
                                    record_type=qtype,
                                    value=exchange,
                                    ttl=rrset_ttl,
                                    preference=rdata.preference,
                                )
                            )
                        elif qtype == DNSQueryType.PTR:
                            target = rdata.target.to_text().rstrip(".")
                            records.append(DNSRecord(record_type=qtype, value=target, ttl=rrset_ttl))

                    min_ttl = min((r.ttl for r in records), default=0)
                    response = DNSResponse(
                        domain=cleaned_domain,
                        query_type=qtype,
                        status=DNSResponseStatus.SUCCESS,
                        records=records,
                        ttl=min_ttl,
                    )
                    self.cache.put(cleaned_domain, qtype, response)
                    return response

                except asyncio.CancelledError:
                    raise

                except dns.resolver.NXDOMAIN as e:
                    self._void_lookups += 1
                    soa_neg_ttl = self._extract_soa_negative_ttl(e)
                    resp = DNSResponse(
                        domain=cleaned_domain,
                        query_type=qtype,
                        status=DNSResponseStatus.NXDOMAIN,
                        error_type=DNSErrorType.NXDOMAIN,
                        error_message=f"Domain {cleaned_domain} does not exist (NXDOMAIN)",
                        ttl=soa_neg_ttl if soa_neg_ttl is not None else 0,
                    )
                    self.cache.put(cleaned_domain, qtype, resp)
                    if raise_on_error:
                        resp.raise_for_status()
                    return resp

                except dns.resolver.NoAnswer as e:
                    self._void_lookups += 1
                    soa_neg_ttl = self._extract_soa_negative_ttl(e)
                    resp = DNSResponse(
                        domain=cleaned_domain,
                        query_type=qtype,
                        status=DNSResponseStatus.NODATA,
                        error_type=DNSErrorType.NODATA,
                        error_message=f"Domain {cleaned_domain} exists but has no {qtype.value} records (NODATA)",
                        ttl=soa_neg_ttl if soa_neg_ttl is not None else 0,
                    )
                    self.cache.put(cleaned_domain, qtype, resp)
                    if raise_on_error:
                        resp.raise_for_status()
                    return resp

                except (dns.resolver.LifetimeTimeout, dns.exception.Timeout, TimeoutError) as e:
                    self._transient_errors += 1
                    resp = DNSResponse(
                        domain=cleaned_domain,
                        query_type=qtype,
                        status=DNSResponseStatus.TIMEOUT,
                        error_type=DNSErrorType.TIMEOUT,
                        error_message=f"DNS query timed out ({type(e).__name__})",
                    )
                    if raise_on_error:
                        resp.raise_for_status()
                    return resp

                except dns.resolver.NoNameservers as e:
                    self._transient_errors += 1
                    resp = DNSResponse(
                        domain=cleaned_domain,
                        query_type=qtype,
                        status=DNSResponseStatus.SERVFAIL,
                        error_type=DNSErrorType.SERVFAIL,
                        error_message=f"DNS server failure ({type(e).__name__})",
                    )
                    if raise_on_error:
                        resp.raise_for_status()
                    return resp

                except (
                    dns.resolver.YXDOMAIN,
                    dns.name.NameTooLong,
                    dns.name.LabelTooLong,
                    dns.name.EmptyLabel,
                    dns.exception.SyntaxError,
                ) as e:
                    self._transient_errors += 1
                    resp = DNSResponse(
                        domain=cleaned_domain,
                        query_type=qtype,
                        status=DNSResponseStatus.ERROR,
                        error_type=DNSErrorType.INVALID_QUERY,
                        error_message=f"Invalid DNS query name or syntax ({type(e).__name__})",
                    )
                    if raise_on_error:
                        resp.raise_for_status()
                    return resp

                except dns.exception.FormError as e:
                    self._transient_errors += 1
                    resp = DNSResponse(
                        domain=cleaned_domain,
                        query_type=qtype,
                        status=DNSResponseStatus.ERROR,
                        error_type=DNSErrorType.FORMERR,
                        error_message=f"Malformed DNS response ({type(e).__name__})",
                    )
                    if raise_on_error:
                        resp.raise_for_status()
                    return resp

                except (ConnectionError, OSError, dns.exception.DNSException) as e:
                    self._transient_errors += 1
                    resp = DNSResponse(
                        domain=cleaned_domain,
                        query_type=qtype,
                        status=DNSResponseStatus.ERROR,
                        error_type=DNSErrorType.RESOLVER_ERROR,
                        error_message=f"DNS transport or resolver failure ({type(e).__name__})",
                    )
                    if raise_on_error:
                        resp.raise_for_status()
                    return resp

                except Exception as e:
                    resp = DNSResponse(
                        domain=cleaned_domain,
                        query_type=qtype,
                        status=DNSResponseStatus.ERROR,
                        error_type=DNSErrorType.INTERNAL_ERROR,
                        error_message=f"DNS resolver internal software error ({type(e).__name__})",
                    )
                    if raise_on_error:
                        resp.raise_for_status()
                    return resp
        except asyncio.CancelledError:
            raise
        except DNSError:
            raise
        except Exception as e:
            resp = DNSResponse(
                domain=cleaned_domain,
                query_type=qtype,
                status=DNSResponseStatus.ERROR,
                error_type=DNSErrorType.INTERNAL_ERROR,
                error_message=f"DNS resolver internal software error ({type(e).__name__})",
            )
            if raise_on_error:
                resp.raise_for_status()
            return resp


class MockDNSResolver(BaseDNSResolver):
    """Deterministic in-memory DNS resolver for hermetic offline testing."""

    def __init__(
        self,
        config: Optional[AuthProtocolsConfig] = None,
        clock: Optional[Callable[[], float]] = None,
        enable_cache: bool = True,
    ):
        super().__init__()
        self.config = config or AuthProtocolsConfig()
        self.enable_cache = enable_cache
        self.cache = DNSCache(
            max_entries=self.config.dns_cache_max_entries,
            max_ttl=self.config.dns_cache_max_ttl,
            cache_negative=self.config.cache_negative_responses,
            max_negative_ttl=self.config.max_negative_cache_ttl,
            clock=clock,
        )
        self._records: Dict[Tuple[str, DNSQueryType], List[DNSRecord]] = {}
        self._errors: Dict[Tuple[str, Optional[DNSQueryType]], Tuple[DNSResponseStatus, DNSErrorType, str, int]] = {}
        self.recorded_queries: List[Tuple[str, DNSQueryType]] = []
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent_dns_queries)

    def _norm(self, domain: str) -> str:
        return domain.strip().lower().rstrip(".")

    def add_record(
        self,
        domain: str,
        query_type: Union[DNSQueryType, str],
        values: List[Union[str, Tuple[int, str]]],
        ttl: int = 300,
    ) -> None:
        qtype = DNSQueryType(query_type.upper()) if isinstance(query_type, str) else query_type
        key = (self._norm(domain), qtype)
        record_list: List[DNSRecord] = []

        for val in values:
            if qtype == DNSQueryType.MX:
                if isinstance(val, tuple):
                    pref, host = val
                else:
                    pref, host = 10, str(val)
                record_list.append(DNSRecord(record_type=qtype, value=host, ttl=ttl, preference=pref))
            else:
                record_list.append(DNSRecord(record_type=qtype, value=str(val), ttl=ttl))

        self._records[key] = record_list

    def add_txt(self, domain: str, txt_strings: List[str], ttl: int = 300) -> None:
        self.add_record(domain, DNSQueryType.TXT, txt_strings, ttl=ttl)

    def add_a(self, domain: str, ip_addresses: List[str], ttl: int = 300) -> None:
        self.add_record(domain, DNSQueryType.A, ip_addresses, ttl=ttl)

    def add_aaaa(self, domain: str, ipv6_addresses: List[str], ttl: int = 300) -> None:
        self.add_record(domain, DNSQueryType.AAAA, ipv6_addresses, ttl=ttl)

    def add_mx(self, domain: str, mx_records: List[Tuple[int, str]], ttl: int = 300) -> None:
        self.add_record(domain, DNSQueryType.MX, mx_records, ttl=ttl)

    def add_ptr(self, ip_address: str, hostnames: List[str], ttl: int = 300) -> None:
        self.add_record(ip_address, DNSQueryType.PTR, hostnames, ttl=ttl)

    def set_error(
        self,
        domain: str,
        status: DNSResponseStatus,
        error_type: DNSErrorType,
        query_type: Optional[Union[DNSQueryType, str]] = None,
        message: str = "",
        ttl: int = 0,
    ) -> None:
        qtype = (
            (DNSQueryType(query_type.upper()) if isinstance(query_type, str) else query_type)
            if query_type is not None
            else None
        )
        self._errors[(self._norm(domain), qtype)] = (status, error_type, message, ttl)

    def set_nxdomain(
        self,
        domain: str,
        soa_ttl: Optional[int] = None,
        soa_minimum: Optional[int] = None,
    ) -> None:
        neg_ttl = (
            min(soa_ttl, soa_minimum)
            if (soa_ttl is not None and soa_minimum is not None and soa_ttl > 0 and soa_minimum > 0)
            else 0
        )
        self.set_error(
            domain=domain,
            status=DNSResponseStatus.NXDOMAIN,
            error_type=DNSErrorType.NXDOMAIN,
            query_type=None,
            message=f"Domain {domain} does not exist (NXDOMAIN)",
            ttl=neg_ttl,
        )

    def set_nodata(
        self,
        domain: str,
        query_type: Union[DNSQueryType, str],
        soa_ttl: Optional[int] = None,
        soa_minimum: Optional[int] = None,
    ) -> None:
        qtype = DNSQueryType(query_type.upper()) if isinstance(query_type, str) else query_type
        neg_ttl = (
            min(soa_ttl, soa_minimum)
            if (soa_ttl is not None and soa_minimum is not None and soa_ttl > 0 and soa_minimum > 0)
            else 0
        )
        self.set_error(
            domain=domain,
            status=DNSResponseStatus.NODATA,
            error_type=DNSErrorType.NODATA,
            query_type=qtype,
            message=f"Domain {domain} has no {qtype.value} records (NODATA)",
            ttl=neg_ttl,
        )

    def set_timeout(self, domain: str, query_type: Optional[Union[DNSQueryType, str]] = None) -> None:
        self.set_error(
            domain=domain,
            status=DNSResponseStatus.TIMEOUT,
            error_type=DNSErrorType.TIMEOUT,
            query_type=query_type,
            message="Simulated DNS timeout",
            ttl=0,
        )

    def set_servfail(self, domain: str, query_type: Optional[Union[DNSQueryType, str]] = None) -> None:
        self.set_error(
            domain=domain,
            status=DNSResponseStatus.SERVFAIL,
            error_type=DNSErrorType.SERVFAIL,
            query_type=query_type,
            message="Simulated DNS SERVFAIL",
            ttl=0,
        )

    def set_resolver_error(self, domain: str, query_type: Optional[Union[DNSQueryType, str]] = None) -> None:
        self.set_error(
            domain=domain,
            status=DNSResponseStatus.ERROR,
            error_type=DNSErrorType.RESOLVER_ERROR,
            query_type=query_type,
            message="Simulated DNS resolver transport failure",
            ttl=0,
        )

    def set_refused(self, domain: str, query_type: Optional[Union[DNSQueryType, str]] = None) -> None:
        self.set_error(
            domain=domain,
            status=DNSResponseStatus.ERROR,
            error_type=DNSErrorType.REFUSED,
            query_type=query_type,
            message="Simulated DNS query refused",
            ttl=0,
        )

    def set_formerr(self, domain: str, query_type: Optional[Union[DNSQueryType, str]] = None) -> None:
        self.set_error(
            domain=domain,
            status=DNSResponseStatus.ERROR,
            error_type=DNSErrorType.FORMERR,
            query_type=query_type,
            message="Simulated malformed DNS response (FORMERR)",
            ttl=0,
        )

    def set_invalid_query(self, domain: str, query_type: Optional[Union[DNSQueryType, str]] = None) -> None:
        self.set_error(
            domain=domain,
            status=DNSResponseStatus.ERROR,
            error_type=DNSErrorType.INVALID_QUERY,
            query_type=query_type,
            message="Simulated invalid DNS query",
            ttl=0,
        )

    def set_internal_error(self, domain: str, query_type: Optional[Union[DNSQueryType, str]] = None) -> None:
        self.set_error(
            domain=domain,
            status=DNSResponseStatus.ERROR,
            error_type=DNSErrorType.INTERNAL_ERROR,
            query_type=query_type,
            message="Simulated DNS resolver internal software error",
            ttl=0,
        )

    def clear(self) -> None:
        self._records.clear()
        self._errors.clear()
        self.recorded_queries.clear()
        self.cache.clear()
        self.reset_telemetry()

    async def resolve(
        self,
        domain: str,
        query_type: Union[DNSQueryType, str],
        raise_on_error: bool = False,
    ) -> DNSResponse:
        self._total_queries += 1

        if isinstance(query_type, str):
            try:
                qtype = DNSQueryType(query_type.upper())
            except ValueError:
                self._transient_errors += 1
                resp = DNSResponse(
                    domain=domain,
                    query_type=DNSQueryType.A,
                    status=DNSResponseStatus.ERROR,
                    error_type=DNSErrorType.INVALID_QUERY,
                    error_message=f"Unsupported DNS record type: {query_type}",
                )
                if raise_on_error:
                    resp.raise_for_status()
                return resp
        else:
            qtype = query_type

        cleaned_domain = self._norm(domain)
        if not cleaned_domain:
            self._transient_errors += 1
            resp = DNSResponse(
                domain=domain,
                query_type=qtype,
                status=DNSResponseStatus.ERROR,
                error_type=DNSErrorType.INVALID_QUERY,
                error_message="Domain cannot be empty",
            )
            if raise_on_error:
                resp.raise_for_status()
            return resp

        self.recorded_queries.append((cleaned_domain, qtype))

        # Check Cache if enabled
        if self.enable_cache:
            cached_resp = self.cache.get(cleaned_domain, qtype)
            if cached_resp is not None:
                self._cache_hits += 1
                if cached_resp.is_void:
                    self._void_lookups += 1
                if raise_on_error:
                    cached_resp.raise_for_status()
                return cached_resp

        self._cache_misses += 1

        # Simulate concurrency semaphore acquisition to mirror production
        async with self._semaphore:
            # Check explicit configured errors
            err_info = self._errors.get((cleaned_domain, qtype)) or self._errors.get((cleaned_domain, None))
            if err_info is not None:
                status, err_type, msg, neg_ttl = err_info
                if status in (DNSResponseStatus.TIMEOUT, DNSResponseStatus.SERVFAIL, DNSResponseStatus.ERROR):
                    self._transient_errors += 1
                elif status in (DNSResponseStatus.NXDOMAIN, DNSResponseStatus.NODATA):
                    self._void_lookups += 1

                resp = DNSResponse(
                    domain=cleaned_domain,
                    query_type=qtype,
                    status=status,
                    error_type=err_type,
                    error_message=msg or f"Simulated {status.value}",
                    ttl=neg_ttl,
                )
                if self.enable_cache:
                    self.cache.put(cleaned_domain, qtype, resp)
                if raise_on_error:
                    resp.raise_for_status()
                return resp

            # Check configured records
            records = self._records.get((cleaned_domain, qtype))
            if records is not None:
                min_ttl = min((r.ttl for r in records), default=0)
                resp = DNSResponse(
                    domain=cleaned_domain,
                    query_type=qtype,
                    status=DNSResponseStatus.SUCCESS,
                    records=list(records),
                    ttl=min_ttl,
                )
                if self.enable_cache:
                    self.cache.put(cleaned_domain, qtype, resp)
                return resp

            # If domain has other records, this is NODATA
            domain_has_other_records = any(
                d == cleaned_domain for (d, qt) in self._records.keys()
            )
            if domain_has_other_records:
                self._void_lookups += 1
                resp = DNSResponse(
                    domain=cleaned_domain,
                    query_type=qtype,
                    status=DNSResponseStatus.NODATA,
                    error_type=DNSErrorType.NODATA,
                    error_message=f"Domain {cleaned_domain} exists but has no {qtype.value} records (NODATA)",
                    ttl=0,
                )
                if self.enable_cache:
                    self.cache.put(cleaned_domain, qtype, resp)
                if raise_on_error:
                    resp.raise_for_status()
                return resp

            # Default: Domain does not exist -> NXDOMAIN without SOA (not cached)
            self._void_lookups += 1
            resp = DNSResponse(
                domain=cleaned_domain,
                query_type=qtype,
                status=DNSResponseStatus.NXDOMAIN,
                error_type=DNSErrorType.NXDOMAIN,
                error_message=f"Domain {cleaned_domain} does not exist (NXDOMAIN)",
                ttl=0,
            )
            if self.enable_cache:
                self.cache.put(cleaned_domain, qtype, resp)
            if raise_on_error:
                resp.raise_for_status()
            return resp
