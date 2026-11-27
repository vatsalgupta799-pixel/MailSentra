"""Comprehensive unit and integration tests for bounded DNS Resolver and Mock Framework."""

import asyncio
from typing import List, Tuple
import pytest

from app.modules.auth_protocols import (
    AsyncDNSResolver,
    AuthProtocolsConfig,
    BaseDNSResolver,
    DNSCache,
    DNSError,
    DNSErrorType,
    DNSQueryType,
    DNSRecord,
    DNSResponse,
    DNSResponseStatus,
    MockDNSResolver,
)


class MockClock:
    """Controllable deterministic clock for TTL testing without time.sleep()."""

    def __init__(self, start_time: float = 1000.0):
        self._time = start_time

    def time(self) -> float:
        return self._time

    def advance(self, seconds: float) -> None:
        self._time += seconds


@pytest.mark.asyncio
async def test_supported_record_types_positive_resolution():
    resolver = MockDNSResolver()
    resolver.add_txt("example.com", ["v=spf1 include:_spf.example.com ~all", "some-other-tag=value"])
    resolver.add_a("example.com", ["192.0.2.1", "192.0.2.2"])
    resolver.add_aaaa("example.com", ["2001:db8::1", "2001:db8::2"])
    resolver.add_mx("example.com", [(20, "backup.mx.example.com"), (10, "primary.mx.example.com")])
    resolver.add_ptr("192.0.2.1", ["mail.example.com", "outbound.example.com"])

    # TXT
    txt_res = await resolver.resolve("example.com", DNSQueryType.TXT)
    assert txt_res.is_success is True
    assert txt_res.is_void is False
    assert len(txt_res.records) == 2
    assert "v=spf1 include:_spf.example.com ~all" in txt_res.txt_values()

    # A
    a_res = await resolver.resolve("example.com", "A")
    assert a_res.is_success is True
    assert a_res.a_values() == ["192.0.2.1", "192.0.2.2"]

    # AAAA
    aaaa_res = await resolver.resolve("example.com", DNSQueryType.AAAA)
    assert aaaa_res.is_success is True
    assert aaaa_res.aaaa_values() == ["2001:db8::1", "2001:db8::2"]

    # MX (must be sorted by preference ascending)
    mx_res = await resolver.resolve("example.com", DNSQueryType.MX)
    assert mx_res.is_success is True
    mxs = mx_res.mx_values()
    assert mxs == [(10, "primary.mx.example.com"), (20, "backup.mx.example.com")]

    # PTR
    ptr_res = await resolver.resolve("192.0.2.1", DNSQueryType.PTR)
    assert ptr_res.is_success is True
    assert ptr_res.ptr_values() == ["mail.example.com", "outbound.example.com"]

    # Helper methods on BaseDNSResolver
    assert await resolver.resolve_txt("example.com") == ["v=spf1 include:_spf.example.com ~all", "some-other-tag=value"]
    assert await resolver.resolve_a("example.com") == ["192.0.2.1", "192.0.2.2"]
    assert await resolver.resolve_aaaa("example.com") == ["2001:db8::1", "2001:db8::2"]
    assert await resolver.resolve_mx("example.com") == [(10, "primary.mx.example.com"), (20, "backup.mx.example.com")]
    assert await resolver.resolve_ptr("192.0.2.1") == ["mail.example.com", "outbound.example.com"]


@pytest.mark.asyncio
async def test_nxdomain_and_nodata_distinction():
    resolver = MockDNSResolver()
    resolver.add_txt("exists.com", ["v=spf1 -all"])

    # 1. NXDOMAIN: Domain has zero records of any type
    nx_res = await resolver.resolve("nonexistent.com", DNSQueryType.A)
    assert nx_res.status == DNSResponseStatus.NXDOMAIN
    assert nx_res.is_nxdomain is True
    assert nx_res.is_void is True
    assert nx_res.is_success is False
    assert nx_res.error_type == DNSErrorType.NXDOMAIN
    assert len(nx_res.records) == 0

    # 2. NODATA: Domain exists (has TXT), but has no A records
    nodata_res = await resolver.resolve("exists.com", DNSQueryType.A)
    assert nodata_res.status == DNSResponseStatus.NODATA
    assert nodata_res.is_nodata is True
    assert nodata_res.is_void is True
    assert nodata_res.is_nxdomain is False
    assert nodata_res.error_type == DNSErrorType.NODATA
    assert len(nodata_res.records) == 0


@pytest.mark.asyncio
async def test_servfail_and_timeout_behavior():
    resolver = MockDNSResolver()
    resolver.set_timeout("timeout.com")
    resolver.set_servfail("servfail.com")

    # Timeout
    timeout_res = await resolver.resolve("timeout.com", DNSQueryType.TXT)
    assert timeout_res.status == DNSResponseStatus.TIMEOUT
    assert timeout_res.is_transient_error is True
    assert timeout_res.error_type == DNSErrorType.TIMEOUT
    assert timeout_res.is_void is False

    # SERVFAIL
    servfail_res = await resolver.resolve("servfail.com", DNSQueryType.TXT)
    assert servfail_res.status == DNSResponseStatus.SERVFAIL
    assert servfail_res.is_transient_error is True
    assert servfail_res.error_type == DNSErrorType.SERVFAIL

    # Telemetry check
    assert resolver.transient_errors == 2


@pytest.mark.asyncio
async def test_ttl_expiration_with_deterministic_clock():
    clock = MockClock(start_time=1000.0)
    config = AuthProtocolsConfig(dns_cache_max_ttl=3600)
    resolver = MockDNSResolver(config=config, clock=clock.time, enable_cache=True)
    resolver.add_txt("ttl.example.com", ["v=spf1 -all"], ttl=60)

    # 1. Initial query: cache miss
    res1 = await resolver.resolve("ttl.example.com", DNSQueryType.TXT)
    assert res1.is_cached is False
    assert resolver.cache_misses == 1
    assert resolver.cache_hits == 0

    # 2. Query within TTL (advance clock by 30 seconds): cache hit
    clock.advance(30.0)
    res2 = await resolver.resolve("ttl.example.com", DNSQueryType.TXT)
    assert res2.is_cached is True
    assert resolver.cache_hits == 1

    # 3. Query after TTL expired (advance clock by another 40 seconds -> total 70s > 60s)
    clock.advance(40.0)
    res3 = await resolver.resolve("ttl.example.com", DNSQueryType.TXT)
    assert res3.is_cached is False
    assert resolver.cache_misses == 2
    assert resolver.cache_hits == 1


@pytest.mark.asyncio
async def test_cache_hits_misses_and_transient_error_isolation():
    clock = MockClock(start_time=1000.0)
    resolver = MockDNSResolver(clock=clock.time, enable_cache=True)
    resolver.add_a("cached.com", ["1.2.3.4"], ttl=100)
    resolver.set_timeout("transient.com")

    # Success is cached
    r1 = await resolver.resolve("cached.com", DNSQueryType.A)
    assert r1.is_cached is False
    r2 = await resolver.resolve("cached.com", DNSQueryType.A)
    assert r2.is_cached is True
    assert resolver.cache_hits == 1

    # Transient error (TIMEOUT) is NEVER cached
    t1 = await resolver.resolve("transient.com", DNSQueryType.A)
    assert t1.status == DNSResponseStatus.TIMEOUT
    assert t1.is_cached is False

    t2 = await resolver.resolve("transient.com", DNSQueryType.A)
    assert t2.status == DNSResponseStatus.TIMEOUT
    assert t2.is_cached is False
    # Transient queries should both be cache misses (not cached)
    assert resolver.cache_hits == 1


def test_cache_size_limits_and_lru_eviction():
    clock = MockClock(start_time=1000.0)
    cache = DNSCache(max_entries=3, clock=clock.time)

    resp_a = DNSResponse(domain="a.com", query_type=DNSQueryType.A, records=[DNSRecord(record_type=DNSQueryType.A, value="1.1.1.1")])
    resp_b = DNSResponse(domain="b.com", query_type=DNSQueryType.A, records=[DNSRecord(record_type=DNSQueryType.A, value="2.2.2.2")])
    resp_c = DNSResponse(domain="c.com", query_type=DNSQueryType.A, records=[DNSRecord(record_type=DNSQueryType.A, value="3.3.3.3")])
    resp_d = DNSResponse(domain="d.com", query_type=DNSQueryType.A, records=[DNSRecord(record_type=DNSQueryType.A, value="4.4.4.4")])

    cache.put("a.com", DNSQueryType.A, resp_a)
    cache.put("b.com", DNSQueryType.A, resp_b)
    cache.put("c.com", DNSQueryType.A, resp_c)
    assert cache.size == 3

    # Inserting 4th item must evict oldest item ("a.com")
    cache.put("d.com", DNSQueryType.A, resp_d)
    assert cache.size == 3
    assert cache.get("a.com", DNSQueryType.A) is None
    assert cache.get("b.com", DNSQueryType.A) is not None
    assert cache.get("d.com", DNSQueryType.A) is not None


@pytest.mark.asyncio
async def test_concurrent_query_limits():
    # Resolver with strict concurrency limit of 2
    config = AuthProtocolsConfig(max_concurrent_dns_queries=2)
    resolver = MockDNSResolver(config=config)
    for i in range(10):
        resolver.add_a(f"host{i}.example.com", [f"192.0.2.{i}"])

    tasks = [resolver.resolve(f"host{i}.example.com", DNSQueryType.A) for i in range(10)]
    results = await asyncio.gather(*tasks)
    assert len(results) == 10
    for i, r in enumerate(results):
        assert r.is_success is True
        assert r.a_values() == [f"192.0.2.{i}"]


@pytest.mark.asyncio
async def test_cancellation_and_resource_cleanup():
    config = AuthProtocolsConfig(max_concurrent_dns_queries=1)
    resolver = MockDNSResolver(config=config)
    resolver.add_a("cancel.example.com", ["192.0.2.1"])

    # Create a task that acquires semaphore and then is cancelled
    async def task_to_cancel():
        async with resolver._semaphore:
            await asyncio.sleep(0.5)

    task = asyncio.create_task(task_to_cancel())
    await asyncio.sleep(0.01)  # Allow task to enter semaphore
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    # Semaphore permit must be cleanly released and available immediately
    res = await resolver.resolve("cancel.example.com", DNSQueryType.A)
    assert res.is_success is True
    assert res.a_values() == ["192.0.2.1"]


@pytest.mark.asyncio
async def test_invalid_query_types_and_malformed_inputs():
    resolver = MockDNSResolver()

    # 1. Unsupported query type string
    resp_inv_qtype = await resolver.resolve("example.com", "INVALID_TYPE")
    assert resp_inv_qtype.status == DNSResponseStatus.ERROR
    assert resp_inv_qtype.error_type == DNSErrorType.INVALID_QUERY
    assert "Unsupported DNS record type" in resp_inv_qtype.error_message

    # 2. Empty domain string
    resp_empty = await resolver.resolve("   ", DNSQueryType.A)
    assert resp_empty.status == DNSResponseStatus.ERROR
    assert resp_empty.error_type == DNSErrorType.INVALID_QUERY

    # 3. raise_on_error=True propagates DNSError
    with pytest.raises(DNSError) as exc_info:
        await resolver.resolve("example.com", "BOGUS", raise_on_error=True)
    assert exc_info.value.error_type == DNSErrorType.INVALID_QUERY


@pytest.mark.asyncio
async def test_errors_converted_into_typed_results_without_silent_empty_answers():
    resolver = MockDNSResolver()
    resolver.set_servfail("failing.com")

    # Normal resolution returns typed DNSResponse with status=SERVFAIL
    resp = await resolver.resolve("failing.com", DNSQueryType.TXT)
    assert resp.status == DNSResponseStatus.SERVFAIL
    assert resp.error_type == DNSErrorType.SERVFAIL
    assert resp.is_success is False
    assert resp.has_error is True

    # Calling raise_for_status() explicitly triggers DNSError
    with pytest.raises(DNSError) as exc:
        resp.raise_for_status()
    assert exc.value.error_type == DNSErrorType.SERVFAIL
    assert "SERVFAIL" in str(exc.value)


@pytest.mark.asyncio
async def test_dependency_injection_using_fake_resolver():
    # Consumer component accepting BaseDNSResolver
    class SPFRecordFetcher:
        def __init__(self, dns_resolver: BaseDNSResolver):
            self.resolver = dns_resolver

        async def get_spf_record(self, domain: str) -> str:
            txt_records = await self.resolver.resolve_txt(domain)
            for record in txt_records:
                if record.startswith("v=spf1"):
                    return record
            return ""

    mock_resolver = MockDNSResolver()
    mock_resolver.add_txt("testcorp.org", ["v=spf1 mx ip4:198.51.100.0/24 -all"])

    service = SPFRecordFetcher(dns_resolver=mock_resolver)
    record = await service.get_spf_record("testcorp.org")
    assert record == "v=spf1 mx ip4:198.51.100.0/24 -all"
    assert ("testcorp.org", DNSQueryType.TXT) in mock_resolver.recorded_queries


@pytest.mark.asyncio
async def test_async_dns_resolver_initialization_and_ptr_normalization():
    # Verifies AsyncDNSResolver construction, config parameters, and PTR normalization logic
    config = AuthProtocolsConfig(
        dns_query_timeout=1.5,
        dns_total_lifetime=3.0,
        max_concurrent_dns_queries=8,
    )
    async_resolver = AsyncDNSResolver(config=config)
    assert async_resolver.config.dns_query_timeout == 1.5
    assert async_resolver._semaphore._value == 8

    # PTR lookup name translation
    v4_name = async_resolver._get_lookup_name("192.0.2.1", DNSQueryType.PTR)
    assert v4_name == "1.2.0.192.in-addr.arpa."

    v6_name = async_resolver._get_lookup_name("2001:db8::1", DNSQueryType.PTR)
    assert "ip6.arpa." in v6_name

    # Invalid IP for PTR lookup raises DNSError
    with pytest.raises(DNSError) as exc:
        async_resolver._get_lookup_name("not-an-ip", DNSQueryType.PTR)
    assert exc.value.error_type == DNSErrorType.INVALID_QUERY


@pytest.mark.asyncio
async def test_authoritative_ttl_shorter_than_15s_is_never_extended():
    # An authoritative TTL of 5s must NEVER be clamped up or extended (e.g. to 15s).
    clock = MockClock(start_time=1000.0)
    resolver = MockDNSResolver(clock=clock.time, enable_cache=True)
    resolver.add_a("short-ttl.example.com", ["192.0.2.1"], ttl=5)

    # Initial query
    r1 = await resolver.resolve("short-ttl.example.com", DNSQueryType.A)
    assert r1.is_cached is False
    assert r1.ttl == 5

    # 4 seconds later: still within authoritative 5s TTL -> cache hit
    clock.advance(4.0)
    r2 = await resolver.resolve("short-ttl.example.com", DNSQueryType.A)
    assert r2.is_cached is True

    # 6 seconds total (elapsed 6s > authoritative 5s TTL): must expire!
    # If clamped to 15s, this would falsely return a cache hit.
    clock.advance(2.0)
    r3 = await resolver.resolve("short-ttl.example.com", DNSQueryType.A)
    assert r3.is_cached is False
    assert resolver.cache_misses == 2


@pytest.mark.asyncio
async def test_zero_ttl_records_are_not_cached():
    # Records with TTL <= 0 must never be stored in cache
    clock = MockClock(start_time=1000.0)
    resolver = MockDNSResolver(clock=clock.time, enable_cache=True)
    resolver.add_txt("zero-ttl.example.com", ["v=spf1 -all"], ttl=0)

    # Initial query
    r1 = await resolver.resolve("zero-ttl.example.com", DNSQueryType.TXT)
    assert r1.is_cached is False

    # Immediate subsequent query (0 seconds elapsed): must STILL be a cache miss
    r2 = await resolver.resolve("zero-ttl.example.com", DNSQueryType.TXT)
    assert r2.is_cached is False
    assert resolver.cache_hits == 0
    assert resolver.cache_misses == 2


@pytest.mark.asyncio
async def test_long_ttls_capped_by_configured_maximum():
    # Long authoritative TTL (e.g. 86400s) must be capped by max_ttl (e.g. 300s)
    clock = MockClock(start_time=1000.0)
    config = AuthProtocolsConfig(dns_cache_max_ttl=300)
    resolver = MockDNSResolver(config=config, clock=clock.time, enable_cache=True)
    resolver.add_a("long-ttl.example.com", ["192.0.2.1"], ttl=86400)

    # Initial query
    await resolver.resolve("long-ttl.example.com", DNSQueryType.A)

    # At 250s (< 300s max_ttl): cache hit
    clock.advance(250.0)
    r2 = await resolver.resolve("long-ttl.example.com", DNSQueryType.A)
    assert r2.is_cached is True

    # At 350s (> 300s max_ttl): expired and must be a cache miss despite 86400s authoritative TTL
    clock.advance(100.0)
    r3 = await resolver.resolve("long-ttl.example.com", DNSQueryType.A)
    assert r3.is_cached is False


@pytest.mark.asyncio
async def test_multiple_record_ttls_do_not_produce_overlong_cache_lifetime():
    # When multiple records have different TTLs, the cache lifetime must be bounded
    # by the shortest applicable TTL among the records.
    clock = MockClock(start_time=1000.0)
    resolver = MockDNSResolver(clock=clock.time, enable_cache=True)
    # Add two records for the same domain: one with TTL=10s and one with TTL=60s
    key = (resolver._norm("multi.example.com"), DNSQueryType.A)
    resolver._records[key] = [
        DNSRecord(record_type=DNSQueryType.A, value="192.0.2.1", ttl=10),
        DNSRecord(record_type=DNSQueryType.A, value="192.0.2.2", ttl=60),
    ]

    r1 = await resolver.resolve("multi.example.com", DNSQueryType.A)
    assert r1.is_cached is False
    assert r1.ttl == 10  # shortest TTL

    # At 5s: within shortest TTL (10s) -> cache hit
    clock.advance(5.0)
    r2 = await resolver.resolve("multi.example.com", DNSQueryType.A)
    assert r2.is_cached is True

    # At 15s (> 10s): shortest TTL expired -> cache miss (not kept until 60s)
    clock.advance(10.0)
    r3 = await resolver.resolve("multi.example.com", DNSQueryType.A)
    assert r3.is_cached is False


@pytest.mark.asyncio
async def test_nxdomain_negative_ttl_derived_from_soa_data():
    # RFC 2308: Negative cache TTL is min(SOA.ttl, SOA.minimum)
    clock = MockClock(start_time=1000.0)
    resolver = MockDNSResolver(clock=clock.time, enable_cache=True)
    # SOA with ttl=300 and minimum=60 -> negative TTL is 60s
    resolver.set_nxdomain("nx-soa.example.com", soa_ttl=300, soa_minimum=60)

    r1 = await resolver.resolve("nx-soa.example.com", DNSQueryType.TXT)
    assert r1.status == DNSResponseStatus.NXDOMAIN
    assert r1.is_cached is False
    assert r1.ttl == 60

    # At 40s (< 60s): cache hit with NXDOMAIN
    clock.advance(40.0)
    r2 = await resolver.resolve("nx-soa.example.com", DNSQueryType.TXT)
    assert r2.status == DNSResponseStatus.NXDOMAIN
    assert r2.is_cached is True

    # At 70s (> 60s): expired -> cache miss
    clock.advance(30.0)
    r3 = await resolver.resolve("nx-soa.example.com", DNSQueryType.TXT)
    assert r3.is_cached is False


@pytest.mark.asyncio
async def test_nodata_negative_ttl_derived_from_soa_data():
    # RFC 2308: NODATA negative cache TTL is min(SOA.ttl, SOA.minimum)
    clock = MockClock(start_time=1000.0)
    resolver = MockDNSResolver(clock=clock.time, enable_cache=True)
    # SOA with ttl=120 and minimum=180 -> negative TTL is 120s
    resolver.set_nodata("nodata-soa.example.com", DNSQueryType.AAAA, soa_ttl=120, soa_minimum=180)

    r1 = await resolver.resolve("nodata-soa.example.com", DNSQueryType.AAAA)
    assert r1.status == DNSResponseStatus.NODATA
    assert r1.is_cached is False
    assert r1.ttl == 120

    # At 60s (< 120s): cache hit with NODATA
    clock.advance(60.0)
    r2 = await resolver.resolve("nodata-soa.example.com", DNSQueryType.AAAA)
    assert r2.status == DNSResponseStatus.NODATA
    assert r2.is_cached is True

    # At 130s (> 120s): expired -> cache miss
    clock.advance(70.0)
    r3 = await resolver.resolve("nodata-soa.example.com", DNSQueryType.AAAA)
    assert r3.is_cached is False


@pytest.mark.asyncio
async def test_missing_soa_information_causes_negative_responses_not_to_be_cached():
    # If SOA information is absent or unusable, negative responses must NOT be cached
    clock = MockClock(start_time=1000.0)
    resolver = MockDNSResolver(clock=clock.time, enable_cache=True)
    # Default NXDOMAIN without SOA
    resolver.set_nxdomain("no-soa-nx.example.com", soa_ttl=None, soa_minimum=None)
    # Default NODATA without SOA
    resolver.set_nodata("no-soa-nodata.example.com", DNSQueryType.A, soa_ttl=None, soa_minimum=None)

    # 1. NXDOMAIN without SOA
    nx1 = await resolver.resolve("no-soa-nx.example.com", DNSQueryType.TXT)
    assert nx1.status == DNSResponseStatus.NXDOMAIN
    assert nx1.ttl == 0
    nx2 = await resolver.resolve("no-soa-nx.example.com", DNSQueryType.TXT)
    assert nx2.is_cached is False  # NOT CACHED!

    # 2. NODATA without SOA
    nd1 = await resolver.resolve("no-soa-nodata.example.com", DNSQueryType.A)
    assert nd1.status == DNSResponseStatus.NODATA
    assert nd1.ttl == 0
    nd2 = await resolver.resolve("no-soa-nodata.example.com", DNSQueryType.A)
    assert nd2.is_cached is False  # NOT CACHED!


@pytest.mark.asyncio
async def test_expired_negative_entries_not_returned():
    # Expired negative cache entries must not be returned as fresh
    clock = MockClock(start_time=1000.0)
    cache = DNSCache(max_ttl=3600, clock=clock.time)
    resp = DNSResponse(
        domain="expired-neg.com",
        query_type=DNSQueryType.TXT,
        status=DNSResponseStatus.NXDOMAIN,
        error_type=DNSErrorType.NXDOMAIN,
        ttl=30,  # derived from SOA
    )
    cache.put("expired-neg.com", DNSQueryType.TXT, resp)

    # At 10s: valid
    clock.advance(10.0)
    assert cache.get("expired-neg.com", DNSQueryType.TXT) is not None

    # At 35s (> 30s): expired -> returns None
    clock.advance(25.0)
    assert cache.get("expired-neg.com", DNSQueryType.TXT) is None


@pytest.mark.asyncio
async def test_timeout_and_servfail_remain_uncached():
    clock = MockClock(start_time=1000.0)
    resolver = MockDNSResolver(clock=clock.time, enable_cache=True)
    resolver.set_timeout("timeout-never-cache.com")
    resolver.set_servfail("servfail-never-cache.com")

    # TIMEOUT
    t1 = await resolver.resolve("timeout-never-cache.com", DNSQueryType.A)
    assert t1.status == DNSResponseStatus.TIMEOUT
    t2 = await resolver.resolve("timeout-never-cache.com", DNSQueryType.A)
    assert t2.is_cached is False

    # SERVFAIL
    s1 = await resolver.resolve("servfail-never-cache.com", DNSQueryType.A)
    assert s1.status == DNSResponseStatus.SERVFAIL
    s2 = await resolver.resolve("servfail-never-cache.com", DNSQueryType.A)
    assert s2.is_cached is False
    assert resolver.cache_hits == 0


@pytest.mark.asyncio
async def test_h3_explicit_dns_outcome_categories_and_error_separation():
    """H3: Resolver failures, invalid queries, and FORMERR never masquerade as authoritative absence."""
    from app.modules.auth_protocols import DNSOutcomeCategory

    resolver = MockDNSResolver()
    resolver.add_txt("valid.example", ["v=spf1 -all"])
    resolver.set_resolver_error("neterr.example", DNSQueryType.TXT)
    resolver.set_refused("refused.example", DNSQueryType.TXT)
    resolver.set_formerr("malformed.example", DNSQueryType.TXT)
    resolver.set_invalid_query("invq.example", DNSQueryType.TXT)

    r_valid = await resolver.resolve("valid.example", DNSQueryType.TXT)
    assert r_valid.outcome_category == DNSOutcomeCategory.VALID_RECORDS
    assert r_valid.is_authoritative_absence is False

    r_nx = await resolver.resolve("missing-nx.example", DNSQueryType.TXT)
    assert r_nx.outcome_category == DNSOutcomeCategory.AUTHORITATIVE_NXDOMAIN
    assert r_nx.is_void is True
    assert r_nx.is_authoritative_absence is True
    assert r_nx.is_transient_error is False

    r_nodata = await resolver.resolve("valid.example", DNSQueryType.A)
    assert r_nodata.outcome_category == DNSOutcomeCategory.NODATA
    assert r_nodata.is_void is True
    assert r_nodata.is_authoritative_absence is True

    r_net = await resolver.resolve("neterr.example", DNSQueryType.TXT)
    assert r_net.outcome_category == DNSOutcomeCategory.TRANSIENT_FAILURE
    assert r_net.is_transient_error is True
    assert r_net.is_void is False
    assert r_net.is_authoritative_absence is False

    r_ref = await resolver.resolve("refused.example", DNSQueryType.TXT)
    assert r_ref.outcome_category == DNSOutcomeCategory.TRANSIENT_FAILURE
    assert r_ref.is_transient_error is True
    assert r_ref.is_authoritative_absence is False

    r_form = await resolver.resolve("malformed.example", DNSQueryType.TXT)
    assert r_form.outcome_category == DNSOutcomeCategory.MALFORMED_RESPONSE
    assert r_form.is_malformed_response is True
    assert r_form.is_void is False
    assert r_form.is_authoritative_absence is False

    r_inv = await resolver.resolve("invq.example", DNSQueryType.TXT)
    assert r_inv.outcome_category == DNSOutcomeCategory.INVALID_QUERY
    assert r_inv.is_invalid_query is True
    assert r_inv.is_transient_error is False
    assert r_inv.is_void is False
    assert r_inv.is_authoritative_absence is False

    # Empty SUCCESS (records=[]) cannot masquerade as NXDOMAIN or NODATA
    empty_success = DNSResponse(domain="empty.example", query_type=DNSQueryType.TXT, status=DNSResponseStatus.SUCCESS, records=[])
    assert empty_success.outcome_category == DNSOutcomeCategory.MALFORMED_RESPONSE
    assert empty_success.is_authoritative_absence is False
    assert empty_success.has_error is True


@pytest.mark.asyncio
async def test_h3_async_resolver_os_socket_runtime_and_cancellation_errors():
    """H3: AsyncDNSResolver classifies OSError/ConnectionError/socket/TimeoutError/RuntimeError without leaking or converting to absence."""
    import socket
    import dns.exception
    import dns.name
    import dns.resolver
    from app.modules.auth_protocols import DNSOutcomeCategory

    async_resolver = AsyncDNSResolver()

    async def _run_with_exc(exc_obj):
        async def _boom(name, rdtype):
            raise exc_obj

        async_resolver._resolver.resolve = _boom  # type: ignore[method-assign]
        return await async_resolver.resolve("test.example", DNSQueryType.TXT)

    # 1. OS/Socket/Connection failures -> RESOLVER_ERROR + TRANSIENT_FAILURE (never TIMEOUT or NXDOMAIN)
    for net_exc in (
        OSError("Network unreachable / secret_host_details"),
        ConnectionResetError("Connection reset by peer"),
        ConnectionRefusedError("DNS socket refused"),
        socket.gaierror(-2, "Name or service not known"),
    ):
        resp = await _run_with_exc(net_exc)
        assert resp.status == DNSResponseStatus.ERROR
        assert resp.error_type == DNSErrorType.RESOLVER_ERROR
        assert resp.outcome_category == DNSOutcomeCategory.TRANSIENT_FAILURE
        assert resp.is_transient_error is True
        assert resp.is_void is False
        assert resp.is_authoritative_absence is False
        assert "secret_host_details" not in (resp.error_message or "")
        assert async_resolver.cache.get("test.example", DNSQueryType.TXT) is None

    # 2. Builtin TimeoutError & dnspython Timeout -> TIMEOUT (distinguished from OSError)
    for to_exc in (TimeoutError("async socket timed out"), dns.exception.Timeout("dnspython timeout")):
        resp_to = await _run_with_exc(to_exc)
        assert resp_to.status == DNSResponseStatus.TIMEOUT
        assert resp_to.error_type == DNSErrorType.TIMEOUT
        assert resp_to.outcome_category == DNSOutcomeCategory.TRANSIENT_FAILURE
        assert resp_to.is_transient_error is True
        assert resp_to.is_authoritative_absence is False

    # 3. SERVFAIL (NoNameservers)
    resp_sf = await _run_with_exc(dns.resolver.NoNameservers())
    assert resp_sf.status == DNSResponseStatus.SERVFAIL
    assert resp_sf.outcome_category == DNSOutcomeCategory.TRANSIENT_FAILURE

    # 4. Unexpected non-DNS runtime exception -> INTERNAL_ERROR (NOT TIMEOUT, NOT absence, NOT cached)
    resp_rt = await _run_with_exc(RuntimeError("INTERNAL_SECRET_KEY_LEAK"))
    assert resp_rt.status == DNSResponseStatus.ERROR
    assert resp_rt.error_type == DNSErrorType.INTERNAL_ERROR
    assert resp_rt.outcome_category == DNSOutcomeCategory.INTERNAL_ERROR
    assert resp_rt.is_internal_error is True
    assert resp_rt.is_transient_error is False
    assert resp_rt.is_void is False
    assert resp_rt.is_authoritative_absence is False
    assert "INTERNAL_SECRET_KEY_LEAK" not in (resp_rt.error_message or "")
    assert "RuntimeError" in (resp_rt.error_message or "")
    assert async_resolver.cache.get("test.example", DNSQueryType.TXT) is None

    # 5. Invalid internal DNS name construction (NameTooLong/YXDOMAIN) -> INVALID_QUERY
    for bad_exc in (dns.name.NameTooLong("too long"), dns.resolver.YXDOMAIN()):
        resp_iq = await _run_with_exc(bad_exc)
        assert resp_iq.status == DNSResponseStatus.ERROR
        assert resp_iq.error_type == DNSErrorType.INVALID_QUERY
        assert resp_iq.is_invalid_query is True
        assert resp_iq.is_transient_error is False

    # 6. Authoritative NXDOMAIN / NoAnswer preserved cleanly
    resp_nx = await _run_with_exc(dns.resolver.NXDOMAIN())
    assert resp_nx.status == DNSResponseStatus.NXDOMAIN and resp_nx.is_authoritative_absence is True
    resp_nd = await _run_with_exc(dns.resolver.NoAnswer())
    assert resp_nd.status == DNSResponseStatus.NODATA and resp_nd.is_authoritative_absence is True

    # 7. Cancellation must never be swallowed
    with pytest.raises(asyncio.CancelledError):
        await _run_with_exc(asyncio.CancelledError())
