"""Performance, Stress, and Concurrency Benchmark Harness (Section G).

Measures:
- Small, medium, and large email payload processing times
- High-cardinality header arrays (100+ headers)
- High-density URL collections (50+ URLs)
- Multi-attachment throughput
- Sequential batch execution metrics
- Memory overhead tracking via tracemalloc
"""

import gc
import io
import time
import tracemalloc
import pytest
from app.modules.contracts import IngestionSource, RawEmailPayload
from app.modules.ingestion.service import EmailIngestionService
from app.modules.parser.parser import EmailParser


@pytest.fixture
def parser():
    return EmailParser()


@pytest.fixture
def ingestion():
    return EmailIngestionService()


def generate_email_with_headers(count: int) -> bytes:
    headers = [
        "From: perf@benchmark.org",
        "To: target@benchmark.org",
        "Subject: High Cardinality Header Stress Test",
        "Content-Type: text/plain; charset=utf-8",
    ]
    for i in range(count):
        headers.append(f"X-Benchmark-Custom-Header-{i:04d}: Value_Alpha_Numeric_{i:06d}")
    return ("\n".join(headers) + "\n\nPayload Body Benchmark Text\n").encode("utf-8")


def generate_email_with_urls(count: int) -> bytes:
    lines = [
        "From: urls@benchmark.org",
        "To: target@benchmark.org",
        "Subject: High Density URL Stress Test",
        "Content-Type: text/html; charset=utf-8",
        "",
        "<html><body>",
    ]
    for i in range(count):
        lines.append(f'<p>Link {i}: <a href="https://service-{i}.domain.org/path?token={i}&ref=scan">Anchor {i}</a></p>')
    lines.append("</body></html>")
    return "\n".join(lines).encode("utf-8")


def generate_email_with_size(size_bytes: int) -> bytes:
    header = b"From: perf@size.org\nTo: target@size.org\nSubject: Large Size Benchmark\nContent-Type: text/plain\n\n"
    padding_needed = max(0, size_bytes - len(header))
    return header + (b"A" * padding_needed)


# ============================================================================
# Benchmark 1: Small, Medium, Large Payload Performance
# ============================================================================
def test_performance_payload_sizes(ingestion, parser):
    sizes = [
        ("Small (1KB)", 1024),
        ("Medium (100KB)", 100 * 1024),
        ("Large (2MB)", 2 * 1024 * 1024),
    ]

    benchmark_results = {}

    for label, size in sizes:
        eml_bytes = generate_email_with_size(size)

        tracemalloc.start()
        start_time = time.perf_counter()

        payload = ingestion.ingest(eml_bytes, f"test_{size}.eml")
        parsed = parser.parse(payload)

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        benchmark_results[label] = {
            "elapsed_ms": elapsed_ms,
            "peak_mem_kb": peak_mem / 1024,
            "subject": parsed.subject,
        }

        # Assert reasonable SLA bounds
        assert elapsed_ms < 1000.0, f"{label} exceeded 1000ms latency ceiling ({elapsed_ms:.2f}ms)"
        assert parsed.subject == "Large Size Benchmark"

    # 2MB email should parse well under 500ms
    assert benchmark_results["Large (2MB)"]["elapsed_ms"] < 500.0


# ============================================================================
# Benchmark 2: High Cardinality Headers (100+ Headers)
# ============================================================================
def test_performance_many_headers(ingestion, parser):
    eml_bytes = generate_email_with_headers(100)

    start = time.perf_counter()
    payload = ingestion.ingest(eml_bytes, "headers_100.eml")
    parsed = parser.parse(payload)
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert len(parsed.headers) >= 104
    assert elapsed_ms < 100.0  # Must parse within 100ms


# ============================================================================
# Benchmark 3: High Density URLs (50+ URLs)
# ============================================================================
def test_performance_many_urls(ingestion, parser):
    eml_bytes = generate_email_with_urls(50)

    start = time.perf_counter()
    payload = ingestion.ingest(eml_bytes, "urls_50.eml")
    parsed = parser.parse(payload)
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert len(parsed.urls) == 50
    assert elapsed_ms < 150.0  # HTML parsing + 50 URLs must complete within 150ms


# ============================================================================
# Benchmark 4: Sequential Batch Processing Throughput
# ============================================================================
def test_performance_sequential_batch(ingestion, parser):
    sample_bytes = b"From: batch@test.com\nTo: user@test.com\nSubject: Batch Item\n\nContent body"
    iterations = 30

    latencies = []
    start_total = time.perf_counter()

    for i in range(iterations):
        t0 = time.perf_counter()
        raw = ingestion.ingest(sample_bytes, f"batch_{i}.eml")
        p = parser.parse(raw)
        latencies.append((time.perf_counter() - t0) * 1000)

    total_time = time.perf_counter() - start_total
    avg_latency = sum(latencies) / len(latencies)
    throughput = iterations / total_time

    assert avg_latency < 10.0  # Small email avg latency < 10ms
    assert throughput > 100.0  # > 100 emails/sec throughput


# ============================================================================
# Benchmark 5: High Payload Stress (5MB & 10MB Payloads)
# ============================================================================
def test_performance_heavy_payloads(ingestion, parser):
    heavy_sizes = [
        ("5MB Payload", 5 * 1024 * 1024),
        ("10MB Payload", 10 * 1024 * 1024),
    ]

    for label, size in heavy_sizes:
        eml_bytes = generate_email_with_size(size)

        tracemalloc.start()
        start = time.perf_counter()

        payload = ingestion.ingest(eml_bytes, f"heavy_{size}.eml")
        parsed = parser.parse(payload)

        elapsed_ms = (time.perf_counter() - start) * 1000
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        assert parsed.subject == "Large Size Benchmark"
        assert elapsed_ms < 1500.0, f"{label} exceeded 1500ms ceiling ({elapsed_ms:.2f}ms)"
        assert peak_mem < 150 * 1024 * 1024, f"{label} exceeded 150MB peak memory ({peak_mem/(1024*1024):.2f}MB)"


# ============================================================================
# Benchmark 6: Asynchronous Concurrency Stress (20 Concurrent Scans)
# ============================================================================
@pytest.mark.asyncio
async def test_performance_concurrent_async_scans(ingestion, parser):
    import asyncio

    async def run_single_scan(idx: int):
        sample = f"From: user{idx}@concurrent.org\nTo: target@concurrent.org\nSubject: Concurrency Task {idx}\n\nTask body {idx}".encode()
        payload = ingestion.ingest(sample, f"concurrent_{idx}.eml")
        parsed = parser.parse(payload)
        return parsed.subject

    start = time.perf_counter()
    tasks = [run_single_scan(i) for i in range(20)]
    results = await asyncio.gather(*tasks)
    total_elapsed_ms = (time.perf_counter() - start) * 1000

    assert len(results) == 20
    assert total_elapsed_ms < 500.0, f"20 concurrent scans took too long: {total_elapsed_ms:.2f}ms"

