"""Targeted tests for DKIM bounded ThreadPool executor and safety guarantees.

Architecture reference: MS-ARCH-SEC-2026-AUTH-PROTOCOLS-REV13
"""

import asyncio
import threading
import time
import pytest

from app.modules.auth_protocols.executor import (
    DKIMCapacityExhaustedError,
    DKIMExecutor,
    DKIMExecutorShuttingDownError,
    DKIMShutdownCancelledError,
)


@pytest.mark.asyncio
async def test_executor_capacity_enforcement_and_exhaustion():
    """Verify strict active + queued capacity enforcement and DKIMCapacityExhaustedError."""
    # 2 workers, 2 queued => max capacity = 4
    executor = DKIMExecutor(max_workers=2, max_queue_size=2)
    thread_release_events = [threading.Event() for _ in range(2)]
    thread_started_events = [threading.Event() for _ in range(2)]

    def _blocking_worker(idx: int) -> str:
        thread_started_events[idx].set()
        thread_release_events[idx].wait(timeout=5.0)
        return f"done-{idx}"

    try:
        # Submit 2 running jobs
        t0 = asyncio.create_task(executor.submit(_blocking_worker, 0))
        t1 = asyncio.create_task(executor.submit(_blocking_worker, 1))

        # Wait until both workers are actually running in threads
        await asyncio.to_thread(thread_started_events[0].wait, 2.0)
        await asyncio.to_thread(thread_started_events[1].wait, 2.0)
        await asyncio.sleep(0.02)

        assert executor.running_count == 2
        assert executor.queued_count == 0
        assert executor.active_capacity == 2

        # Submit 2 queued jobs
        def _quick_worker(val: int) -> int:
            return val * 10

        t2 = asyncio.create_task(executor.submit(_quick_worker, 2))
        t3 = asyncio.create_task(executor.submit(_quick_worker, 3))
        await asyncio.sleep(0.02)

        assert executor.running_count == 2
        assert executor.queued_count == 2
        assert executor.active_capacity == 4

        # 5th job must be rejected with DKIMCapacityExhaustedError
        with pytest.raises(DKIMCapacityExhaustedError) as exc_info:
            await executor.submit(_quick_worker, 99)

        assert "capacity exhausted" in str(exc_info.value).lower()
        assert executor.active_capacity == 4

        # Release thread workers so all queued jobs execute
        for ev in thread_release_events:
            ev.set()

        res0 = await t0
        res1 = await t1
        res2 = await t2
        res3 = await t3

        assert res0 == "done-0"
        assert res1 == "done-1"
        assert res2 == 20
        assert res3 == 30

        await asyncio.sleep(0.02)
        assert executor.running_count == 0
        assert executor.queued_count == 0
        assert executor.active_capacity == 0
    finally:
        for ev in thread_release_events:
            ev.set()
        await executor.shutdown(wait=True)


@pytest.mark.asyncio
async def test_executor_submission_during_shutdown():
    """Verify submissions during or after shutdown raise DKIMExecutorShuttingDownError."""
    executor = DKIMExecutor(max_workers=2, max_queue_size=2)
    await executor.shutdown(wait=True)

    assert executor.is_shutdown is True

    with pytest.raises(DKIMExecutorShuttingDownError) as exc_info:
        await executor.submit(lambda: 42)

    assert "shutting down or has terminated" in str(exc_info.value)


@pytest.mark.asyncio
async def test_executor_cancellation_before_submission():
    """Verify cancelled caller coroutine does not consume or leak executor capacity."""
    executor = DKIMExecutor(max_workers=2, max_queue_size=2)

    async def _cancelled_caller():
        cur = asyncio.current_task()
        cur.cancel()
        await executor.submit(lambda: 123)

    with pytest.raises(asyncio.CancelledError):
        await _cancelled_caller()

    assert executor.running_count == 0
    assert executor.queued_count == 0
    assert executor.active_capacity == 0

    await executor.shutdown()


@pytest.mark.asyncio
async def test_executor_cancellation_while_queued():
    """Verify cancelling a queued job removes it from the queue and releases queued capacity."""
    executor = DKIMExecutor(max_workers=1, max_queue_size=2)
    release_ev = threading.Event()
    started_ev = threading.Event()

    def _block():
        started_ev.set()
        release_ev.wait(timeout=5.0)
        return "unblocked"

    try:
        # Occupy the 1 worker
        t0 = asyncio.create_task(executor.submit(_block))
        await asyncio.to_thread(started_ev.wait, 2.0)
        await asyncio.sleep(0.02)

        assert executor.running_count == 1
        assert executor.queued_count == 0

        # Submit queued job
        t_queued = asyncio.create_task(executor.submit(lambda: "never"))
        await asyncio.sleep(0.02)

        assert executor.queued_count == 1
        assert executor.active_capacity == 2

        # Cancel the queued task
        t_queued.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t_queued

        await asyncio.sleep(0.02)
        # Queued capacity must be freed immediately
        assert executor.queued_count == 0
        assert executor.running_count == 1
        assert executor.active_capacity == 1

        # Release running worker
        release_ev.set()
        res0 = await t0
        assert res0 == "unblocked"

        await asyncio.sleep(0.02)
        assert executor.active_capacity == 0
    finally:
        release_ev.set()
        await executor.shutdown(wait=True)


@pytest.mark.asyncio
async def test_executor_cancellation_while_running_preserves_capacity_until_thread_exits():
    """Verify cancelling an awaiting coroutine does NOT prematurely release capacity while thread runs."""
    executor = DKIMExecutor(max_workers=1, max_queue_size=2)
    release_ev = threading.Event()
    started_ev = threading.Event()

    def _slow_thread():
        started_ev.set()
        release_ev.wait(timeout=5.0)
        return "thread-done"

    try:
        t_caller = asyncio.create_task(executor.submit(_slow_thread))
        await asyncio.to_thread(started_ev.wait, 2.0)
        await asyncio.sleep(0.02)

        assert executor.running_count == 1
        assert executor.active_capacity == 1

        # Cancel the awaiting coroutine
        t_caller.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t_caller

        # CRITICAL REV13 REQUIREMENT:
        # Capacity MUST NOT be released while the OS worker thread is still running!
        await asyncio.sleep(0.02)
        assert executor.running_count == 1
        assert executor.active_capacity == 1

        # Release thread and verify capacity is freed once the thread completes
        release_ev.set()
        await asyncio.sleep(0.05)

        assert executor.running_count == 0
        assert executor.active_capacity == 0
    finally:
        release_ev.set()
        await executor.shutdown(wait=True)


@pytest.mark.asyncio
async def test_executor_worker_exception_propagation():
    """Verify exceptions raised inside worker threads propagate cleanly to the caller."""
    executor = DKIMExecutor(max_workers=2, max_queue_size=2)

    def _failing_worker():
        raise ValueError("Cryptographic verification fault")

    try:
        with pytest.raises(ValueError) as exc_info:
            await executor.submit(_failing_worker)

        assert "Cryptographic verification fault" in str(exc_info.value)
        assert executor.running_count == 0
        assert executor.active_capacity == 0
    finally:
        await executor.shutdown(wait=True)


@pytest.mark.asyncio
async def test_executor_two_phase_shutdown_drains_queue_and_waits_for_workers():
    """Verify two-phase shutdown cancels queued jobs with DKIMShutdownCancelledError and awaits running."""
    executor = DKIMExecutor(max_workers=1, max_queue_size=2)
    release_ev = threading.Event()
    started_ev = threading.Event()

    def _long_worker():
        started_ev.set()
        release_ev.wait(timeout=5.0)
        return "done-worker"

    try:
        t_run = asyncio.create_task(executor.submit(_long_worker))
        await asyncio.to_thread(started_ev.wait, 2.0)
        await asyncio.sleep(0.02)

        t_queued1 = asyncio.create_task(executor.submit(lambda: "q1"))
        t_queued2 = asyncio.create_task(executor.submit(lambda: "q2"))
        await asyncio.sleep(0.02)

        assert executor.running_count == 1
        assert executor.queued_count == 2

        # Start shutdown task in background
        shutdown_task = asyncio.create_task(executor.shutdown(wait=True, timeout=3.0))
        await asyncio.sleep(0.02)

        # Phase 1: Queued jobs must fail immediately with DKIMShutdownCancelledError
        with pytest.raises(DKIMShutdownCancelledError):
            await t_queued1
        with pytest.raises(DKIMShutdownCancelledError):
            await t_queued2

        assert executor.queued_count == 0
        assert executor.running_count == 1

        # Phase 2: Running worker continues until finished
        release_ev.set()
        res_run = await t_run
        assert res_run == "done-worker"

        await shutdown_task
        assert executor.is_shutdown is True
        assert executor.running_count == 0
    finally:
        release_ev.set()


@pytest.mark.asyncio
async def test_executor_concurrent_and_idempotent_shutdown():
    """Verify concurrent shutdown calls share the same underlying task and shutdown is idempotent."""
    executor = DKIMExecutor(max_workers=2, max_queue_size=2)

    # Submit quick job
    res = await executor.submit(lambda: 99)
    assert res == 99

    # Trigger concurrent shutdowns
    s1 = asyncio.create_task(executor.shutdown(wait=True))
    s2 = asyncio.create_task(executor.shutdown(wait=True))
    s3 = asyncio.create_task(executor.shutdown(wait=True))

    await asyncio.gather(s1, s2, s3)
    assert executor.is_shutdown is True

    # Sequential follow-up shutdown call is a no-op
    await executor.shutdown(wait=True)
    assert executor.is_shutdown is True


@pytest.mark.asyncio
async def test_executor_shutdown_cancellation_shield():
    """Verify cancellation of a coroutine awaiting shutdown does not abort background shutdown."""
    executor = DKIMExecutor(max_workers=1, max_queue_size=2)
    release_ev = threading.Event()
    started_ev = threading.Event()

    def _worker():
        started_ev.set()
        release_ev.wait(timeout=5.0)
        return "ok"

    t_run = asyncio.create_task(executor.submit(_worker))
    await asyncio.to_thread(started_ev.wait, 2.0)

    # Caller awaits shutdown but gets cancelled
    async def _await_shutdown_and_cancel():
        shut_task = asyncio.create_task(executor.shutdown(wait=True, timeout=5.0))
        await asyncio.sleep(0.02)
        shut_task.cancel()
        await shut_task

    with pytest.raises(asyncio.CancelledError):
        await _await_shutdown_and_cancel()

    # The background shutdown task must continue running!
    release_ev.set()
    await t_run
    await asyncio.sleep(0.05)

    # Calling shutdown again will await the already-completed or finishing shared task
    await executor.shutdown(wait=True)
    assert executor.is_shutdown is True


@pytest.mark.asyncio
async def test_executor_no_capacity_leaks_under_churn():
    """Verify clean capacity accounting across multiple concurrent jobs."""
    async with DKIMExecutor(max_workers=4, max_queue_size=20) as executor:
        def _job(i: int) -> int:
            return i * i

        tasks = [asyncio.create_task(executor.submit(_job, i)) for i in range(20)]
        results = await asyncio.gather(*tasks)

        assert results == [i * i for i in range(20)]
        await asyncio.sleep(0.02)
        assert executor.running_count == 0
        assert executor.queued_count == 0
        assert executor.active_capacity == 0


@pytest.mark.asyncio
async def test_shutdown_remediation_worker_finishes_before_timeout():
    """Test A: Start a worker that blocks on an Event; release before timeout; verify clean shutdown."""
    executor = DKIMExecutor(max_workers=2, max_queue_size=2)
    release_ev = threading.Event()
    started_ev = threading.Event()

    def _worker():
        started_ev.set()
        release_ev.wait(timeout=5.0)
        return "worker-completed-cleanly"

    try:
        t_job = asyncio.create_task(executor.submit(_worker))
        await asyncio.to_thread(started_ev.wait, 2.0)
        await asyncio.sleep(0.01)

        # Start shutdown with generous timeout
        shut_task = asyncio.create_task(executor.shutdown(wait=True, timeout=5.0))
        await asyncio.sleep(0.02)

        # Release the worker before the timeout expires
        release_ev.set()
        await shut_task

        assert executor.is_shutdown is True
        assert executor.shutdown_timed_out is False
        assert executor.all_workers_done is True
        assert executor.has_pending_workers is False
        assert executor.running_count == 0
        assert executor.active_capacity == 0
        assert await t_job == "worker-completed-cleanly"
    finally:
        release_ev.set()
        await executor.shutdown(wait=False)


@pytest.mark.asyncio
async def test_shutdown_remediation_worker_exceeds_timeout_bounded_and_tracked():
    """Test B: Worker blocked beyond shutdown timeout; verify bounded return, tracked worker, and rejection of new submissions."""
    executor = DKIMExecutor(max_workers=1, max_queue_size=2)
    release_ev = threading.Event()
    started_ev = threading.Event()

    def _slow_worker():
        started_ev.set()
        release_ev.wait(timeout=5.0)
        return "eventual-result"

    t_job = asyncio.create_task(executor.submit(_slow_worker))
    await asyncio.to_thread(started_ev.wait, 2.0)
    await asyncio.sleep(0.01)

    try:
        start_time = time.monotonic()
        # Shutdown with short 0.1s timeout; worker is NOT released yet
        await executor.shutdown(wait=True, timeout=0.1)
        elapsed = time.monotonic() - start_time

        # 1. Bounded return: must return promptly in ~0.1s, NOT hang indefinitely
        assert elapsed < 0.5, f"Shutdown took {elapsed}s; expected bounded return within ~0.1s"

        # 2. Worker is still tracked and NOT falsely marked complete
        assert executor.is_shutdown is True
        assert executor.shutdown_timed_out is True
        assert executor.has_pending_workers is True
        assert executor.all_workers_done is False
        assert executor.running_count == 1
        assert executor.active_capacity == 1

        # 3. New submissions are rejected
        with pytest.raises(DKIMExecutorShuttingDownError):
            await executor.submit(lambda: "rejected")

    finally:
        # Release worker so the test thread terminates cleanly
        release_ev.set()
        completed = await executor.wait_for_workers(timeout=2.0)
        assert completed is True
        assert executor.running_count == 0
        assert executor.has_pending_workers is False
        assert executor.all_workers_done is True
        assert await t_job == "eventual-result"


@pytest.mark.asyncio
async def test_shutdown_remediation_concurrent_shutdown_after_timeout():
    """Test C: Multiple callers await shutdown; verify consistent shared outcome and cancellation safety."""
    executor = DKIMExecutor(max_workers=1, max_queue_size=2)
    release_ev = threading.Event()
    started_ev = threading.Event()

    def _blocking():
        started_ev.set()
        release_ev.wait(timeout=5.0)
        return "done-c"

    t_job = asyncio.create_task(executor.submit(_blocking))
    await asyncio.to_thread(started_ev.wait, 2.0)
    await asyncio.sleep(0.01)

    try:
        # Launch 3 concurrent shutdown callers
        s1 = asyncio.create_task(executor.shutdown(wait=True, timeout=0.1))
        s2 = asyncio.create_task(executor.shutdown(wait=True, timeout=0.1))
        s3 = asyncio.create_task(executor.shutdown(wait=True, timeout=0.1))

        # Cancel caller s1
        s1.cancel()
        with pytest.raises(asyncio.CancelledError):
            await s1

        # Callers s2 and s3 must finish normally within bounded time
        await asyncio.gather(s2, s3)

        assert executor.is_shutdown is True
        assert executor.shutdown_timed_out is True
        assert executor.has_pending_workers is True
    finally:
        release_ev.set()
        await executor.wait_for_workers(timeout=2.0)
        assert await t_job == "done-c"


@pytest.mark.asyncio
async def test_shutdown_remediation_capacity_and_completion_accounting():
    """Test D: Capacity accounting remains exact under shutdown timeout and deferred completion."""
    executor = DKIMExecutor(max_workers=2, max_queue_size=2)
    release_ev = threading.Event()
    started_ev = threading.Event()

    def _worker():
        started_ev.set()
        release_ev.wait(timeout=5.0)
        return "accounted"

    t_job = asyncio.create_task(executor.submit(_worker))
    await asyncio.to_thread(started_ev.wait, 2.0)

    try:
        assert executor.running_count == 1
        assert executor.active_capacity == 1

        # Shutdown with short timeout
        await executor.shutdown(wait=True, timeout=0.08)

        # Worker is still running: capacity must NOT be released prematurely
        assert executor.running_count == 1
        assert executor.active_capacity == 1

        # Now release worker
        release_ev.set()
        await executor.wait_for_workers(timeout=2.0)

        # Capacity must be released exactly once
        assert executor.running_count == 0
        assert executor.active_capacity == 0
        assert executor.all_workers_done is True

        # Duplicate completion check: safe no-op on already completed job
        from app.modules.auth_protocols.executor import _DKIMJob
        loop = asyncio.get_running_loop()
        dummy_job = _DKIMJob(lambda: None, (), {}, 1.0, loop)
        dummy_job.result_future.set_result(None)
        executor._on_job_success(dummy_job, "extra")
        assert executor.running_count == 0
        assert executor.active_capacity == 0
    finally:
        release_ev.set()


@pytest.mark.asyncio
async def test_shutdown_remediation_event_loop_responsiveness_during_timeout():
    """Test E: Verify event loop remains responsive and can execute other coroutines while worker exceeds shutdown timeout."""
    executor = DKIMExecutor(max_workers=1, max_queue_size=2)
    release_ev = threading.Event()
    started_ev = threading.Event()

    def _hung_worker():
        started_ev.set()
        release_ev.wait(timeout=5.0)
        return "eventually"

    t_job = asyncio.create_task(executor.submit(_hung_worker))
    await asyncio.to_thread(started_ev.wait, 2.0)

    try:
        # Shutdown with short timeout
        await executor.shutdown(wait=True, timeout=0.05)

        # Worker is still blocked in background
        assert executor.has_pending_workers is True

        # Verify event loop can execute an independent coroutine immediately
        loop_executed = False
        async def _independent_coroutine():
            nonlocal loop_executed
            await asyncio.sleep(0.01)
            loop_executed = True
            return "success"

        result = await _independent_coroutine()
        assert result == "success"
        assert loop_executed is True
    finally:
        release_ev.set()
        await executor.wait_for_workers(timeout=2.0)
        assert await t_job == "eventually"

