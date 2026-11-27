"""DKIM Bounded ThreadPool Executor with capacity enforcement and cancellation safety.

Architecture reference: MS-ARCH-SEC-2026-AUTH-PROTOCOLS-REV13
Enforces active-plus-queued capacity limits, two-phase shutdown,
and thread lifetime isolation from asyncio coroutine cancellation.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import logging
import time
from typing import Any, Callable, List, Optional, Set, TypeVar

from app.modules.auth_protocols.config import AuthProtocolsConfig

logger = logging.getLogger(__name__)

T = TypeVar("T")


class DKIMExecutorError(Exception):
    """Base exception for all DKIM executor errors."""
    pass


class DKIMCapacityExhaustedError(DKIMExecutorError):
    """Raised when active + queued verification capacity exceeds configured maximum.
    
    This occurs when the total number of currently executing worker threads plus
    jobs waiting in the executor queue reaches max_capacity.
    """
    pass


class DKIMExecutorShuttingDownError(DKIMExecutorError):
    """Raised when job submission is attempted while the executor is shutting down or shut down."""
    pass


class DKIMShutdownCancelledError(DKIMExecutorError):
    """Raised when a queued job is cancelled because the executor initiated shutdown before it executed."""
    pass


class _DKIMJob:
    """Internal tracking context for a DKIM executor job."""

    def __init__(
        self,
        fn: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        timeout: float,
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.timeout = timeout
        self.loop = loop
        self.result_future: asyncio.Future[Any] = loop.create_future()
        self.start_time: Optional[float] = None
        self.thread_future: Optional[Any] = None


class DKIMExecutor:
    """Bounded, cancellation-safe ThreadPoolExecutor for CPU-bound DKIM verification.
    
    Invariants (MS-ARCH-SEC-2026-AUTH-PROTOCOLS-REV13):
    1. Capacity bounds: total active (running in thread) + queued jobs strictly <= max_capacity.
    2. Cancellation safety: cancelling an awaiting coroutine does not cancel a running
       OS worker thread. Capacity reserved for a running thread is released ONLY when the
       underlying thread terminates.
    3. Two-phase shutdown:
       - Phase 1: Immediately reject new submissions and drain queued jobs with
         DKIMShutdownCancelledError.
       - Phase 2: Await running thread workers up to timeout, then terminate ThreadPoolExecutor.
    4. Idempotency & Shielding: Multiple concurrent shutdown calls share the same underlying
       shutdown task, protected with asyncio.shield against caller cancellation.
    """

    def __init__(
        self,
        max_workers: int = 8,
        max_queue_size: int = 24,
        max_capacity: Optional[int] = None,
        default_timeout: float = 3.0,
        config: Optional[AuthProtocolsConfig] = None,
    ) -> None:
        if config is not None:
            max_workers = config.dkim_worker_threads
            max_queue_size = config.dkim_queue_capacity
            default_timeout = config.dkim_verification_timeout

        self._max_workers = max(1, max_workers)
        self._max_queue_size = max(0, max_queue_size)
        self._max_capacity = (
            max_capacity if max_capacity is not None else (self._max_workers + self._max_queue_size)
        )
        self._default_timeout = default_timeout

        self._thread_pool = ThreadPoolExecutor(
            max_workers=self._max_workers,
            thread_name_prefix="dkim-worker",
        )

        self._running_jobs: Set[_DKIMJob] = set()
        self._queued_jobs: List[_DKIMJob] = []

        self._is_shutting_down: bool = False
        self._is_shutdown: bool = False
        self._shutdown_timed_out: bool = False
        self._shutdown_task: Optional[asyncio.Task[None]] = None
        self._lock = asyncio.Lock()

    @property
    def max_workers(self) -> int:
        return self._max_workers

    @property
    def max_queue_size(self) -> int:
        return self._max_queue_size

    @property
    def max_capacity(self) -> int:
        return self._max_capacity

    @property
    def running_count(self) -> int:
        return len(self._running_jobs)

    @property
    def queued_count(self) -> int:
        return len(self._queued_jobs)

    @property
    def active_capacity(self) -> int:
        return len(self._running_jobs) + len(self._queued_jobs)

    @property
    def is_shutting_down(self) -> bool:
        return self._is_shutting_down

    @property
    def is_shutdown(self) -> bool:
        return self._is_shutdown

    @property
    def shutdown_timed_out(self) -> bool:
        return self._shutdown_timed_out

    @property
    def has_pending_workers(self) -> bool:
        return len(self._running_jobs) > 0

    @property
    def all_workers_done(self) -> bool:
        return len(self._running_jobs) == 0

    @property
    def submission_disabled(self) -> bool:
        return self._is_shutting_down or self._is_shutdown

    async def submit(
        self,
        fn: Callable[..., T],
        *args: Any,
        timeout: Optional[float] = None,
        **kwargs: Any,
    ) -> T:
        """Submits a CPU-bound callable for execution in the thread pool.
        
        Enforces capacity limits and handles cancellation safely.
        """
        # Fast-path check: if current coroutine is already cancelled
        cur_task = asyncio.current_task()
        if cur_task is not None and cur_task.cancelled():
            raise asyncio.CancelledError()

        if self._is_shutting_down or self._is_shutdown:
            raise DKIMExecutorShuttingDownError(
                "Cannot submit new job: DKIM executor is shutting down or has terminated"
            )

        # Capacity enforcement: active + queued <= max_capacity
        if len(self._running_jobs) + len(self._queued_jobs) >= self._max_capacity:
            raise DKIMCapacityExhaustedError(
                f"DKIM executor capacity exhausted (active: {len(self._running_jobs)}, "
                f"queued: {len(self._queued_jobs)}, max: {self._max_capacity})"
            )

        loop = asyncio.get_running_loop()
        effective_timeout = timeout if timeout is not None else self._default_timeout
        job = _DKIMJob(fn, args, kwargs, effective_timeout, loop)
        self._queued_jobs.append(job)

        # Pump the queue to dispatch to available worker threads
        self._pump_queue()

        # Await completion with cancellation and timeout safety
        try:
            return await asyncio.wait_for(
                asyncio.shield(job.result_future),
                timeout=job.timeout,
            )
        except (asyncio.TimeoutError, asyncio.CancelledError):
            # If the job was still queued (never started in a thread), remove it
            # and free its queued capacity reservation immediately.
            if job in self._queued_jobs:
                self._queued_jobs.remove(job)
                if not job.result_future.done():
                    job.result_future.cancel()
            else:
                # Job is already executing in an OS worker thread.
                # Per REV13: capacity MUST NOT be released while the thread is running.
                # Attach a drain handler to consume any exception when the thread completes.
                def _swallow_exc(fut: asyncio.Future[Any]) -> None:
                    try:
                        fut.exception()
                    except (asyncio.CancelledError, Exception):
                        pass

                job.result_future.add_done_callback(_swallow_exc)
            raise

    def _pump_queue(self) -> None:
        """Dispatches queued jobs to worker threads up to max_workers."""
        if self._is_shutting_down or self._is_shutdown:
            return

        while self._queued_jobs and len(self._running_jobs) < self._max_workers:
            job = self._queued_jobs.pop(0)
            self._running_jobs.add(job)
            job.start_time = time.monotonic()

            def _worker_wrapper(j: _DKIMJob) -> None:
                try:
                    res = j.fn(*j.args, **j.kwargs)
                    if not j.loop.is_closed():
                        j.loop.call_soon_threadsafe(self._on_job_success, j, res)
                except BaseException as exc:
                    if not j.loop.is_closed():
                        j.loop.call_soon_threadsafe(self._on_job_failure, j, exc)

            try:
                job.thread_future = self._thread_pool.submit(_worker_wrapper, job)
            except RuntimeError as exc:
                self._running_jobs.discard(job)
                if not job.result_future.done():
                    job.result_future.set_exception(
                        DKIMExecutorShuttingDownError(f"ThreadPoolExecutor submission failed: {exc}")
                    )
                break

    def _on_job_success(self, job: _DKIMJob, result: Any) -> None:
        """Called on event loop thread when worker completes successfully."""
        self._running_jobs.discard(job)
        if not job.result_future.done():
            job.result_future.set_result(result)
        if not (self._is_shutting_down or self._is_shutdown):
            self._pump_queue()

    def _on_job_failure(self, job: _DKIMJob, exc: BaseException) -> None:
        """Called on event loop thread when worker raises an exception."""
        self._running_jobs.discard(job)
        if not job.result_future.done():
            job.result_future.set_exception(exc)
        if not (self._is_shutting_down or self._is_shutdown):
            self._pump_queue()

    async def wait_for_workers(self, timeout: Optional[float] = None) -> bool:
        """Awaits any remaining running worker threads.
        
        Returns True if all workers have finished, False if timeout expired.
        """
        if not self._running_jobs:
            return True
        remaining = timeout if timeout is not None else self._default_timeout
        running_futures = [j.result_future for j in list(self._running_jobs)]
        if not running_futures:
            return True
        try:
            done, pending = await asyncio.wait(
                running_futures,
                timeout=remaining,
                return_when=asyncio.ALL_COMPLETED,
            )
            return len(pending) == 0
        except Exception as exc:
            logger.warning("Error waiting for pending DKIM workers: %s", exc)
            return len(self._running_jobs) == 0

    async def shutdown(self, wait: bool = True, timeout: Optional[float] = None) -> None:
        """Initiates idempotent two-phase shutdown.
        
        Phase 1: Stop accepting jobs and cancel queued jobs with DKIMShutdownCancelledError.
        Phase 2: Wait for running thread workers to complete (up to timeout).
        
        If timeout expires and workers remain active, non-blocking shutdown(wait=False)
        is initiated; running threads remain tracked until their eventual completion.
        
        Protected by asyncio.shield so caller cancellation does not abort shutdown.
        """
        async with self._lock:
            if self._is_shutdown:
                if wait and self._running_jobs:
                    await self.wait_for_workers(timeout=timeout)
                return
            if self._shutdown_task is None:
                self._shutdown_task = asyncio.create_task(
                    self._do_shutdown(wait=wait, timeout=timeout)
                )

        try:
            await asyncio.shield(self._shutdown_task)
        except asyncio.CancelledError:
            # Caller was cancelled, but background shutdown task continues
            raise

    async def _do_shutdown(self, wait: bool = True, timeout: Optional[float] = None) -> None:
        """Internal implementation of two-phase bounded shutdown."""
        self._is_shutting_down = True

        # Phase 1: Drain and cancel queued jobs immediately
        queued_to_drain = list(self._queued_jobs)
        self._queued_jobs.clear()
        for job in queued_to_drain:
            if not job.result_future.done():
                job.result_future.set_exception(
                    DKIMShutdownCancelledError("Job cancelled due to DKIM executor shutdown")
                )

        # Phase 2: Await currently running worker threads up to timeout
        timed_out = False
        if wait and self._running_jobs:
            remaining = timeout if timeout is not None else self._default_timeout
            running_futures = [j.result_future for j in list(self._running_jobs)]
            if running_futures:
                try:
                    done, pending = await asyncio.wait(
                        running_futures,
                        timeout=remaining,
                        return_when=asyncio.ALL_COMPLETED,
                    )
                    if pending:
                        timed_out = True
                        logger.warning(
                            "DKIM executor shutdown wait timed out (%ss) with %d jobs still active",
                            remaining,
                            len(pending),
                        )
                except Exception as exc:
                    logger.warning("Error waiting for running DKIM jobs during shutdown: %s", exc)

        self._shutdown_timed_out = timed_out

        # Final cleanup:
        # If workers timed out or wait was False:
        # Initiate non-blocking shutdown without waiting for running threads to finish.
        # DO NOT call shutdown(wait=True) because it would block indefinitely!
        # Running threads continue to be tracked in self._running_jobs until completion.
        if timed_out or not wait:
            self._thread_pool.shutdown(wait=False, cancel_futures=True)
        else:
            # All running workers finished within timeout; safe to perform normal shutdown
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None, lambda: self._thread_pool.shutdown(wait=True, cancel_futures=True)
            )

        self._is_shutdown = True
        self._is_shutting_down = False

    async def __aenter__(self) -> "DKIMExecutor":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.shutdown(wait=True)
