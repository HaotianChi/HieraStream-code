"""Open-loop rate-controlled load generator.

Schedules submissions at t_i = t_0 + i / lambda without waiting for
commit of transaction i before *scheduling* i+1, subject to a bounded
outstanding semaphore.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class TxTiming:
    tx_index: int
    scheduled_submission_s: float
    actual_submission_s: float
    commit_completion_s: float
    status: str
    reason: str = ""
    tx_id: str = ""

    @property
    def queue_delay_s(self) -> float:
        return self.actual_submission_s - self.scheduled_submission_s

    @property
    def completion_latency_s(self) -> float:
        return self.commit_completion_s - self.actual_submission_s

    @property
    def e2e_offered_latency_s(self) -> float:
        return self.commit_completion_s - self.scheduled_submission_s


@dataclass
class OpenLoopResult:
    target_offered_tps: float
    n: int
    max_outstanding: int
    timings: List[TxTiming] = field(default_factory=list)
    wall_s: float = 0.0
    submission_span_s: float = 0.0
    bound_wait_events: int = 0
    max_outstanding_observed: int = 0
    bound_saturated: bool = False

    @property
    def submitted(self) -> int:
        return len(self.timings)

    @property
    def completed(self) -> int:
        return len(self.timings)

    @property
    def actual_submission_tps(self) -> float:
        if self.submission_span_s <= 0:
            return float(self.submitted)
        # n submissions span from first actual submit to last actual submit;
        # rate ≈ (n-1)/span for n>1, else 1/eps
        if self.submitted <= 1:
            return float(self.submitted) / max(self.submission_span_s, 1e-9)
        return (self.submitted - 1) / self.submission_span_s

    @property
    def valid_committed(self) -> int:
        return sum(1 for t in self.timings if t.status == "VALID")

    @property
    def invalid(self) -> int:
        return self.submitted - self.valid_committed

    @property
    def valid_committed_tps(self) -> float:
        return self.valid_committed / max(self.wall_s, 1e-9)


WorkerFn = Callable[[int], Dict[str, Any]]
# worker returns dict with status, reason?, tx_id?


def run_open_loop(
    *,
    target_offered_tps: float,
    n: int,
    max_outstanding: int,
    worker: WorkerFn,
    worker_threads: Optional[int] = None,
) -> OpenLoopResult:
    """Inject n transactions at open-loop rate target_offered_tps.

    worker(i) executes one transaction and must return
    {"status": "VALID"|"...", "reason": str, "tx_id": str}.
    Timing around worker call is recorded by the harness.
    """
    if target_offered_tps <= 0:
        raise ValueError("target_offered_tps must be > 0")
    if n <= 0:
        raise ValueError("n must be > 0")
    if max_outstanding <= 0:
        raise ValueError("max_outstanding must be > 0")

    threads = worker_threads or max_outstanding
    sem = threading.BoundedSemaphore(max_outstanding)
    lock = threading.Lock()
    outstanding = 0
    max_out = 0
    bound_waits = 0
    timings: List[TxTiming] = []
    futures: List[Future] = []

    t0 = time.perf_counter()
    first_submit: Optional[float] = None
    last_submit: Optional[float] = None

    def _wrapped(i: int, scheduled: float) -> TxTiming:
        nonlocal outstanding, max_out
        actual = time.perf_counter()
        try:
            out = worker(i)
        except Exception as exc:  # noqa: BLE001
            out = {"status": "INVALID", "reason": str(exc), "tx_id": ""}
        done = time.perf_counter()
        with lock:
            outstanding -= 1
        sem.release()
        return TxTiming(
            tx_index=i,
            scheduled_submission_s=scheduled - t0,
            actual_submission_s=actual - t0,
            commit_completion_s=done - t0,
            status=str(out.get("status", "INVALID")),
            reason=str(out.get("reason", "")),
            tx_id=str(out.get("tx_id", "")),
        )

    with ThreadPoolExecutor(max_workers=threads) as pool:
        for i in range(n):
            scheduled_abs = t0 + (i / float(target_offered_tps))
            now = time.perf_counter()
            if now < scheduled_abs:
                time.sleep(scheduled_abs - now)

            # Acquire outstanding slot (may delay submission past schedule)
            acquired = sem.acquire(blocking=False)
            if not acquired:
                bound_waits += 1
                sem.acquire(blocking=True)
            with lock:
                outstanding += 1
                if outstanding > max_out:
                    max_out = outstanding

            submit_abs = time.perf_counter()
            if first_submit is None:
                first_submit = submit_abs
            last_submit = submit_abs
            fut = pool.submit(_wrapped, i, scheduled_abs)
            futures.append(fut)

        for fut in futures:
            timings.append(fut.result())

    wall = time.perf_counter() - t0
    timings.sort(key=lambda t: t.tx_index)
    span = 0.0
    if first_submit is not None and last_submit is not None:
        span = max(last_submit - first_submit, 1e-9)

    return OpenLoopResult(
        target_offered_tps=target_offered_tps,
        n=n,
        max_outstanding=max_outstanding,
        timings=timings,
        wall_s=wall,
        submission_span_s=span,
        bound_wait_events=bound_waits,
        max_outstanding_observed=max_out,
        bound_saturated=bound_waits > 0,
    )
