"""Fixed-duration open-loop steady-state load generator.

Phases: warm-up → measurement → drain.
Primary committed TPS uses ONLY commits inside the measurement window.
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
    phase: str  # warmup | measure | drain_completion_of_prior
    scheduled_submission_s: float
    actual_submission_s: float
    commit_completion_s: float
    status: str
    reason: str = ""
    tx_id: str = ""
    owner_key: str = ""
    code: str = ""
    invalid_category: str = ""

    @property
    def scheduling_delay_s(self) -> float:
        return self.actual_submission_s - self.scheduled_submission_s

    @property
    def transaction_latency_s(self) -> float:
        return self.commit_completion_s - self.actual_submission_s

    @property
    def offered_load_e2e_latency_s(self) -> float:
        return self.commit_completion_s - self.scheduled_submission_s


@dataclass
class SteadyStateResult:
    target_offered_tps: float
    warmup_s: float
    measure_s: float
    max_outstanding: int
    timings: List[TxTiming] = field(default_factory=list)
    t0: float = 0.0
    warmup_end_s: float = 0.0
    measure_end_s: float = 0.0
    drain_end_s: float = 0.0
    bound_wait_events: int = 0
    max_outstanding_observed: int = 0
    bound_hit: bool = False
    outstanding_at_measurement_end: int = 0
    configured_worker_threads: int = 0

    @property
    def drain_duration_s(self) -> float:
        return max(0.0, self.drain_end_s - self.measure_end_s)

    @property
    def total_submitted(self) -> int:
        return sum(1 for t in self.timings if t.phase in {"warmup", "measure"})

    @property
    def measure_submitted(self) -> int:
        return sum(
            1
            for t in self.timings
            if self.warmup_end_s <= t.actual_submission_s < self.measure_end_s
        )

    @property
    def measure_valid_commits(self) -> int:
        return sum(
            1
            for t in self.timings
            if t.status == "VALID"
            and self.warmup_end_s <= t.commit_completion_s < self.measure_end_s
        )

    @property
    def actual_submission_tps(self) -> float:
        return self.measure_submitted / max(self.measure_s, 1e-9)

    @property
    def steady_state_valid_commit_tps(self) -> float:
        return self.measure_valid_commits / max(self.measure_s, 1e-9)

    @property
    def total_valid_eventually(self) -> int:
        return sum(1 for t in self.timings if t.status == "VALID")

    @property
    def total_invalid(self) -> int:
        return sum(1 for t in self.timings if t.status != "VALID")

    def measure_latencies(self) -> List[float]:
        # Primary: txs submitted during measurement (completion may be after window)
        return [
            t.transaction_latency_s
            for t in self.timings
            if self.warmup_end_s <= t.actual_submission_s < self.measure_end_s
        ]

    def measure_sched_delays(self) -> List[float]:
        return [
            t.scheduling_delay_s
            for t in self.timings
            if self.warmup_end_s <= t.actual_submission_s < self.measure_end_s
        ]


WorkerFn = Callable[[int], Dict[str, Any]]


def run_steady_state(
    *,
    target_offered_tps: float,
    warmup_s: float,
    measure_s: float,
    max_outstanding: int,
    worker: WorkerFn,
    worker_threads: Optional[int] = None,
) -> SteadyStateResult:
    if target_offered_tps <= 0:
        raise ValueError("target_offered_tps must be > 0")
    if measure_s < 1:
        raise ValueError("measure_s too small")
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
    warmup_end = t0 + warmup_s
    measure_end = warmup_end + measure_s
    outstanding_at_measure_end = 0
    measure_end_captured = False

    def _wrapped(i: int, scheduled: float, phase: str) -> TxTiming:
        nonlocal outstanding, max_out
        actual = time.perf_counter()
        try:
            out = worker(i)
        except Exception as exc:  # noqa: BLE001
            out = {"status": "INVALID", "reason": str(exc), "tx_id": "", "owner_key": "", "code": "WORKER_EXCEPTION"}
        done = time.perf_counter()
        with lock:
            outstanding -= 1
        sem.release()
        status = str(out.get("status", "INVALID"))
        reason = str(out.get("reason", out.get("error", "")))
        code = str(out.get("code", ""))
        try:
            from experiments.harness.invalid_taxonomy import classify_failure

            cat = "VALID" if status.upper() == "VALID" else classify_failure(status, reason, code)
        except Exception:
            cat = "H_UNKNOWN" if status.upper() != "VALID" else "VALID"
        return TxTiming(
            tx_index=i,
            phase=phase,
            scheduled_submission_s=scheduled - t0,
            actual_submission_s=actual - t0,
            commit_completion_s=done - t0,
            status=status,
            reason=reason,
            tx_id=str(out.get("tx_id", "")),
            owner_key=str(out.get("owner_key", "")),
            code=code,
            invalid_category=cat,
        )

    i = 0
    with ThreadPoolExecutor(max_workers=threads) as pool:
        while True:
            now = time.perf_counter()
            if now >= measure_end:
                break
            scheduled_abs = t0 + (i / float(target_offered_tps))
            # If schedule is in the future, sleep (but don't go past measure_end)
            if scheduled_abs > now:
                sleep_for = min(scheduled_abs - now, max(0.0, measure_end - now))
                if sleep_for > 0:
                    time.sleep(sleep_for)
                now = time.perf_counter()
                if now >= measure_end:
                    break
            # If we are behind schedule, submit immediately
            if scheduled_abs < t0:
                scheduled_abs = now

            phase = "warmup" if now < warmup_end else "measure"

            acquired = sem.acquire(blocking=False)
            if not acquired:
                bound_waits += 1
                # Don't block past measure_end
                remaining = measure_end - time.perf_counter()
                if remaining <= 0:
                    break
                got = sem.acquire(timeout=remaining)
                if not got:
                    break
            with lock:
                outstanding += 1
                if outstanding > max_out:
                    max_out = outstanding

            fut = pool.submit(_wrapped, i, max(scheduled_abs, t0), phase)
            futures.append(fut)
            i += 1

        # Capture outstanding at measurement end
        with lock:
            outstanding_at_measure_end = outstanding
            measure_end_captured = True

        # PHASE 3 — drain: wait for all outstanding
        for fut in futures:
            timings.append(fut.result())

    drain_end = time.perf_counter()
    timings.sort(key=lambda t: t.tx_index)

    return SteadyStateResult(
        target_offered_tps=target_offered_tps,
        warmup_s=warmup_s,
        measure_s=measure_s,
        max_outstanding=max_outstanding,
        timings=timings,
        t0=0.0,
        warmup_end_s=warmup_s,
        measure_end_s=warmup_s + measure_s,
        drain_end_s=drain_end - t0,
        bound_wait_events=bound_waits,
        max_outstanding_observed=max_out,
        bound_hit=bound_waits > 0,
        outstanding_at_measurement_end=outstanding_at_measure_end if measure_end_captured else 0,
        configured_worker_threads=threads,
    )
