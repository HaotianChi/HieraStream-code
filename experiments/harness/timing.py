"""Measurement helpers: warm-up, repeats, monotonic clocks, counters.

Outliers are not discarded — all timed samples remain in raw.jsonl.
Aggregates (mean/median/p95/p99) are derived from the full sample set.
"""

from __future__ import annotations

import random
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, TypeVar

from experiments.harness.metrics import latency_summary
from experiments.harness.run_context import resource_snapshot

T = TypeVar("T")


@dataclass
class TimedSample:
    """One raw per-operation timing record (kept in full)."""

    elapsed_s: float
    clock: str = "perf_counter"  # monotonic wall clock
    process_time_s: Optional[float] = None
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TxCounters:
    """Valid/invalid / backlog counters for Fabric-like workloads."""

    submitted: int = 0
    valid: int = 0
    invalid: int = 0
    mvcc_conflict: int = 0
    acl_denied: int = 0
    pending_backlog: int = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "tx_submitted": self.submitted,
            "tx_valid": self.valid,
            "tx_invalid": self.invalid,
            "tx_mvcc_conflict": self.mvcc_conflict,
            "tx_acl_denied": self.acl_denied,
            "queue_backlog": self.pending_backlog,
        }


@contextmanager
def timed_op(*, collect_process_time: bool = True) -> Iterator[Dict[str, float]]:
    """Measure one operation with time.perf_counter (monotonic) + optional process_time."""
    out: Dict[str, float] = {}
    t0 = time.perf_counter()
    p0 = time.process_time() if collect_process_time else 0.0
    try:
        yield out
    finally:
        out["elapsed_s"] = time.perf_counter() - t0
        if collect_process_time:
            out["process_time_s"] = time.process_time() - p0


def warm_then_measure(
    fn: Callable[[], T],
    *,
    warmup: int,
    repeats: int,
    on_sample: Optional[Callable[[int, T, TimedSample], None]] = None,
) -> List[TimedSample]:
    """Run warmup (discarded from returned list) then repeats (all kept)."""
    for _ in range(max(0, warmup)):
        fn()
    samples: List[TimedSample] = []
    for i in range(repeats):
        with timed_op() as t:
            result = fn()
        sample = TimedSample(
            elapsed_s=t["elapsed_s"],
            process_time_s=t.get("process_time_s"),
        )
        samples.append(sample)
        if on_sample is not None:
            on_sample(i, result, sample)
    return samples


def shuffled_order(items: Sequence[T], *, seed: Optional[int], enabled: bool) -> List[T]:
    """Randomize experiment / parameter order when profile requests it."""
    out = list(items)
    if not enabled:
        return out
    rng = random.Random(seed)
    rng.shuffle(out)
    return out


def attach_resource_delta(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    """CPU/memory delta fields for longitudinal / stress rows."""
    out: Dict[str, Any] = {
        "cpu_percent_end": after.get("cpu_percent"),
        "rss_bytes_end": after.get("rss_bytes"),
        "ru_maxrss_kb_end": after.get("ru_maxrss_kb"),
    }
    if before.get("ru_utime_s") is not None and after.get("ru_utime_s") is not None:
        out["ru_utime_delta_s"] = float(after["ru_utime_s"]) - float(before["ru_utime_s"])
    return out


def summarize_keep_all(samples: Sequence[float], *, prefix: str = "latency_s") -> Dict[str, Any]:
    """Aggregate without dropping outliers; also record min/max and full count."""
    xs = [float(x) for x in samples]
    agg = latency_summary(xs, prefix=prefix)
    agg[f"{prefix}_min"] = min(xs) if xs else float("nan")
    agg[f"{prefix}_max"] = max(xs) if xs else float("nan")
    agg["outliers_discarded"] = False
    agg["all_samples_retained"] = True
    return agg


def snapshot_pair() -> tuple[Dict[str, Any], Callable[[], Dict[str, Any]]]:
    before = resource_snapshot()

    def end() -> Dict[str, Any]:
        return attach_resource_delta(before, resource_snapshot())

    return before, end
