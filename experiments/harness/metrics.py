"""Latency / rate summaries computed only from measured samples."""

from __future__ import annotations

import statistics
from typing import Dict, List, Sequence


def percentile(samples: Sequence[float], p: float) -> float:
    """Inclusive nearest-rank percentile; p in [0, 100]."""
    if not samples:
        return float("nan")
    xs = sorted(float(x) for x in samples)
    if len(xs) == 1:
        return xs[0]
    # Nearest-rank: index = ceil(p/100 * n) - 1
    k = max(0, min(len(xs) - 1, int((p / 100.0) * len(xs) + 0.999999999) - 1))
    return xs[k]


def latency_summary(samples: Sequence[float], *, prefix: str = "latency_s") -> Dict[str, float]:
    """mean / median / p95 / p99 + count from measured samples.

    Outliers are never discarded: the full sample set is retained in raw.jsonl;
    aggregates are computed over all samples.
    """
    xs = [float(x) for x in samples]
    if not xs:
        return {
            f"{prefix}_mean": float("nan"),
            f"{prefix}_median": float("nan"),
            f"{prefix}_p95": float("nan"),
            f"{prefix}_p99": float("nan"),
            "operation_count": 0,
            "outliers_discarded": False,  # type: ignore[dict-item]
        }
    return {
        f"{prefix}_mean": statistics.mean(xs),
        f"{prefix}_median": statistics.median(xs),
        f"{prefix}_p95": percentile(xs, 95),
        f"{prefix}_p99": percentile(xs, 99),
        "operation_count": len(xs),
        "outliers_discarded": False,  # type: ignore[dict-item]
    }


def summarize_named(rows: List[Dict], key: str, group_keys: Sequence[str]) -> List[Dict]:
    """Group raw rows and attach latency summaries for `key`."""
    buckets: Dict[tuple, List[float]] = {}
    meta: Dict[tuple, Dict] = {}
    for r in rows:
        gk = tuple(r[g] for g in group_keys)
        buckets.setdefault(gk, []).append(float(r[key]))
        if gk not in meta:
            meta[gk] = {g: r[g] for g in group_keys}
    out: List[Dict] = []
    for gk, vals in buckets.items():
        row = dict(meta[gk])
        row.update(latency_summary(vals, prefix=key.replace("_s", "") if key.endswith("_s") else key))
        out.append(row)
    return out
