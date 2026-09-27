"""Common timing helpers for baseline E10B."""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Dict, Iterator, List


@dataclass
class OpCounter:
    """Approximate algebraic operation counts for sanity checks."""

    g_exp: int = 0
    gt_exp: int = 0
    pairings: int = 0
    g_mul: int = 0
    gt_mul: int = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "g_exp": self.g_exp,
            "gt_exp": self.gt_exp,
            "pairings": self.pairings,
            "g_mul": self.g_mul,
            "gt_mul": self.gt_mul,
        }


@contextmanager
def timed() -> Iterator[List[float]]:
    """Yield a one-element list filled with elapsed seconds."""
    slot: List[float] = [0.0]
    t0 = time.perf_counter()
    try:
        yield slot
    finally:
        slot[0] = time.perf_counter() - t0


@dataclass
class SampleBank:
    protection: List[float] = field(default_factory=list)
    recovery: List[float] = field(default_factory=list)
    matching: List[float] = field(default_factory=list)
