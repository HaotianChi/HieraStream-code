"""MASS multiattribute sketch with paper Eq. (1) replacement rule."""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple


def _h(seed: bytes, key: bytes, array_idx: int, width: int) -> int:
    digest = hashlib.sha256(seed + struct.pack(">I", array_idx) + key).digest()
    return int.from_bytes(digest[:8], "big") % width


@dataclass
class Bucket:
    key: Optional[bytes] = None
    attrs: Optional[List[float]] = None

    @property
    def empty(self) -> bool:
        return self.key is None

    def l2_norm(self) -> float:
        if not self.attrs:
            return 0.0
        return math.sqrt(sum(x * x for x in self.attrs))


@dataclass
class MASketch:
    """d hash arrays × w buckets; A attribute dimensions.

    Eq. (1): P = ||a||_2 / ( ||a||_2 + ||B||_2 )
    Win → replace bucket, scale attrs by 1/P.
    Lose → scale existing bucket attrs by 1/(1-P).
    """

    d: int = 4
    w: int = 64
    num_attrs: int = 4
    seed: bytes = b"mass-sketch-v1"
    arrays: List[List[Bucket]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.arrays:
            self.arrays = [[Bucket() for _ in range(self.w)] for _ in range(self.d)]

    def _positions(self, key: bytes) -> List[Tuple[int, int]]:
        return [(i, _h(self.seed, key, i, self.w)) for i in range(self.d)]

    def insert(self, key: bytes, attrs: Sequence[float]) -> str:
        if len(attrs) != self.num_attrs:
            raise ValueError("attribute arity mismatch")
        vec = [float(x) for x in attrs]
        positions = self._positions(key)

        for i, j in positions:
            b = self.arrays[i][j]
            if b.key == key and b.attrs is not None:
                b.attrs = [a + b for a, b in zip(b.attrs, vec)]
                return "update"

        for i, j in positions:
            b = self.arrays[i][j]
            if b.empty:
                b.key = key
                b.attrs = list(vec)
                return "empty"

        candidates = [(i, j, self.arrays[i][j]) for i, j in positions]
        _, _, victim = min(candidates, key=lambda t: t[2].l2_norm())
        new_l2 = math.sqrt(sum(x * x for x in vec))
        old_l2 = victim.l2_norm()
        # Eq. (1)
        denom = new_l2 + old_l2
        if denom <= 0.0:
            P = 0.5
        else:
            P = new_l2 / denom
        digest = hashlib.sha256(self.seed + key + (victim.key or b"")).digest()
        u = int.from_bytes(digest[:8], "big") / float(2**64)
        if u < P and P > 0.0:
            # input wins: replace; each attribute divided by P
            victim.key = key
            victim.attrs = [a / P for a in vec]
            return "replace"
        # bucket wins: scale existing attrs by 1/(1-P)
        if victim.attrs is not None and P < 1.0:
            scale = 1.0 / (1.0 - P)
            victim.attrs = [a * scale for a in victim.attrs]
        return "reject"

    def query_subset_sum(self, attr_indices: Sequence[int] | None = None) -> Dict[bytes, float]:
        idxs = list(attr_indices) if attr_indices is not None else list(range(self.num_attrs))
        table: Dict[bytes, float] = {}
        for arr in self.arrays:
            for b in arr:
                if b.key is None or b.attrs is None:
                    continue
                s = sum(b.attrs[t] for t in idxs)
                prev = table.get(b.key)
                table[b.key] = s if prev is None else max(prev, s)
        return table

    def nonempty_count(self) -> int:
        return sum(1 for arr in self.arrays for b in arr if not b.empty)
