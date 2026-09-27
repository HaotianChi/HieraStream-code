"""Shared AND-policy LSSS for baseline comparison (n-of-n = full AND)."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple


def _zp_mod():
    if (os.environ.get("HIERASTREAM_CRYPTO_BACKEND") or "").lower() in ("pbc", "native"):
        from core.crypto.python.pbc_field import Zp
    else:
        from core.crypto.python.field import Zp
    return Zp


@dataclass(frozen=True)
class NamedAttribute:
    name: str
    value: object  # Zp


@dataclass
class LSSSPolicy:
    matrix: List[List[object]]
    rho: List[str]
    values: List[object]
    names: List[str]

    @property
    def num_rows(self) -> int:
        return len(self.matrix)

    @property
    def num_cols(self) -> int:
        return len(self.matrix[0]) if self.matrix else 0


def attr_value_from_name(name: str, *, salt: bytes = b"e10b-attr-value"):
    Zp = _zp_mod()
    digest = hashlib.sha256(salt + name.encode()).digest()
    return Zp.from_int(int.from_bytes(digest, "big"))


def and_policy(names: Sequence[str]) -> LSSSPolicy:
    Zp = _zp_mod()
    L = len(names)
    if L < 1:
        raise ValueError("policy needs at least one attribute")
    matrix: List[List[object]] = []
    values: List[object] = []
    for i in range(L):
        x = Zp.from_int(i + 1)
        row = [Zp.one()]
        pow_x = Zp.one()
        for _ in range(1, L):
            pow_x = pow_x * x
            row.append(pow_x)
        matrix.append(row)
        values.append(attr_value_from_name(names[i]))
    return LSSSPolicy(matrix=matrix, rho=list(names), values=values, names=list(names))


def lagrange_at_zero(xs: Sequence) -> List:
    Zp = _zp_mod()
    out = []
    for i, xi in enumerate(xs):
        num = Zp.one()
        den = Zp.one()
        for j, xj in enumerate(xs):
            if i == j:
                continue
            num = num * (Zp.zero() - xj)
            den = den * (xi - xj)
        out.append(num * den.inv())
    return out


def and_reconstruction_coeffs(policy: LSSSPolicy) -> Dict[int, object]:
    Zp = _zp_mod()
    L = policy.num_rows
    xs = [Zp.from_int(i + 1) for i in range(L)]
    omega = lagrange_at_zero(xs)
    return {i: omega[i] for i in range(L)}


def share_vector(s, n_cols: int) -> List:
    Zp = _zp_mod()
    v = [s]
    for _ in range(1, n_cols):
        v.append(Zp.random())
    return v


def row_dot(row: Sequence, v: Sequence):
    Zp = _zp_mod()
    acc = Zp.zero()
    for a, b in zip(row, v):
        acc = acc + (a * b)
    return acc


def policy_names_for_size(n: int, universe: Sequence[str] | None = None) -> List[str]:
    return [f"attr_{i}" for i in range(n)]
