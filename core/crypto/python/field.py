"""Z_p scalars with secure sampling, inversion, and canonical serialization."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Union

# Large prime field for algebraic simulation (secp256k1 prime).
# NOT a pairing-security claim — see core/crypto/params for PBC parameters.
P = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
    16,
)


def _redacted() -> str:
    return "<Zp:REDACTED>"


@dataclass(frozen=True)
class Zp:
    """Element of Z_p (or Z_p^* when nonzero)."""

    v: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "v", int(self.v) % P)

    @staticmethod
    def from_int(x: int) -> "Zp":
        return Zp(x % P)

    @staticmethod
    def zero() -> "Zp":
        return Zp(0)

    @staticmethod
    def one() -> "Zp":
        return Zp(1)

    @staticmethod
    def random() -> "Zp":
        """Uniform in Z_p^* (nonzero) via CSPRNG."""
        while True:
            x = secrets.randbelow(P)
            if x != 0:
                return Zp(x)

    @staticmethod
    def random_including_zero() -> "Zp":
        return Zp(secrets.randbelow(P))

    def is_zero(self) -> bool:
        return self.v == 0

    def __add__(self, other: "Zp") -> "Zp":
        return Zp((self.v + other.v) % P)

    def __sub__(self, other: "Zp") -> "Zp":
        return Zp((self.v - other.v) % P)

    def __mul__(self, other: "Zp") -> "Zp":
        return Zp((self.v * other.v) % P)

    def __neg__(self) -> "Zp":
        return Zp((-self.v) % P)

    def inv(self) -> "Zp":
        if self.v == 0:
            raise ZeroDivisionError("inversion of 0 in Z_p")
        return Zp(pow(self.v, -1, P))

    def __pow__(self, exp: Union[int, "Zp"]) -> "Zp":  # type: ignore[override]
        e = exp.v if isinstance(exp, Zp) else int(exp)
        return Zp(pow(self.v, e % (P - 1), P))  # not used for group; keep for completeness

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Zp) and self.v == other.v

    def __hash__(self) -> int:
        return hash(self.v)

    def __repr__(self) -> str:
        return _redacted()

    def __str__(self) -> str:
        return _redacted()

    def to_bytes(self) -> bytes:
        """Canonical big-endian 32-byte encoding."""
        return self.v.to_bytes(32, "big")

    @staticmethod
    def from_bytes(data: bytes) -> "Zp":
        if len(data) != 32:
            raise ValueError("Zp requires 32-byte canonical encoding")
        return Zp(int.from_bytes(data, "big"))

    @staticmethod
    def hash_to_zp(msg: bytes, domain: bytes = b"HieraStream-Hp-v1") -> "Zp":
        """H_p : {0,1}* → Z_p via SHA-256 domain-separated hash."""
        digest = hashlib.sha256(domain + b"|" + msg).digest()
        return Zp(int.from_bytes(digest, "big") % P)
