"""G / G_T group elements and pairing context (symmetric bilinear map model)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .field import Zp


@dataclass(frozen=True)
class GElement:
    """Element of G, represented as g^{exp}."""

    exp: Zp

    @staticmethod
    def generator() -> "GElement":
        return GElement(Zp.one())

    @staticmethod
    def identity() -> "GElement":
        return GElement(Zp.zero())

    def mul(self, other: "GElement") -> "GElement":
        return GElement(self.exp + other.exp)

    def inv(self) -> "GElement":
        return GElement(-self.exp)

    def pow(self, s: Zp) -> "GElement":
        return GElement(self.exp * s)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, GElement) and self.exp == other.exp

    def __repr__(self) -> str:
        return "<G:REDACTED>"

    def __str__(self) -> str:
        return "<G:REDACTED>"

    def to_bytes(self) -> bytes:
        return b"G1|" + self.exp.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> "GElement":
        if not data.startswith(b"G1|") or len(data) != 3 + 32:
            raise ValueError("invalid G serialization")
        return GElement(Zp.from_bytes(data[3:]))


@dataclass(frozen=True)
class GTElement:
    """Element of G_T, represented as e(g,g)^{exp}."""

    exp: Zp

    @staticmethod
    def identity() -> "GTElement":
        return GTElement(Zp.zero())

    def mul(self, other: "GTElement") -> "GTElement":
        return GTElement(self.exp + other.exp)

    def inv(self) -> "GTElement":
        return GTElement(-self.exp)

    def pow(self, s: Zp) -> "GTElement":
        return GTElement(self.exp * s)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, GTElement) and self.exp == other.exp

    def __repr__(self) -> str:
        return "<GT:REDACTED>"

    def __str__(self) -> str:
        return "<GT:REDACTED>"

    def to_bytes(self) -> bytes:
        """Canonical G_T serialization for KDF input — fixed 32-byte BE."""
        return self.exp.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> "GTElement":
        return GTElement(Zp.from_bytes(data))


class PairingContext:
    """Symmetric bilinear map e : G × G → G_T."""

    def __init__(self) -> None:
        self.g = GElement.generator()

    def pairing(self, a: GElement, b: GElement) -> GTElement:
        return GTElement(a.exp * b.exp)

    def g_pow(self, s: Zp) -> GElement:
        return self.g.pow(s)

    def gt_pow_gg(self, s: Zp) -> GTElement:
        """e(g,g)^s."""
        return GTElement(s)

    def sample_gt(self) -> GTElement:
        return GTElement(Zp.random())

    def sample_zr(self) -> Zp:
        return Zp.random()
