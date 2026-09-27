"""PBC-backed G / G_T elements (symmetric Type-A pairing)."""

from __future__ import annotations

from typing import Any, Optional

from .pbc_field import Zp, _load_native, default_param_path, get_shared_context


class GElement:
    __slots__ = ("_e",)

    def __init__(self, *, _raw: Any = None) -> None:
        if _raw is None:
            raise ValueError("GElement requires native Element")
        self._e = _raw

    @staticmethod
    def _new() -> "GElement":
        native = _load_native()
        ctx = get_shared_context()
        return GElement(_raw=native.Element(ctx, native.ELEM_G))

    @staticmethod
    def generator() -> "GElement":
        # PBC G1 generator: g = random^1 after setting from pairing — use g^1 via set then pow
        # CryptoEngine uses pp.g; here sample random generator base once per process.
        g = GElement._new()
        g._e.set_random()
        return g

    @staticmethod
    def identity() -> "GElement":
        g = GElement._new()
        g._e.set_one()
        return g

    def mul(self, other: "GElement") -> "GElement":
        out = GElement._new()
        out._e.mul(self._e, other._e)
        return out

    def inv(self) -> "GElement":
        out = GElement._new()
        out._e.invert(self._e)
        return out

    def pow(self, s: Zp) -> "GElement":
        out = GElement._new()
        out._e.pow_zn(self._e, s._e)
        return out

    def __eq__(self, other: object) -> bool:
        return isinstance(other, GElement) and self._e.equals(other._e)

    def __repr__(self) -> str:
        return "<G:REDACTED>"

    def __str__(self) -> str:
        return "<G:REDACTED>"

    def to_bytes(self) -> bytes:
        return bytes(self._e.to_bytes())

    @staticmethod
    def from_bytes(data: bytes) -> "GElement":
        g = GElement._new()
        g._e.from_bytes(data)
        return g

    def __getstate__(self) -> bytes:
        return self.to_bytes()

    def __setstate__(self, data: bytes) -> None:
        self._e = GElement.from_bytes(data)._e

    def __deepcopy__(self, memo):
        return GElement.from_bytes(self.to_bytes())


class GTElement:
    __slots__ = ("_e",)

    def __init__(self, *, _raw: Any = None) -> None:
        if _raw is None:
            raise ValueError("GTElement requires native Element")
        self._e = _raw

    @staticmethod
    def _new() -> "GTElement":
        native = _load_native()
        ctx = get_shared_context()
        return GTElement(_raw=native.Element(ctx, native.ELEM_GT))

    @staticmethod
    def identity() -> "GTElement":
        g = GTElement._new()
        g._e.set_one()
        return g

    def mul(self, other: "GTElement") -> "GTElement":
        out = GTElement._new()
        out._e.mul(self._e, other._e)
        return out

    def inv(self) -> "GTElement":
        out = GTElement._new()
        out._e.invert(self._e)
        return out

    def pow(self, s: Zp) -> "GTElement":
        out = GTElement._new()
        out._e.pow_zn(self._e, s._e)
        return out

    def __eq__(self, other: object) -> bool:
        return isinstance(other, GTElement) and self._e.equals(other._e)

    def __repr__(self) -> str:
        return "<GT:REDACTED>"

    def __str__(self) -> str:
        return "<GT:REDACTED>"

    def to_bytes(self) -> bytes:
        """Canonical G_T serialization for KDF input."""
        return bytes(self._e.to_bytes())

    @staticmethod
    def from_bytes(data: bytes) -> "GTElement":
        g = GTElement._new()
        g._e.from_bytes(data)
        return g

    def __getstate__(self) -> bytes:
        return self.to_bytes()

    def __setstate__(self, data: bytes) -> None:
        self._e = GTElement.from_bytes(data)._e

    def __deepcopy__(self, memo):
        return GTElement.from_bytes(self.to_bytes())


class PairingContext:
    """Symmetric bilinear map e : G × G → G_T via PBC Type-A params."""

    def __init__(self, param_path: Optional[str] = None) -> None:
        # Ensure shared context uses the requested params (first wins).
        get_shared_context(param_path or default_param_path())
        self.g = GElement.generator()
        # Freeze a stable generator for this context instance
        self._g_bytes = self.g.to_bytes()

    def pairing(self, a: GElement, b: GElement) -> GTElement:
        out = GTElement._new()
        out._e.pairing(a._e, b._e)
        return out

    def g_pow(self, s: Zp) -> GElement:
        return self.g.pow(s)

    def gt_pow_gg(self, s: Zp) -> GTElement:
        """e(g,g)^s"""
        gg = self.pairing(self.g, self.g)
        return gg.pow(s)

    def sample_gt(self) -> GTElement:
        s = Zp.random()
        return self.gt_pow_gg(s)

    def sample_zr(self) -> Zp:
        return Zp.random()
