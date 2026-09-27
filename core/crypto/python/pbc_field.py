"""PBC-backed Z_p (Zr) using hierastream_native Element.

Compatible API with algebraic ``field.Zp`` for SegmentCrypto backend swap.
Pairing order comes from the loaded Type-A parameter file — no security-level claim.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional, Union

if TYPE_CHECKING:
    pass

_native = None
_ctx = None


def _load_native():
    global _native
    if _native is not None:
        return _native
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    for p in (root / "core" / "crypto" / "bindings", root / "build" / "core" / "crypto"):
        if str(p) not in sys.path:
            sys.path.insert(0, str(p))
    import hierastream_native as native  # type: ignore

    _native = native
    return native


def default_param_path() -> str:
    from pathlib import Path

    return str(Path(__file__).resolve().parents[1] / "params" / "a.param")


def get_shared_context(param_path: Optional[str] = None):
    """Process-wide pairing context for PBC Zp/G/GT wrappers."""
    global _ctx
    native = _load_native()
    if _ctx is None:
        _ctx = native.PairingContext(param_path or default_param_path())
    return _ctx


class Zp:
    """Zr element over the PBC pairing order."""

    __slots__ = ("_e",)

    def __init__(self, element: Any = None, *, _raw: Any = None) -> None:
        if _raw is not None:
            self._e = _raw
            return
        if element is not None:
            self._e = element
            return
        raise ValueError("Zp requires a native Element")

    @staticmethod
    def _new() -> "Zp":
        native = _load_native()
        ctx = get_shared_context()
        return Zp(_raw=native.Element(ctx, native.ELEM_ZR))

    @staticmethod
    def from_int(x: int) -> "Zp":
        z = Zp._new()
        z._e.set_mpz_str(str(int(x)))
        return z

    @staticmethod
    def zero() -> "Zp":
        z = Zp._new()
        z._e.set_si(0)
        return z

    @staticmethod
    def one() -> "Zp":
        z = Zp._new()
        z._e.set_one()
        return z

    @staticmethod
    def random() -> "Zp":
        while True:
            z = Zp._new()
            z._e.set_random()
            if not z._e.is_0():
                return z

    @staticmethod
    def random_including_zero() -> "Zp":
        z = Zp._new()
        z._e.set_random()
        return z

    def is_zero(self) -> bool:
        return bool(self._e.is_0())

    def __add__(self, other: "Zp") -> "Zp":
        out = Zp._new()
        out._e.add(self._e, other._e)
        return out

    def __sub__(self, other: "Zp") -> "Zp":
        out = Zp._new()
        out._e.sub(self._e, other._e)
        return out

    def __mul__(self, other: "Zp") -> "Zp":
        out = Zp._new()
        out._e.mul(self._e, other._e)
        return out

    def __neg__(self) -> "Zp":
        out = Zp._new()
        out._e.neg(self._e)
        return out

    def inv(self) -> "Zp":
        if self.is_zero():
            raise ZeroDivisionError("inversion of 0 in Z_p")
        out = Zp._new()
        out._e.invert(self._e)
        return out

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Zp) and self._e.equals(other._e)

    def __repr__(self) -> str:
        return "<Zp:REDACTED>"

    def __str__(self) -> str:
        return "<Zp:REDACTED>"

    def to_bytes(self) -> bytes:
        return bytes(self._e.to_bytes())

    @staticmethod
    def from_bytes(data: bytes) -> "Zp":
        z = Zp._new()
        z._e.from_bytes(data)
        return z

    @staticmethod
    def hash_to_zp(data: bytes) -> "Zp":
        z = Zp._new()
        z._e.set_zr_from_hash(data)
        return z

    def __getstate__(self) -> bytes:
        return self.to_bytes()

    def __setstate__(self, data: bytes) -> None:
        z = Zp.from_bytes(data)
        self._e = z._e

    def __deepcopy__(self, memo):
        return Zp.from_bytes(self.to_bytes())
