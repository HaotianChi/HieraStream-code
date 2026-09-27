"""Secrecy helpers: update ratios must never leave AA internals.

ABSOLUTE REQUIREMENT (Section III-E): the attribute update ratio
  t_a^(ν) / t_a^(ν+1)
must never appear in user-facing APIs, serialized update messages,
persistent logs, or experiment raw data.
"""

from __future__ import annotations

from typing import Any, Iterable

from core.crypto.python.field import Zp
from core.crypto.python.groups import GElement


class UpdateRatio:
    """AA-private ratio holder. Not serializable; redacted repr."""

    __slots__ = ("_ratio",)

    def __init__(self, ratio: Zp) -> None:
        self._ratio = ratio

    def apply(self, old: GElement) -> GElement:
        return old.pow(self._ratio)

    def __repr__(self) -> str:
        return "<UpdateRatio:REDACTED>"

    def __str__(self) -> str:
        return "<UpdateRatio:REDACTED>"

    def __getstate__(self) -> None:
        raise TypeError("UpdateRatio must never be pickled/serialized")


def compute_attr_update_ratio(t_old: Zp, t_new: Zp) -> UpdateRatio:
    """Internal only: ratio = t_old / t_new."""
    return UpdateRatio(t_old * t_new.inv())


FORBIDDEN_EXPORT_KEYS = frozenset(
    {
        "ratio",
        "update_ratio",
        "updateRatio",
        "t_a_ratio",
        "tOld",
        "tNew",
        "t_old",
        "t_new",
        "_ratio",
    }
)


def assert_no_ratio_fields(obj: Any, path: str = "$") -> None:
    if isinstance(obj, UpdateRatio):
        raise AssertionError(f"UpdateRatio leaked at {path}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            ks = str(k)
            if ks in FORBIDDEN_EXPORT_KEYS or "ratio" in ks.lower():
                raise AssertionError(f"forbidden key {ks!r} at {path}")
            assert_no_ratio_fields(v, f"{path}.{ks}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            assert_no_ratio_fields(v, f"{path}[{i}]")


def scan_text_blob_for_ratio_leak(blob: str) -> None:
    lowered = blob.lower()
    for token in ("updateratio", "update_ratio", "t_a_ratio"):
        if token in lowered:
            raise AssertionError(f"ratio token {token!r} found in text export")
