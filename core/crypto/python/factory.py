"""Factory for SegmentCrypto backends (algebraic | pbc)."""

from __future__ import annotations

import os
from typing import Optional

from core.crypto.python.segment import SegmentCrypto


def create_segment_crypto(backend: Optional[str] = None) -> SegmentCrypto:
    """Create SegmentCrypto honoring HIERASTREAM_CRYPTO_BACKEND when backend is None."""
    return SegmentCrypto(backend=backend)


def resolve_backend(explicit: Optional[str] = None) -> str:
    raw = (explicit or os.environ.get("HIERASTREAM_CRYPTO_BACKEND") or "algebraic").lower()
    if raw in ("pbc", "native"):
        return "pbc"
    return "algebraic"
