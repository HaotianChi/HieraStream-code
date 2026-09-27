"""Deprecated shim; use core.crypto.python."""

from core.crypto.python import (  # noqa: F401
    AccessTree,
    HEALTHCARE_FIXTURE,
    SegmentCrypto,
    aead_decrypt,
    aead_encrypt,
    derive_segment_key,
    leaf,
)

# Legacy name kept for older imports during migration.
SimulatedCrypto = SegmentCrypto
