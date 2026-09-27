"""HieraStream cryptographic core (Section III) — standalone Python package.

Algebraic backend models a symmetric bilinear map via exponent encoding:
  g^x          ↔  Scalar x
  e(g,g)^z     ↔  Scalar z
  e(g^a,g^b)   ↔  a*b

This is for protocol-faithful unit/property testing. Formal evaluation
microbenchmarks should use the C++/PBC backend (core/crypto) via pybind11.

Secrets never appear in __repr__/__str__/logs.
"""

from .access_tree import AccessTree, leaf, gate, AND, OR
from .hierarchy import RoleHierarchy, HEALTHCARE_FIXTURE, linear_hierarchy
from .segment import (
    SegmentCrypto,
    SystemSecrets,
    PublicParams,
    UserAttrMaterial,
    UserRoleMaterial,
    ProtectedSegmentCrypto,
    OutsourceAttrKeys,
    OutsourcePartialAttrCT,
)
from .kdf_aead import derive_segment_key, aead_encrypt, aead_decrypt, PayloadBlob

__all__ = [
    "AccessTree",
    "leaf",
    "gate",
    "AND",
    "OR",
    "RoleHierarchy",
    "HEALTHCARE_FIXTURE",
    "linear_hierarchy",
    "SegmentCrypto",
    "SystemSecrets",
    "PublicParams",
    "UserAttrMaterial",
    "UserRoleMaterial",
    "ProtectedSegmentCrypto",
    "derive_segment_key",
    "aead_encrypt",
    "aead_decrypt",
    "PayloadBlob",
]
