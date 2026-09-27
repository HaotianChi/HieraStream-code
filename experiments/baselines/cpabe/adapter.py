"""Bethencourt–Sahai–Waters-style conventional CP-ABE baseline.

Pairing environment: same algebraic `PairingContext` / `Zp` as HieraStream's
Section III attribute engine (`core.crypto.python`). Formal PBC backend may be
substituted via the same group API when available.

This baseline is attribute-tree CP-ABE only — no hierarchical role envelopes,
no AuthKey versioning, no HieraStream dual-layer KDF of (Z^A, Z^R).

Reference: J. Bethencourt, A. Sahai, B. Waters, “Ciphertext-policy
attribute-based encryption,” IEEE S&P 2007.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from core.crypto.python.access_tree import AccessTree
from core.crypto.python.kdf_aead import aead_decrypt, aead_encrypt
from core.crypto.python.segment import SegmentCrypto, UserAttrMaterial


@dataclass
class CPABEBaseline:
    """Conventional CP-ABE using HieraStream's attribute crypto path only."""

    crypto: SegmentCrypto
    attrs: List[str]
    baseline_id: str = "conventional_cpabe_bsw"
    # Symmetric payload key is derived from recovered ZA alone (no role share).
    _payload_kdf_note: str = field(
        default="AES key = SHA256(ZA.to_bytes() || b'|CPABE'); no ZR/role share",
        repr=False,
    )

    @classmethod
    def setup(cls, attrs: Sequence[str] | None = None) -> "CPABEBaseline":
        attrs = list(attrs or ["doctor", "cardiology", "nurse", "emergency", "researcher"])
        crypto = SegmentCrypto()
        crypto.ca_setup()
        crypto.aa_setup(attrs)
        # Intentionally NO role_setup — conventional CP-ABE has no role hierarchy.
        # Public Y, h, pk_attr suffice for gateway_partial + policy encrypt.
        return cls(crypto=crypto, attrs=attrs)

    def keygen(self, user_id: str, user_attrs: Sequence[str]) -> UserAttrMaterial:
        return self.crypto.aa_keygen(user_id, user_attrs)

    @staticmethod
    def _payload_key(za) -> bytes:
        import hashlib

        return hashlib.sha256(za.to_bytes() + b"|CPABE").digest()

    def encrypt(self, plaintext: bytes, tree: AccessTree) -> Dict[str, Any]:
        """Measured encrypt = ZA sample + partial CT + policy encrypt + AES.

        NOT included: CA/AA setup, keygen, role ops, Fabric, IPFS.
        Online randomness (ZA) is inside the timer for fairness with other schemes.
        """
        t0 = time.perf_counter()
        ZA = self.crypto.sample_ZA()
        key = self._payload_key(ZA)
        partial = self.crypto.gateway_partial_attr(ZA)
        ct = self.crypto.outsource_policy_encrypt(partial, tree)
        ct_aes = aead_encrypt(key, plaintext)
        enc_s = time.perf_counter() - t0
        return {
            "scheme": "CP-ABE",
            "baseline_id": self.baseline_id,
            "attr_ct": ct,
            "ct_aes": ct_aes,
            "ZA": ZA,
            "encrypt_s": enc_s,
            "leaf_components": len(ct.C_a),
            "measured_ops": [
                "sample_ZA",
                "gateway_partial_attr",
                "outsource_policy_encrypt",
                "aead_encrypt",
            ],
        }

    def decrypt(self, blob: Dict[str, Any], user_keys: UserAttrMaterial) -> Dict[str, Any]:
        """Measured decrypt = tree transform + ZA recover + AES.

        NOT included: keygen, Fabric, IPFS, role transform.
        """
        t0 = time.perf_counter()
        Bj = self.crypto.outsource_attr_transform(blob["attr_ct"], user_keys)
        if Bj is None:
            raise PermissionError("CP-ABE policy not satisfied")
        ZA = self.crypto.user_recover_ZA(blob["attr_ct"], Bj, user_keys.usk1)
        key = self._payload_key(ZA)
        pt = aead_decrypt(key, blob["ct_aes"])
        dec_s = time.perf_counter() - t0
        return {
            "plaintext": pt,
            "decrypt_s": dec_s,
            "measured_ops": [
                "outsource_attr_transform",
                "user_recover_ZA",
                "aead_decrypt",
            ],
        }
