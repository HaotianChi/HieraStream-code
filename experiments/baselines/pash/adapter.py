"""PASH baseline adapter for formal E10B."""

from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

from experiments.baselines.common.policy.lsss import and_policy, attr_value_from_name, policy_names_for_size
from experiments.baselines.pash.src.scheme import PASHScheme, decode_candidate, encode_message


class PASHAdapter:
    citation = (
        "L. Zhang et al., "
        '"Security and Privacy for Healthcare: Efficient Policy-Hiding '
        'Attribute-Based Access Control," IEEE IoT J., 2018.'
    )

    def __init__(self) -> None:
        self.scheme: Optional[PASHScheme] = None
        self._sk = None
        self._policy = None
        self._payload: Optional[bytes] = None

    def available(self) -> bool:
        return True

    def probe(self) -> Dict[str, Any]:
        return {
            "scheme": "PASH",
            "status": "AVAILABLE_NORMALIZED",
            "available": True,
            "reproducibility_class": "PERFORMANCE_ORIENTED_REIMPLEMENTATION",
            "citation": self.citation,
            "mode": "pash-normalized",
            "note": "Normalized onto common PBC Type-A substrate",
            "missing_information": [],
        }

    def setup_for_policy_size(self, n: int) -> None:
        names = policy_names_for_size(n)
        self.scheme = PASHScheme.setup()
        self._policy = and_policy(names)
        self._sk = self.scheme.keygen([(nm, attr_value_from_name(nm)) for nm in names])
        self._payload = os.urandom(32)

    def encrypt(self, plaintext: bytes | None = None) -> Dict[str, Any]:
        if self.scheme is None or self._policy is None:
            raise RuntimeError("call setup_for_policy_size first")
        payload = plaintext if plaintext is not None else (self._payload or os.urandom(32))
        if len(payload) != 32:
            import hashlib

            payload = hashlib.sha256(payload).digest()
        t0 = time.perf_counter()
        M = encode_message(payload, self.scheme.pairing)
        ct = self.scheme.encrypt(M, self._policy)
        enc_s = time.perf_counter() - t0
        return {
            "scheme": "PASH",
            "ct": ct,
            "payload": payload,
            "encrypt_s": enc_s,
            "ciphertext_bytes": self.scheme.ciphertext_bytes(ct),
            "op_counts_encrypt": self.scheme.last_encrypt.as_dict(),
            "num_rows": ct.num_rows,
        }

    def decrypt(self, blob: Dict[str, Any]) -> Dict[str, Any]:
        if self.scheme is None or self._policy is None or self._sk is None:
            raise RuntimeError("call setup_for_policy_size first")
        t0 = time.perf_counter()
        omega = self.scheme.matching_test(blob["ct"], self._sk, self._policy)
        match_s = time.perf_counter() - t0
        match_ops = self.scheme.last_matching.as_dict()
        if omega is None:
            raise PermissionError("PASH matching failed")
        t1 = time.perf_counter()
        pt_gt = self.scheme.full_decrypt(blob["ct"], self._sk, omega, self._policy)
        full_s = time.perf_counter() - t1
        recover_s = match_s + full_s
        if not decode_candidate(pt_gt, blob["payload"], self.scheme.pairing):
            raise RuntimeError("PASH decrypt message mismatch")
        return {
            "plaintext": blob["payload"],
            "matching_s": match_s,
            "full_decrypt_s": full_s,
            "decrypt_s": recover_s,
            "op_counts_matching": match_ops,
            "op_counts_full_decrypt": self.scheme.last_full_decrypt.as_dict(),
            "matching_pairings": match_ops["Pair"],
        }
