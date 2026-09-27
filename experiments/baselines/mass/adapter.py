"""MASS baseline adapter for E10B."""

from __future__ import annotations

import os
from typing import Any, Dict, Optional, Sequence

from experiments.baselines.common.policy.lsss import policy_names_for_size
from experiments.baselines.mass.src.workflow import MASSWorkflow, and_tree_from_names


class MASSAdapter:
    """MASS-style workflow with common CP-ABE backend."""

    citation = (
        "Chen et al., "
        '"MASS: Multiattribute Sketch Secure Data Sharing for IoT '
        'Wearable Medical Devices Based on Blockchain," IEEE IoT J., 2025.'
    )

    def __init__(self) -> None:
        self.wf: Optional[MASSWorkflow] = None
        self._user = None
        self._tree = None
        self._names: Sequence[str] = []

    def available(self) -> bool:
        return True

    def probe(self) -> Dict[str, Any]:
        return {
            "scheme": "MASS",
            "status": "AVAILABLE_COMMON_CPABE",
            "available": True,
            "reproducibility_class": "PERFORMANCE_ORIENTED_REIMPLEMENTATION",
            "citation": self.citation,
            "note": "Access-control path uses common CP-ABE; MA-sketch is separate",
            "missing_information": [],
        }

    def setup_for_policy_size(self, n: int) -> None:
        names = policy_names_for_size(n)
        self._names = names
        self.wf = MASSWorkflow.setup(attrs=list(names))
        self._user = self.wf.keygen("u", list(names))
        self._tree = and_tree_from_names(names)

    def encrypt(self, plaintext: bytes | None = None, *, doc_id: str = "doc0") -> Dict[str, Any]:
        if self.wf is None or self._tree is None:
            raise RuntimeError("call setup_for_policy_size first")
        payload = plaintext if plaintext is not None else os.urandom(32)
        if len(payload) != 32:
            import hashlib

            payload = hashlib.sha256(payload).digest()
        out = self.wf.protect(payload, self._tree, doc_id=doc_id, sketch_attrs=[1.0] * self.wf.sketch.num_attrs)
        out["payload"] = payload
        out["encrypt_s"] = out["protect_s"]
        return out

    def decrypt(self, blob: Dict[str, Any]) -> Dict[str, Any]:
        if self.wf is None or self._user is None:
            raise RuntimeError("call setup_for_policy_size first")
        out = self.wf.recover(blob["doc_id"], self._user)
        if out["obj_hash"] != blob["obj_hash"]:
            raise RuntimeError("MASS hash mismatch")
        return {
            "plaintext": out["obj_hash"],
            "decrypt_s": out["recover_s"],
            "cpabe_decrypt_s": out["cpabe_decrypt_s"],
        }

    def on_chain_policy_op(self) -> None:
        raise NotImplementedError(
            "MASS blockchain path is not used for the primary baseline figure"
        )
