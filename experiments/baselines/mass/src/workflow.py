"""MASS-style access-control workflow over the common CP-ABE backend."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from core.crypto.python.access_tree import AND, AccessTree, leaf

from experiments.baselines.cpabe.adapter import CPABEBaseline
from experiments.baselines.mass.src.sketch import MASketch


def _hash_object(data: bytes) -> bytes:
    return hashlib.sha256(b"MASS-OBJ|" + data).digest()


@dataclass
class MASSWorkflow:
    """MASS protection/recovery without Fabric/IPFS (Fig.7 scope)."""

    cpabe: CPABEBaseline
    sketch: MASketch = field(default_factory=MASketch)
    local_index: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    baseline_id: str = "mass_common_cpabe"

    @classmethod
    def setup(cls, attrs: Sequence[str] | None = None) -> "MASSWorkflow":
        return cls(cpabe=CPABEBaseline.setup(attrs=attrs))

    def keygen(self, user_id: str, user_attrs: Sequence[str]):
        return self.cpabe.keygen(user_id, user_attrs)

    def protect(
        self,
        logical_object: bytes,
        tree: AccessTree,
        *,
        doc_id: str,
        sketch_attrs: Sequence[float] | None = None,
    ) -> Dict[str, Any]:
        """hash + CP-ABE encrypt + local MASS metadata/index (+ sketch insert)."""
        t0 = time.perf_counter()
        obj_hash = _hash_object(logical_object)
        blob = self.cpabe.encrypt(obj_hash, tree)
        meta = {
            "doc_id": doc_id,
            "hash": obj_hash.hex(),
            "baseline_id": self.baseline_id,
        }
        self.local_index[doc_id] = {"meta": meta, "blob": blob}
        attrs = list(sketch_attrs) if sketch_attrs is not None else [1.0] * self.sketch.num_attrs
        if len(attrs) < self.sketch.num_attrs:
            attrs = attrs + [0.0] * (self.sketch.num_attrs - len(attrs))
        attrs = attrs[: self.sketch.num_attrs]
        path = self.sketch.insert(doc_id.encode(), attrs)
        protect_s = time.perf_counter() - t0
        return {
            "scheme": "MASS",
            "doc_id": doc_id,
            "obj_hash": obj_hash,
            "blob": blob,
            "meta": meta,
            "sketch_path": path,
            "protect_s": protect_s,
            "cpabe_encrypt_s": blob["encrypt_s"],
            "measured_ops": ["hash", "cpabe_encrypt", "metadata_index", "sketch_insert"],
        }

    def recover(self, doc_id: str, user_keys) -> Dict[str, Any]:
        t0 = time.perf_counter()
        entry = self.local_index.get(doc_id)
        if entry is None:
            raise KeyError(doc_id)
        blob = entry["blob"]
        out = self.cpabe.decrypt(blob, user_keys)
        recover_s = time.perf_counter() - t0
        return {
            "obj_hash": out["plaintext"],
            "recover_s": recover_s,
            "cpabe_decrypt_s": out["decrypt_s"],
            "measured_ops": ["local_index_lookup", "cpabe_decrypt"],
        }


def and_tree_from_names(names: Sequence[str]) -> AccessTree:
    children = [leaf(a) for a in names]
    return AND(*children)
