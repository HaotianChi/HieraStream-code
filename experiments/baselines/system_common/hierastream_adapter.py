"""HieraStream local system-level adapter for Fig. 8 baselines.

Uses native PBC SegmentCrypto + local PeerMVCC CommitSegment + local IPFS,
with the evaluation's representative authorization configuration:

    policy leaves = 80
    target roles  = 4
    ancestor/path = 20

Shared in-process HieraStream path used by system_baselines
and is aligned with Fig.3/4/7 cryptographic microbenchmarks (PBC).
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

from core.crypto.python.access_tree import AccessTree, leaf
from core.crypto.python.hierarchy import linear_hierarchy
from core.crypto.python.kdf_aead import PayloadBlob
from core.crypto.python.segment import SegmentCrypto
from core.protocol.metadata import metadata_bytes
from core.protocol.workflow import HieraStreamWorkflow
from core.canonical import canonical_json_dumps

BASELINE_STATUS = "OFFICIAL_ARTIFACT"
SCHEME = "HieraStream"

# Representative configuration used elsewhere in the evaluation (not invented).
POLICY_LEAVES = 80
TARGET_ROLES = 4
PATH_SIZE = 20


def _policy_tree(n_leaves: int, attrs: List[str]) -> AccessTree:
    children = [leaf(attrs[i % len(attrs)]) for i in range(n_leaves)]
    return AccessTree(
        kind="internal",
        threshold=max(1, min(2, n_leaves)),
        children=children,
    )


class HieraStreamLocalAdapter:
    """Full Section III local protect → store → retrieve → recover path."""

    def __init__(
        self,
        *,
        policy_leaves: int = POLICY_LEAVES,
        target_roles: int = TARGET_ROLES,
        path_size: int = PATH_SIZE,
        crypto_backend: str = "pbc",
    ) -> None:
        self.policy_leaves = int(policy_leaves)
        self.target_roles = int(target_roles)
        self.path_size = int(path_size)
        self.crypto_backend = crypto_backend
        self.wf: Optional[HieraStreamWorkflow] = None
        self.targets: List[str] = []
        self._sizes: Dict[str, Dict[str, int]] = {}
        self._n = 0
        self.last_stage_ms: Dict[str, float] = {}
        self.config: Dict[str, Any] = {}

    def setup(self) -> None:
        os.environ["HIERASTREAM_CRYPTO_BACKEND"] = self.crypto_backend
        crypto = SegmentCrypto(backend=self.crypto_backend)
        if crypto.backend != "pbc":
            raise RuntimeError(
                f"Fig.8 HieraStream requires native PBC; got backend={crypto.backend!r}"
            )

        attrs = [f"A{i}" for i in range(max(8, min(40, self.policy_leaves)))]
        role_names = [f"R{i}" for i in range(self.path_size + 1)]
        self.targets = role_names[-self.target_roles :]
        tree = _policy_tree(self.policy_leaves, attrs)
        hier = linear_hierarchy(role_names)

        self.wf = HieraStreamWorkflow(
            owner_id="owner-sysbase",
            hierarchy=hier,
            attr_universe=list(attrs),
            crypto=crypto,
        )
        self.wf.setup(initial_policy=tree)
        # User satisfies entire attr universe used in the policy, assigned deepest target.
        user_attrs = list(attrs)
        self.wf.provision_user("alice", user_attrs, [self.targets[-1]])
        self._sizes = {}
        self._n = 0
        self.config = {
            "crypto_backend": crypto.backend,
            "policy_leaves": self.policy_leaves,
            "target_roles": self.target_roles,
            "path_size": self.path_size,
            "targets": list(self.targets),
            "attr_universe_size": len(attrs),
            "hierarchy_roles": len(role_names),
            "user_attrs": len(user_attrs),
            "user_role": self.targets[-1],
            "ledger": "PeerMVCC",
            "ipfs": "local_content_addressed",
        }

    def protect_and_store(self, payload: bytes, stream_context: Dict[str, Any] | None = None) -> Dict[str, Any]:
        assert self.wf and self.wf.gateway and self.wf.policy_tree
        t0 = time.perf_counter()
        seg = f"sb-{self._n}"
        self._n += 1
        pending = self.wf.gateway.protect_payload(seg, payload, self.targets)
        snap = self.wf.gateway.read_active_snapshot()
        tree = self.wf.policy_tree
        result, meta, mcid, _eta = self.wf.gateway.attempt_commit(pending, snap, tree)
        if result.status.value not in {"VALID", "valid"}:
            raise RuntimeError(f"CommitSegment failed: {result.status} {result.reason}")
        self.wf.gateway.publish_metadata_after_valid(pending, meta, mcid)
        self.wf.pendings[seg] = pending

        blob = PayloadBlob.decode(pending.ct_aes)
        enc_ct = len(blob.ciphertext_and_tag) - 16
        aead_overhead = 2 + 12 + 16  # version + IV + tag
        meta_b = metadata_bytes(meta)
        cta_ser = canonical_json_dumps({"CTA": meta["CTA"]})
        ctr_ser = canonical_json_dumps({"CTR": meta["CTR"]})
        crypto_envelope_bytes = len(cta_ser) + len(ctr_ser)
        auth_segment_meta = len(meta_b) - crypto_envelope_bytes
        if auth_segment_meta < 0:
            auth_segment_meta = 0
        other = aead_overhead  # AEAD framing outside plaintext ciphertext
        total = len(pending.ct_aes) + len(meta_b)
        self._sizes[seg] = {
            "plaintext_bytes": len(payload),
            "protected_bytes": enc_ct,
            "encrypted_payload_bytes": enc_ct,
            "aead_overhead_bytes": aead_overhead,
            "crypto_envelope_bytes": crypto_envelope_bytes,
            "crypto_metadata_bytes": crypto_envelope_bytes + aead_overhead,
            "authorization_segment_metadata_bytes": auth_segment_meta,
            "other_serialized_metadata_bytes": auth_segment_meta,
            "metadata_bytes": len(meta_b),
            "total_bytes": total,
            "cta_bytes": len(cta_ser),
            "ctr_bytes": len(ctr_ser),
            "ct_aes_bytes": len(pending.ct_aes),
        }
        ms = (time.perf_counter() - t0) * 1000.0
        return {"object_id": seg, "protect_latency_ms": ms, **self._sizes[seg], "success": True}

    def retrieve_and_recover(self, object_id: str, access_context: Dict[str, Any] | None = None) -> Dict[str, Any]:
        assert self.wf
        t0 = time.perf_counter()
        payload = self.wf.access("alice", object_id)
        ms = (time.perf_counter() - t0) * 1000.0
        return {"payload": payload, "recover_latency_ms": ms, "success": True}

    def run_stage_diagnostics(self, payload: bytes) -> Dict[str, float]:
        """Separately timed stages for stage timing (not used as Fig.8 sample)."""
        assert self.wf and self.wf.gateway and self.wf.policy_tree and self.wf.outsource
        from core.protocol.selective_retry import regenerate_role_envelopes
        from core.protocol.metadata import (
            build_metadata_object,
            deserialize_attr_ct,
            deserialize_role_envelope,
            parse_metadata,
        )
        from core.canonical import eta_digest

        stages: Dict[str, float] = {}
        gw = self.wf.gateway
        crypto = self.wf.crypto
        tree = self.wf.policy_tree

        t = time.perf_counter()
        snap = gw.read_active_snapshot()
        stages["snapshot_read_ms"] = (time.perf_counter() - t) * 1000.0

        t = time.perf_counter()
        ZA = crypto.sample_ZA()
        ZR = crypto.sample_ZR()
        stages["sample_ZA_ZR_ms"] = (time.perf_counter() - t) * 1000.0

        from core.crypto.python.kdf_aead import derive_segment_key, aead_encrypt, aead_decrypt

        t = time.perf_counter()
        key = derive_segment_key(ZA, ZR)
        ct_aes = aead_encrypt(key, payload)
        stages["aes_encrypt_ms"] = (time.perf_counter() - t) * 1000.0

        t = time.perf_counter()
        cid = self.wf.ipfs.add(ct_aes)
        stages["ipfs_put_payload_ms"] = (time.perf_counter() - t) * 1000.0

        t = time.perf_counter()
        partial = crypto.gateway_partial_attr(ZA)
        stages["gateway_partial_ms"] = (time.perf_counter() - t) * 1000.0

        t = time.perf_counter()
        attr_ct = crypto.outsource_policy_encrypt(partial.to_outsource_view(), tree)
        stages["outsourced_attr_encrypt_ms"] = (time.perf_counter() - t) * 1000.0

        t = time.perf_counter()
        role_envs = regenerate_role_envelopes(crypto, ZR, self.targets)
        stages["role_envelope_construct_ms"] = (time.perf_counter() - t) * 1000.0

        t = time.perf_counter()
        meta = build_metadata_object(
            attr_ct,
            role_envs,
            snap.version,
            snap.policy_id,
            snap.attr_state_id,
            snap.role_state_id,
            list(self.targets),
        )
        meta_b = metadata_bytes(meta)
        mcid = self.wf.ipfs.only_hash(meta_b)
        stages["metadata_serialize_ms"] = (time.perf_counter() - t) * 1000.0

        eta = eta_digest(
            cid, mcid, snap.version, snap.policy_id, snap.attr_state_id, snap.role_state_id
        )
        seg = f"diag-{self._n}"
        self._n += 1
        t = time.perf_counter()
        result = self.wf.fabric.commit_segment(
            self.wf.owner_id,
            seg,
            cid,
            mcid,
            snap.version,
            snap.policy_id,
            snap.attr_state_id,
            snap.role_state_id,
            eta,
            caller="gw",
        )
        stages["peermvcc_commit_ms"] = (time.perf_counter() - t) * 1000.0
        if result.status.value not in {"VALID", "valid"}:
            raise RuntimeError(f"diag commit failed: {result.status}")

        t = time.perf_counter()
        actual = self.wf.ipfs.add(meta_b)
        stages["ipfs_put_metadata_ms"] = (time.perf_counter() - t) * 1000.0
        if actual != mcid:
            raise RuntimeError("diag MCID mismatch")

        # Recovery stages
        t = time.perf_counter()
        record = self.wf.fabric.get_segment(self.wf.owner_id, seg)
        stages["ledger_get_ms"] = (time.perf_counter() - t) * 1000.0
        assert record is not None

        t = time.perf_counter()
        ct_got = self.wf.ipfs.get(record["CID"])
        meta_raw = self.wf.ipfs.get(record["MCID"])
        stages["ipfs_get_ms"] = (time.perf_counter() - t) * 1000.0

        mj = parse_metadata(meta_raw)
        attr_ct2 = deserialize_attr_ct(
            mj["CTA"], GElementCls=crypto.GElement, GTElementCls=crypto.GTElement
        )
        envelopes = [
            deserialize_role_envelope(
                e, GElementCls=crypto.GElement, GTElementCls=crypto.GTElement, ZpCls=crypto.Zp
            )
            for e in mj["CTR"]
        ]
        user = self.wf.users["alice"]
        attr_mat = user.attr_for(record["attrStateId"])
        role_mat, assigned = user.role_for(record["roleStateId"])

        t = time.perf_counter()
        Bj = self.wf.outsource.attr_transform(attr_ct2, attr_mat.to_outsource_keys())
        stages["attr_outsourced_decrypt_ms"] = (time.perf_counter() - t) * 1000.0
        assert Bj is not None

        t = time.perf_counter()
        ZA2 = crypto.user_recover_ZA(attr_ct2, Bj, attr_mat.usk1)
        stages["attr_user_final_ms"] = (time.perf_counter() - t) * 1000.0

        chosen = None
        assigned_role = None
        for ri in mj["targetRoles"]:
            for rx in assigned:
                if self.wf.hierarchy.dominates(rx, ri) and rx in role_mat.RK:
                    chosen = next(e for e in envelopes if e.target_role == ri)
                    assigned_role = rx
                    break
            if chosen:
                break
        assert chosen is not None and assigned_role is not None

        omega = crypto.Zp.random()
        TR = user.make_TR(crypto, role_mat.RK[assigned_role], omega)
        t = time.perf_counter()
        P, Q = self.wf.outsource.role_transform(
            chosen, TR, role_mat.D0, assigned_role, chosen.target_role
        )
        stages["role_outsourced_transform_ms"] = (time.perf_counter() - t) * 1000.0

        t = time.perf_counter()
        ZR2 = user.recover_ZR(crypto, chosen, P, Q, omega, role_mat.rho)
        stages["role_user_final_ms"] = (time.perf_counter() - t) * 1000.0

        t = time.perf_counter()
        pt = aead_decrypt(derive_segment_key(ZA2, ZR2), ct_got)
        stages["aes_decrypt_ms"] = (time.perf_counter() - t) * 1000.0
        if pt != payload:
            raise RuntimeError("stage diagnostic plaintext mismatch")

        protect_crypto = (
            stages["gateway_partial_ms"]
            + stages["outsourced_attr_encrypt_ms"]
            + stages["role_envelope_construct_ms"]
        )
        recover_crypto = (
            stages["attr_outsourced_decrypt_ms"]
            + stages["attr_user_final_ms"]
            + stages["role_outsourced_transform_ms"]
            + stages["role_user_final_ms"]
        )
        stages["protect_crypto_sum_ms"] = protect_crypto
        stages["recover_crypto_sum_ms"] = recover_crypto
        stages["aes_encrypt_ms"]  # noqa: keep key present
        self.last_stage_ms = stages
        return stages

    def protected_size(self, object_id: str) -> int:
        return self._sizes[object_id]["protected_bytes"]

    def metadata_size(self, object_id: str) -> int:
        return self._sizes[object_id]["metadata_bytes"]

    def teardown(self) -> None:
        return None
