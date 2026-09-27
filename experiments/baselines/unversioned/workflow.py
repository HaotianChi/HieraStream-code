"""Unversioned publication baseline — same stack, no AuthKey MVCC on commit.

Uses identical crypto / IPFS / Fabric peer ledger. Commit does not GetState(AuthKey).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from core.authorization.errors import AuthorizationUpdateRejected
from core.authorization.lifecycle import AuthorizationLifecycle
from core.authorization.snapshot import AuthorizationSnapshot
from core.blockchain.client.fabric_client import FabricClient
from core.blockchain.client.peer_backend import FabricTxStatus, TxResult
from core.canonical import eta_digest
from core.crypto.python.access_tree import AND, AccessTree, leaf
from core.crypto.python.hierarchy import HEALTHCARE_FIXTURE, RoleHierarchy
from core.crypto.python.kdf_aead import aead_encrypt, derive_segment_key
from core.crypto.python.segment import AttrCT, RoleEnvelope, SegmentCrypto
from core.storage.ipfs_client import IPFSClient


@dataclass
class _Pending:
    seg_id: str
    ZA: object
    ZR: object
    key: bytes
    ct_aes: bytes
    cid: str
    targets: List[str]


@dataclass
class _Published:
    seg_id: str
    cid: str
    mcid: str
    eta: str
    snapshot: AuthorizationSnapshot
    ct_aes: bytes
    metadata_obj: dict
    targets: List[str]


@dataclass
class UnversionedWorkflow:
    """Full publish path identical to HieraStream except unversioned commit."""

    owner_id: str = "owner-unversioned"
    hierarchy: RoleHierarchy = field(default_factory=lambda: HEALTHCARE_FIXTURE)
    attr_universe: List[str] = field(
        default_factory=lambda: ["doctor", "cardiology", "nurse", "emergency", "researcher"]
    )
    crypto: SegmentCrypto = field(default_factory=SegmentCrypto)
    lifecycle: Optional[AuthorizationLifecycle] = None
    fabric: FabricClient = field(default_factory=lambda: FabricClient(owner_gateway_id="gw", authority_id="aa"))
    ipfs: IPFSClient = field(default_factory=lambda: IPFSClient(use_local=True))
    users: Dict[str, object] = field(default_factory=dict)
    segments: Dict[str, _Published] = field(default_factory=dict)
    policy_tree: Optional[AccessTree] = None
    baseline_id: str = "unversioned_publication"
    _last_stale: bool = False

    def setup(self, initial_policy: Optional[AccessTree] = None) -> AuthorizationSnapshot:
        self.policy_tree = initial_policy or AND(leaf("doctor"), leaf("cardiology"))
        self.lifecycle = AuthorizationLifecycle(
            owner_id=self.owner_id,
            crypto=self.crypto,
            hierarchy=self.hierarchy,
            attr_universe=list(self.attr_universe),
            commit_backend="external",
        )
        snap = self.lifecycle.setup(initial_policy=self.policy_tree)
        init = self.fabric.init_auth(snap)
        if init.status != FabricTxStatus.VALID:
            raise RuntimeError(f"InitAuth failed: {init}")
        self.fabric.register_owner(self.owner_id, "gw")
        self.fabric.register_policy_state(snap.policy_id, 0, {"tree": self.policy_tree.to_dict()})
        self.fabric.register_attribute_state(snap.attr_state_id, 0, {"pk": "v0"})
        self.fabric.register_role_state(snap.role_state_id, 0, {"pk": "v0"})
        return snap

    def provision_user(self, user_id: str, attrs: Sequence[str], roles: Sequence[str]):
        assert self.lifecycle
        return self.lifecycle.provision_user(user_id, attrs, roles)

    def read_active_snapshot(self) -> AuthorizationSnapshot:
        snap = self.fabric.get_authorization_snapshot(self.owner_id)
        if snap is None:
            raise RuntimeError("no AuthKey")
        return snap

    def protect_payload(self, seg_id: str, plaintext: bytes, targets: Sequence[str]) -> _Pending:
        ZA = self.crypto.sample_ZA()
        ZR = self.crypto.sample_ZR()
        key = derive_segment_key(ZA, ZR)
        ct_aes = aead_encrypt(key, plaintext)
        cid = self.ipfs.add(ct_aes)
        return _Pending(seg_id=seg_id, ZA=ZA, ZR=ZR, key=key, ct_aes=ct_aes, cid=cid, targets=list(targets))

    def prepare_unversioned_artifacts(
        self, pending: _Pending, observed: AuthorizationSnapshot, tree: AccessTree
    ) -> Tuple[dict, str, str]:
        """Crypto/metadata prep only (no ledger write). Mirrors OwnerGateway.prepare_commit_artifacts."""
        from core.protocol.metadata import build_metadata_object, metadata_bytes

        partial = self.crypto.gateway_partial_attr(pending.ZA)  # type: ignore[arg-type]
        attr_ct: AttrCT = self.crypto.outsource_policy_encrypt(partial.to_outsource_view(), tree)
        envelopes: List[RoleEnvelope] = self.crypto.role_encrypt_multi(pending.ZR, pending.targets)  # type: ignore[arg-type]
        metadata_obj = build_metadata_object(
            attr_ct,
            envelopes,
            observed.version,
            observed.policy_id,
            observed.attr_state_id,
            observed.role_state_id,
            pending.targets,
        )
        meta_bytes = metadata_bytes(metadata_obj)
        mcid = self.ipfs.only_hash(meta_bytes)
        eta = eta_digest(
            pending.cid,
            mcid,
            observed.version,
            observed.policy_id,
            observed.attr_state_id,
            observed.role_state_id,
        )
        return metadata_obj, mcid, eta

    def commit_prepared_unversioned(
        self, pending: _Pending, observed: AuthorizationSnapshot, mcid: str, eta: str
    ) -> TxResult:
        """Ledger write only — Call after prepare; AuthKey must NOT be read here."""
        return self.fabric.commit_segment_unversioned(
            self.owner_id,
            pending.seg_id,
            pending.cid,
            mcid,
            observed.version,
            observed.policy_id,
            observed.attr_state_id,
            observed.role_state_id,
            eta,
            caller="gw",
        )

    def attempt_commit_unversioned(
        self, pending: _Pending, observed: AuthorizationSnapshot, tree: AccessTree
    ) -> Tuple[TxResult, dict, str, str]:
        metadata_obj, mcid, eta = self.prepare_unversioned_artifacts(pending, observed, tree)
        result = self.commit_prepared_unversioned(pending, observed, mcid, eta)
        return result, metadata_obj, mcid, eta

    def publish_metadata_after_valid(self, pending: _Pending, metadata_obj: dict, mcid: str) -> str:
        from core.protocol.metadata import metadata_bytes

        actual = self.ipfs.add(metadata_bytes(metadata_obj))
        if actual != mcid:
            raise RuntimeError("MCID mismatch")
        return actual

    def _fabric_commit_pending(self, prev: AuthorizationSnapshot, next_snap: AuthorizationSnapshot) -> TxResult:
        return self.fabric.update_authorization(
            self.owner_id,
            prev,
            new_policy_id="" if next_snap.policy_id == prev.policy_id else next_snap.policy_id,
            new_attr_state_id="" if next_snap.attr_state_id == prev.attr_state_id else next_snap.attr_state_id,
            new_role_state_id="" if next_snap.role_state_id == prev.role_state_id else next_snap.role_state_id,
            caller="aa",
        )

    def revoke_attribute(self, attr: str, revoked_users: Sequence[str]) -> AuthorizationSnapshot:
        assert self.lifecycle
        from core.authorization.errors import AuthorizationUpdateRejected

        prev = self.lifecycle.active
        pending = self.lifecycle.prepare_attribute_revocation(attr, revoked_users)
        next_snap = self.lifecycle.preview_snapshot(pending)
        res = self._fabric_commit_pending(prev, next_snap)
        if res.status != FabricTxStatus.VALID:
            self.lifecycle.abort_pending_update(pending)
            raise AuthorizationUpdateRejected(f"UpdateAuthorization failed: {res}")
        snap = self.lifecycle.activate_committed_update(pending, next_snap)
        self.fabric.register_attribute_state(snap.attr_state_id, snap.version, {"revoked": attr})
        return snap

    def update_policy(self, tree: AccessTree) -> AuthorizationSnapshot:
        assert self.lifecycle
        from core.authorization.errors import AuthorizationUpdateRejected

        prev = self.lifecycle.active
        pending = self.lifecycle.prepare_policy_update(tree)
        next_snap = self.lifecycle.preview_snapshot(pending)
        res = self._fabric_commit_pending(prev, next_snap)
        if res.status != FabricTxStatus.VALID:
            self.lifecycle.abort_pending_update(pending)
            raise AuthorizationUpdateRejected(f"UpdateAuthorization failed: {res}")
        self.policy_tree = tree
        snap = self.lifecycle.activate_committed_update(pending, next_snap)
        self.fabric.register_policy_state(snap.policy_id, snap.version, {"tree": tree.to_dict()})
        return snap

    def reassign_roles(self, membership: Dict[str, List[str]]) -> AuthorizationSnapshot:
        """Same AuthKey UpdateAuthorization path as HieraStream (needed for paired E4)."""
        assert self.lifecycle
        from core.authorization.errors import AuthorizationUpdateRejected

        prev = self.lifecycle.active
        pending = self.lifecycle.prepare_role_reassignment(membership)
        next_snap = self.lifecycle.preview_snapshot(pending)
        res = self._fabric_commit_pending(prev, next_snap)
        if res.status != FabricTxStatus.VALID:
            self.lifecycle.abort_pending_update(pending)
            raise AuthorizationUpdateRejected(f"UpdateAuthorization failed: {res}")
        snap = self.lifecycle.activate_committed_update(pending, next_snap)
        self.fabric.register_role_state(snap.role_state_id, snap.version, {"membership": membership})
        return snap

    def publish(self, plaintext: bytes, targets: Sequence[str], seg_id: str) -> _Published:
        assert self.lifecycle
        tree = self.policy_tree or self.lifecycle.active_policy_tree()
        observed = self.read_active_snapshot()
        pending = self.protect_payload(seg_id, plaintext, targets)
        result, metadata_obj, mcid, eta = self.attempt_commit_unversioned(pending, observed, tree)
        if result.status != FabricTxStatus.VALID:
            raise RuntimeError(f"unversioned commit failed: {result}")
        mcid_pub = self.publish_metadata_after_valid(pending, metadata_obj, mcid)
        cur = self.fabric.get_authorization_snapshot(self.owner_id)
        self._last_stale = cur is not None and (
            observed.version != cur.version
            or observed.policy_id != cur.policy_id
            or observed.attr_state_id != cur.attr_state_id
            or observed.role_state_id != cur.role_state_id
        )
        pub = _Published(
            seg_id=seg_id,
            cid=pending.cid,
            mcid=mcid_pub,
            eta=eta,
            snapshot=observed,
            ct_aes=pending.ct_aes,
            metadata_obj=metadata_obj,
            targets=list(targets),
        )
        self.segments[seg_id] = pub
        return pub

    def last_publish_was_stale(self) -> bool:
        return self._last_stale

    # Compatibility shims used by E4 runner
    @property
    def gateway(self) -> "UnversionedWorkflow":
        return self
