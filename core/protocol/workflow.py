"""Complete end-to-end HieraStream journal protocol workflow.

Integrates: SegmentCrypto, AuthorizationLifecycle, FabricClient, IPFS,
OwnerGateway, authorities, OutsourceService, DataUser.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from core.actors.authorities.actors import AttributeAuthority, CentralAuthority, RoleManager
from core.actors.gateway.owner import OwnerGateway, PendingProtection, PublishedSegment
from core.actors.outsource.service import OutsourceService
from core.actors.users.client import DataUser
from core.authorization.errors import AuthorizationUpdateRejected
from core.authorization.lifecycle import AuthorizationLifecycle
from core.authorization.snapshot import AuthorizationSnapshot
from core.blockchain.client.fabric_client import FabricClient
from core.blockchain.client.peer_backend import FabricTxStatus
from core.canonical import eta_digest
from core.crypto.python.access_tree import AND, AccessTree, leaf
from core.crypto.python.field import Zp
from core.crypto.python.hierarchy import HEALTHCARE_FIXTURE, RoleHierarchy
from core.crypto.python.segment import SegmentCrypto
from core.protocol.metadata import (
    deserialize_attr_ct,
    deserialize_role_envelope,
    metadata_bytes,
    parse_metadata,
)
from core.storage.ipfs_client import IPFSClient


@dataclass
class HieraStreamWorkflow:
    """Runnable journal prototype on one host with protocol trust boundaries."""

    owner_id: str = "owner-1"
    hierarchy: RoleHierarchy = field(default_factory=lambda: HEALTHCARE_FIXTURE)
    attr_universe: List[str] = field(
        default_factory=lambda: ["doctor", "cardiology", "nurse", "emergency", "researcher"]
    )
    crypto: SegmentCrypto = field(default_factory=SegmentCrypto)
    lifecycle: Optional[AuthorizationLifecycle] = None
    fabric: FabricClient = field(default_factory=lambda: FabricClient(owner_gateway_id="gw", authority_id="aa"))
    ipfs: IPFSClient = field(default_factory=lambda: IPFSClient(use_local=True))
    gateway: Optional[OwnerGateway] = None
    outsource: Optional[OutsourceService] = None
    ca: Optional[CentralAuthority] = None
    aa: Optional[AttributeAuthority] = None
    rm: Optional[RoleManager] = None
    users: Dict[str, DataUser] = field(default_factory=dict)
    segments: Dict[str, PublishedSegment] = field(default_factory=dict)
    # Retain pending protections for retry tests
    pendings: Dict[str, PendingProtection] = field(default_factory=dict)
    policy_tree: Optional[AccessTree] = None

    def setup(self, initial_policy: Optional[AccessTree] = None) -> AuthorizationSnapshot:
        self.policy_tree = initial_policy or AND(leaf("doctor"), leaf("cardiology"))
        self.lifecycle = AuthorizationLifecycle(
            owner_id=self.owner_id,
            crypto=self.crypto,
            hierarchy=self.hierarchy,
            attr_universe=list(self.attr_universe),
            commit_backend="external",
        )
        # Authorities — ordered provisioning
        self.ca = CentralAuthority(self.crypto)
        self.aa = AttributeAuthority(self.crypto, self.lifecycle)
        self.rm = RoleManager(self.crypto, self.hierarchy)

        snap = self.lifecycle.setup(initial_policy=self.policy_tree)
        # Fabric AuthKey bootstrap (same identity tuple)
        init = self.fabric.init_auth(snap)
        if init.status != FabricTxStatus.VALID:
            raise RuntimeError(f"Fabric InitAuth failed: {init}")
        self.fabric.register_owner(self.owner_id, "gw")
        self.fabric.register_policy_state(snap.policy_id, 0, {"tree": self.policy_tree.to_dict()})
        self.fabric.register_attribute_state(snap.attr_state_id, 0, {"pk": "v0"})
        self.fabric.register_role_state(snap.role_state_id, 0, {"pk": "v0"})

        self.gateway = OwnerGateway(
            owner_id=self.owner_id,
            crypto=self.crypto,
            fabric=self.fabric,
            ipfs=self.ipfs,
            caller_id="gw",
        )
        self.outsource = OutsourceService(crypto=self.crypto, hierarchy=self.hierarchy)
        return snap

    def provision_user(self, user_id: str, attrs: Sequence[str], roles: Sequence[str]) -> DataUser:
        assert self.lifecycle and self.aa and self.rm
        ak, rm = self.lifecycle.provision_user(user_id, attrs, roles)
        user = DataUser(
            user_id=user_id,
            attr_keys=ak,
            role_mat=rm,
            assigned_roles=list(roles),
        )
        snap = self.lifecycle.active
        user.store_attr_version(snap.attr_state_id, ak)
        user.store_role_version(snap.role_state_id, rm, roles)
        self.users[user_id] = user
        return user

    def _sync_user_keys_from_lifecycle(self) -> None:
        """After auth update, pull versioned keys into DataUser stores."""
        assert self.lifecycle and self.lifecycle.keys
        snap = self.lifecycle.active
        for uid, user in self.users.items():
            a = self.lifecycle.keys.current_attr(uid)
            r = self.lifecycle.keys.current_role(uid)
            if a is not None:
                user.store_attr_version(snap.attr_state_id, a.material)
            if r is not None:
                user.store_role_version(snap.role_state_id, r.material, r.assigned_roles)

    def _fabric_commit_pending(self, prev: AuthorizationSnapshot, next_snap: AuthorizationSnapshot):
        """Single authoritative UpdateAuthorization via Fabric."""
        new_p = "" if next_snap.policy_id == prev.policy_id else next_snap.policy_id
        new_a = "" if next_snap.attr_state_id == prev.attr_state_id else next_snap.attr_state_id
        new_r = "" if next_snap.role_state_id == prev.role_state_id else next_snap.role_state_id
        return self.fabric.update_authorization(
            self.owner_id,
            prev,
            new_policy_id=new_p,
            new_attr_state_id=new_a,
            new_role_state_id=new_r,
            caller="aa",
        )

    def update_policy(self, tree: AccessTree) -> AuthorizationSnapshot:
        assert self.lifecycle
        prev = self.lifecycle.active
        pending = self.lifecycle.prepare_policy_update(tree)
        next_snap = self.lifecycle.preview_snapshot(pending)
        res = self._fabric_commit_pending(prev, next_snap)
        if res.status != FabricTxStatus.VALID:
            self.lifecycle.abort_pending_update(pending)
            raise AuthorizationUpdateRejected(f"Fabric UpdateAuthorization failed: {res}")
        self.policy_tree = tree
        snap = self.lifecycle.activate_committed_update(pending, next_snap)
        self.fabric.register_policy_state(snap.policy_id, snap.version, {"tree": tree.to_dict()})
        return snap

    def revoke_attribute(self, attr: str, revoked_users: Sequence[str]) -> AuthorizationSnapshot:
        assert self.lifecycle
        prev = self.lifecycle.active
        pending = self.lifecycle.prepare_attribute_revocation(attr, revoked_users)
        next_snap = self.lifecycle.preview_snapshot(pending)
        res = self._fabric_commit_pending(prev, next_snap)
        if res.status != FabricTxStatus.VALID:
            self.lifecycle.abort_pending_update(pending)
            raise AuthorizationUpdateRejected(f"Fabric UpdateAuthorization failed: {res}")
        snap = self.lifecycle.activate_committed_update(pending, next_snap)
        self._sync_user_keys_from_lifecycle()
        self.fabric.register_attribute_state(snap.attr_state_id, snap.version, {"revoked": attr})
        return snap

    def reassign_roles(self, membership: Dict[str, List[str]]) -> AuthorizationSnapshot:
        assert self.lifecycle
        prev = self.lifecycle.active
        pending = self.lifecycle.prepare_role_reassignment(membership)
        next_snap = self.lifecycle.preview_snapshot(pending)
        res = self._fabric_commit_pending(prev, next_snap)
        if res.status != FabricTxStatus.VALID:
            self.lifecycle.abort_pending_update(pending)
            raise AuthorizationUpdateRejected(f"Fabric UpdateAuthorization failed: {res}")
        snap = self.lifecycle.activate_committed_update(pending, next_snap)
        self._sync_user_keys_from_lifecycle()
        self.fabric.register_role_state(snap.role_state_id, snap.version, {"membership": membership})
        return snap

    # ------------------------------------------------------------------
    # E. Normal publication (+ F. stale retry)
    # ------------------------------------------------------------------
    def publish(
        self,
        plaintext: bytes,
        targets: Sequence[str],
        seg_id: str,
        *,
        max_retries: int = 5,
        policy: Optional[AccessTree] = None,
        aad: bytes = b"",
    ) -> PublishedSegment:
        assert self.gateway and self.lifecycle
        tree = policy or self.policy_tree or self.lifecycle.active_policy_tree()
        pending = self.gateway.protect_payload(seg_id, plaintext, targets, aad=aad)
        self.pendings[seg_id] = pending
        return self._commit_loop(pending, tree, max_retries=max_retries)

    def _commit_loop(
        self,
        pending: PendingProtection,
        tree: AccessTree,
        *,
        max_retries: int,
    ) -> PublishedSegment:
        assert self.gateway
        last = ""
        for _ in range(max_retries):
            snap = self.gateway.read_active_snapshot()
            # Use policy tree from lifecycle for current policyId when possible
            if self.lifecycle:
                try:
                    tree = self.lifecycle.active_policy_tree()
                except Exception:
                    pass
            result, metadata_obj, mcid, eta = self.gateway.attempt_commit(pending, snap, tree)
            if result.status == FabricTxStatus.VALID:
                published = self.gateway.publish_metadata_after_valid(pending, metadata_obj, mcid)
                seg = PublishedSegment(
                    seg_id=pending.seg_id,
                    cid=pending.cid,
                    mcid=published,
                    eta=eta,
                    snapshot=snap,
                    ct_aes=pending.ct_aes,
                    metadata_obj=metadata_obj,
                    meta_published=True,
                    targets=list(pending.targets),
                    ZA=pending.ZA,
                    ZR=pending.ZR,
                )
                self.segments[pending.seg_id] = seg
                return seg
            last = f"{result.status}:{result.reason}"
            # Stale authorization only: regenerate envelopes/metadata/eta — never CT_AES/CID
            if result.status == FabricTxStatus.MVCC_READ_CONFLICT:
                continue
            break
        raise RuntimeError(f"CommitSegment failed after retries: {last}")

    def publish_with_stale_race(
        self,
        plaintext: bytes,
        targets: Sequence[str],
        seg_id: str,
        *,
        race_update: str = "attr",
    ) -> tuple[FabricTxStatus, PublishedSegment]:
        """Case: endorse under ν, UpdateAuthorization first, then retry successfully.

        Returns (first_validation_status, final_published_segment).
        """
        assert self.gateway and self.lifecycle
        tree = self.policy_tree or self.lifecycle.active_policy_tree()
        pending = self.gateway.protect_payload(seg_id, plaintext, targets)
        self.pendings[seg_id] = pending
        snap0 = self.gateway.read_active_snapshot()
        # Endorse only (pending validation)
        pending_tx, meta0, mcid0, _eta0 = self.gateway.attempt_commit(
            pending, snap0, tree, defer_validation=True
        )
        assert pending_tx.status == FabricTxStatus.PENDING
        assert not self.gateway.metadata_was_published(seg_id)

        # Concurrent authorization update commits first
        if race_update == "attr":
            self.revoke_attribute("emergency", revoked_users=[])
        elif race_update == "policy":
            from core.crypto.python.access_tree import OR

            self.update_policy(OR(leaf("doctor"), leaf("nurse")))
        else:
            # role — need at least one user; no-op membership refresh via lifecycle xi
            mem = {uid: list(u.assigned_roles) for uid, u in self.users.items()}
            if mem:
                self.reassign_roles(mem)

        first = self.fabric.await_validation(pending_tx.tx_id)
        # Metadata still unpublished
        assert not self.gateway.metadata_was_published(seg_id)

        # Successful retry under new snapshot — same CT_AES / CID
        final = self._commit_loop(pending, tree, max_retries=5)
        assert final.cid == pending.cid
        assert final.ct_aes == pending.ct_aes
        assert final.mcid != mcid0  # authorization metadata changed ⇒ MCID changes
        return first.status, final

    # ------------------------------------------------------------------
    # G. Data access
    # ------------------------------------------------------------------
    def access(self, user_id: str, seg_id: str, aad: bytes = b"") -> bytes:
        assert self.outsource and self.gateway
        user = self.users[user_id]
        record = self.fabric.get_segment(self.owner_id, seg_id)
        if record is None:
            raise KeyError(f"segment {seg_id} not on Fabric")

        ct_aes = self.ipfs.get(record["CID"])
        meta_raw = self.ipfs.get(record["MCID"])

        # Verify CIDs
        if not self.ipfs.verify_cid(record["CID"], ct_aes):
            raise ValueError("tampered payload / CID mismatch")
        if not self.ipfs.verify_cid(record["MCID"], meta_raw):
            raise ValueError("tampered metadata / MCID mismatch")

        # Verify eta
        eta_prime = eta_digest(
            record["CID"],
            record["MCID"],
            int(record["version"]),
            record["policyId"],
            record["attrStateId"],
            record["roleStateId"],
        )
        if eta_prime != record["eta"]:
            raise ValueError("eta mismatch")

        mj = parse_metadata(meta_raw)
        attr_ct = deserialize_attr_ct(
            mj["CTA"],
            GElementCls=self.crypto.GElement,
            GTElementCls=self.crypto.GTElement,
        )
        envelopes = [
            deserialize_role_envelope(
                e,
                GElementCls=self.crypto.GElement,
                GTElementCls=self.crypto.GTElement,
                ZpCls=self.crypto.Zp,
            )
            for e in mj["CTR"]
        ]
        targets = list(mj["targetRoles"])

        # Select versioned keys for segment's authorization state
        attr_mat = user.attr_for(record["attrStateId"])
        role_mat, assigned = user.role_for(record["roleStateId"])

        # Outsourced attribute transform (E, E1, E_ua only — never usk1)
        Bj = self.outsource.attr_transform(attr_ct, attr_mat.to_outsource_keys())
        if Bj is None:
            raise PermissionError("attribute policy not satisfied")
        ZA = self.crypto.user_recover_ZA(attr_ct, Bj, attr_mat.usk1)

        # Role path with inheritance
        chosen = None
        assigned_role = None
        for ri in targets:
            for rx in assigned:
                if self.hierarchy.dominates(rx, ri) and rx in role_mat.RK:
                    chosen = next(e for e in envelopes if e.target_role == ri)
                    assigned_role = rx
                    break
            if chosen:
                break
        if chosen is None or assigned_role is None:
            raise PermissionError("no authorized role")

        omega = self.crypto.Zp.random()
        TR = user.make_TR(self.crypto, role_mat.RK[assigned_role], omega)
        P, Q = self.outsource.role_transform(
            chosen, TR, role_mat.D0, assigned_role, chosen.target_role
        )
        ZR = user.recover_ZR(self.crypto, chosen, P, Q, omega, role_mat.rho)
        return user.decrypt_payload(ZA, ZR, ct_aes, aad=aad)

    def active_snapshot(self) -> AuthorizationSnapshot:
        snap = self.fabric.get_authorization_snapshot(self.owner_id)
        assert snap is not None
        return snap
