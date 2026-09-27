"""Complete authorization lifecycle orchestration (Section III-C / III-E).

Modes:
  commit_backend=\"standalone\"  — LocalAuthLedger is the commit authority
                                  (unit / state-machine tests only).
  commit_backend=\"external\"    — caller commits via Fabric; this class only
                                  prepare → (external VALID) → activate / abort.
                                  LocalAuthLedger is NOT an authority.

Active SegmentCrypto public parameters are never mutated during prepare.
"""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from core.authorization.errors import (
    AuthorizationStateMismatch,
    AuthorizationUpdateRejected,
    HistoricalAttributeKeyUnavailable,
    HistoricalRoleKeyUnavailable,
)
from core.authorization.history import HistoricalAuthorizationArchive
from core.authorization.machine import AuthMachine, AuthPhase, PendingBundle
from core.authorization.secrecy import (
    assert_no_ratio_fields,
    compute_attr_update_ratio,
    scan_text_blob_for_ratio_leak,
)
from core.authorization.snapshot import AuthKeyRecord, AuthorizationSnapshot
from core.authorization.states import AttributePublicState, PolicyState, RoleState
from core.authorization.store import CommitRejected, LocalAuthLedger
from core.authorization.user_keys import (
    AttrKeyVersion,
    RoleKeyVersion,
    VersionedUserKeyStore,
    apply_issued_Eua,
    apply_issued_RK,
)
from core.crypto.python.access_tree import AccessTree
from core.crypto.python.field import Zp
from core.crypto.python.groups import GElement
from core.crypto.python.hierarchy import HEALTHCARE_FIXTURE, RoleHierarchy
from core.crypto.python.segment import (
    ProtectedSegmentCrypto,
    SegmentCrypto,
    UserAttrMaterial,
    UserRoleMaterial,
)


@dataclass
class SegmentRecord:
    """Protected segment bound to an authorization snapshot (local, no Fabric)."""

    seg_id: str
    snapshot: AuthorizationSnapshot
    crypto: ProtectedSegmentCrypto
    plaintext_aad: bytes = b""


@dataclass
class AuthorizationLifecycle:
    """Owner-domain authorization state manager + dual-layer crypto."""

    owner_id: str
    crypto: SegmentCrypto = field(default_factory=SegmentCrypto)
    hierarchy: RoleHierarchy = field(default_factory=lambda: HEALTHCARE_FIXTURE)
    attr_universe: List[str] = field(
        default_factory=lambda: ["doctor", "cardiology", "nurse", "emergency", "researcher"]
    )
    ledger: LocalAuthLedger = field(default_factory=LocalAuthLedger)
    machine: Optional[AuthMachine] = None
    archive: Optional[HistoricalAuthorizationArchive] = None
    keys: Optional[VersionedUserKeyStore] = None
    # Current public state objects (indexed also in archive)
    policy_by_ver: Dict[int, PolicyState] = field(default_factory=dict)
    attr_by_ver: Dict[int, AttributePublicState] = field(default_factory=dict)
    role_by_ver: Dict[int, RoleState] = field(default_factory=dict)
    # Experiment / test durable export (public only)
    experiment_raw: List[dict] = field(default_factory=list)
    segments: Dict[str, SegmentRecord] = field(default_factory=dict)
    # Base hierarchy AR / s preserved across role updates
    _base_ar_hex: Dict[str, str] = field(default_factory=dict)
    _base_s_hex: Dict[str, str] = field(default_factory=dict)
    # "standalone" = LocalAuthLedger authority; "external" = Fabric commits
    commit_backend: str = "standalone"

    # ------------------------------------------------------------------
    # Setup / bootstrap (ν = 0)
    # ------------------------------------------------------------------
    def setup(
        self,
        initial_policy: Optional[AccessTree] = None,
        initial_membership: Optional[Dict[str, List[str]]] = None,
        ledger_path: Optional[Path] = None,
    ) -> AuthorizationSnapshot:
        if ledger_path is not None:
            self.ledger.path = ledger_path
            self.ledger.load()

        self.crypto.ca_setup()
        self.crypto.aa_setup(self.attr_universe)
        self.crypto.role_setup(self.hierarchy)

        assert self.crypto.pp and self.crypto.secrets
        self._base_ar_hex = {r: g.to_bytes().hex() for r, g in self.crypto.pp.ar.items()}
        self._base_s_hex = {
            r: s.to_bytes().hex() for r, s in self.crypto.secrets.rm.s_i.items()
        }

        if initial_policy is None:
            from core.crypto.python.access_tree import AND, leaf

            initial_policy = AND(leaf("doctor"), leaf("cardiology"))

        membership = initial_membership or {}
        policy0 = PolicyState.from_tree(0, initial_policy)
        attr0 = AttributePublicState.from_pk(0, self.crypto.pp.pk_attr)
        role0 = RoleState.build(0, self.crypto.secrets.rm.xi, self.crypto.pp.pk_role, membership)

        self.policy_by_ver[0] = policy0
        self.attr_by_ver[0] = attr0
        self.role_by_ver[0] = role0

        snap = AuthorizationSnapshot(
            owner_id=self.owner_id,
            version=0,
            policy_id=policy0.state_id(),
            attr_state_id=attr0.state_id(),
            role_state_id=role0.state_id(),
        )

        self.machine = AuthMachine(owner_id=self.owner_id, phase=AuthPhase.ACTIVE, active=snap)
        self.archive = HistoricalAuthorizationArchive(owner_id=self.owner_id)
        self.keys = VersionedUserKeyStore(owner_id=self.owner_id)

        self.archive.store_policy(policy0)
        self.archive.store_attr(attr0)
        self.archive.store_role(role0)
        self.archive.store_snapshot(snap)
        self.archive.attr_secrets.record(0, dict(self.crypto.secrets.aa.t_a))
        self.archive.role_secrets.record(
            0, self.crypto.secrets.rm.xi, dict(self.crypto.secrets.rm.rs)
        )

        self.ledger.bootstrap(snap)
        self._export_public({"event": "bootstrap", "snapshot": snap.as_dict()})
        return snap

    @property
    def active(self) -> AuthorizationSnapshot:
        assert self.machine and self.machine.active
        return self.machine.active

    def active_policy_tree(self) -> AccessTree:
        ver = self.active.version
        # Resolve policy by id: may be carried forward from earlier version
        pid = self.active.policy_id
        for p in self.policy_by_ver.values():
            if p.state_id() == pid:
                return p.tree()
        return self.policy_by_ver[ver].tree()

    # ------------------------------------------------------------------
    # User provisioning
    # ------------------------------------------------------------------
    def provision_user(
        self,
        user_id: str,
        attrs: Sequence[str],
        roles: Sequence[str],
    ) -> Tuple[UserAttrMaterial, UserRoleMaterial]:
        assert self.keys and self.machine
        snap = self.machine.require_active()
        ak = self.crypto.aa_keygen(user_id, attrs)
        rm = self.crypto.ca_role_user(user_id)
        for r in roles:
            self.crypto.rm_issue_rk(r, rm)

        self.keys.put_attr(
            AttrKeyVersion(
                owner_id=self.owner_id,
                user_id=user_id,
                attr_version=snap.version,
                attr_state_id=snap.attr_state_id,
                material=self.keys.clone_attr_material(ak),
            )
        )
        self.keys.put_role(
            RoleKeyVersion(
                owner_id=self.owner_id,
                user_id=user_id,
                role_version=snap.version,
                role_state_id=snap.role_state_id,
                material=self.keys.clone_role_material(rm),
                assigned_roles=list(roles),
            )
        )

        # Membership is part of role state; provisioning alone does not bump ν.
        # Track provisional membership for subsequent role updates.
        cur_role = self.role_by_ver[snap.version]
        mem = dict(cur_role.membership.as_lists())
        mem[user_id] = list(roles)
        # Replace in-memory membership view without changing state_id of active snap
        # (formal roleStateId updates occur only via role reassignment commit).
        self._provisional_membership = mem  # type: ignore[attr-defined]
        return ak, rm

    def _membership_map(self) -> Dict[str, List[str]]:
        if hasattr(self, "_provisional_membership"):
            return dict(self._provisional_membership)  # type: ignore[attr-defined]
        snap = self.active
        role = self.role_by_ver.get(snap.version)
        if role is None:
            # Find by state id
            for r in self.role_by_ver.values():
                if r.state_id() == snap.role_state_id:
                    return r.membership.as_lists()
            return {}
        return role.membership.as_lists()

    # ------------------------------------------------------------------
    # Segment protect / recover (uses active / historical keys)
    # ------------------------------------------------------------------
    def protect_segment(
        self,
        seg_id: str,
        plaintext: bytes,
        targets: Sequence[str],
        policy: Optional[AccessTree] = None,
        aad: bytes = b"",
    ) -> SegmentRecord:
        tree = policy or self.active_policy_tree()
        protected = self.crypto.protect_segment(plaintext, tree, targets, aad=aad)
        rec = SegmentRecord(
            seg_id=seg_id,
            snapshot=self.active,
            crypto=protected,
            plaintext_aad=aad,
        )
        self.segments[seg_id] = rec
        self._export_public(
            {
                "event": "protect",
                "segId": seg_id,
                "auth": self.active.as_dict(),
                "ctAesLen": len(protected.ct_aes),
            }
        )
        return rec

    def _resolve_attr_keys(self, user_id: str, snap: AuthorizationSnapshot) -> Optional[AttrKeyVersion]:
        assert self.keys
        # State ID is authoritative; version may differ under carry-forward.
        for ver in self.keys.attr_versions_for(user_id):
            e = self.keys.get_attr(user_id, ver)
            if e and e.attr_state_id == snap.attr_state_id:
                return e
        return None

    def _resolve_role_keys(self, user_id: str, snap: AuthorizationSnapshot) -> Optional[RoleKeyVersion]:
        assert self.keys
        for ver in self.keys.role_versions_for(user_id):
            e = self.keys.get_role(user_id, ver)
            if e and e.role_state_id == snap.role_state_id:
                return e
        return None

    def recover_segment(self, user_id: str, seg_id: str) -> bytes:
        assert self.keys
        seg = self.segments[seg_id]
        snap = seg.snapshot
        attr_entry = self._resolve_attr_keys(user_id, snap)
        role_entry = self._resolve_role_keys(user_id, snap)
        if attr_entry is None:
            raise HistoricalAttributeKeyUnavailable(
                f"no attr keys for user={user_id} attrStateId={snap.attr_state_id}"
            )
        if role_entry is None:
            raise HistoricalRoleKeyUnavailable(
                f"no role keys for user={user_id} roleStateId={snap.role_state_id}"
            )
        if attr_entry.attr_state_id != snap.attr_state_id:
            raise AuthorizationStateMismatch("attrStateId mismatch")
        if role_entry.role_state_id != snap.role_state_id:
            raise AuthorizationStateMismatch("roleStateId mismatch")
        return self.crypto.recover_segment(
            seg.crypto,
            attr_entry.material,
            role_entry.material,
            role_entry.assigned_roles,
            aad=seg.plaintext_aad,
        )

    # ------------------------------------------------------------------
    # Prepare / Commit / Activate
    # ------------------------------------------------------------------
    def preview_snapshot(self, bundle: PendingBundle) -> AuthorizationSnapshot:
        """Public preview of Θ^(ν+1) from ACTIVE(ν) fields + pending objects."""
        assert self.machine and self.machine.active is not None
        return self._preview_snapshot(bundle, self.machine.active)

    def _preview_snapshot(self, bundle: PendingBundle, active: AuthorizationSnapshot) -> AuthorizationSnapshot:
        policy_id = active.policy_id if bundle.policy is None else bundle.policy.state_id()
        attr_id = active.attr_state_id if bundle.attr is None else bundle.attr.state_id()
        role_id = active.role_state_id if bundle.role is None else bundle.role.state_id()
        return AuthorizationSnapshot(
            owner_id=self.owner_id,
            version=bundle.next_version,
            policy_id=policy_id,
            attr_state_id=attr_id,
            role_state_id=role_id,
        )

    def abort_pending_update(self, _bundle: Optional[PendingBundle] = None) -> None:
        """Discard pending; ACTIVE(ν) unchanged. No active-crypto rollback needed."""
        assert self.machine
        self.machine.abort_pending()

    def activate_committed_update(
        self, bundle: PendingBundle, committed_snapshot: AuthorizationSnapshot
    ) -> AuthorizationSnapshot:
        """Install prepared state ONLY after external (or standalone) commit VALID."""
        assert self.machine and self.archive and self.keys and self.crypto.secrets and self.crypto.pp
        if self.machine.phase != AuthPhase.PENDING or self.machine.pending is None:
            raise RuntimeError("activate requires PENDING prepared state")
        if committed_snapshot.version != bundle.next_version:
            raise AuthorizationStateMismatch("committed snapshot version mismatch")

        active = self.machine.active
        assert active is not None
        next_snap = committed_snapshot

        # Apply pending AA secrets to active crypto (first time visible)
        aa = self.crypto.secrets.aa
        for attr, t_new in bundle.pending_t_a.items():
            t_old = bundle.pending_t_a_old[attr]
            aa.t_a_prev[attr] = t_old
            aa.t_a[attr] = t_new
            self.crypto.pp.pk_attr[attr] = self.crypto.ctx.g_pow(t_new)

        # Apply pending RM secrets
        if bundle.pending_xi is not None:
            rm = self.crypto.secrets.rm
            rm.xi = bundle.pending_xi
            rm.rs.clear()
            rm.rs.update(bundle.pending_rs)
            self.crypto.pp.pk_role.clear()
            self.crypto.pp.pk_role.update(bundle.pending_pk_role)

        self.machine.mark_committed(next_snap)

        nu = bundle.next_version
        if bundle.policy is not None:
            self.policy_by_ver[nu] = bundle.policy
            self.archive.store_policy(bundle.policy)
        else:
            prev = self._policy_for_id(active.policy_id)
            carried = PolicyState(version=nu, policy_expr=deepcopy(prev.policy_expr))
            self.policy_by_ver[nu] = carried
            self.archive.store_policy(carried)

        if bundle.attr is not None:
            self.attr_by_ver[nu] = bundle.attr
            self.archive.store_attr(bundle.attr)
        else:
            prev_a = self._attr_for_id(active.attr_state_id)
            carried_a = AttributePublicState(version=nu, pk_attr=dict(prev_a.pk_attr))
            self.attr_by_ver[nu] = carried_a
            self.archive.store_attr(carried_a)

        if bundle.role is not None:
            self.role_by_ver[nu] = bundle.role
            self.archive.store_role(bundle.role)
            if hasattr(self, "_provisional_membership"):
                self._provisional_membership = bundle.role.membership.as_lists()  # type: ignore[attr-defined]
        else:
            prev_r = self._role_for_id(active.role_state_id)
            carried_r = RoleState(
                version=nu,
                xi_hex=prev_r.xi_hex,
                pk_role=dict(prev_r.pk_role),
                membership=prev_r.membership,
            )
            self.role_by_ver[nu] = carried_r
            self.archive.store_role(carried_r)

        self._activate_user_keys(bundle, next_snap)
        activated = self.machine.activate()
        self.archive.store_snapshot(activated)
        self.archive.attr_secrets.record(nu, dict(self.crypto.secrets.aa.t_a))
        self.archive.role_secrets.record(
            nu, self.crypto.secrets.rm.xi, dict(self.crypto.secrets.rm.rs)
        )
        self._export_public({"event": "activate", "snapshot": activated.as_dict(), "kind": bundle.kind})
        return activated

    def _standalone_commit_and_activate(self, bundle: PendingBundle) -> AuthorizationSnapshot:
        """LocalAuthLedger is the sole authority (unit tests). Not used by Fabric workflow."""
        if self.commit_backend != "standalone":
            raise RuntimeError(
                "standalone commit forbidden when commit_backend=external; "
                "use prepare + Fabric VALID + activate_committed_update"
            )
        assert self.machine
        active = self.machine.active
        assert active is not None
        next_snap = self._preview_snapshot(bundle, active)
        public_payload = bundle.public_commit_payload()
        assert_no_ratio_fields(public_payload)
        scan_text_blob_for_ratio_leak(json.dumps(public_payload))
        try:
            self.ledger.update_authorization(
                self.owner_id,
                AuthKeyRecord.from_snapshot(active),
                AuthKeyRecord.from_snapshot(next_snap),
                public_payload=public_payload,
            )
        except CommitRejected as e:
            self.abort_pending_update(bundle)
            raise AuthorizationUpdateRejected(str(e)) from e
        return self.activate_committed_update(bundle, next_snap)

    # Keep old name as alias used nowhere after refactor — removed.

    def _policy_for_id(self, policy_id: str) -> PolicyState:
        for p in self.policy_by_ver.values():
            if p.state_id() == policy_id:
                return p
        raise KeyError(policy_id)

    def _attr_for_id(self, attr_state_id: str) -> AttributePublicState:
        for a in self.attr_by_ver.values():
            if a.state_id() == attr_state_id:
                return a
        raise KeyError(attr_state_id)

    def _role_for_id(self, role_state_id: str) -> RoleState:
        for r in self.role_by_ver.values():
            if r.state_id() == role_state_id:
                return r
        raise KeyError(role_state_id)

    def _activate_user_keys(self, bundle: PendingBundle, snap: AuthorizationSnapshot) -> None:
        assert self.keys
        users = set(self.keys.latest_attr_ver) | set(self.keys.latest_role_ver)
        for uid in users:
            cur_a = self.keys.current_attr(uid)
            cur_r = self.keys.current_role(uid)
            if cur_a is None or cur_r is None:
                continue

            # Attribute side
            if bundle.attr is None:
                # Carry forward: same attr_state_id, re-index under new ν for lookup ease
                self.keys.put_attr(
                    AttrKeyVersion(
                        owner_id=self.owner_id,
                        user_id=uid,
                        attr_version=snap.version,
                        attr_state_id=snap.attr_state_id,
                        material=self.keys.clone_attr_material(cur_a.material),
                    )
                )
            else:
                revoked = set(bundle.revoked_attrs.get(uid, []))
                issued = bundle.issued_Eua.get(uid, {})
                new_attrs = [a for a in cur_a.material.attrs if a not in revoked]
                # Keep only attrs still held; apply opaque issued refreshes
                mat = apply_issued_Eua(cur_a.material, issued, new_attrs)
                # Drop revoked from E_ua
                mat.E_ua = {a: g for a, g in mat.E_ua.items() if a in new_attrs}
                mat.attrs = new_attrs
                self.keys.put_attr(
                    AttrKeyVersion(
                        owner_id=self.owner_id,
                        user_id=uid,
                        attr_version=snap.version,
                        attr_state_id=snap.attr_state_id,
                        material=mat,
                    )
                )

            # Role side
            if bundle.role is None:
                self.keys.put_role(
                    RoleKeyVersion(
                        owner_id=self.owner_id,
                        user_id=uid,
                        role_version=snap.version,
                        role_state_id=snap.role_state_id,
                        material=self.keys.clone_role_material(cur_r.material),
                        assigned_roles=list(cur_r.assigned_roles),
                    )
                )
            else:
                mem = bundle.role.membership.as_lists()
                new_roles = list(mem.get(uid, []))
                issued_rk = bundle.issued_RK.get(uid, {})
                if issued_rk:
                    mat_r = apply_issued_RK(cur_r.material, issued_rk)
                else:
                    # User removed from all roles or not refreshed
                    mat_r = self.keys.clone_role_material(cur_r.material)
                    mat_r.RK = {}
                self.keys.put_role(
                    RoleKeyVersion(
                        owner_id=self.owner_id,
                        user_id=uid,
                        role_version=snap.version,
                        role_state_id=snap.role_state_id,
                        material=mat_r,
                        assigned_roles=new_roles,
                    )
                )

    # ------------------------------------------------------------------
    # E–G Prepare (no active crypto mutation) / standalone convenience
    # ------------------------------------------------------------------
    def prepare_policy_update(self, new_tree: AccessTree) -> PendingBundle:
        assert self.machine
        active = self.machine.require_active()
        nu = active.version + 1
        policy = PolicyState.from_tree(nu, new_tree)
        bundle = PendingBundle(
            next_version=nu,
            policy=policy,
            attr=None,
            role=None,
            kind="policy",
            xi_refreshed=False,
        )
        assert_no_ratio_fields(bundle.public_commit_payload())
        self.machine.enter_pending(bundle)
        return bundle

    def prepare_attribute_revocation(
        self, attr: str, revoked_users: Sequence[str]
    ) -> PendingBundle:
        """Compute pending t_a / PK_a / E_ua without mutating active AA state."""
        assert self.machine and self.keys and self.crypto.secrets and self.crypto.pp
        active = self.machine.require_active()
        nu = active.version + 1
        revoked_set = set(revoked_users)

        aa = self.crypto.secrets.aa
        t_old = aa.t_a[attr]
        ZpT = type(t_old)
        t_new = ZpT.random()
        # Pending public PK map — do NOT write aa.t_a / pp.pk_attr yet
        pk_map = dict(self.crypto.pp.pk_attr)
        pk_map[attr] = self.crypto.ctx.g_pow(t_new)

        ratio = compute_attr_update_ratio(t_old, t_new)
        issued_Eua: Dict[str, Dict[str, str]] = {}
        revoked_attrs: Dict[str, List[str]] = {}

        for uid, ver in list(self.keys.latest_attr_ver.items()):
            entry = self.keys.get_attr(uid, ver)
            if entry is None:
                continue
            if uid in revoked_set:
                if attr in entry.material.attrs or attr in entry.material.E_ua:
                    revoked_attrs[uid] = [attr]
                continue
            if attr in entry.material.E_ua:
                new_e = ratio.apply(entry.material.E_ua[attr])
                issued_Eua.setdefault(uid, {})[attr] = new_e.to_bytes().hex()
        del ratio

        new_attr = AttributePublicState.from_pk(nu, pk_map)
        assert new_attr.state_id() != active.attr_state_id

        bundle = PendingBundle(
            next_version=nu,
            policy=None,
            attr=new_attr,
            role=None,
            issued_Eua=issued_Eua,
            revoked_attrs=revoked_attrs,
            kind="attribute",
            xi_refreshed=False,
            pending_t_a={attr: t_new},
            pending_t_a_old={attr: t_old},
        )
        assert_no_ratio_fields(bundle.public_commit_payload())
        self.machine.enter_pending(bundle)
        return bundle

    def prepare_role_reassignment(self, membership: Dict[str, List[str]]) -> PendingBundle:
        """Compute pending ξ / PK_r / RK without mutating active RM state."""
        assert self.machine and self.keys and self.crypto.secrets and self.crypto.pp
        active = self.machine.require_active()
        nu = active.version + 1

        for rid, hx in self._base_ar_hex.items():
            assert self.crypto.pp.ar[rid].to_bytes().hex() == hx
        for rid, hx in self._base_s_hex.items():
            assert self.crypto.secrets.rm.s_i[rid].to_bytes().hex() == hx

        rm = self.crypto.secrets.rm
        # Sample new ξ offline
        ZpT = type(rm.xi)
        while True:
            xi_new = ZpT.random()
            if all(not (s + xi_new).is_zero() for s in rm.s_i.values()):
                break
        pending_pk: Dict[str, GElement] = {}
        pending_rs: Dict[str, Zp] = {}
        for rid, s in rm.s_i.items():
            sm = s + xi_new
            pending_pk[rid] = self.crypto.ctx.g_pow(sm)
            pending_rs[rid] = sm.inv()

        merged = self._membership_map()
        for uid, roles in membership.items():
            merged[uid] = list(roles)

        issued_RK: Dict[str, Dict[str, str]] = {}
        revoked_roles: Dict[str, List[str]] = {}
        for uid, roles in merged.items():
            cur = self.keys.current_role(uid)
            if cur is None:
                continue
            old_roles = set(cur.assigned_roles)
            new_roles = set(roles)
            lost = sorted(old_roles - new_roles)
            if lost:
                revoked_roles[uid] = lost
            mat = self.keys.clone_role_material(cur.material)
            mat.RK = {}
            issued: Dict[str, str] = {}
            hid = ZpT.hash_to_zp(uid.encode("utf-8"))
            for r in roles:
                base = mat.D1.mul(rm.W.pow(hid))
                rk = base.pow(pending_rs[r])
                mat.RK[r] = rk
                issued[r] = rk.to_bytes().hex()
            issued_RK[uid] = issued

        new_role = RoleState.build(nu, xi_new, pending_pk, merged)
        assert new_role.state_id() != active.role_state_id

        bundle = PendingBundle(
            next_version=nu,
            policy=None,
            attr=None,
            role=new_role,
            issued_RK=issued_RK,
            revoked_roles=revoked_roles,
            kind="role",
            xi_refreshed=True,
            pending_xi=xi_new,
            pending_rs=pending_rs,
            pending_pk_role=pending_pk,
        )
        assert_no_ratio_fields(bundle.public_commit_payload())
        self.machine.enter_pending(bundle)
        return bundle

    def update_policy(self, new_tree: AccessTree) -> AuthorizationSnapshot:
        """Standalone convenience: prepare → LocalAuthLedger → activate."""
        return self._standalone_commit_and_activate(self.prepare_policy_update(new_tree))

    def revoke_attribute(
        self,
        attr: str,
        revoked_users: Sequence[str],
    ) -> AuthorizationSnapshot:
        return self._standalone_commit_and_activate(
            self.prepare_attribute_revocation(attr, revoked_users)
        )

    def reassign_roles(self, membership: Dict[str, List[str]]) -> AuthorizationSnapshot:
        return self._standalone_commit_and_activate(
            self.prepare_role_reassignment(membership)
        )

    # ------------------------------------------------------------------
    # Export / secrecy
    # ------------------------------------------------------------------
    def _export_public(self, obj: dict) -> None:
        assert_no_ratio_fields(obj)
        self.experiment_raw.append(obj)

    def current_xi_hex(self) -> str:
        """Test helper: public RoleState xi encoding (not the update ratio)."""
        snap = self.active
        role = self._role_for_id(snap.role_state_id)
        return role.xi_hex

    def assert_base_hierarchy_preserved(self) -> None:
        assert self.crypto.pp and self.crypto.secrets
        for rid, hx in self._base_ar_hex.items():
            assert self.crypto.pp.ar[rid].to_bytes().hex() == hx
        for rid, hx in self._base_s_hex.items():
            assert self.crypto.secrets.rm.s_i[rid].to_bytes().hex() == hx
