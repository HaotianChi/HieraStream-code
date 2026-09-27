"""End-to-end HieraStream system runtime (research prototype).

Maps paper actors onto one-process logical separation with explicit
secret boundaries. Uses simulated crypto by default; C++/PBC is
preferred for formal manuscript microbenchmarks.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from core.authorization.snapshot import AuthKeyRecord, AuthorizationSnapshot
from core.authorization.versioned_state import (
    AttrPublicState,
    PendingUpdate,
    PolicyState,
    RolePublicState,
    VersionedAuthorizationStore,
)
from core.blockchain.client.chaincode_api import (
    bootstrap_auth,
    commit_segment,
    update_authorization,
)
from core.blockchain.client.ledger import MVCCLedger, TxStatus
from core.canonical import canonical_json_dumps, eta_digest
from core.crypto.python_ref.simulated import (
    AccessTree,
    SimulatedCrypto,
    aead_decrypt,
    aead_encrypt,
    derive_segment_key,
)
from core.roles.hierarchy import DEFAULT_HEALTHCARE_HIERARCHY, RoleHierarchy
from core.storage.ipfs_client import IPFSClient


def and_gate(*children: AccessTree) -> AccessTree:
    return AccessTree(kind="internal", threshold=len(children), children=list(children))


def or_gate(*children: AccessTree) -> AccessTree:
    return AccessTree(kind="internal", threshold=1, children=list(children))


def thresh(k: int, *children: AccessTree) -> AccessTree:
    return AccessTree(kind="internal", threshold=k, children=list(children))


def leaf(attr: str) -> AccessTree:
    return AccessTree(kind="leaf", attr=attr)


def tree_to_dict(node: AccessTree) -> Dict[str, Any]:
    if node.kind == "leaf":
        return {"kind": "leaf", "attr": node.attr}
    return {
        "kind": "internal",
        "threshold": node.threshold,
        "children": [tree_to_dict(c) for c in node.children],
    }


def tree_from_dict(d: Dict[str, Any]) -> AccessTree:
    if d["kind"] == "leaf":
        return leaf(d["attr"])
    return AccessTree(
        kind="internal",
        threshold=int(d["threshold"]),
        children=[tree_from_dict(c) for c in d["children"]],
    )


@dataclass
class UserRecord:
    user_id: str
    attrs: List[str]
    roles: List[str]
    attr_keys: Any  # current (latest) attribute material
    role_mat: Any  # current role material
    # Outsourced components (NOT usk1 / rho)
    outsource_attr: Dict[str, Any] = field(default_factory=dict)
    outsource_role: Dict[str, Any] = field(default_factory=dict)
    # Prospective revocation: keep historical components by auth version ν
    # hist_Eua[ν][attr] / hist_RK[ν][role]
    hist_Eua: Dict[int, Dict[str, int]] = field(default_factory=dict)
    hist_RK: Dict[int, Dict[str, int]] = field(default_factory=dict)
    # Snapshot of full attr key object fields needed per version (E, E1 fixed)
    hist_attr_ver: Dict[int, Any] = field(default_factory=dict)


@dataclass
class ProtectedSegment:
    owner_id: str
    seg_id: str
    ZA: int
    ZR: int
    key: bytes
    ct_aes: bytes
    cid: str
    attr_ct: Any
    role_envelopes: List[Any]
    targets: List[str]
    snapshot: AuthorizationSnapshot
    metadata_obj: Dict[str, Any]
    mcid: str
    eta: str
    published_mcid: Optional[str] = None


class HieraStreamSystem:
    """Full journal protocol orchestration for demos / tests / experiments."""

    def __init__(
        self,
        hierarchy: RoleHierarchy = DEFAULT_HEALTHCARE_HIERARCHY,
        attr_universe: Optional[Sequence[str]] = None,
    ) -> None:
        self.hierarchy = hierarchy
        self.crypto = SimulatedCrypto()
        self.ipfs = IPFSClient(use_local=True)
        self.ledger = MVCCLedger()
        self.attr_universe = list(
            attr_universe
            or ["doctor", "cardiology", "nurse", "emergency", "researcher"]
        )
        self.users: Dict[str, UserRecord] = {}
        self.auth_store: Optional[VersionedAuthorizationStore] = None
        self.owner_id = "owner-1"
        self.active_tree: Optional[AccessTree] = None
        self.segments: Dict[str, ProtectedSegment] = {}
        # Historical ciphertext bytes (must remain unchanged on revocation)
        self.hist_ct_aes: Dict[str, bytes] = {}

    def setup(self, owner_id: str = "owner-1") -> AuthorizationSnapshot:
        self.owner_id = owner_id
        # CA / AA / RM secret separation retained even in one process.
        self.crypto.ca_setup()
        self.crypto.aa_setup(self.attr_universe)
        self.crypto.role_setup(self.hierarchy.auth_paths(), self.hierarchy.role_order)

        self.active_tree = and_gate(leaf("doctor"), leaf("cardiology"))
        policy = PolicyState(version=0, policy_expr=tree_to_dict(self.active_tree))
        attr = AttrPublicState(version=0, pk_attr=dict(self.crypto.pp.pk_attr))  # type: ignore
        role = RolePublicState(
            version=0,
            xi=self.crypto.pp.xi,  # type: ignore
            pk_role=dict(self.crypto.pp.pk_role),  # type: ignore
            membership={},
        )
        self.auth_store = VersionedAuthorizationStore(owner_id=owner_id)
        snap = self.auth_store.install_initial(policy, attr, role)
        bootstrap_auth(self.ledger, owner_id, AuthKeyRecord.from_snapshot(snap))
        self.ledger.set_acl("CommitSegment", {f"gateway:{owner_id}"})
        self.ledger.set_acl("UpdateAuthorization", {"authority:AA", "authority:RM", "authority:CA"})
        return snap

    def provision_user(self, user_id: str, attrs: Sequence[str], roles: Sequence[str]) -> UserRecord:
        assert self.auth_store and self.auth_store.active
        ak = self.crypto.aa_keygen(attrs)
        rm = self.crypto.ca_role_user(user_id)
        for r in roles:
            self.crypto.rm_issue_rk(r, rm)
        # Boundaries: usk1 and rho stay user-side only
        out_attr = {
            "E_exp_g": ak.E_exp_g,
            "E_exp_h": ak.E_exp_h,
            "E1_exp": ak.E1_exp,
            "E_ua": dict(ak.E_ua),
            "attrs": list(ak.attrs),
        }
        out_role = {"D0_exp": rm.D0_exp, "RK": dict(rm.RK)}
        ver = self.auth_store.active.version
        rec = UserRecord(
            user_id=user_id,
            attrs=list(attrs),
            roles=list(roles),
            attr_keys=ak,
            role_mat=rm,
            outsource_attr=out_attr,
            outsource_role=out_role,
            hist_Eua={ver: dict(ak.E_ua)},
            hist_RK={ver: dict(rm.RK)},
            hist_attr_ver={ver: ak},
        )
        self.users[user_id] = rec
        # Update membership in active role state (version unchanged until commit)
        rs = self.auth_store.roles[self.auth_store.active.version]
        rs.membership[user_id] = list(roles)
        return rec

    def _active_snapshot(self) -> AuthorizationSnapshot:
        assert self.auth_store and self.auth_store.active
        return self.auth_store.active

    def protect_and_publish(
        self,
        plaintext: bytes,
        targets: Sequence[str],
        seg_id: Optional[str] = None,
        max_retries: int = 3,
    ) -> ProtectedSegment:
        """Publication order §28 with stale-segment retry §29."""
        assert self.active_tree is not None
        seg_id = seg_id or str(uuid.uuid4())
        # Sample dual shares once — never regenerate on stale retry
        ZA = self.crypto.sample_ZA()
        ZR = self.crypto.sample_ZR()
        key = derive_segment_key(ZA, ZR)
        ct_aes = aead_encrypt(key, plaintext)
        cid = self.ipfs.add(ct_aes)
        self.hist_ct_aes[seg_id] = ct_aes

        last_err = ""
        for _ in range(max_retries):
            snap = self._active_snapshot()
            # Gateway fixed-size partial attr encrypt (no policy loop)
            partial = self.crypto.gateway_partial_attr(ZA)
            # Outsourced policy-dependent work
            attr_ct = self.crypto.outsource_policy_encrypt(partial, self.active_tree)
            # Independent role envelopes, same ZR, independent d
            envelopes = []
            for ri in targets:
                H_ri = self.hierarchy.H(ri)
                envelopes.append(self.crypto.role_encrypt(ZR, ri, H_ri))

            metadata_obj = {
                "CTA": {
                    "C_tilde": attr_ct.C_tilde,
                    "C_prime_exp": attr_ct.C_prime_exp,
                    "C_tilde_prime_exp": attr_ct.C_tilde_prime_exp,
                    "C_tilde_dprime_exp": attr_ct.C_tilde_dprime_exp,
                    "C_a_exp": attr_ct.C_a_exp,
                    "tree": tree_to_dict(attr_ct.tree),
                },
                "CTR": [
                    {
                        "target": e.target_role,
                        "C1": e.C1,
                        "C2_exp": e.C2_exp,
                        "C3_exp": e.C3_exp,
                        "Ci_exp": e.Ci_exp,
                    }
                    for e in envelopes
                ],
                "version": snap.version,
                "policyId": snap.policy_id,
                "attrStateId": snap.attr_state_id,
                "roleStateId": snap.role_state_id,
                "Rtar": list(targets),
            }
            meta_bytes = canonical_json_dumps(metadata_obj)
            mcid = self.ipfs.only_hash(meta_bytes)
            eta = eta_digest(
                cid,
                mcid,
                snap.version,
                snap.policy_id,
                snap.attr_state_id,
                snap.role_state_id,
            )
            result = commit_segment(
                self.ledger,
                tx_id=str(uuid.uuid4()),
                caller=f"gateway:{self.owner_id}",
                owner_id=self.owner_id,
                seg_id=seg_id,
                cid=cid,
                mcid=mcid,
                version=snap.version,
                policy_id=snap.policy_id,
                attr_state_id=snap.attr_state_id,
                role_state_id=snap.role_state_id,
                eta=eta,
            )
            if result.status == TxStatus.VALID:
                # ONLY after valid commit: publish Mj
                published = self.ipfs.add(meta_bytes)
                if published != mcid:
                    raise RuntimeError("MCID invariant failed: predicted != actual")
                seg = ProtectedSegment(
                    owner_id=self.owner_id,
                    seg_id=seg_id,
                    ZA=ZA,
                    ZR=ZR,
                    key=key,
                    ct_aes=ct_aes,
                    cid=cid,
                    attr_ct=attr_ct,
                    role_envelopes=envelopes,
                    targets=list(targets),
                    snapshot=snap,
                    metadata_obj=metadata_obj,
                    mcid=mcid,
                    eta=eta,
                    published_mcid=published,
                )
                self.segments[seg_id] = seg
                return seg
            last_err = f"{result.status}:{result.reason}"
            # Stale retry: keep ZA, ZR, ct_aes, cid; regenerate envelopes only
            continue
        raise RuntimeError(f"CommitSegment failed after retries: {last_err}")

    def access(self, user_id: str, seg_id: str) -> bytes:
        """Dual-layer recovery with tamper checks before plaintext accept."""
        user = self.users[user_id]
        seg = self.segments[seg_id]
        # Verify CID / MCID / eta
        if not self.ipfs.verify_cid(seg.cid, seg.ct_aes):
            raise ValueError("payload CID mismatch")
        meta_bytes = canonical_json_dumps(seg.metadata_obj)
        if self.ipfs.only_hash(meta_bytes) != seg.mcid:
            raise ValueError("metadata CID mismatch")
        eta2 = eta_digest(
            seg.cid,
            seg.mcid,
            seg.snapshot.version,
            seg.snapshot.policy_id,
            seg.snapshot.attr_state_id,
            seg.snapshot.role_state_id,
        )
        if eta2 != seg.eta:
            raise ValueError("eta mismatch")

        # Attribute outsourced transform — keys MUST match segment authorization ν
        nu = seg.snapshot.version
        attr_keys = user.hist_attr_ver.get(nu, user.attr_keys)
        Bj = self.crypto.outsource_attr_transform(seg.attr_ct, attr_keys)
        if Bj is None:
            raise PermissionError("attribute policy not satisfied")
        # User-side only: usk1 (stable across attribute refreshes)
        ZA = self.crypto.user_recover_ZA(seg.attr_ct, Bj, user.attr_keys.usk1_exp)

        # Role: historical RK issued under the segment's role-state version
        rk_map = user.hist_RK.get(nu, user.role_mat.RK)
        hist_roles = list(rk_map.keys())
        chosen = None
        assigned = None
        for ri in seg.targets:
            for rx in hist_roles:
                if self.hierarchy.dominates(rx, ri):
                    chosen = next(e for e in seg.role_envelopes if e.target_role == ri)
                    assigned = rx
                    break
            if chosen:
                break
        if chosen is None or assigned is None:
            raise PermissionError("no authorized role for target set")
        if assigned not in rk_map:
            raise PermissionError("missing RK for assigned role at segment version")

        omega = secrets.randbelow(2**64) or 1
        from core.crypto.python_ref.simulated import _P

        omega = (omega % (_P - 1)) + 1
        TR = self.crypto.make_TR(rk_map[assigned], omega)
        Gamma = self.hierarchy.Gamma(assigned, chosen.target_role)
        P, Q = self.crypto.outsource_role_transform(
            chosen, TR, user.role_mat.D0_exp, Gamma
        )
        ZR = self.crypto.user_recover_ZR(chosen, P, Q, omega, user.role_mat.rho)
        key = derive_segment_key(ZA, ZR)
        return aead_decrypt(key, seg.ct_aes)

    def revoke_attribute(self, attr: str, revoked_users: Sequence[str]) -> AuthorizationSnapshot:
        """Prospective attribute revocation — Eqs.(37)-(39)."""
        assert self.auth_store and self.auth_store.active
        expected = self.auth_store.active
        self.crypto.revoke_attribute(attr)
        refreshed: Dict[str, Dict[str, int]] = {}
        next_ver = expected.version + 1
        from copy import deepcopy

        for uid, user in self.users.items():
            if uid in revoked_users:
                # Revoked: keep obsolete components for historical ν only;
                # do not issue refreshed component for next_ver.
                if attr in user.attrs:
                    user.attrs = [a for a in user.attrs if a != attr]
                carried = {a: e for a, e in user.attr_keys.E_ua.items() if a != attr}
                user.hist_Eua[next_ver] = carried
                ak_new = deepcopy(user.attr_keys)
                ak_new.E_ua = dict(carried)
                ak_new.attrs = [a for a in ak_new.attrs if a != attr]
                user.attr_keys = ak_new
                user.hist_attr_ver[next_ver] = ak_new
                user.outsource_attr["E_ua"] = dict(carried)
                user.hist_RK[next_ver] = dict(user.role_mat.RK)
                continue
            if attr in user.attr_keys.E_ua:
                # Refresh WITHOUT exposing update ratio; preserve old hist_*
                new_e = self.crypto.refresh_Eua(user.attr_keys.E_ua[attr], attr)
                ak_new = deepcopy(user.attr_keys)
                ak_new.E_ua = dict(user.attr_keys.E_ua)
                ak_new.E_ua[attr] = new_e
                user.attr_keys = ak_new
                user.outsource_attr["E_ua"] = dict(ak_new.E_ua)
                user.hist_Eua[next_ver] = dict(ak_new.E_ua)
                user.hist_attr_ver[next_ver] = ak_new
                user.hist_RK[next_ver] = dict(user.role_mat.RK)
                refreshed.setdefault(uid, {})[attr] = new_e
            else:
                user.hist_Eua[next_ver] = dict(user.attr_keys.E_ua)
                user.hist_attr_ver[next_ver] = user.attr_keys
                user.hist_RK[next_ver] = dict(user.role_mat.RK)

        new_attr = AttrPublicState(
            version=next_ver,
            pk_attr=dict(self.crypto.pp.pk_attr),  # type: ignore
        )
        pending = PendingUpdate(
            next_version=next_ver,
            attr=new_attr,
            refreshed_Eua=refreshed,
        )
        self.auth_store.prepare(pending)
        new_snap_preview = AuthorizationSnapshot(
            owner_id=self.owner_id,
            version=next_ver,
            policy_id=expected.policy_id,
            attr_state_id=new_attr.state_id(),
            role_state_id=expected.role_state_id,
        )
        res = update_authorization(
            self.ledger,
            tx_id=str(uuid.uuid4()),
            caller="authority:AA",
            owner_id=self.owner_id,
            expected=expected,
            new_record=AuthKeyRecord.from_snapshot(new_snap_preview),
        )
        if res.status != TxStatus.VALID:
            self.auth_store.abort_pending()
            raise RuntimeError(f"UpdateAuthorization failed: {res.status} {res.reason}")
        return self.auth_store.activate_after_commit()

    def reassign_roles(self, membership: Dict[str, List[str]]) -> AuthorizationSnapshot:
        """Role reassignment — Eq.(40); cost scales with active bindings."""
        assert self.auth_store and self.auth_store.active
        expected = self.auth_store.active
        self.crypto.refresh_xi()
        refreshed_rk: Dict[str, Dict[str, int]] = {}
        next_ver = expected.version + 1
        for uid, roles in membership.items():
            user = self.users[uid]
            user.roles = list(roles)
            # Keep historical RK under previous versions for prospective access
            new_rk: Dict[str, int] = {}
            user.outsource_role["RK"] = {}
            for r in roles:
                rk = self.crypto.rm_issue_rk(r, user.role_mat)
                new_rk[r] = rk
                refreshed_rk.setdefault(uid, {})[r] = rk
                user.outsource_role["RK"][r] = rk
            user.role_mat.RK = new_rk
            user.hist_RK[next_ver] = dict(new_rk)
            user.hist_Eua[next_ver] = dict(user.attr_keys.E_ua)
            user.hist_attr_ver[next_ver] = user.attr_keys

        new_role = RolePublicState(
            version=next_ver,
            xi=self.crypto.pp.xi,  # type: ignore
            pk_role=dict(self.crypto.pp.pk_role),  # type: ignore
            membership={u: list(rs) for u, rs in membership.items()},
        )
        pending = PendingUpdate(
            next_version=next_ver,
            role=new_role,
            refreshed_RK=refreshed_rk,
        )
        self.auth_store.prepare(pending)
        new_snap_preview = AuthorizationSnapshot(
            owner_id=self.owner_id,
            version=next_ver,
            policy_id=expected.policy_id,
            attr_state_id=expected.attr_state_id,
            role_state_id=new_role.state_id(),
        )
        res = update_authorization(
            self.ledger,
            tx_id=str(uuid.uuid4()),
            caller="authority:RM",
            owner_id=self.owner_id,
            expected=expected,
            new_record=AuthKeyRecord.from_snapshot(new_snap_preview),
        )
        if res.status != TxStatus.VALID:
            self.auth_store.abort_pending()
            raise RuntimeError(f"UpdateAuthorization failed: {res.status} {res.reason}")
        return self.auth_store.activate_after_commit()
