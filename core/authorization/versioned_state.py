"""Versioned / historical authorization state (prospective revocation).

Do not overwrite historical objects needed for legitimate access to
previously committed segments. Current-state lookup remains O(1).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from core.canonical import content_id
from core.authorization.snapshot import AuthorizationSnapshot


@dataclass
class PolicyState:
    version: int
    policy_expr: Dict[str, Any]  # serialized access-tree / policy object

    def state_id(self) -> str:
        return content_id({"kind": "policy", "version": self.version, "policy": self.policy_expr})


@dataclass
class AttrPublicState:
    version: int
    pk_attr: Dict[str, int]  # attribute -> public scalar encoding (sim) / digest ref

    def state_id(self) -> str:
        # Deterministic: sort attribute keys
        ordered = {k: self.pk_attr[k] for k in sorted(self.pk_attr)}
        return content_id({"kind": "attr", "version": self.version, "pk": ordered})


@dataclass
class RolePublicState:
    version: int
    xi: int
    pk_role: Dict[str, int]
    membership: Dict[str, List[str]]  # user_id -> roles

    def state_id(self) -> str:
        ordered_pk = {k: self.pk_role[k] for k in sorted(self.pk_role)}
        ordered_m = {u: sorted(rs) for u, rs in sorted(self.membership.items())}
        return content_id(
            {
                "kind": "role",
                "version": self.version,
                "xi": self.xi,
                "pk": ordered_pk,
                "membership": ordered_m,
            }
        )


@dataclass
class PendingUpdate:
    next_version: int
    policy: Optional[PolicyState] = None
    attr: Optional[AttrPublicState] = None
    role: Optional[RolePublicState] = None
    # Internal AA refresh payloads (never logged / exported)
    refreshed_Eua: Dict[str, Dict[str, int]] = field(default_factory=dict)  # user -> attr -> E
    refreshed_RK: Dict[str, Dict[str, int]] = field(default_factory=dict)  # user -> role -> RK


@dataclass
class VersionedAuthorizationStore:
    """Per-owner historical authorization objects + active/pending pointers."""

    owner_id: str
    policies: Dict[int, PolicyState] = field(default_factory=dict)
    attrs: Dict[int, AttrPublicState] = field(default_factory=dict)
    roles: Dict[int, RolePublicState] = field(default_factory=dict)
    active: Optional[AuthorizationSnapshot] = None
    pending: Optional[PendingUpdate] = None

    # Historical user key components by (version, user)
    hist_Eua: Dict[int, Dict[str, Dict[str, int]]] = field(default_factory=dict)
    hist_RK: Dict[int, Dict[str, Dict[str, int]]] = field(default_factory=dict)

    def install_initial(
        self,
        policy: PolicyState,
        attr: AttrPublicState,
        role: RolePublicState,
    ) -> AuthorizationSnapshot:
        assert policy.version == attr.version == role.version == 0
        self.policies[0] = policy
        self.attrs[0] = attr
        self.roles[0] = role
        snap = AuthorizationSnapshot(
            owner_id=self.owner_id,
            version=0,
            policy_id=policy.state_id(),
            attr_state_id=attr.state_id(),
            role_state_id=role.state_id(),
        )
        self.active = snap
        return snap

    def prepare(self, update: PendingUpdate) -> None:
        if self.active is None:
            raise RuntimeError("no active authorization")
        if update.next_version != self.active.version + 1:
            raise ValueError("pending version must be active+1")
        self.pending = update

    def activate_after_commit(self) -> AuthorizationSnapshot:
        """Activate pending state only after UpdateAuthorization is valid."""
        if self.pending is None or self.active is None:
            raise RuntimeError("no pending state")
        nu = self.pending.next_version
        policy = self.pending.policy or self.policies[self.active.version]
        # Carry forward unchanged objects but re-tag version if needed
        if self.pending.policy is None:
            # Carry forward same policy contents under new version id reference:
            # paper: replace only state references that changed.
            policy_id = self.active.policy_id
            # Keep historical policy object under old version; also index under nu
            self.policies[nu] = PolicyState(version=nu, policy_expr=policy.policy_expr)
        else:
            self.policies[nu] = self.pending.policy
            policy_id = self.pending.policy.state_id()

        if self.pending.attr is None:
            attr = self.attrs[self.active.version]
            self.attrs[nu] = AttrPublicState(version=nu, pk_attr=dict(attr.pk_attr))
            attr_id = self.active.attr_state_id
        else:
            self.attrs[nu] = self.pending.attr
            attr_id = self.pending.attr.state_id()

        if self.pending.role is None:
            role = self.roles[self.active.version]
            self.roles[nu] = RolePublicState(
                version=nu,
                xi=role.xi,
                pk_role=dict(role.pk_role),
                membership={u: list(rs) for u, rs in role.membership.items()},
            )
            role_id = self.active.role_state_id
        else:
            self.roles[nu] = self.pending.role
            role_id = self.pending.role.state_id()

        # Store refreshed key material historically (prospective: new keys for new ν)
        if self.pending.refreshed_Eua:
            self.hist_Eua[nu] = self.pending.refreshed_Eua
        if self.pending.refreshed_RK:
            self.hist_RK[nu] = self.pending.refreshed_RK

        snap = AuthorizationSnapshot(
            owner_id=self.owner_id,
            version=nu,
            policy_id=policy_id if self.pending.policy is None else self.policies[nu].state_id(),
            attr_state_id=attr_id if self.pending.attr is None else self.attrs[nu].state_id(),
            role_state_id=role_id if self.pending.role is None else self.roles[nu].state_id(),
        )
        # When carried forward, paper says replace only changed refs and carry
        # unchanged references — use exact previous ids for unchanged.
        if self.pending.policy is None:
            snap = AuthorizationSnapshot(
                owner_id=self.owner_id,
                version=nu,
                policy_id=self.active.policy_id,
                attr_state_id=snap.attr_state_id,
                role_state_id=snap.role_state_id,
            )
        if self.pending.attr is None:
            snap = AuthorizationSnapshot(
                owner_id=self.owner_id,
                version=snap.version,
                policy_id=snap.policy_id,
                attr_state_id=self.active.attr_state_id,
                role_state_id=snap.role_state_id,
            )
        if self.pending.role is None:
            snap = AuthorizationSnapshot(
                owner_id=self.owner_id,
                version=snap.version,
                policy_id=snap.policy_id,
                attr_state_id=snap.attr_state_id,
                role_state_id=self.active.role_state_id,
            )

        self.active = snap
        self.pending = None
        return snap

    def abort_pending(self) -> None:
        self.pending = None
