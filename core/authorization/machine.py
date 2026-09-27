"""Prepare -> Commit -> Activate state machine (Section III-C / III-E).

    ACTIVE(ν)
       --prepare-->  PENDING(ν+1)
       --commit-->   COMMITTED(ν+1)   [ledger AuthKey updated]
       --activate--> ACTIVE(ν+1)

A failed commit must not activate pending state; ACTIVE(ν) remains.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from core.authorization.snapshot import AuthorizationSnapshot
from core.authorization.states import (
    AttributePublicState,
    PolicyState,
    RoleState,
)


class AuthPhase(str, Enum):
    ACTIVE = "ACTIVE"
    PENDING = "PENDING"
    COMMITTED = "COMMITTED"


@dataclass
class PendingBundle:
    """Prepared ν+1 cryptographic / policy objects awaiting commit.

    does not contain update ratios. Personalized refreshed key material is
    held only as opaque issued components for delivery to users.

    Pending AA/RM secrets live HERE until activate — active SegmentCrypto
    public parameters remain at ν throughout PENDING.
    """

    next_version: int
    policy: Optional[PolicyState] = None  # None => carry forward
    attr: Optional[AttributePublicState] = None
    role: Optional[RoleState] = None
    # Opaque personalized issuances (hex G elements), never ratios
    issued_Eua: Dict[str, Dict[str, str]] = field(default_factory=dict)  # user->attr->G hex
    issued_RK: Dict[str, Dict[str, str]] = field(default_factory=dict)  # user->role->G hex
    # Users who lose attribute / role under this update
    revoked_attrs: Dict[str, List[str]] = field(default_factory=dict)  # user -> attrs removed
    revoked_roles: Dict[str, List[str]] = field(default_factory=dict)  # user -> roles removed
    # Kind flags for tests / orchestration
    kind: str = "mixed"  # policy | attribute | role | mixed
    # Whether xi was refreshed (role membership change)
    xi_refreshed: bool = False
    # Pending AA secrets (applied only on activate)
    pending_t_a: Dict[str, Any] = field(default_factory=dict)  # attr -> Zp t_new
    pending_t_a_old: Dict[str, Any] = field(default_factory=dict)  # attr -> Zp t_old
    # Pending RM secrets (applied only on activate)
    pending_xi: Any = None  # Optional[Zp]
    pending_rs: Dict[str, Any] = field(default_factory=dict)  # role -> Zp
    pending_pk_role: Dict[str, Any] = field(default_factory=dict)  # role -> GElement

    def public_commit_payload(self) -> Dict[str, Any]:
        """Serializable message for UpdateAuthorization — no secrets/ratios."""
        out: Dict[str, Any] = {
            "nextVersion": self.next_version,
            "kind": self.kind,
            "xiRefreshed": self.xi_refreshed,
        }
        if self.policy is not None:
            out["policyId"] = self.policy.state_id()
            out["policy"] = self.policy.canonical()
        if self.attr is not None:
            out["attrStateId"] = self.attr.state_id()
            out["attr"] = self.attr.canonical()
        if self.role is not None:
            out["roleStateId"] = self.role.state_id()
            out["role"] = self.role.canonical()
        # Issued components and pending secrets are never ledger payload.
        return out


@dataclass
class AuthMachine:
    owner_id: str
    phase: AuthPhase = AuthPhase.ACTIVE
    active: Optional[AuthorizationSnapshot] = None
    pending: Optional[PendingBundle] = None
    committed_snap: Optional[AuthorizationSnapshot] = None

    def require_active(self) -> AuthorizationSnapshot:
        if self.phase != AuthPhase.ACTIVE or self.active is None:
            raise RuntimeError(f"expected ACTIVE, got {self.phase}")
        return self.active

    def enter_pending(self, bundle: PendingBundle) -> None:
        active = self.require_active()
        if bundle.next_version != active.version + 1:
            raise ValueError("pending version must be active+1")
        self.pending = bundle
        self.committed_snap = None
        self.phase = AuthPhase.PENDING

    def mark_committed(self, snap: AuthorizationSnapshot) -> None:
        if self.phase != AuthPhase.PENDING or self.pending is None:
            raise RuntimeError("commit requires PENDING")
        if snap.version != self.pending.next_version:
            raise ValueError("committed snapshot version mismatch")
        if snap.owner_id != self.owner_id:
            raise ValueError("owner mismatch")
        self.committed_snap = snap
        self.phase = AuthPhase.COMMITTED

    def activate(self) -> AuthorizationSnapshot:
        if self.phase != AuthPhase.COMMITTED or self.committed_snap is None:
            raise RuntimeError("activate requires COMMITTED (failed commit must not activate)")
        self.active = self.committed_snap
        self.pending = None
        self.committed_snap = None
        self.phase = AuthPhase.ACTIVE
        return self.active

    def abort_pending(self) -> None:
        """Discard pending / committed-but-not-activated; keep ACTIVE."""
        self.pending = None
        self.committed_snap = None
        self.phase = AuthPhase.ACTIVE
