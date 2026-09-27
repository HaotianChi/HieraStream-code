"""Authorization snapshot Θ^(ν) — Eq.(10).

Consistency concerns the COMPLETE identity tuple
  (version, policyId, attrStateId, roleStateId)
plus the owning sharing domain (ownerId).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class AuthorizationSnapshot:
    """Active authorization identity for one owner's sharing domain."""

    owner_id: str
    version: int
    policy_id: str
    attr_state_id: str
    role_state_id: str

    def identity_tuple(self) -> Tuple[int, str, str, str]:
        """Complete authorization identity (excluding owner)."""
        return (self.version, self.policy_id, self.attr_state_id, self.role_state_id)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ownerId": self.owner_id,
            "version": self.version,
            "policyId": self.policy_id,
            "attrStateId": self.attr_state_id,
            "roleStateId": self.role_state_id,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuthorizationSnapshot":
        return cls(
            owner_id=str(d["ownerId"]),
            version=int(d["version"]),
            policy_id=str(d["policyId"]),
            attr_state_id=str(d["attrStateId"]),
            role_state_id=str(d["roleStateId"]),
        )

    def matches(self, other: "AuthorizationSnapshot") -> bool:
        # Owner compared only when both sides carry a non-empty ownerId
        # (ledger AuthKey records may omit owner in the value blob).
        if self.owner_id and other.owner_id and self.owner_id != other.owner_id:
            return False
        return self.identity_tuple() == other.identity_tuple()


@dataclass
class AuthKeyRecord:
    """World-state value under AuthKey(ownerId) — ledger-facing view of Θ."""

    version: int
    policy_id: str
    attr_state_id: str
    role_state_id: str

    def snapshot(self, owner_id: str = "") -> AuthorizationSnapshot:
        return AuthorizationSnapshot(
            owner_id=owner_id,
            version=self.version,
            policy_id=self.policy_id,
            attr_state_id=self.attr_state_id,
            role_state_id=self.role_state_id,
        )

    @classmethod
    def from_snapshot(cls, snap: AuthorizationSnapshot) -> "AuthKeyRecord":
        return cls(
            version=snap.version,
            policy_id=snap.policy_id,
            attr_state_id=snap.attr_state_id,
            role_state_id=snap.role_state_id,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "policyId": self.policy_id,
            "attrStateId": self.attr_state_id,
            "roleStateId": self.role_state_id,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AuthKeyRecord":
        return cls(
            version=int(d["version"]),
            policy_id=str(d["policyId"]),
            attr_state_id=str(d["attrStateId"]),
            role_state_id=str(d["roleStateId"]),
        )


def auth_key(owner_id: str) -> str:
    return f"AuthKey/{owner_id}"


def segment_key(owner_id: str, seg_id: str) -> str:
    return f"Segment/{owner_id}/{seg_id}"


# Backward-compat alias used by older call sites that omit owner in constructors.
def make_snapshot(
    version: int,
    policy_id: str,
    attr_state_id: str,
    role_state_id: str,
    owner_id: str = "",
) -> AuthorizationSnapshot:
    return AuthorizationSnapshot(
        owner_id=owner_id,
        version=version,
        policy_id=policy_id,
        attr_state_id=attr_state_id,
        role_state_id=role_state_id,
    )
