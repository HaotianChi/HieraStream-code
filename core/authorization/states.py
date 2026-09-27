"""Immutable / versioned authorization state objects (Section III-E).

State references (policyId, attrStateId, roleStateId) are deterministic
content digests of canonical serializations. Distinct contents never share
an identifier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

from core.canonical import content_id
from core.crypto.python.access_tree import AccessTree
from core.crypto.python.groups import GElement
from core.crypto.python.field import Zp


def _g_hex(g: GElement) -> str:
    return g.to_bytes().hex()


def _g_from_hex(h: str) -> GElement:
    return GElement.from_bytes(bytes.fromhex(h))


@dataclass(frozen=True)
class PolicyState:
    """Immutable policy object for one authorization version."""

    version: int
    policy_expr: Dict[str, Any]

    def canonical(self) -> Dict[str, Any]:
        return {
            "kind": "PolicyState",
            "version": self.version,
            "policy": self.policy_expr,
        }

    def state_id(self) -> str:
        return content_id(self.canonical())

    def tree(self) -> AccessTree:
        return AccessTree.from_dict(self.policy_expr)

    @classmethod
    def from_tree(cls, version: int, tree: AccessTree) -> "PolicyState":
        return cls(version=version, policy_expr=tree.to_dict())


@dataclass(frozen=True)
class AttributePublicState:
    """Public attribute state: PK_a = g^{t_a} for each attribute."""

    version: int
    pk_attr: Dict[str, str]  # attr -> canonical G hex

    def canonical(self) -> Dict[str, Any]:
        ordered = {k: self.pk_attr[k] for k in sorted(self.pk_attr)}
        return {"kind": "AttributePublicState", "version": self.version, "pk": ordered}

    def state_id(self) -> str:
        return content_id(self.canonical())

    def pk_elements(self) -> Dict[str, GElement]:
        return {a: _g_from_hex(h) for a, h in self.pk_attr.items()}

    @classmethod
    def from_pk(cls, version: int, pk: Mapping[str, GElement]) -> "AttributePublicState":
        return cls(version=version, pk_attr={a: _g_hex(g) for a, g in pk.items()})


@dataclass(frozen=True)
class RoleMembershipState:
    """Internal membership map: user_id -> assigned roles (sharing domain)."""

    membership: Dict[str, tuple]  # user -> sorted roles tuple

    def canonical(self) -> Dict[str, Any]:
        ordered = {u: list(rs) for u, rs in sorted(self.membership.items())}
        return {"kind": "RoleMembershipState", "membership": ordered}

    def state_id(self) -> str:
        return content_id(self.canonical())

    def as_lists(self) -> Dict[str, List[str]]:
        return {u: list(rs) for u, rs in self.membership.items()}

    @classmethod
    def from_mapping(cls, membership: Mapping[str, List[str]]) -> "RoleMembershipState":
        frozen = {u: tuple(sorted(rs)) for u, rs in membership.items()}
        return cls(membership=frozen)


@dataclass(frozen=True)
class RoleState:
    """Public role state per paper III-A/E: published PK_ri and membership.

    Manuscript publishes PK_ri = g^{s_i+ξ} (and membership/state refs); RS remains
    RM-private. The scalar ξ is retained on this object for RM/test helpers only and
    is NOT part of the public canonical digest (state_id) — choosing the manuscript
    published set over exposing ξ in cleartext.
    """

    version: int
    xi_hex: str  # RM/internal; excluded from canonical()/state_id
    pk_role: Dict[str, str]  # role -> G hex  (published)
    membership: RoleMembershipState

    def canonical(self) -> Dict[str, Any]:
        ordered_pk = {k: self.pk_role[k] for k in sorted(self.pk_role)}
        return {
            "kind": "RoleState",
            "version": self.version,
            "pk": ordered_pk,
            "membership": self.membership.canonical(),
        }

    def state_id(self) -> str:
        return content_id(self.canonical())

    def xi(self) -> Zp:
        return Zp.from_bytes(bytes.fromhex(self.xi_hex))

    def pk_elements(self) -> Dict[str, GElement]:
        return {r: _g_from_hex(h) for r, h in self.pk_role.items()}

    @classmethod
    def build(
        cls,
        version: int,
        xi: Zp,
        pk_role: Mapping[str, GElement],
        membership: Mapping[str, List[str]],
    ) -> "RoleState":
        return cls(
            version=version,
            xi_hex=xi.to_bytes().hex(),
            pk_role={r: _g_hex(g) for r, g in pk_role.items()},
            membership=RoleMembershipState.from_mapping(membership),
        )


@dataclass
class HistoricalAttrSecrets:
    """AA-private historical t_a values — never published, never logged."""

    # version -> attr -> Zp
    t_a_by_version: Dict[int, Dict[str, Zp]] = field(default_factory=dict)

    def record(self, version: int, t_a: Mapping[str, Zp]) -> None:
        self.t_a_by_version[version] = {a: t for a, t in t_a.items()}

    def get(self, version: int, attr: str) -> Optional[Zp]:
        row = self.t_a_by_version.get(version)
        if row is None:
            return None
        return row.get(attr)


@dataclass
class HistoricalRoleSecrets:
    """RM-private historical xi / RS — never published."""

    xi_by_version: Dict[int, Zp] = field(default_factory=dict)
    rs_by_version: Dict[int, Dict[str, Zp]] = field(default_factory=dict)

    def record(self, version: int, xi: Zp, rs: Mapping[str, Zp]) -> None:
        self.xi_by_version[version] = xi
        self.rs_by_version[version] = {r: v for r, v in rs.items()}
