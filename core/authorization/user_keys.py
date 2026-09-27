"""Versioned user-side key store (prospective revocation).

Retains current and historical attribute / role material so legitimate
historical segments remain decryptable after forward revocation.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from core.crypto.python.groups import GElement
from core.crypto.python.segment import UserAttrMaterial, UserRoleMaterial


@dataclass
class AttrKeyVersion:
    """Attribute-side keys bound to a specific attrStateId / version."""

    owner_id: str
    user_id: str
    attr_version: int
    attr_state_id: str
    material: UserAttrMaterial


@dataclass
class RoleKeyVersion:
    owner_id: str
    user_id: str
    role_version: int
    role_state_id: str
    material: UserRoleMaterial
    assigned_roles: List[str]


@dataclass
class VersionedUserKeyStore:
    """Per-owner user key vault distinguishing attr vs role key versions."""

    owner_id: str
    # (user_id, attr_version) -> AttrKeyVersion
    attr_keys: Dict[Tuple[str, int], AttrKeyVersion] = field(default_factory=dict)
    # (user_id, role_version) -> RoleKeyVersion
    role_keys: Dict[Tuple[str, int], RoleKeyVersion] = field(default_factory=dict)
    # Latest pointers
    latest_attr_ver: Dict[str, int] = field(default_factory=dict)
    latest_role_ver: Dict[str, int] = field(default_factory=dict)

    def put_attr(self, entry: AttrKeyVersion) -> None:
        if entry.owner_id != self.owner_id:
            raise ValueError("owner mismatch")
        self.attr_keys[(entry.user_id, entry.attr_version)] = entry
        cur = self.latest_attr_ver.get(entry.user_id, -1)
        if entry.attr_version >= cur:
            self.latest_attr_ver[entry.user_id] = entry.attr_version

    def put_role(self, entry: RoleKeyVersion) -> None:
        if entry.owner_id != self.owner_id:
            raise ValueError("owner mismatch")
        self.role_keys[(entry.user_id, entry.role_version)] = entry
        cur = self.latest_role_ver.get(entry.user_id, -1)
        if entry.role_version >= cur:
            self.latest_role_ver[entry.user_id] = entry.role_version

    def get_attr(self, user_id: str, attr_version: int) -> Optional[AttrKeyVersion]:
        return self.attr_keys.get((user_id, attr_version))

    def get_role(self, user_id: str, role_version: int) -> Optional[RoleKeyVersion]:
        return self.role_keys.get((user_id, role_version))

    def current_attr(self, user_id: str) -> Optional[AttrKeyVersion]:
        v = self.latest_attr_ver.get(user_id)
        if v is None:
            return None
        return self.get_attr(user_id, v)

    def current_role(self, user_id: str) -> Optional[RoleKeyVersion]:
        v = self.latest_role_ver.get(user_id)
        if v is None:
            return None
        return self.get_role(user_id, v)

    def attr_versions_for(self, user_id: str) -> List[int]:
        return sorted(v for (u, v) in self.attr_keys if u == user_id)

    def role_versions_for(self, user_id: str) -> List[int]:
        return sorted(v for (u, v) in self.role_keys if u == user_id)

    def clone_attr_material(self, mat: UserAttrMaterial) -> UserAttrMaterial:
        return UserAttrMaterial(
            user_id=mat.user_id,
            attrs=list(mat.attrs),
            usk1=mat.usk1,
            E=mat.E,
            E1=mat.E1,
            E_ua=dict(mat.E_ua),
            _r_u=mat._r_u,
            _mu_u=mat._mu_u,
        )

    def clone_role_material(self, mat: UserRoleMaterial) -> UserRoleMaterial:
        return UserRoleMaterial(
            user_id=mat.user_id,
            rho=mat.rho,
            D0=mat.D0,
            D1=mat.D1,
            RK=dict(mat.RK),
        )


def apply_issued_Eua(
    base: UserAttrMaterial,
    issued: Dict[str, str],
    attrs: List[str],
) -> UserAttrMaterial:
    """Apply opaque refreshed E_ua hex map; never touches update ratios."""
    GCls = type(base.E)
    out = UserAttrMaterial(
        user_id=base.user_id,
        attrs=list(attrs),
        usk1=base.usk1,
        E=base.E,
        E1=base.E1,
        E_ua={},
        _r_u=base._r_u,
        _mu_u=base._mu_u,
    )
    for a in attrs:
        if a in issued:
            out.E_ua[a] = GCls.from_bytes(bytes.fromhex(issued[a]))
        elif a in base.E_ua:
            out.E_ua[a] = base.E_ua[a]
    return out


def apply_issued_RK(
    base: UserRoleMaterial,
    issued: Dict[str, str],
) -> UserRoleMaterial:
    GCls = type(base.D0)
    out = UserRoleMaterial(
        user_id=base.user_id,
        rho=base.rho,
        D0=base.D0,
        D1=base.D1,
        RK={},
    )
    for role, hx in issued.items():
        out.RK[role] = GCls.from_bytes(bytes.fromhex(hx))
    return out
