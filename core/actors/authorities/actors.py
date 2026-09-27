"""Logical authority actors with explicit secret boundaries."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence

from core.authorization.lifecycle import AuthorizationLifecycle
from core.crypto.python.hierarchy import RoleHierarchy
from core.crypto.python.segment import SegmentCrypto, UserAttrMaterial, UserRoleMaterial


@dataclass
class CentralAuthority:
    """Holds alpha, delta; provisions A=g^alpha to AA, W=g^delta to RM."""

    crypto: SegmentCrypto

    def setup(self) -> None:
        self.crypto.ca_setup()


@dataclass
class AttributeAuthority:
    """Holds beta, t_a; never discloses update ratios."""

    crypto: SegmentCrypto
    lifecycle: AuthorizationLifecycle

    def setup(self, universe: Sequence[str]) -> None:
        self.crypto.aa_setup(universe)

    def keygen(self, user_id: str, attrs: Sequence[str]) -> UserAttrMaterial:
        return self.crypto.aa_keygen(user_id, attrs)


@dataclass
class RoleManager:
    """Holds RS_r, xi; issues RK; preserves base hierarchy s_i / AR_i."""

    crypto: SegmentCrypto
    hierarchy: RoleHierarchy

    def setup(self, hierarchy: RoleHierarchy) -> None:
        self.crypto.role_setup(hierarchy)
        self.hierarchy = hierarchy

    def issue_bindings(self, mat: UserRoleMaterial, roles: Sequence[str]) -> None:
        for r in roles:
            self.crypto.rm_issue_rk(r, mat)
