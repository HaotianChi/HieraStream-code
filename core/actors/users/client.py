"""Data user client — holds U_sk,1 and rho; final ZA/ZR recovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from core.authorization.errors import (
    HistoricalAttributeKeyUnavailable,
    HistoricalRoleKeyUnavailable,
)
from core.crypto.python.field import Zp
from core.crypto.python.groups import GElement, GTElement
from core.crypto.python.segment import (
    AttrCT,
    RoleEnvelope,
    SegmentCrypto,
    UserAttrMaterial,
    UserRoleMaterial,
)
from core.crypto.python.kdf_aead import aead_decrypt, derive_segment_key


@dataclass
class DataUser:
    user_id: str
    attr_keys: UserAttrMaterial
    role_mat: UserRoleMaterial
    assigned_roles: List[str]
    # Historical material by (attr_state_id / role_state_id) — exact match only
    hist_attr: Dict[str, UserAttrMaterial] = field(default_factory=dict)
    hist_role: Dict[str, UserRoleMaterial] = field(default_factory=dict)
    hist_roles_assigned: Dict[str, List[str]] = field(default_factory=dict)

    def store_attr_version(self, attr_state_id: str, mat: UserAttrMaterial) -> None:
        self.hist_attr[attr_state_id] = mat
        self.attr_keys = mat

    def store_role_version(
        self, role_state_id: str, mat: UserRoleMaterial, roles: Sequence[str]
    ) -> None:
        self.hist_role[role_state_id] = mat
        self.hist_roles_assigned[role_state_id] = list(roles)
        self.role_mat = mat
        self.assigned_roles = list(roles)

    def attr_for(self, attr_state_id: str) -> UserAttrMaterial:
        if attr_state_id not in self.hist_attr:
            raise HistoricalAttributeKeyUnavailable(
                f"user={self.user_id} missing attrStateId={attr_state_id}"
            )
        return self.hist_attr[attr_state_id]

    def role_for(self, role_state_id: str) -> tuple[UserRoleMaterial, List[str]]:
        if role_state_id not in self.hist_role:
            raise HistoricalRoleKeyUnavailable(
                f"user={self.user_id} missing roleStateId={role_state_id}"
            )
        mat = self.hist_role[role_state_id]
        roles = self.hist_roles_assigned[role_state_id]
        return mat, list(roles)

    def recover_ZA(self, crypto: SegmentCrypto, ct: AttrCT, Bj: GTElement) -> GTElement:
        return crypto.user_recover_ZA(ct, Bj, self.attr_keys.usk1)

    def recover_ZR(
        self,
        crypto: SegmentCrypto,
        env: RoleEnvelope,
        P: GTElement,
        Q: GTElement,
        omega: Zp,
        rho: Zp,
    ) -> GTElement:
        return crypto.user_recover_ZR(env, P, Q, omega, rho)

    def decrypt_payload(
        self, ZA: GTElement, ZR: GTElement, ct_aes: bytes, aad: bytes = b""
    ) -> bytes:
        key = derive_segment_key(ZA, ZR)
        return aead_decrypt(key, ct_aes, aad=aad)

    def make_TR(self, crypto: SegmentCrypto, rk: GElement, omega: Zp) -> GElement:
        return crypto.make_TR(rk, omega)
