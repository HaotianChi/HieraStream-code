"""Outsourcing service — receives E, E1, E_ua, D0, TR; never U_sk,1 or rho or Z^A."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple, Union

from core.crypto.python.groups import GElement, GTElement
from core.crypto.python.hierarchy import RoleHierarchy
from core.crypto.python.segment import (
    AttrCT,
    OutsourceAttrKeys,
    OutsourcePartialAttrCT,
    PartialAttrCT,
    RoleEnvelope,
    SegmentCrypto,
    UserAttrMaterial,
)


@dataclass
class OutsourceService:
    crypto: SegmentCrypto
    hierarchy: RoleHierarchy

    def attr_transform(
        self, ct: AttrCT, keys: Union[OutsourceAttrKeys, UserAttrMaterial]
    ) -> Optional[GTElement]:
        """Eq.(27). Protocol: outsource receives only E, E1, E_ua (not U_sk,1)."""
        view = keys.to_outsource_keys() if isinstance(keys, UserAttrMaterial) else keys
        return self.crypto.outsource_attr_transform(ct, view)

    def role_transform(
        self,
        env: RoleEnvelope,
        TR: GElement,
        D0: GElement,
        assigned: str,
        target: str,
    ) -> Tuple[GTElement, GTElement]:
        Gamma = self.hierarchy.Gamma(assigned, target)
        return self.crypto.outsource_role_transform(env, TR, D0, Gamma)

    def policy_encrypt(self, partial: Union[PartialAttrCT, OutsourcePartialAttrCT], tree):
        view = partial.to_outsource_view() if isinstance(partial, PartialAttrCT) else partial
        return self.crypto.outsource_policy_encrypt(view, tree)
