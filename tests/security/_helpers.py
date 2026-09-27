"""Shared helpers for adversarial security tests."""

from __future__ import annotations

from copy import deepcopy
from typing import List, Sequence, Tuple

from core.crypto.python import HEALTHCARE_FIXTURE, SegmentCrypto
from core.crypto.python.access_tree import AND, leaf
from core.crypto.python.field import Zp
from core.crypto.python.groups import GElement, GTElement
from core.crypto.python.segment import (
    ProtectedSegmentCrypto,
    RoleEnvelope,
    UserAttrMaterial,
    UserRoleMaterial,
)


def setup_crypto(universe=None) -> SegmentCrypto:
    c = SegmentCrypto()
    c.ca_setup()
    c.aa_setup(universe or ["doctor", "cardiology", "nurse", "emergency", "researcher"])
    c.role_setup(HEALTHCARE_FIXTURE)
    return c


def provision(
    c: SegmentCrypto, uid: str, attrs: Sequence[str], roles: Sequence[str]
) -> Tuple[UserAttrMaterial, UserRoleMaterial, List[str]]:
    ak = c.aa_keygen(uid, attrs)
    rk = c.ca_role_user(uid)
    for r in roles:
        c.rm_issue_rk(r, rk)
    return ak, rk, list(roles)


def default_tree():
    return AND(leaf("doctor"), leaf("cardiology"))


def must_fail_recover(
    c: SegmentCrypto,
    seg: ProtectedSegmentCrypto,
    ak: UserAttrMaterial,
    rk: UserRoleMaterial,
    roles: Sequence[str],
    *,
    plaintext: bytes | None = None,
) -> None:
    """Recovery must raise or not equal the honest plaintext."""
    try:
        out = c.recover_segment(seg, ak, rk, roles)
    except (PermissionError, ValueError, Exception):
        return
    if plaintext is not None:
        assert out != plaintext, "adversary recovered correct plaintext"


def mutate_g(el: GElement) -> GElement:
    delta = Zp.random()
    while delta.is_zero():
        delta = Zp.random()
    return GElement(el.exp + delta)


def mutate_gt(el: GTElement) -> GTElement:
    delta = Zp.random()
    while delta.is_zero():
        delta = Zp.random()
    return GTElement(el.exp + delta)


def clone_seg(seg: ProtectedSegmentCrypto) -> ProtectedSegmentCrypto:
    return deepcopy(seg)


def clone_attr(ak: UserAttrMaterial) -> UserAttrMaterial:
    return deepcopy(ak)


def clone_role(rk: UserRoleMaterial) -> UserRoleMaterial:
    return deepcopy(rk)


def with_mutated_envelope(env: RoleEnvelope) -> RoleEnvelope:
    e = deepcopy(env)
    if e.C3:
        k = next(iter(e.C3))
        e.C3[k] = mutate_g(e.C3[k])
    else:
        e.Ci = mutate_g(e.Ci)
    e.C1 = mutate_gt(e.C1)
    return e
