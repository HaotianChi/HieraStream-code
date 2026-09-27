"""Comprehensive Section III cryptographic tests (requirements 1–16)."""

from __future__ import annotations

import os

import pytest

from core.crypto.python import (
    HEALTHCARE_FIXTURE,
    AccessTree,
    SegmentCrypto,
    leaf,
)
from core.crypto.python.access_tree import AND, OR, gate
from core.crypto.python.field import Zp
from core.crypto.python.groups import GElement, GTElement, PairingContext
from core.crypto.python.hierarchy import linear_hierarchy
from core.crypto.python.kdf_aead import aead_decrypt, aead_encrypt, derive_segment_key
from core.crypto.python.segment import UserAttrMaterial


def _setup(universe=None, hierarchy=None) -> SegmentCrypto:
    crypto = SegmentCrypto()
    crypto.ca_setup()
    crypto.aa_setup(universe or ["doctor", "cardiology", "nurse", "emergency", "researcher"])
    crypto.role_setup(hierarchy or HEALTHCARE_FIXTURE)
    return crypto


def _provision(crypto: SegmentCrypto, uid: str, attrs, roles):
    ak = crypto.aa_keygen(uid, attrs)
    rk = crypto.ca_role_user(uid)
    for r in roles:
        crypto.rm_issue_rk(r, rk)
    return ak, rk, list(roles)


def test_01_authorized_cpabe_succeeds():
    c = _setup()
    ak, rk, roles = _provision(c, "u1", ["doctor", "cardiology"], ["AttendingPhysician"])
    tree = AND(leaf("doctor"), leaf("cardiology"))
    seg = c.protect_segment(b"ehr-ok", tree, ["Resident"])
    assert c.recover_segment(seg, ak, rk, roles) == b"ehr-ok"


def test_02_unauthorized_policy_fails():
    c = _setup()
    ak, rk, roles = _provision(c, "u2", ["nurse"], ["Nurse"])
    tree = AND(leaf("doctor"), leaf("cardiology"))
    seg = c.protect_segment(b"secret", tree, ["Nurse"])
    with pytest.raises(PermissionError):
        c.recover_segment(seg, ak, rk, roles)


def test_03_multiple_threshold_structures():
    c = _setup()
    # 2-of-3 threshold
    tree = gate(2, leaf("doctor"), leaf("nurse"), leaf("researcher"))
    ak, rk, roles = _provision(c, "u3", ["doctor", "researcher"], ["AttendingPhysician"])
    seg = c.protect_segment(b"thresh", tree, ["AttendingPhysician"])
    assert c.recover_segment(seg, ak, rk, roles) == b"thresh"
    # nested OR/AND
    tree2 = OR(AND(leaf("doctor"), leaf("cardiology")), leaf("emergency"))
    ak2, rk2, roles2 = _provision(c, "u3b", ["emergency"], ["Nurse"])
    seg2 = c.protect_segment(b"nested", tree2, ["Nurse"])
    assert c.recover_segment(seg2, ak2, rk2, roles2) == b"nested"


def test_04_cross_user_attribute_components_fail():
    c = _setup()
    ak1, rk1, roles1 = _provision(c, "alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    ak2, rk2, _ = _provision(c, "bob", ["doctor", "cardiology"], ["AttendingPhysician"])
    tree = AND(leaf("doctor"), leaf("cardiology"))
    seg = c.protect_segment(b"mix", tree, ["AttendingPhysician"])
    # Mix E_ua from bob into alice's key object
    mixed = UserAttrMaterial(
        user_id="alice",
        attrs=ak1.attrs,
        usk1=ak1.usk1,
        E=ak1.E,
        E1=ak1.E1,
        E_ua={"doctor": ak2.E_ua["doctor"], "cardiology": ak1.E_ua["cardiology"]},
        _r_u=ak1._r_u,
        _mu_u=ak1._mu_u,
    )
    # Outsourced transform may return a value, but final recovery must not yield correct ZA
    Bj = c.outsource_attr_transform(seg.attr_ct, mixed)
    if Bj is not None:
        ZA_wrong = c.user_recover_ZA(seg.attr_ct, Bj, mixed.usk1)
        assert ZA_wrong != seg.ZA


def test_05_exact_target_role_succeeds():
    c = _setup()
    ak, rk, roles = _provision(c, "u5", ["doctor", "cardiology"], ["Resident"])
    tree = AND(leaf("doctor"), leaf("cardiology"))
    seg = c.protect_segment(b"exact", tree, ["Resident"])
    assert c.recover_segment(seg, ak, rk, roles) == b"exact"


def test_06_ancestor_role_succeeds():
    c = _setup()
    ak, rk, roles = _provision(c, "chief", ["doctor", "cardiology"], ["ChiefMedicalOfficer"])
    tree = AND(leaf("doctor"), leaf("cardiology"))
    seg = c.protect_segment(b"anc", tree, ["Resident"])
    assert c.recover_segment(seg, ak, rk, roles) == b"anc"


def test_07_unrelated_role_fails():
    c = _setup()
    ak, rk, roles = _provision(c, "nurse", ["doctor", "cardiology"], ["Nurse"])
    tree = AND(leaf("doctor"), leaf("cardiology"))
    seg = c.protect_segment(b"nope", tree, ["Resident"])
    with pytest.raises(PermissionError):
        c.recover_segment(seg, ak, rk, roles)


def test_08_multi_target_same_ZR():
    c = _setup()
    ak_n, rk_n, roles_n = _provision(c, "n1", ["doctor", "cardiology"], ["Nurse"])
    ak_r, rk_r, roles_r = _provision(c, "r1", ["doctor", "cardiology"], ["Resident"])
    tree = AND(leaf("doctor"), leaf("cardiology"))
    seg = c.protect_segment(b"multi", tree, ["Nurse", "Resident"])
    assert len(seg.role_envelopes) == 2
    # Recover ZA once via nurse path attributes, then ZR via each envelope
    Bj = c.outsource_attr_transform(seg.attr_ct, ak_n)
    assert Bj is not None
    ZA = c.user_recover_ZA(seg.attr_ct, Bj, ak_n.usk1)

    def recover_ZR(ak_role, roles, target):
        env = next(e for e in seg.role_envelopes if e.target_role == target)
        assigned = next(r for r in roles if c.hierarchy.dominates(r, target))
        omega = Zp.random()
        TR = c.make_TR(ak_role.RK[assigned], omega)
        Gamma = c.hierarchy.Gamma(assigned, target)
        P, Q = c.outsource_role_transform(env, TR, ak_role.D0, Gamma)
        return c.user_recover_ZR(env, P, Q, omega, ak_role.rho)

    ZR_n = recover_ZR(rk_n, roles_n, "Nurse")
    ZR_r = recover_ZR(rk_r, roles_r, "Resident")
    assert ZR_n == ZR_r == seg.ZR
    assert derive_segment_key(ZA, ZR_n) == seg.key


def test_09_independent_d_values():
    c = _setup()
    ak, rk, roles = _provision(c, "u9", ["doctor", "cardiology"], ["Nurse"])
    tree = AND(leaf("doctor"), leaf("cardiology"))
    seg = c.protect_segment(b"dvals", tree, ["Nurse", "Resident"])
    ds = [e.d for e in seg.role_envelopes]
    assert len(ds) == 2 and ds[0] != ds[1]


def test_10_dual_layer_exact_reconstruction():
    c = _setup()
    ak, rk, roles = _provision(c, "u10", ["doctor", "cardiology"], ["AttendingPhysician"])
    tree = AND(leaf("doctor"), leaf("cardiology"))
    ZA, ZR = c.sample_ZA(), c.sample_ZR()
    key = derive_segment_key(ZA, ZR)
    partial = c.gateway_partial_attr(ZA)
    # gateway work independent of policy: only 3 components
    assert partial.C_tilde and partial.C_prime and partial.C_dprime
    attr_ct = c.outsource_policy_encrypt(partial, tree)
    Bj = c.outsource_attr_transform(attr_ct, ak)
    assert Bj is not None
    ZA2 = c.user_recover_ZA(attr_ct, Bj, ak.usk1)
    assert ZA2 == ZA
    env = c.role_encrypt(ZR, "AttendingPhysician")
    omega = Zp.random()
    TR = c.make_TR(rk.RK["AttendingPhysician"], omega)
    P, Q = c.outsource_role_transform(env, TR, rk.D0, [])
    ZR2 = c.user_recover_ZR(env, P, Q, omega, rk.rho)
    assert ZR2 == ZR
    assert derive_segment_key(ZA2, ZR2) == key


def test_11_wrong_ZA_fails_decrypt():
    c = _setup()
    ak, rk, roles = _provision(c, "u11", ["doctor", "cardiology"], ["AttendingPhysician"])
    tree = AND(leaf("doctor"), leaf("cardiology"))
    seg = c.protect_segment(b"za", tree, ["AttendingPhysician"])
    wrong_key = derive_segment_key(c.sample_ZA(), seg.ZR)
    with pytest.raises(Exception):
        aead_decrypt(wrong_key, seg.ct_aes)


def test_12_wrong_ZR_fails_decrypt():
    c = _setup()
    ak, rk, roles = _provision(c, "u12", ["doctor", "cardiology"], ["AttendingPhysician"])
    tree = AND(leaf("doctor"), leaf("cardiology"))
    seg = c.protect_segment(b"zr", tree, ["AttendingPhysician"])
    wrong_key = derive_segment_key(seg.ZA, c.sample_ZR())
    with pytest.raises(Exception):
        aead_decrypt(wrong_key, seg.ct_aes)


def test_13_aes_gcm_tampering_fails():
    key = os.urandom(32)
    blob = aead_encrypt(key, b"payload")
    tampered = bytearray(blob)
    tampered[-1] ^= 0x01
    with pytest.raises(Exception):
        aead_decrypt(key, bytes(tampered))


def test_14_serialization_round_trips():
    z = Zp.random()
    assert Zp.from_bytes(z.to_bytes()) == z
    g = GElement(z)
    assert GElement.from_bytes(g.to_bytes()) == g
    gt = GTElement(z)
    assert GTElement.from_bytes(gt.to_bytes()) == gt
    ctx = PairingContext()
    a, b = Zp.random(), Zp.random()
    left = ctx.pairing(ctx.g_pow(a), ctx.g_pow(b))
    right = ctx.gt_pow_gg(a * b)
    assert left == right


def test_15_randomized_many_users_policies_hierarchies():
    for i in range(8):
        names = [f"R{j}" for j in range(4)]
        h = linear_hierarchy(names)
        c = _setup(hierarchy=h)
        attrs = ["doctor", "cardiology", "nurse"]
        # random-ish policy: 2-of-3
        tree = gate(2, leaf("doctor"), leaf("cardiology"), leaf("nurse"))
        uid = f"user{i}"
        held = attrs[: 2 + (i % 2)]
        role = names[i % 3]
        ak, rk, roles = _provision(c, uid, held, [role])
        target = names[min(i % 3 + 1, 3)] if h.dominates(role, names[-1]) else role
        # pick a target dominated by assigned role
        target = names[-1]
        if not h.dominates(role, target):
            target = role
        try:
            seg = c.protect_segment(f"rand-{i}".encode(), tree, [target])
            if len(held) >= 2:
                pt = c.recover_segment(seg, ak, rk, roles)
                assert pt == f"rand-{i}".encode()
        except PermissionError:
            assert len(held) < 2 or not h.dominates(role, target)


def test_16_no_zero_inversion():
    c = _setup()
    # s_i + xi != 0 for all roles
    assert c.secrets is not None
    for rid, s in c.secrets.rm.s_i.items():
        assert not (s + c.secrets.rm.xi).is_zero()
        c.secrets.rm.rs[rid]  # already inverted at setup
    # Zp.inv(0) raises
    with pytest.raises(ZeroDivisionError):
        Zp.zero().inv()
    # refresh xi still enforces
    c.rm_refresh_xi()
    for rid, s in c.secrets.rm.s_i.items():
        assert not (s + c.secrets.rm.xi).is_zero()


def test_gateway_independent_of_policy_size():
    """Gateway partial encrypt does not loop over attributes/policy."""
    c = _setup()
    ZA = c.sample_ZA()
    p1 = c.gateway_partial_attr(ZA)
    # Only fixed components — no C_a map at gateway
    assert not hasattr(p1, "C_a")
    big = gate(3, leaf("doctor"), leaf("cardiology"), leaf("nurse"), leaf("emergency"), leaf("researcher"))
    ct = c.outsource_policy_encrypt(p1, big)
    assert len(ct.C_a) >= 3


def test_secrets_not_in_repr():
    c = _setup()
    ak, rk, _ = _provision(c, "x", ["doctor"], ["Nurse"])
    assert "REDACTED" in repr(ak.usk1) or "G:" in repr(ak.usk1)
    assert str(c.secrets.ca.alpha) == "<Zp:REDACTED>"
    assert "alpha" not in repr(c.secrets.ca.alpha).lower() or "REDACTED" in repr(c.secrets.ca.alpha)
