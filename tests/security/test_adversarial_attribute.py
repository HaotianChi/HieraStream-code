"""Attribute-side adversarial / negative tests."""

from __future__ import annotations

import pytest

from core.crypto.python.access_tree import AccessTree, AND, gate, leaf
from core.crypto.python.segment import UserAttrMaterial

from tests.security._helpers import (
    clone_attr,
    clone_seg,
    default_tree,
    must_fail_recover,
    mutate_g,
    mutate_gt,
    provision,
    setup_crypto,
)


def test_missing_required_attributes():
    c = setup_crypto()
    ak, rk, roles = provision(c, "u", ["doctor"], ["AttendingPhysician"])  # missing cardiology
    tree = default_tree()
    seg = c.protect_segment(b"secret", tree, ["AttendingPhysician"])
    with pytest.raises(PermissionError, match="attribute"):
        c.recover_segment(seg, ak, rk, roles)


def test_insufficient_threshold():
    c = setup_crypto()
    # 2-of-3; user has only 1 leaf
    tree = gate(2, leaf("doctor"), leaf("nurse"), leaf("researcher"))
    ak, rk, roles = provision(c, "u", ["doctor"], ["AttendingPhysician"])
    seg = c.protect_segment(b"thresh", tree, ["AttendingPhysician"])
    with pytest.raises(PermissionError, match="attribute"):
        c.recover_segment(seg, ak, rk, roles)


def test_attributes_combined_across_different_users():
    c = setup_crypto()
    ak1, rk1, roles1 = provision(c, "alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    ak2, _, _ = provision(c, "bob", ["doctor", "cardiology"], ["AttendingPhysician"])
    tree = default_tree()
    pt = b"cross-user"
    seg = c.protect_segment(pt, tree, ["AttendingPhysician"])
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
    Bj = c.outsource_attr_transform(seg.attr_ct, mixed)
    if Bj is None:
        return
    ZA = c.user_recover_ZA(seg.attr_ct, Bj, mixed.usk1)
    assert ZA != seg.ZA
    must_fail_recover(c, seg, mixed, rk1, roles1, plaintext=pt)


def test_old_revoked_attribute_component_on_new_ciphertext():
    c = setup_crypto()
    ak_a, rk_a, roles_a = provision(c, "alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    ak_b, rk_b, roles_b = provision(c, "bob", ["doctor", "cardiology"], ["AttendingPhysician"])
    tree = default_tree()
    old_bob = clone_attr(ak_b)
    c.aa_revoke_attribute("doctor")
    # Alice refreshed under new t_a; Bob keeps stale E_ua[doctor]
    ak_a.E_ua["doctor"] = c.aa_refresh_Eua(ak_a.E_ua["doctor"], "doctor")
    # New CT under refreshed PK
    pt = b"post-revoke"
    seg = c.protect_segment(pt, tree, ["AttendingPhysician"])
    assert c.recover_segment(seg, ak_a, rk_a, roles_a) == pt
    # Stale E_ua must not yield correct plaintext (PermissionError or AEAD failure)
    must_fail_recover(c, seg, old_bob, rk_b, roles_b, plaintext=pt)
    # Stale component alone cannot open new leaf
    Bj = c.outsource_attr_transform(seg.attr_ct, old_bob)
    if Bj is not None:
        assert c.user_recover_ZA(seg.attr_ct, Bj, old_bob.usk1) != seg.ZA


def test_refreshed_component_combined_with_revoked_user_keys():
    c = setup_crypto()
    ak_a, rk_a, roles_a = provision(c, "alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    ak_b, rk_b, roles_b = provision(c, "bob", ["doctor", "cardiology"], ["AttendingPhysician"])
    tree = default_tree()
    c.aa_revoke_attribute("doctor")
    refreshed_doctor = c.aa_refresh_Eua(ak_a.E_ua["doctor"], "doctor")
    ak_a.E_ua["doctor"] = refreshed_doctor
    # Adversary: revoked bob's usk1/E with alice's refreshed E_ua
    franken = UserAttrMaterial(
        user_id="bob",
        attrs=ak_b.attrs,
        usk1=ak_b.usk1,
        E=ak_b.E,
        E1=ak_b.E1,
        E_ua={"doctor": refreshed_doctor, "cardiology": ak_b.E_ua["cardiology"]},
        _r_u=ak_b._r_u,
        _mu_u=ak_b._mu_u,
    )
    pt = b"franken"
    seg = c.protect_segment(pt, tree, ["AttendingPhysician"])
    assert c.recover_segment(seg, ak_a, rk_a, roles_a) == pt
    must_fail_recover(c, seg, franken, rk_b, roles_b, plaintext=pt)


def test_malformed_tree_rejects_or_fails_recovery():
    c = setup_crypto()
    ak, rk, roles = provision(c, "u", ["doctor", "cardiology"], ["AttendingPhysician"])
    # Threshold exceeds children — construction must reject
    with pytest.raises(ValueError):
        gate(3, leaf("doctor"), leaf("cardiology"))
    # Encrypt under honest tree then replace with malformed leaf (attr not in C_a)
    tree = default_tree()
    pt = b"mal-tree"
    seg = c.protect_segment(pt, tree, ["AttendingPhysician"])
    bad = clone_seg(seg)
    bad.attr_ct.tree = AND(leaf("doctor"), leaf("nonexistent-attr"))
    must_fail_recover(c, bad, ak, rk, roles, plaintext=pt)
    # Empty-child internal with threshold 1
    bad2 = clone_seg(seg)
    bad2.attr_ct.tree = AccessTree(kind="internal", threshold=1, children=[])
    must_fail_recover(c, bad2, ak, rk, roles, plaintext=pt)


def test_modified_ciphertext_components():
    c = setup_crypto()
    ak, rk, roles = provision(c, "u", ["doctor", "cardiology"], ["AttendingPhysician"])
    tree = default_tree()
    pt = b"tamper-ct"
    seg = c.protect_segment(pt, tree, ["AttendingPhysician"])

    for field in ("C_tilde", "C_prime", "C_tilde_prime", "C_tilde_dprime"):
        bad = clone_seg(seg)
        cur = getattr(bad.attr_ct, field)
        if field == "C_tilde":
            setattr(bad.attr_ct, field, mutate_gt(cur))
        else:
            setattr(bad.attr_ct, field, mutate_g(cur))
        must_fail_recover(c, bad, ak, rk, roles, plaintext=pt)

    bad_leaf = clone_seg(seg)
    a = next(iter(bad_leaf.attr_ct.C_a))
    bad_leaf.attr_ct.C_a[a] = mutate_g(bad_leaf.attr_ct.C_a[a])
    must_fail_recover(c, bad_leaf, ak, rk, roles, plaintext=pt)

    # Drop a required leaf component (keys are path-qualified: R/1:doctor)
    bad_drop = clone_seg(seg)
    doctor_key = next(k for k in bad_drop.attr_ct.C_a if k.endswith(":doctor"))
    bad_drop.attr_ct.C_a.pop(doctor_key)
    must_fail_recover(c, bad_drop, ak, rk, roles, plaintext=pt)
