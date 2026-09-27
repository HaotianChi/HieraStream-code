"""Role-side adversarial / negative tests."""

from __future__ import annotations

from copy import deepcopy

import pytest

from core.crypto.python.segment import UserRoleMaterial
from tests.security._helpers import (
    clone_role,
    clone_seg,
    default_tree,
    must_fail_recover,
    mutate_g,
    mutate_gt,
    provision,
    setup_crypto,
)


def test_descendant_cannot_access_ancestor_only_permission():
    """Resident does not dominate ChiefMedicalOfficer target."""
    c = setup_crypto()
    ak, rk, roles = provision(c, "res", ["doctor", "cardiology"], ["Resident"])
    tree = default_tree()
    pt = b"chief-only"
    seg = c.protect_segment(pt, tree, ["ChiefMedicalOfficer"])
    with pytest.raises(PermissionError, match="role"):
        c.recover_segment(seg, ak, rk, roles)


def test_unrelated_role_fails():
    c = setup_crypto()
    ak, rk, roles = provision(c, "nurse", ["doctor", "cardiology"], ["Nurse"])
    tree = default_tree()
    seg = c.protect_segment(b"nope", tree, ["AttendingPhysician"])
    with pytest.raises(PermissionError, match="role"):
        c.recover_segment(seg, ak, rk, roles)


def test_obsolete_xi_version_fails_on_future_envelope():
    c = setup_crypto()
    ak, rk, roles = provision(c, "alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    stale_rk = clone_role(rk)
    tree = default_tree()
    # Refresh ξ and re-issue honest keys under new ξ
    c.rm_refresh_xi()
    for r in roles:
        c.rm_issue_rk(r, rk)
    pt = b"new-xi"
    seg = c.protect_segment(pt, tree, ["AttendingPhysician"])
    assert c.recover_segment(seg, ak, rk, roles) == pt
    # Stale RK / D0 from pre-refresh material must not open new envelopes
    must_fail_recover(c, seg, ak, stale_rk, roles, plaintext=pt)


def test_role_key_from_another_user():
    """Stolen RK must not combine with a different user's D0/ρ."""
    c = setup_crypto()
    ak1, rk1, _ = provision(c, "alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    ak2, rk2, _ = provision(c, "bob", ["doctor", "cardiology"], ["Nurse"])
    tree = default_tree()
    pt = b"stolen-rk"
    seg = c.protect_segment(pt, tree, ["AttendingPhysician"])
    # Bob grafts Alice's Attending RK onto his own D0/ρ
    stolen = UserRoleMaterial(
        user_id="bob",
        rho=rk2.rho,
        D0=rk2.D0,
        D1=rk2.D1,
        RK={"AttendingPhysician": rk1.RK["AttendingPhysician"]},
    )
    must_fail_recover(c, seg, ak2, stolen, ["AttendingPhysician"], plaintext=pt)
    # Alice attrs + Bob Nurse material cannot open Attending target
    with pytest.raises(PermissionError, match="role"):
        c.recover_segment(seg, ak1, rk2, ["Nurse"])
    assert c.recover_segment(seg, ak1, rk1, ["AttendingPhysician"]) == pt


def test_mixed_role_components_from_different_users():
    c = setup_crypto()
    ak1, rk1, roles1 = provision(c, "alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    _, rk2, _ = provision(c, "bob", ["doctor", "cardiology"], ["AttendingPhysician"])
    tree = default_tree()
    pt = b"mix-role"
    seg = c.protect_segment(pt, tree, ["AttendingPhysician"])
    mixed = UserRoleMaterial(
        user_id="alice",
        rho=rk1.rho,
        D0=rk2.D0,
        D1=rk1.D1,
        RK=dict(rk1.RK),
    )
    must_fail_recover(c, seg, ak1, mixed, roles1, plaintext=pt)
    mixed2 = UserRoleMaterial(
        user_id="alice",
        rho=rk1.rho,
        D0=rk1.D0,
        D1=rk1.D1,
        RK={"AttendingPhysician": rk2.RK["AttendingPhysician"]},
    )
    must_fail_recover(c, seg, ak1, mixed2, roles1, plaintext=pt)


def test_wrong_target_role_envelope():
    c = setup_crypto()
    ak, rk, roles = provision(c, "alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    # Also issue Nurse so adversary can try wrong envelope with a held RK
    c.rm_issue_rk("Nurse", rk)
    roles_both = ["AttendingPhysician", "Nurse"]
    tree = default_tree()
    pt = b"wrong-env"
    seg = c.protect_segment(pt, tree, ["AttendingPhysician", "Nurse"])
    # Force recovery path to use Nurse envelope while claiming Attending target only
    bad = clone_seg(seg)
    nurse_env = next(e for e in bad.role_envelopes if e.target_role == "Nurse")
    # Replace Attending envelope components with Nurse's (wrong target)
    for i, e in enumerate(bad.role_envelopes):
        if e.target_role == "AttendingPhysician":
            swapped = deepcopy(nurse_env)
            swapped.target_role = "AttendingPhysician"
            bad.role_envelopes[i] = swapped
            break
    bad.targets = ["AttendingPhysician"]
    must_fail_recover(c, bad, ak, rk, ["AttendingPhysician"], plaintext=pt)


def test_malicious_modification_of_ancestor_path_components():
    c = setup_crypto()
    # Chief uses Gamma path components in C3 when decrypting Attending target
    ak, rk, roles = provision(c, "chief", ["doctor", "cardiology"], ["ChiefMedicalOfficer"])
    tree = default_tree()
    pt = b"path-tamper"
    seg = c.protect_segment(pt, tree, ["AttendingPhysician"])
    assert c.recover_segment(seg, ak, rk, roles) == pt

    bad = clone_seg(seg)
    env = bad.role_envelopes[0]
    assert env.C3, "expected ancestor-path C3 components for Attending target"
    k = next(iter(env.C3))
    env.C3[k] = mutate_g(env.C3[k])
    must_fail_recover(c, bad, ak, rk, roles, plaintext=pt)

    bad2 = clone_seg(seg)
    bad2.role_envelopes[0].Ci = mutate_g(bad2.role_envelopes[0].Ci)
    must_fail_recover(c, bad2, ak, rk, roles, plaintext=pt)

    bad3 = clone_seg(seg)
    bad3.role_envelopes[0].C2 = mutate_g(bad3.role_envelopes[0].C2)
    must_fail_recover(c, bad3, ak, rk, roles, plaintext=pt)

    bad4 = clone_seg(seg)
    bad4.role_envelopes[0].C1 = mutate_gt(bad4.role_envelopes[0].C1)
    must_fail_recover(c, bad4, ak, rk, roles, plaintext=pt)
