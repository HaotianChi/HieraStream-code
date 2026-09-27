"""Historical key material and resolver fail-closed tests."""

from __future__ import annotations

import pytest

from core.actors.users.client import DataUser
from core.authorization.errors import (
    AuthorizationStateMismatch,
    HistoricalAttributeKeyUnavailable,
    HistoricalRoleKeyUnavailable,
)
from core.authorization.lifecycle import AuthorizationLifecycle
from core.authorization.snapshot import AuthorizationSnapshot
from core.crypto.python.access_tree import OR, leaf
from core.crypto.python.hierarchy import HEALTHCARE_FIXTURE
from core.crypto.python.segment import SegmentCrypto, UserAttrMaterial, UserRoleMaterial
from core.protocol.workflow import HieraStreamWorkflow


def _dummy_attr() -> UserAttrMaterial:
    c = SegmentCrypto()
    c.ca_setup()
    c.aa_setup(["doctor", "cardiology"])
    return c.aa_keygen("u", ["doctor", "cardiology"])


def _dummy_role() -> UserRoleMaterial:
    c = SegmentCrypto()
    c.ca_setup()
    c.aa_setup(["doctor"])
    c.role_setup(HEALTHCARE_FIXTURE)
    return c.ca_role_user("u")


def test_01_matching_historical_attr_succeeds():
    mat = _dummy_attr()
    u = DataUser("u", mat, _dummy_role(), ["AttendingPhysician"])
    u.store_attr_version("attr-A", mat)
    assert u.attr_for("attr-A").attrs == mat.attrs


def test_02_absent_historical_attr_fails():
    mat = _dummy_attr()
    u = DataUser("u", mat, _dummy_role(), ["AttendingPhysician"])
    u.store_attr_version("attr-A", mat)
    with pytest.raises(HistoricalAttributeKeyUnavailable):
        u.attr_for("attr-missing")


def test_03_matching_historical_role_succeeds():
    role = _dummy_role()
    u = DataUser("u", _dummy_attr(), role, ["AttendingPhysician"])
    u.store_role_version("role-A", role, ["AttendingPhysician"])
    got, roles = u.role_for("role-A")
    assert roles == ["AttendingPhysician"]
    assert got.D0.to_bytes() == role.D0.to_bytes()


def test_04_absent_historical_role_fails():
    role = _dummy_role()
    u = DataUser("u", _dummy_attr(), role, ["AttendingPhysician"])
    u.store_role_version("role-A", role, ["AttendingPhysician"])
    with pytest.raises(HistoricalRoleKeyUnavailable):
        u.role_for("role-missing")


def test_05_current_attr_exists_but_old_id_missing_fails():
    mat = _dummy_attr()
    u = DataUser("u", mat, _dummy_role(), ["Nurse"])
    u.store_attr_version("current-id", mat)
    assert u.attr_keys is not None
    with pytest.raises(HistoricalAttributeKeyUnavailable):
        u.attr_for("old-missing-id")


def test_06_current_role_exists_but_old_id_missing_fails():
    role = _dummy_role()
    u = DataUser("u", _dummy_attr(), role, ["Nurse"])
    u.store_role_version("current-role", role, ["Nurse"])
    with pytest.raises(HistoricalRoleKeyUnavailable):
        u.role_for("old-missing-role")


def test_07_same_version_wrong_attr_state_id_fails_resolver():
    lc = AuthorizationLifecycle(owner_id="res-a")
    lc.setup()
    lc.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    snap = lc.active
    wrong = AuthorizationSnapshot(
        owner_id=snap.owner_id,
        version=snap.version,
        policy_id=snap.policy_id,
        attr_state_id="wrong-attr-state",
        role_state_id=snap.role_state_id,
    )
    assert lc._resolve_attr_keys("alice", wrong) is None
    lc.protect_segment("s", b"x", targets=["AttendingPhysician"])
    lc.segments["s"].snapshot = wrong
    with pytest.raises((HistoricalAttributeKeyUnavailable, AuthorizationStateMismatch)):
        lc.recover_segment("alice", "s")


def test_08_same_version_wrong_role_state_id_fails_resolver():
    lc = AuthorizationLifecycle(owner_id="res-r")
    lc.setup()
    lc.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    snap = lc.active
    wrong = AuthorizationSnapshot(
        owner_id=snap.owner_id,
        version=snap.version,
        policy_id=snap.policy_id,
        attr_state_id=snap.attr_state_id,
        role_state_id="wrong-role-state",
    )
    assert lc._resolve_role_keys("alice", wrong) is None
    lc.protect_segment("s", b"x", targets=["AttendingPhysician"])
    lc.segments["s"].snapshot = wrong
    with pytest.raises((HistoricalRoleKeyUnavailable, AuthorizationStateMismatch)):
        lc.recover_segment("alice", "s")


def test_09_pending_keys_never_resolve_via_datauser():
    wf = HieraStreamWorkflow(owner_id="pend-keys")
    wf.setup()
    wf.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    assert wf.lifecycle
    active_attr = wf.lifecycle.active.attr_state_id
    pending = wf.lifecycle.prepare_attribute_revocation("doctor", ["nobody"])
    next_snap = wf.lifecycle.preview_snapshot(pending)
    assert next_snap.attr_state_id not in wf.users["alice"].hist_attr
    with pytest.raises(HistoricalAttributeKeyUnavailable):
        wf.users["alice"].attr_for(next_snap.attr_state_id)
    assert wf.users["alice"].attr_for(active_attr).attrs
    wf.lifecycle.abort_pending_update(pending)


def test_10_carried_forward_exact_state_id_resolvable():
    wf = HieraStreamWorkflow(owner_id="carry")
    wf.setup()
    wf.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    attr0 = wf.lifecycle.active.attr_state_id
    role0 = wf.lifecycle.active.role_state_id
    wf.publish(b"before", targets=["AttendingPhysician"], seg_id="c0")
    snap1 = wf.update_policy(OR(leaf("doctor"), leaf("nurse")))
    assert snap1.attr_state_id == attr0
    assert snap1.role_state_id == role0
    assert snap1.version == 1
    assert wf.users["alice"].attr_for(attr0).attrs
    assert wf.users["alice"].role_for(role0)[1] == ["AttendingPhysician"]
    assert wf.access("alice", "c0") == b"before"
    entry = wf.lifecycle._resolve_attr_keys("alice", snap1)
    assert entry is not None and entry.attr_state_id == attr0
