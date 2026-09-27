"""Authorization lifecycle tests (requirements 1–15)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.authorization.lifecycle import AuthorizationLifecycle
from core.authorization.secrecy import assert_no_ratio_fields, scan_text_blob_for_ratio_leak
from core.authorization.errors import AuthorizationUpdateRejected
from core.crypto.python.access_tree import AND, OR, gate, leaf


def _lc() -> AuthorizationLifecycle:
    lc = AuthorizationLifecycle(owner_id="owner-A")
    lc.setup()
    return lc


def _provision_pair(lc: AuthorizationLifecycle) -> None:
    lc.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    lc.provision_user("bob", ["doctor", "cardiology"], ["AttendingPhysician"])


# --- 1–4 version increments ---


def test_01_version_starts_at_zero():
    lc = _lc()
    assert lc.active.version == 0
    assert lc.active.identity_tuple()[0] == 0


def test_02_policy_update_creates_exactly_nu_plus_one():
    lc = _lc()
    assert lc.active.version == 0
    old_attr = lc.active.attr_state_id
    old_role = lc.active.role_state_id
    snap = lc.update_policy(OR(leaf("doctor"), leaf("nurse")))
    assert snap.version == 1
    assert snap.policy_id != lc.archive.snapshots[0].policy_id  # type: ignore[union-attr]
    assert snap.attr_state_id == old_attr
    assert snap.role_state_id == old_role


def test_03_attribute_update_creates_exactly_nu_plus_one():
    lc = _lc()
    _provision_pair(lc)
    snap = lc.revoke_attribute("doctor", revoked_users=["bob"])
    assert snap.version == 1
    assert snap.attr_state_id != lc.archive.snapshots[0].attr_state_id  # type: ignore[union-attr]


def test_04_role_update_creates_exactly_nu_plus_one():
    lc = _lc()
    _provision_pair(lc)
    snap = lc.reassign_roles({"bob": ["Nurse"]})
    assert snap.version == 1
    assert snap.role_state_id != lc.archive.snapshots[0].role_state_id  # type: ignore[union-attr]


# --- 5 failed commit ---


def test_05_failed_commit_leaves_active_unchanged():
    lc = _lc()
    _provision_pair(lc)
    before = lc.active
    lc.ledger.fail_next_commit = True
    with pytest.raises(AuthorizationUpdateRejected):
        lc.revoke_attribute("doctor", revoked_users=["bob"])
    assert lc.active.matches(before)
    assert lc.machine.phase.value == "ACTIVE"  # type: ignore[union-attr]
    assert lc.machine.pending is None  # type: ignore[union-attr]


# --- 6 unaffected attributes ---


def test_06_unaffected_attributes_carried_forward():
    lc = _lc()
    _provision_pair(lc)
    before = dict(lc.attr_by_ver[0].pk_attr)
    lc.revoke_attribute("doctor", revoked_users=["bob"])
    after = lc.attr_by_ver[1].pk_attr
    assert after["doctor"] != before["doctor"]
    for a in before:
        if a != "doctor":
            assert after[a] == before[a]


# --- 7–8 xi refresh policy ---


def test_07_policy_only_preserves_xi():
    lc = _lc()
    xi0 = lc.current_xi_hex()
    lc.update_policy(AND(leaf("doctor"), leaf("cardiology"), leaf("emergency")))
    assert lc.current_xi_hex() == xi0
    assert lc.active.role_state_id == lc.archive.snapshots[0].role_state_id  # type: ignore[union-attr]


def test_08_role_membership_change_refreshes_xi():
    lc = _lc()
    _provision_pair(lc)
    xi0 = lc.current_xi_hex()
    ar_before = dict(lc._base_ar_hex)
    lc.reassign_roles({"bob": ["Nurse"]})
    assert lc.current_xi_hex() != xi0
    lc.assert_base_hierarchy_preserved()
    assert lc._base_ar_hex == ar_before


# --- 9–12 prospective revocation ---


def test_09_revoked_attribute_user_fails_future():
    lc = _lc()
    _provision_pair(lc)
    lc.revoke_attribute("doctor", revoked_users=["bob"])
    lc.protect_segment("fut", b"future-data", targets=["AttendingPhysician"])
    assert lc.recover_segment("alice", "fut") == b"future-data"
    with pytest.raises(PermissionError):
        lc.recover_segment("bob", "fut")


def test_10_non_revoked_refreshed_user_succeeds():
    lc = _lc()
    _provision_pair(lc)
    # Capture alice E_ua before refresh
    e_before = lc.keys.current_attr("alice").material.E_ua["doctor"].to_bytes()  # type: ignore
    lc.revoke_attribute("doctor", revoked_users=["bob"])
    e_after = lc.keys.current_attr("alice").material.E_ua["doctor"].to_bytes()  # type: ignore
    assert e_before != e_after  # refreshed component
    lc.protect_segment("ok", b"alice-ok", targets=["AttendingPhysician"])
    assert lc.recover_segment("alice", "ok") == b"alice-ok"


def test_11_revoked_role_user_fails_future():
    lc = _lc()
    _provision_pair(lc)
    lc.reassign_roles({"bob": ["Nurse"]})
    lc.protect_segment("fut-r", b"attending-only", targets=["AttendingPhysician"])
    with pytest.raises(PermissionError):
        lc.recover_segment("bob", "fut-r")


def test_12_active_refreshed_role_user_succeeds():
    lc = _lc()
    _provision_pair(lc)
    lc.reassign_roles(
        {
            "alice": ["AttendingPhysician"],
            "bob": ["Nurse"],
        }
    )
    lc.protect_segment("ok-r", b"alice-role", targets=["AttendingPhysician"])
    assert lc.recover_segment("alice", "ok-r") == b"alice-role"
    lc.protect_segment("nurse-ok", b"bob-nurse", targets=["Nurse"])
    assert lc.recover_segment("bob", "nurse-ok") == b"bob-nurse"


# --- 13–14 historical ---


def test_13_historical_legitimate_segment_remains_decryptable():
    lc = _lc()
    _provision_pair(lc)
    lc.protect_segment("hist", b"historical-payload", targets=["AttendingPhysician"])
    assert lc.recover_segment("alice", "hist") == b"historical-payload"
    assert lc.recover_segment("bob", "hist") == b"historical-payload"

    lc.revoke_attribute("doctor", revoked_users=["bob"])
    # Both still decrypt historical under ν=0 keys (prospective)
    assert lc.recover_segment("alice", "hist") == b"historical-payload"
    assert lc.recover_segment("bob", "hist") == b"historical-payload"

    lc.reassign_roles({"bob": ["Nurse"], "alice": ["AttendingPhysician"]})
    assert lc.recover_segment("alice", "hist") == b"historical-payload"
    assert lc.recover_segment("bob", "hist") == b"historical-payload"


def test_14_historical_ciphertext_bytes_unchanged():
    lc = _lc()
    _provision_pair(lc)
    lc.protect_segment("hct", b"immutable-ct", targets=["AttendingPhysician"])
    ct0 = lc.segments["hct"].crypto.ct_aes
    attr_blob0 = json.dumps(
        {k: v.to_bytes().hex() for k, v in lc.segments["hct"].crypto.attr_ct.C_a.items()},
        sort_keys=True,
    )
    lc.revoke_attribute("doctor", revoked_users=["bob"])
    lc.reassign_roles({"bob": ["Nurse"], "alice": ["AttendingPhysician"]})
    assert lc.segments["hct"].crypto.ct_aes == ct0
    attr_blob1 = json.dumps(
        {k: v.to_bytes().hex() for k, v in lc.segments["hct"].crypto.attr_ct.C_a.items()},
        sort_keys=True,
    )
    assert attr_blob0 == attr_blob1


# --- 15 no update ratio ---


def test_15_no_update_ratio_exposed():
    lc = _lc()
    _provision_pair(lc)
    lc.revoke_attribute("doctor", revoked_users=["bob"])
    lc.update_policy(gate(2, leaf("doctor"), leaf("cardiology"), leaf("emergency")))
    lc.reassign_roles({"alice": ["AttendingPhysician"], "bob": ["Nurse"]})

    for row in lc.experiment_raw:
        assert_no_ratio_fields(row)
        scan_text_blob_for_ratio_leak(json.dumps(row))
    for entry in lc.ledger.commit_log:
        assert_no_ratio_fields(entry)
        scan_text_blob_for_ratio_leak(json.dumps(entry))
    # Pending bundles / user API surfaces
    for uid in ("alice", "bob"):
        mat = lc.keys.current_attr(uid).material  # type: ignore
        assert not hasattr(mat, "ratio")
        assert not hasattr(mat, "update_ratio")


# --- extras: state machine, ids, file store, multi-step ---


def test_state_ids_unique_for_different_contents():
    lc = _lc()
    a0 = lc.active.attr_state_id
    lc.provision_user("u", ["doctor", "cardiology"], ["Nurse"])
    lc.revoke_attribute("nurse", revoked_users=[])  # refresh nurse PK even with no holders
    a1 = lc.active.attr_state_id
    assert a0 != a1


def test_file_backed_ledger_roundtrip(tmp_path: Path):
    path = tmp_path / "auth.json"
    lc = AuthorizationLifecycle(owner_id="owner-B")
    lc.setup(ledger_path=path)
    assert path.exists()
    snap = lc.active

    lc2 = AuthorizationLifecycle(owner_id="owner-B")
    lc2.ledger.path = path
    lc2.ledger.load()
    rec = lc2.ledger.get("owner-B")
    assert rec is not None
    assert rec.version == snap.version
    assert rec.policy_id == snap.policy_id


def test_attribute_only_does_not_refresh_xi():
    lc = _lc()
    _provision_pair(lc)
    xi0 = lc.current_xi_hex()
    role0 = lc.active.role_state_id
    lc.revoke_attribute("doctor", revoked_users=["bob"])
    assert lc.current_xi_hex() == xi0
    assert lc.active.role_state_id == role0


def test_chained_versions_increment_monotonically():
    lc = _lc()
    _provision_pair(lc)
    assert lc.update_policy(OR(leaf("doctor"), leaf("nurse"))).version == 1
    assert lc.revoke_attribute("emergency", revoked_users=[]).version == 2
    assert lc.reassign_roles({"alice": ["ChiefMedicalOfficer"], "bob": ["Nurse"]}).version == 3
    assert lc.active.version == 3
