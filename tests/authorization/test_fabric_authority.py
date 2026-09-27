"""Fabric-only authority + prepare/abort/activate failure tests."""

from __future__ import annotations

import pytest

from core.authorization.errors import AuthorizationUpdateRejected
from core.authorization.machine import AuthPhase
from core.authorization.snapshot import auth_key
from core.blockchain.client.peer_backend import FabricTxStatus
from core.crypto.python.access_tree import OR, leaf
from core.protocol.workflow import HieraStreamWorkflow


def _wf() -> HieraStreamWorkflow:
    w = HieraStreamWorkflow(owner_id="auth-test")
    w.setup()
    w.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    w.provision_user("bob", ["doctor", "cardiology"], ["AttendingPhysician"])
    return w


def _force_acl_deny(wf: HieraStreamWorkflow) -> None:
    wf.fabric.ledger.set_acl("UpdateAuthorization", {"admin"})


def test_A_policy_update_fabric_failure_no_activate():
    wf = _wf()
    prev = wf.lifecycle.active
    policy0 = wf.policy_tree
    fabric_v0 = wf.fabric.get_authorization_snapshot(wf.owner_id)
    assert fabric_v0 is not None and fabric_v0.version == 0
    ledger_v0 = wf.lifecycle.ledger.get(wf.owner_id)
    assert ledger_v0 is not None and ledger_v0.version == 0

    _force_acl_deny(wf)
    with pytest.raises(AuthorizationUpdateRejected):
        wf.update_policy(OR(leaf("doctor"), leaf("nurse")))

    assert wf.lifecycle.active.matches(prev)
    assert wf.lifecycle.machine.phase == AuthPhase.ACTIVE
    assert wf.lifecycle.machine.pending is None
    assert wf.policy_tree is policy0
    fab = wf.fabric.get_authorization_snapshot(wf.owner_id)
    assert fab is not None and fab.version == 0 and fab.matches(prev)
    # LocalAuthLedger must not have independently committed ν+1
    assert wf.lifecycle.ledger.get(wf.owner_id).version == 0
    # Segment protection still uses ν=0 policy state
    seg = wf.publish(b"still-old", targets=["AttendingPhysician"], seg_id="pol-fail")
    assert seg.snapshot.version == 0
    assert wf.access("alice", "pol-fail") == b"still-old"


def test_B_attribute_revocation_fabric_failure_crypto_unchanged():
    wf = _wf()
    assert wf.lifecycle and wf.crypto.secrets and wf.crypto.pp
    t_before = wf.crypto.secrets.aa.t_a["doctor"].to_bytes()
    pk_before = wf.crypto.pp.pk_attr["doctor"].to_bytes()
    attr0 = wf.lifecycle.active.attr_state_id
    bob_e = wf.users["bob"].attr_keys.E_ua["doctor"].to_bytes()
    alice_e = wf.users["alice"].attr_keys.E_ua["doctor"].to_bytes()

    _force_acl_deny(wf)
    with pytest.raises(AuthorizationUpdateRejected):
        wf.revoke_attribute("doctor", revoked_users=["bob"])

    assert wf.lifecycle.active.version == 0
    assert wf.lifecycle.active.attr_state_id == attr0
    assert wf.crypto.secrets.aa.t_a["doctor"].to_bytes() == t_before
    assert wf.crypto.pp.pk_attr["doctor"].to_bytes() == pk_before
    assert wf.users["bob"].attr_keys.E_ua["doctor"].to_bytes() == bob_e
    assert wf.users["alice"].attr_keys.E_ua["doctor"].to_bytes() == alice_e
    # No ν=1 attr state activated
    assert 1 not in wf.lifecycle.attr_by_ver
    seg = wf.publish(b"attr-fail-seg", targets=["AttendingPhysician"], seg_id="af")
    assert seg.snapshot.attr_state_id == attr0
    assert wf.access("bob", "af") == b"attr-fail-seg"


def test_C_role_update_fabric_failure_crypto_unchanged():
    wf = _wf()
    assert wf.crypto.secrets and wf.crypto.pp
    xi_before = wf.crypto.secrets.rm.xi.to_bytes()
    pk_before = {r: g.to_bytes() for r, g in wf.crypto.pp.pk_role.items()}
    role0 = wf.lifecycle.active.role_state_id
    bob_rk = wf.users["bob"].role_mat.RK["AttendingPhysician"].to_bytes()

    _force_acl_deny(wf)
    with pytest.raises(AuthorizationUpdateRejected):
        wf.reassign_roles({"alice": ["AttendingPhysician"], "bob": ["Nurse"]})

    assert wf.lifecycle.active.version == 0
    assert wf.lifecycle.active.role_state_id == role0
    assert wf.crypto.secrets.rm.xi.to_bytes() == xi_before
    assert {r: g.to_bytes() for r, g in wf.crypto.pp.pk_role.items()} == pk_before
    assert wf.users["bob"].role_mat.RK["AttendingPhysician"].to_bytes() == bob_rk
    assert 1 not in wf.lifecycle.role_by_ver
    assert wf.access("bob", wf.publish(b"role-fail", targets=["AttendingPhysician"], seg_id="rf").seg_id) == b"role-fail"


def test_D_delayed_fabric_validation_uses_active_nu():
    wf = _wf()
    assert wf.lifecycle
    prev = wf.lifecycle.active
    t_before = wf.crypto.secrets.aa.t_a["doctor"].to_bytes()
    pending = wf.lifecycle.prepare_attribute_revocation("doctor", ["bob"])
    next_snap = wf.lifecycle.preview_snapshot(pending)
    assert wf.lifecycle.machine.phase == AuthPhase.PENDING
    assert wf.lifecycle.active.version == 0
    # Active crypto still ν
    assert wf.crypto.secrets.aa.t_a["doctor"].to_bytes() == t_before

    res = wf.fabric.update_authorization(
        wf.owner_id,
        prev,
        new_attr_state_id=next_snap.attr_state_id,
        caller="aa",
        defer_validation=True,
    )
    assert res.status == FabricTxStatus.PENDING

    # Protect while Fabric + lifecycle still pending — must bind ACTIVE(ν)
    seg = wf.publish(b"during-pending", targets=["AttendingPhysician"], seg_id="delay1")
    assert seg.snapshot.version == 0
    assert seg.snapshot.attr_state_id == prev.attr_state_id
    assert seg.snapshot.matches(prev)
    assert wf.access("bob", "delay1") == b"during-pending"

    # Abort path: reject pending Fabric tx by competing VALID update then abort lifecycle
    # (simpler: await VALID then activate — success path covered elsewhere)
    # Here abort cleanly without activation:
    # Drop pending fabric by letting a competing update win → MVCC, then abort lifecycle.
    # Restore: abort lifecycle first (pending crypto never applied), leave fabric pending.
    wf.lifecycle.abort_pending_update(pending)
    assert wf.lifecycle.active.version == 0
    assert wf.crypto.secrets.aa.t_a["doctor"].to_bytes() == t_before
    # Competing update so deferred tx fails; Fabric AuthKey may advance — lifecycle stays 0
    hijack = wf.fabric.update_authorization(wf.owner_id, prev, new_policy_id="hijack-pol")
    assert hijack.status == FabricTxStatus.VALID
    assert wf.fabric.await_validation(res.tx_id).status == FabricTxStatus.MVCC_READ_CONFLICT
    assert wf.lifecycle.active.version == 0


def test_E_mvcc_invalid_update_no_activation():
    wf = _wf()
    assert wf.lifecycle
    prev = wf.lifecycle.active
    t_before = wf.crypto.secrets.aa.t_a["doctor"].to_bytes()
    pending = wf.lifecycle.prepare_attribute_revocation("doctor", ["bob"])
    next_snap = wf.lifecycle.preview_snapshot(pending)

    deferred = wf.fabric.update_authorization(
        wf.owner_id,
        prev,
        new_attr_state_id=next_snap.attr_state_id,
        caller="aa",
        defer_validation=True,
    )
    # Competing UpdateAuthorization VALID first → deferred becomes MVCC-invalid
    win = wf.fabric.update_authorization(wf.owner_id, prev, new_policy_id="win-pol")
    assert win.status == FabricTxStatus.VALID
    lost = wf.fabric.await_validation(deferred.tx_id)
    assert lost.status == FabricTxStatus.MVCC_READ_CONFLICT

    wf.lifecycle.abort_pending_update(pending)
    assert wf.lifecycle.active.version == 0
    assert wf.lifecycle.active.attr_state_id == prev.attr_state_id
    assert wf.crypto.secrets.aa.t_a["doctor"].to_bytes() == t_before
    assert 1 not in wf.lifecycle.attr_by_ver


def test_F_acl_failure_no_activation():
    wf = _wf()
    prev = wf.lifecycle.active
    _force_acl_deny(wf)
    with pytest.raises(AuthorizationUpdateRejected):
        wf.revoke_attribute("doctor", revoked_users=["bob"])
    assert wf.lifecycle.active.matches(prev)
    assert wf.fabric.get_authorization_snapshot(wf.owner_id).version == 0  # type: ignore[union-attr]


def test_success_policy_fabric_then_activate_once():
    wf = _wf()
    assert wf.lifecycle
    local_before = wf.lifecycle.ledger.get(wf.owner_id).version
    prev = wf.lifecycle.active
    snap = wf.update_policy(OR(leaf("doctor"), leaf("nurse")))
    assert snap.version == 1
    fab = wf.fabric.get_authorization_snapshot(wf.owner_id)
    assert fab is not None
    assert fab.version == 1
    assert fab.policy_id == snap.policy_id
    assert fab.matches(snap)
    # No second LocalAuthLedger commit
    assert wf.lifecycle.ledger.get(wf.owner_id).version == local_before == 0
    assert wf.lifecycle.ledger.commit_log == []
    assert snap.attr_state_id == prev.attr_state_id  # carried forward


def test_success_attr_and_role_activate_after_valid_only():
    wf = _wf()
    assert wf.lifecycle and wf.crypto.secrets
    t0 = wf.crypto.secrets.aa.t_a["doctor"].to_bytes()
    pending = wf.lifecycle.prepare_attribute_revocation("doctor", ["bob"])
    assert wf.crypto.secrets.aa.t_a["doctor"].to_bytes() == t0
    wf.lifecycle.abort_pending_update(pending)
    assert wf.lifecycle.machine.phase == AuthPhase.ACTIVE

    t_before = wf.crypto.secrets.aa.t_a["doctor"].to_bytes()
    snap_a = wf.revoke_attribute("doctor", revoked_users=["bob"])
    assert snap_a.version == 1
    assert wf.crypto.secrets.aa.t_a["doctor"].to_bytes() != t_before
    assert wf.fabric.get_authorization_snapshot(wf.owner_id).attr_state_id == snap_a.attr_state_id
    assert wf.lifecycle.ledger.get(wf.owner_id).version == 0

    xi_before = wf.crypto.secrets.rm.xi.to_bytes()
    snap_r = wf.reassign_roles({"alice": ["AttendingPhysician"], "bob": ["Nurse"]})
    assert snap_r.version == 2
    assert wf.crypto.secrets.rm.xi.to_bytes() != xi_before
    assert wf.lifecycle.ledger.commit_log == []


def test_no_dual_authority_on_workflow_update():
    """LocalAuthLedger records stay at bootstrap ν=0; Fabric alone advances."""
    wf = _wf()
    key = auth_key(wf.owner_id)
    assert key in wf.lifecycle.ledger.records
    assert wf.lifecycle.ledger.records[key].version == 0
    wf.update_policy(OR(leaf("nurse"), leaf("doctor")))
    wf.revoke_attribute("doctor", revoked_users=["bob"])
    assert wf.lifecycle.ledger.records[key].version == 0
    assert len(wf.lifecycle.ledger.commit_log) == 0
    fab = wf.fabric.get_authorization_snapshot(wf.owner_id)
    assert fab is not None and fab.version == 2


def test_regression_failed_attr_then_segment_unchanged():
    wf = _wf()
    wf.publish(b"pre", targets=["AttendingPhysician"], seg_id="pre")
    _force_acl_deny(wf)
    with pytest.raises(AuthorizationUpdateRejected):
        wf.revoke_attribute("doctor", revoked_users=["bob"])
    # Restore ACL for subsequent publish
    wf.fabric.ledger.set_acl(
        "UpdateAuthorization",
        {wf.fabric.authority_id, "admin", "aa"},
    )
    wf.publish(b"post-fail", targets=["AttendingPhysician"], seg_id="post")
    assert wf.access("bob", "pre") == b"pre"
    assert wf.access("bob", "post") == b"post-fail"


def test_regression_failed_role_then_behavior_unchanged():
    wf = _wf()
    wf.publish(b"pre-r", targets=["AttendingPhysician"], seg_id="pr")
    _force_acl_deny(wf)
    with pytest.raises(AuthorizationUpdateRejected):
        wf.reassign_roles({"alice": ["AttendingPhysician"], "bob": ["Nurse"]})
    wf.fabric.ledger.set_acl(
        "UpdateAuthorization",
        {wf.fabric.authority_id, "admin", "aa"},
    )
    assert wf.access("bob", "pr") == b"pre-r"
    wf.publish(b"post-r", targets=["AttendingPhysician"], seg_id="por")
    assert wf.access("bob", "por") == b"post-r"


def test_prospective_attr_success_after_repair():
    wf = _wf()
    wf.publish(b"S_old", targets=["AttendingPhysician"], seg_id="Sold")
    wf.revoke_attribute("doctor", revoked_users=["bob"])
    wf.publish(b"S_new", targets=["AttendingPhysician"], seg_id="Snew")
    assert wf.access("alice", "Sold") == b"S_old"
    assert wf.access("alice", "Snew") == b"S_new"
    assert wf.access("bob", "Sold") == b"S_old"
    with pytest.raises(PermissionError):
        wf.access("bob", "Snew")


def test_prospective_role_success_after_repair():
    wf = _wf()
    wf.publish(b"R_old", targets=["AttendingPhysician"], seg_id="Rold")
    wf.reassign_roles({"alice": ["AttendingPhysician"], "bob": ["Nurse"]})
    wf.publish(b"R_new", targets=["AttendingPhysician"], seg_id="Rnew")
    assert wf.access("alice", "Rold") == b"R_old"
    assert wf.access("bob", "Rold") == b"R_old"
    assert wf.access("alice", "Rnew") == b"R_new"
    with pytest.raises(PermissionError):
        wf.access("bob", "Rnew")


def test_property1_still_enforced_in_fabric():
    """Refactor must not move consistency out of Fabric MVCC."""
    from core.authorization.snapshot import AuthorizationSnapshot
    from core.blockchain.client.fabric_client import FabricClient
    from core.canonical import eta_digest

    c = FabricClient()
    snap = AuthorizationSnapshot("o1", 0, "p", "a", "r")
    c.init_auth(snap)
    eta = eta_digest("c", "m", 0, "p", "a", "r")
    # Case A
    pending = c.commit_segment(
        "o1", "s1", "c", "m", 0, "p", "a", "r", eta, defer_validation=True
    )
    assert c.update_authorization("o1", snap, new_attr_state_id="a2").status == FabricTxStatus.VALID
    assert c.await_validation(pending.tx_id).status == FabricTxStatus.MVCC_READ_CONFLICT
    # Case B
    c2 = FabricClient()
    snap2 = AuthorizationSnapshot("o2", 0, "p", "a", "r")
    c2.init_auth(snap2)
    eta2 = eta_digest("c2", "m2", 0, "p", "a", "r")
    assert (
        c2.commit_segment("o2", "s2", "c2", "m2", 0, "p", "a", "r", eta2).status
        == FabricTxStatus.VALID
    )
    assert c2.update_authorization("o2", snap2, new_policy_id="p2").status == FabricTxStatus.VALID
