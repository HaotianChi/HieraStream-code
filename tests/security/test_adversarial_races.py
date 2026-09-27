"""Authorization races + prepare–commit–activate adversarial tests."""

from __future__ import annotations

import itertools

import pytest

from core.authorization.lifecycle import AuthorizationLifecycle
from core.authorization.machine import AuthPhase, PendingBundle
from core.authorization.snapshot import AuthorizationSnapshot
from core.authorization.store import CommitRejected
from core.authorization.errors import AuthorizationUpdateRejected
from core.blockchain.client.fabric_client import FabricClient
from core.blockchain.client.peer_backend import FabricTxStatus
from core.canonical import eta_digest
from core.protocol.workflow import HieraStreamWorkflow


def _snap(owner="o1", v=0, p="p", a="a", r="r") -> AuthorizationSnapshot:
    return AuthorizationSnapshot(
        owner_id=owner, version=v, policy_id=p, attr_state_id=a, role_state_id=r
    )


# ---------------------------------------------------------------------------
# Authorization races — Property 1 vs ledger order
# ---------------------------------------------------------------------------


def test_race_commit_vs_policy_update_orders():
    """Different validation orders: Update first ⇒ segment MVCC; Commit first ⇒ both VALID."""
    # Order A: update then segment
    c = FabricClient()
    c.init_auth(_snap())
    eta = eta_digest("c", "m", 0, "p", "a", "r")
    pend = c.commit_segment("o1", "sA", "c", "m", 0, "p", "a", "r", eta, defer_validation=True)
    snap0 = c.get_authorization_snapshot("o1")
    assert c.update_authorization("o1", snap0, new_policy_id="p2").status == FabricTxStatus.VALID
    assert c.await_validation(pend.tx_id).status == FabricTxStatus.MVCC_READ_CONFLICT
    assert c.get_segment("o1", "sA") is None

    # Order B: segment then update
    c2 = FabricClient()
    c2.init_auth(_snap(owner="o2"))
    eta2 = eta_digest("c2", "m2", 0, "p", "a", "r")
    assert (
        c2.commit_segment("o2", "sB", "c2", "m2", 0, "p", "a", "r", eta2).status
        == FabricTxStatus.VALID
    )
    snap = c2.get_authorization_snapshot("o2")
    assert c2.update_authorization("o2", snap, new_policy_id="p3").status == FabricTxStatus.VALID
    assert c2.get_segment("o2", "sB") is not None


def test_race_attr_revocation_vs_commit_serialization():
    c = FabricClient()
    c.init_auth(_snap())
    eta = eta_digest("c", "m", 0, "p", "a", "r")
    pend_s = c.commit_segment("o1", "s1", "c", "m", 0, "p", "a", "r", eta, defer_validation=True)
    snap0 = c.get_authorization_snapshot("o1")
    pend_u = c.update_authorization(
        "o1", snap0, new_attr_state_id="a_rev", defer_validation=True
    )
    # Force update validated before segment (ledger serialization)
    assert c.await_validation(pend_u.tx_id).status == FabricTxStatus.VALID
    assert c.await_validation(pend_s.tx_id).status == FabricTxStatus.MVCC_READ_CONFLICT
    # Property 1: published segment must match AuthKey that preceded it — none published
    assert c.get_segment("o1", "s1") is None
    snap1 = c.get_authorization_snapshot("o1")
    assert snap1 is not None and snap1.attr_state_id == "a_rev"


def test_race_role_reassignment_vs_commit():
    wf = HieraStreamWorkflow(owner_id="race-role")
    wf.setup()
    wf.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    status, final = wf.publish_with_stale_race(
        b"role-race", targets=["AttendingPhysician"], seg_id="rr", race_update="role"
    )
    assert status == FabricTxStatus.MVCC_READ_CONFLICT
    assert wf.access("alice", final.seg_id) == b"role-race"
    rec = wf.fabric.get_segment(wf.owner_id, final.seg_id)
    assert rec is not None
    # Property 1: segment tuple equals the AuthKey snapshot used at VALID commit
    assert (
        int(rec["version"]),
        rec["policyId"],
        rec["attrStateId"],
        rec["roleStateId"],
    ) == final.snapshot.identity_tuple()


def test_endorsement_timing_permutations_property1():
    """All non-empty endorsement/submit orders among 1 CommitSegment + 1 Update."""
    eta = eta_digest("c", "m", 0, "p", "a", "r")
    for order in itertools.permutations(["seg", "upd"]):
        c = FabricClient()
        c.init_auth(_snap(owner=f"o-{''.join(order)}"))
        owner = f"o-{''.join(order)}"
        # re-init with correct owner
        c = FabricClient()
        c.init_auth(_snap(owner=owner))
        snap0 = c.get_authorization_snapshot(owner)
        assert snap0 is not None
        pend_s = c.commit_segment(
            owner, "s", "c", "m", 0, "p", "a", "r", eta, defer_validation=True
        )
        pend_u = c.update_authorization(
            owner, snap0, new_role_state_id="rX", defer_validation=True
        )
        results = {}
        for step in order:
            tid = pend_s.tx_id if step == "seg" else pend_u.tx_id
            results[step] = c.await_validation(tid)
        if order[0] == "upd":
            assert results["upd"].status == FabricTxStatus.VALID
            assert results["seg"].status == FabricTxStatus.MVCC_READ_CONFLICT
            assert c.get_segment(owner, "s") is None
        else:
            assert results["seg"].status == FabricTxStatus.VALID
            # Update still VALID after segment (read AuthKey version advanced by write)
            assert results["upd"].status == FabricTxStatus.VALID
            assert c.get_segment(owner, "s") is not None


def test_triple_race_commit_policy_attr():
    """Three deferred txs; AuthKey writers collide; Property 1 on survivors."""
    c = FabricClient()
    c.init_auth(_snap())
    eta = eta_digest("c", "m", 0, "p", "a", "r")
    snap0 = c.get_authorization_snapshot("o1")
    assert snap0 is not None
    p_seg = c.commit_segment("o1", "s1", "c", "m", 0, "p", "a", "r", eta, defer_validation=True)
    p_pol = c.update_authorization("o1", snap0, new_policy_id="p2", defer_validation=True)
    p_attr = c.update_authorization("o1", snap0, new_attr_state_id="a2", defer_validation=True)
    # Serialize: policy first wins AuthKey write
    assert c.await_validation(p_pol.tx_id).status == FabricTxStatus.VALID
    assert c.await_validation(p_attr.tx_id).status == FabricTxStatus.MVCC_READ_CONFLICT
    assert c.await_validation(p_seg.tx_id).status == FabricTxStatus.MVCC_READ_CONFLICT
    snap = c.get_authorization_snapshot("o1")
    assert snap is not None and snap.policy_id == "p2" and snap.version == 1


# ---------------------------------------------------------------------------
# Prepare → Commit → Activate
# ---------------------------------------------------------------------------


def test_failed_authorization_transaction_no_activate():
    lc = AuthorizationLifecycle(owner_id="fail-act")
    lc.setup()
    lc.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    before = lc.active
    lc.ledger.fail_next_commit = True
    with pytest.raises(AuthorizationUpdateRejected):
        lc.revoke_attribute("doctor", revoked_users=["alice"])
    assert lc.active.matches(before)
    assert lc.machine.phase == AuthPhase.ACTIVE
    assert lc.machine.pending is None


def test_delayed_commit_segments_bind_active_not_pending():
    lc = AuthorizationLifecycle(owner_id="delay")
    lc.setup()
    lc.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    v0 = lc.active.version
    # Manually enter PENDING without committing
    lc.machine.enter_pending(PendingBundle(next_version=v0 + 1, kind="policy"))
    assert lc.machine.phase == AuthPhase.PENDING
    assert lc.active.version == v0
    rec = lc.protect_segment("during-pending", b"still-v0", targets=["AttendingPhysician"])
    assert rec.snapshot.version == v0
    assert rec.snapshot.identity_tuple() == lc.active.identity_tuple()
    # Abort pending — ACTIVE unchanged
    lc.machine.abort_pending()
    assert lc.active.version == v0
    assert lc.recover_segment("alice", "during-pending") == b"still-v0"


def test_concurrent_segment_during_pending_state():
    lc = AuthorizationLifecycle(owner_id="conc-pend")
    lc.setup()
    lc.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    active = lc.active
    lc.machine.enter_pending(
        PendingBundle(next_version=active.version + 1, kind="attribute")
    )
    # Concurrent publication must not observe pending ν+1
    for i in range(3):
        rec = lc.protect_segment(f"s{i}", f"p{i}".encode(), targets=["AttendingPhysician"])
        assert rec.snapshot.matches(active)
        assert rec.snapshot.version != active.version + 1
    lc.machine.abort_pending()


def test_retry_after_activation():
    lc = AuthorizationLifecycle(owner_id="retry-act")
    lc.setup()
    lc.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    lc.provision_user("bob", ["doctor", "cardiology"], ["AttendingPhysician"])
    # Fail once, then succeed
    lc.ledger.fail_next_commit = True
    with pytest.raises(AuthorizationUpdateRejected):
        lc.revoke_attribute("doctor", revoked_users=["bob"])
    assert lc.active.version == 0
    snap = lc.revoke_attribute("doctor", revoked_users=["bob"])
    assert snap.version == 1
    assert lc.machine.phase == AuthPhase.ACTIVE
    lc.protect_segment("post", b"after", targets=["AttendingPhysician"])
    assert lc.recover_segment("alice", "post") == b"after"
    with pytest.raises(PermissionError):
        lc.recover_segment("bob", "post")


def test_activate_requires_committed():
    lc = AuthorizationLifecycle(owner_id="act-req")
    lc.setup()
    with pytest.raises(RuntimeError, match="COMMITTED"):
        lc.machine.activate()
    lc.machine.enter_pending(PendingBundle(next_version=1, kind="policy"))
    with pytest.raises(RuntimeError, match="COMMITTED"):
        lc.machine.activate()
