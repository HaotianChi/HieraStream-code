"""UpdateAuthorization expectedVersion semantics (manuscript sync).

Covers PeerMVCC FabricClient path: AuthKey(ownerId) read/write, explicit
expectedVersion guard, carry-forward nextRefs, MVCC races, and selective retry
invariants unchanged by the guard.
"""

from __future__ import annotations

import pytest

from core.authorization.snapshot import AuthorizationSnapshot, auth_key
from core.blockchain.client.fabric_client import FabricClient
from core.blockchain.client.peer_backend import FabricTxStatus
from core.canonical import eta_digest
from core.crypto.python.access_tree import AND, leaf
from core.protocol.workflow import HieraStreamWorkflow


def _snap(owner: str = "o1", v: int = 0, p: str = "p", a: str = "a", r: str = "r") -> AuthorizationSnapshot:
    return AuthorizationSnapshot(
        owner_id=owner, version=v, policy_id=p, attr_state_id=a, role_state_id=r
    )


@pytest.fixture
def client() -> FabricClient:
    c = FabricClient(owner_gateway_id="gw", authority_id="aa")
    c.init_auth(_snap())
    return c


def test_01_matching_expected_version_succeeds(client: FabricClient):
    snap = client.get_authorization_snapshot("o1")
    assert snap is not None and snap.version == 0
    res = client.update_authorization("o1", snap, new_policy_id="p1")
    assert res.status == FabricTxStatus.VALID
    out = client.get_authorization_snapshot("o1")
    assert out is not None and out.version == 1 and out.policy_id == "p1"


def test_02_mismatched_expected_version_rejects(client: FabricClient):
    stale = _snap(v=1)  # ledger is still ν=0
    res = client.update_authorization("o1", stale, new_policy_id="pX")
    assert res.status == FabricTxStatus.INVALID
    assert "expectedVersion" in res.reason


def test_03_rejected_update_leaves_state_unchanged(client: FabricClient):
    before = client.get_authorization_snapshot("o1")
    assert before is not None
    res = client.update_authorization("o1", _snap(v=99), new_policy_id="nope")
    assert res.status == FabricTxStatus.INVALID
    after = client.get_authorization_snapshot("o1")
    assert after == before


def test_04_successful_update_increments_exactly_once(client: FabricClient):
    snap = client.get_authorization_snapshot("o1")
    assert snap is not None
    assert client.update_authorization("o1", snap, new_attr_state_id="a1").status == FabricTxStatus.VALID
    out = client.get_authorization_snapshot("o1")
    assert out is not None and out.version == snap.version + 1


def test_05_unchanged_refs_carried_forward(client: FabricClient):
    snap = client.get_authorization_snapshot("o1")
    assert snap is not None
    assert client.update_authorization("o1", snap, new_policy_id="pOnly").status == FabricTxStatus.VALID
    out = client.get_authorization_snapshot("o1")
    assert out is not None
    assert out.policy_id == "pOnly"
    assert out.attr_state_id == snap.attr_state_id
    assert out.role_state_id == snap.role_state_id


def test_06_policy_only_update(client: FabricClient):
    snap = client.get_authorization_snapshot("o1")
    assert snap is not None
    assert client.update_authorization("o1", snap, new_policy_id="p2").status == FabricTxStatus.VALID
    out = client.get_authorization_snapshot("o1")
    assert out is not None
    assert out.identity_tuple() == (1, "p2", "a", "r")


def test_07_attribute_only_update(client: FabricClient):
    snap = client.get_authorization_snapshot("o1")
    assert snap is not None
    assert client.update_authorization("o1", snap, new_attr_state_id="a2").status == FabricTxStatus.VALID
    out = client.get_authorization_snapshot("o1")
    assert out is not None
    assert out.identity_tuple() == (1, "p", "a2", "r")


def test_08_role_only_update(client: FabricClient):
    snap = client.get_authorization_snapshot("o1")
    assert snap is not None
    assert client.update_authorization("o1", snap, new_role_state_id="r2").status == FabricTxStatus.VALID
    out = client.get_authorization_snapshot("o1")
    assert out is not None
    assert out.identity_tuple() == (1, "p", "a", "r2")


def test_09_joint_update(client: FabricClient):
    snap = client.get_authorization_snapshot("o1")
    assert snap is not None
    res = client.update_authorization(
        "o1", snap, new_policy_id="pJ", new_attr_state_id="aJ", new_role_state_id="rJ"
    )
    assert res.status == FabricTxStatus.VALID
    out = client.get_authorization_snapshot("o1")
    assert out is not None
    assert out.identity_tuple() == (1, "pJ", "aJ", "rJ")


def test_10_two_concurrent_updates_from_same_version_at_most_one_wins(client: FabricClient):
    snap0 = client.get_authorization_snapshot("o1")
    assert snap0 is not None
    pend_a = client.update_authorization(
        "o1", snap0, new_policy_id="pA", defer_validation=True
    )
    pend_b = client.update_authorization(
        "o1", snap0, new_attr_state_id="aB", defer_validation=True
    )
    assert pend_a.status == FabricTxStatus.PENDING
    assert pend_b.status == FabricTxStatus.PENDING
    r1 = client.await_validation(pend_a.tx_id)
    r2 = client.await_validation(pend_b.tx_id)
    statuses = {r1.status, r2.status}
    assert FabricTxStatus.VALID in statuses
    assert FabricTxStatus.MVCC_READ_CONFLICT in statuses
    out = client.get_authorization_snapshot("o1")
    assert out is not None and out.version == 1
    # Exactly one of the two nextRefs tuples is installed.
    assert (out.policy_id == "pA" and out.attr_state_id == "a") or (
        out.policy_id == "p" and out.attr_state_id == "aB"
    )


def test_11_commit_segment_and_update_share_authkey(client: FabricClient):
    snap0 = client.get_authorization_snapshot("o1")
    assert snap0 is not None
    eta = eta_digest("c", "m", 0, "p", "a", "r")
    pend_s = client.commit_segment(
        "o1", "s1", "c", "m", 0, "p", "a", "r", eta, defer_validation=True
    )
    pend_u = client.update_authorization(
        "o1", snap0, new_role_state_id="r2", defer_validation=True
    )
    key = auth_key("o1")
    tx_s = client.ledger.pending[pend_s.tx_id]
    tx_u = client.ledger.pending[pend_u.tx_id]
    assert key in client.read_set_keys(tx_s)
    assert key in client.read_set_keys(tx_u)
    assert key in tx_u.write_set


def test_12_fabric_mvcc_conflict_still_correct(client: FabricClient):
    snap0 = client.get_authorization_snapshot("o1")
    assert snap0 is not None
    eta = eta_digest("c", "m", 0, "p", "a", "r")
    pending = client.commit_segment(
        "o1", "s1", "c", "m", 0, "p", "a", "r", eta, defer_validation=True
    )
    assert client.update_authorization("o1", snap0, new_attr_state_id="a2").status == FabricTxStatus.VALID
    res_s = client.await_validation(pending.tx_id)
    assert res_s.status == FabricTxStatus.MVCC_READ_CONFLICT
    assert "AuthKey/o1" in res_s.reason


def test_13_selective_retry_behavior_unchanged():
    """Stale CommitSegment + selective regen still works with expectedVersion guard."""
    wf = HieraStreamWorkflow(owner_id="owner-ua-retry")
    wf.setup(initial_policy=AND(leaf("doctor"), leaf("cardiology")))
    wf.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    status, final = wf.publish_with_stale_race(
        b"payload-ua", targets=["AttendingPhysician"], seg_id="seg-ua", race_update="attr"
    )
    assert status == FabricTxStatus.MVCC_READ_CONFLICT
    assert wf.access("alice", "seg-ua") == b"payload-ua"
    assert final.snapshot.version >= 1
    assert final.meta_published


def test_stale_expected_version_after_prior_update(client: FabricClient):
    snap0 = client.get_authorization_snapshot("o1")
    assert snap0 is not None
    assert client.update_authorization("o1", snap0, new_policy_id="p1").status == FabricTxStatus.VALID
    # Reusing snap0 must fail expectedVersion (ledger is ν=1).
    res = client.update_authorization("o1", snap0, new_policy_id="p2")
    assert res.status == FabricTxStatus.INVALID
    assert "expectedVersion" in res.reason
    out = client.get_authorization_snapshot("o1")
    assert out is not None and out.version == 1 and out.policy_id == "p1"
