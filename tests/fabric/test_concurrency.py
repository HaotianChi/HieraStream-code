"""Tests for test_concurrency."""
from __future__ import annotations

import pytest

from core.authorization.snapshot import AuthorizationSnapshot, auth_key
from core.blockchain.client.fabric_client import FabricClient
from core.blockchain.client.peer_backend import FabricTxStatus
from core.canonical import eta_digest


def _snap(owner="o1", v=0, p="p", a="a", r="r") -> AuthorizationSnapshot:
    return AuthorizationSnapshot(
        owner_id=owner, version=v, policy_id=p, attr_state_id=a, role_state_id=r
    )


@pytest.fixture
def client() -> FabricClient:
    c = FabricClient(owner_gateway_id="gw", authority_id="aa")
    c.init_auth(_snap())
    return c


def test_case1_update_first_invalidates_stale_commit(client: FabricClient):
    snap0 = client.get_authorization_snapshot("o1")
    assert snap0 is not None
    eta = eta_digest("c", "m", 0, "p", "a", "r")

    # Endorse CommitSegment under ν — defer peer validation
    pending = client.commit_segment(
        "o1", "s1", "c", "m", 0, "p", "a", "r", eta, defer_validation=True
    )
    assert pending.status == FabricTxStatus.PENDING

    # UpdateAuthorization commits first
    res_u = client.update_authorization("o1", snap0, new_attr_state_id="a2")
    assert res_u.status == FabricTxStatus.VALID

    # Stale CommitSegment fails Fabric MVCC on AuthKey
    res_s = client.await_validation(pending.tx_id)
    assert res_s.status == FabricTxStatus.MVCC_READ_CONFLICT
    assert "AuthKey/o1" in res_s.reason


def test_case2_commit_first_then_update_both_valid(client: FabricClient):
    snap0 = client.get_authorization_snapshot("o1")
    assert snap0 is not None
    eta = eta_digest("c", "m", 0, "p", "a", "r")
    res_s = client.commit_segment("o1", "s1", "c", "m", 0, "p", "a", "r", eta)
    assert res_s.status == FabricTxStatus.VALID
    res_u = client.update_authorization("o1", snap0, new_policy_id="p2")
    assert res_u.status == FabricTxStatus.VALID
    assert client.get_authorization_snapshot("o1").version == 1  # type: ignore
    assert client.get_segment("o1", "s1") is not None


def test_case3_mismatched_tuple_rejected(client: FabricClient):
    eta = eta_digest("c", "m", 0, "p", "a", "r")
    # Wrong version in commit args
    res = client.commit_segment("o1", "s", "c", "m", 1, "p", "a", "r", eta)
    assert res.status == FabricTxStatus.INVALID
    assert "mismatch" in res.reason


def test_case4_acl_rejection(client: FabricClient):
    snap0 = client.get_authorization_snapshot("o1")
    assert snap0 is not None
    res = client.update_authorization("o1", snap0, new_policy_id="pX", caller="evil")
    assert res.status == FabricTxStatus.ACL_DENIED


def test_case5_both_paths_touch_same_authkey(client: FabricClient):
    snap0 = client.get_authorization_snapshot("o1")
    assert snap0 is not None
    eta = eta_digest("c", "m", 0, "p", "a", "r")
    # Defer both to inspect read-sets
    pend_s = client.commit_segment(
        "o1", "s1", "c", "m", 0, "p", "a", "r", eta, defer_validation=True
    )
    pend_u = client.update_authorization(
        "o1", snap0, new_role_state_id="r2", defer_validation=True
    )
    tx_s = client.ledger.pending[pend_s.tx_id]
    tx_u = client.ledger.pending[pend_u.tx_id]
    key = auth_key("o1")
    assert key in client.read_set_keys(tx_s)
    assert key in client.read_set_keys(tx_u)
    assert key in tx_u.write_set
    assert f"Segment/o1/s1" in tx_s.write_set


def test_management_register_and_query(client: FabricClient):
    assert client.register_owner("o1", "gw").status == FabricTxStatus.VALID
    assert client.register_policy_state("p", 0, {"kind": "policy"}).status == FabricTxStatus.VALID
    assert client.register_attribute_state("a", 0, {"pk": {}}).status == FabricTxStatus.VALID
    assert client.register_role_state("r", 0, {"pk": {}}).status == FabricTxStatus.VALID
    snap = client.get_authorization_snapshot("o1")
    assert snap is not None
    assert snap.identity_tuple() == (0, "p", "a", "r")


def test_inspect_status_and_eta_mismatch(client: FabricClient):
    res = client.commit_segment("o1", "s", "c", "m", 0, "p", "a", "r", "deadbeef")
    assert res.status == FabricTxStatus.INVALID
    assert client.inspect_transaction_status(res.tx_id) is not None
