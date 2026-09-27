"""IPFS tamper + ACL adversarial tests."""

from __future__ import annotations

import pytest

from core.authorization.snapshot import AuthorizationSnapshot, auth_key
from core.blockchain.client.fabric_client import FabricClient
from core.blockchain.client.peer_backend import FabricTxStatus
from core.canonical import eta_digest
from core.crypto.python.access_tree import AND, leaf
from core.protocol.workflow import HieraStreamWorkflow


def _wf() -> HieraStreamWorkflow:
    w = HieraStreamWorkflow(owner_id="ipfs-acl")
    w.setup()
    w.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    return w


# ---------------------------------------------------------------------------
# IPFS
# ---------------------------------------------------------------------------


def test_incorrect_payload_cid():
    wf = _wf()
    wf.publish(b"payload", targets=["AttendingPhysician"], seg_id="cid1")
    rec = wf.fabric.get_segment(wf.owner_id, "cid1")
    assert rec is not None
    from core.blockchain.client.fabric_client import _json_bytes

    wrong = wf.ipfs.add(b"other-bytes")
    bad = dict(rec)
    bad["CID"] = wrong
    key = f"Segment/{wf.owner_id}/cid1"
    wf.fabric.ledger.bootstrap_put(key, _json_bytes(bad))
    with pytest.raises(ValueError, match="CID|tamper|payload|eta"):
        wf.access("alice", "cid1")


def test_incorrect_metadata_cid():
    wf = _wf()
    wf.publish(b"meta", targets=["AttendingPhysician"], seg_id="mcid1")
    rec = wf.fabric.get_segment(wf.owner_id, "mcid1")
    assert rec is not None
    from core.blockchain.client.fabric_client import _json_bytes

    bad = dict(rec)
    bad["MCID"] = wf.ipfs.add(b'{"forged":true}')
    key = f"Segment/{wf.owner_id}/mcid1"
    wf.fabric.ledger.bootstrap_put(key, _json_bytes(bad))
    with pytest.raises(ValueError, match="MCID|tamper|metadata|eta"):
        wf.access("alice", "mcid1")


def test_predicted_mcid_mismatch():
    wf = _wf()
    pending = wf.gateway.protect_payload("pm", b"x", ["AttendingPhysician"])
    snap = wf.gateway.read_active_snapshot()
    tree = AND(leaf("doctor"), leaf("cardiology"))
    result, meta, mcid, _eta = wf.gateway.attempt_commit(pending, snap, tree)
    assert result.status == FabricTxStatus.VALID
    # Mutate metadata before publish → predicted MCID mismatch
    meta = dict(meta)
    meta["tampered"] = True
    with pytest.raises(RuntimeError, match="MCID"):
        wf.gateway.publish_metadata_after_valid(pending, meta, mcid)


def test_metadata_byte_mutation():
    wf = _wf()
    seg = wf.publish(b"honest-meta", targets=["AttendingPhysician"], seg_id="mb")
    rec = wf.fabric.get_segment(wf.owner_id, "mb")
    assert rec is not None
    raw = bytearray(wf.ipfs.get(rec["MCID"]))
    raw[0] ^= 0xFF
    wf.ipfs.local._store[rec["MCID"]] = bytes(raw)
    with pytest.raises(ValueError, match="MCID|tamper|metadata"):
        wf.access("alice", "mb")


def test_payload_byte_mutation():
    wf = _wf()
    seg = wf.publish(b"honest-payload", targets=["AttendingPhysician"], seg_id="pb")
    rec = wf.fabric.get_segment(wf.owner_id, "pb")
    assert rec is not None
    raw = bytearray(wf.ipfs.get(rec["CID"]))
    raw[-3] ^= 0xAA
    wf.ipfs.local._store[rec["CID"]] = bytes(raw)
    with pytest.raises(ValueError, match="CID|tamper|payload"):
        wf.access("alice", "pb")


def test_stale_metadata_publication_attempt():
    """Metadata for stale endorsement must not be published; retry uses new MCID."""
    wf = _wf()
    status, final = wf.publish_with_stale_race(
        b"stale-meta", targets=["AttendingPhysician"], seg_id="sm", race_update="policy"
    )
    assert status == FabricTxStatus.MVCC_READ_CONFLICT
    assert final.meta_published
    assert wf.gateway.published_mcids.get("sm") == final.mcid
    # unpublished_predictions is overwritten on retry; published set has only final
    assert list(wf.gateway.published_mcids.values()).count(final.mcid) == 1


# ---------------------------------------------------------------------------
# ACL
# ---------------------------------------------------------------------------


def test_acl_unauthorized_commit_segment():
    c = FabricClient()
    snap = AuthorizationSnapshot("o1", 0, "p", "a", "r")
    c.init_auth(snap)
    eta = eta_digest("c", "m", 0, "p", "a", "r")
    res = c.commit_segment("o1", "s", "c", "m", 0, "p", "a", "r", eta, caller="eve")
    assert res.status == FabricTxStatus.ACL_DENIED


def test_acl_unauthorized_update_authorization():
    c = FabricClient()
    snap = AuthorizationSnapshot("o1", 0, "p", "a", "r")
    c.init_auth(snap)
    res = c.update_authorization("o1", snap, new_policy_id="pX", caller="eve")
    assert res.status == FabricTxStatus.ACL_DENIED


def test_acl_unauthorized_state_mutation():
    """Unauthorized caller cannot Register* / UpdateAuthorization state writes."""
    c = FabricClient()
    snap = AuthorizationSnapshot("o1", 0, "p", "a", "r")
    c.init_auth(snap)
    # Forge UpdateAuthorization endorsement as attacker
    tx_id = "evil-upd"
    ctx = c.ledger.begin(tx_id, "eve", "UpdateAuthorization")
    key = auth_key("o1")
    ctx.get_state(key)
    from core.blockchain.client.fabric_client import _json_bytes

    ctx.put_state(
        key,
        _json_bytes(
            {
                "ownerId": "o1",
                "version": 99,
                "policyId": "evil",
                "attrStateId": "evil",
                "roleStateId": "evil",
            }
        ),
    )
    endorsed = ctx.endorse()
    res = c.ledger.validate_and_commit(endorsed)
    assert res.status == FabricTxStatus.ACL_DENIED
    # AuthKey unchanged
    after = c.get_authorization_snapshot("o1")
    assert after is not None and after.version == 0
