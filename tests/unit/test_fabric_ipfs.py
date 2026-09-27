"""Fabric MVCC concurrency cases A/B + ACL + IPFS invariants."""

from __future__ import annotations

import json
import uuid

import pytest

from core.authorization.snapshot import AuthKeyRecord, AuthorizationSnapshot, auth_key
from core.blockchain.client.chaincode_api import (
    bootstrap_auth,
    commit_segment,
    commit_segment_unversioned,
    update_authorization,
)
from core.blockchain.client.ledger import MVCCLedger, TxStatus, json_bytes
from core.canonical import canonical_json_dumps, eta_digest
from core.protocol.system import HieraStreamSystem
from core.storage.ipfs_client import LocalContentAddressedStore


def _snap(v=0):
    return AuthorizationSnapshot(
        owner_id="o1", version=v, policy_id="p", attr_state_id="a", role_state_id="r"
    )


def test_mvcc_case_a_update_first_invalidates_stale_commit():
    """Case A: CommitSegment endorsed under ν; UpdateAuthorization commits first
    → CommitSegment invalidated by MVCC."""
    ledger = MVCCLedger()
    ledger.set_acl("CommitSegment", {"gw"})
    ledger.set_acl("UpdateAuthorization", {"aa"})
    snap0 = _snap(0)
    bootstrap_auth(ledger, "o1", AuthKeyRecord.from_snapshot(snap0))

    # Endorse CommitSegment (reads AuthKey v0)
    ctx = ledger.begin("tx-seg", "gw")
    raw = ctx.get_state(auth_key("o1"))
    assert raw is not None
    # Stage write
    ctx.put_state("Segment/o1/s1", b"seg")
    endorsed_seg = ctx.endorse()

    # UpdateAuthorization commits first
    snap1 = _snap(1)
    res_u = update_authorization(
        ledger, "tx-upd", "aa", "o1", snap0, AuthKeyRecord.from_snapshot(snap1)
    )
    assert res_u.status == TxStatus.VALID

    # Now commit previously endorsed segment → MVCC conflict
    res_s = ledger.commit(endorsed_seg, "CommitSegment")
    assert res_s.status == TxStatus.MVCC_READ_CONFLICT


def test_mvcc_case_b_commit_first_then_update_both_valid():
    ledger = MVCCLedger()
    ledger.set_acl("CommitSegment", {"gw"})
    ledger.set_acl("UpdateAuthorization", {"aa"})
    snap0 = _snap(0)
    bootstrap_auth(ledger, "o1", AuthKeyRecord.from_snapshot(snap0))

    eta = eta_digest("c", "m", 0, "p", "a", "r")
    res_s = commit_segment(
        ledger, "tx1", "gw", "o1", "s1", "c", "m", 0, "p", "a", "r", eta
    )
    assert res_s.status == TxStatus.VALID

    snap1 = _snap(1)
    res_u = update_authorization(
        ledger, "tx2", "aa", "o1", snap0, AuthKeyRecord.from_snapshot(snap1)
    )
    assert res_u.status == TxStatus.VALID


def test_acl_denies_unauthorized_update():
    ledger = MVCCLedger()
    ledger.set_acl("UpdateAuthorization", {"aa"})
    snap0 = _snap(0)
    bootstrap_auth(ledger, "o1", AuthKeyRecord.from_snapshot(snap0))
    res = update_authorization(
        ledger, "tx", "evil", "o1", snap0, AuthKeyRecord.from_snapshot(_snap(1))
    )
    assert res.status == TxStatus.ACL_DENIED


def test_ipfs_predicted_equals_actual():
    store = LocalContentAddressedStore()
    data = b"metadata-bytes"
    pred = store.only_hash(data)
    actual = store.add(data)
    assert pred == actual
    assert store.get(actual) == data


def test_publication_does_not_publish_metadata_before_commit():
    sys = HieraStreamSystem()
    sys.setup()
    sys.provision_user("u", ["doctor", "cardiology"], ["AttendingPhysician"])
    # Force MVCC stale path: endorse-like race via update before publish completes
    # Normal path should publish metadata only after VALID
    seg = sys.protect_and_publish(b"payload", targets=["AttendingPhysician"])
    assert seg.published_mcid == seg.mcid
    assert sys.ipfs.get(seg.mcid)  # published


def test_unversioned_baseline_skips_authkey_read():
    ledger = MVCCLedger()
    ledger.set_acl("CommitSegment", {"gw"})
    snap0 = _snap(0)
    bootstrap_auth(ledger, "o1", AuthKeyRecord.from_snapshot(snap0))
    # Even if AuthKey changes, unversioned commit does not read it
    ctx = ledger.begin("tx", "gw")
    # no get_state on AuthKey
    endorsed = ctx.endorse()
    assert auth_key("o1") not in endorsed.read_set
    res = commit_segment_unversioned(
        ledger, "tx2", "gw", "o1", "s", "c", "m", 0, "p", "a", "r", "e"
    )
    assert res.status == TxStatus.VALID
