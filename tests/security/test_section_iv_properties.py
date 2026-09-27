"""Section IV Properties 1–3 + confidentiality / tamper evidence (executable)."""

from __future__ import annotations

import pytest

from core.authorization.lifecycle import AuthorizationLifecycle
from core.authorization.snapshot import AuthorizationSnapshot
from core.blockchain.client.fabric_client import FabricClient
from core.blockchain.client.peer_backend import FabricTxStatus
from core.canonical import eta_digest
from core.crypto.python.access_tree import AND, leaf
from core.crypto.python.hierarchy import HEALTHCARE_FIXTURE
from core.crypto.python.segment import SegmentCrypto
from core.protocol.workflow import HieraStreamWorkflow


def test_property1_authorization_consistent_publication():
    """Prop.1: UpdateAuthorization before CommitSegment ⇒ MVCC invalidates segment."""
    client = FabricClient()
    snap = AuthorizationSnapshot("o1", 0, "p", "a", "r")
    client.init_auth(snap)
    eta = eta_digest("c", "m", 0, "p", "a", "r")
    pending = client.commit_segment(
        "o1", "s1", "c", "m", 0, "p", "a", "r", eta, defer_validation=True
    )
    assert pending.status == FabricTxStatus.PENDING
    assert client.update_authorization("o1", snap, new_attr_state_id="a2").status == FabricTxStatus.VALID
    res = client.await_validation(pending.tx_id)
    assert res.status == FabricTxStatus.MVCC_READ_CONFLICT
    assert "AuthKey/o1" in res.reason
    # Segment must not be present
    assert client.get_segment("o1", "s1") is None


def test_property1_valid_segment_matches_authkey_tuple():
    """Prop.1: every VALID R_j equals AuthKey that preceded it."""
    wf = HieraStreamWorkflow(owner_id="prop1")
    snap0 = wf.setup()
    wf.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    seg = wf.publish(b"p1", targets=["AttendingPhysician"], seg_id="s0")
    rec = wf.fabric.get_segment(wf.owner_id, "s0")
    assert rec is not None
    assert int(rec["version"]) == seg.snapshot.version == snap0.version
    assert rec["policyId"] == seg.snapshot.policy_id
    assert rec["attrStateId"] == seg.snapshot.attr_state_id
    assert rec["roleStateId"] == seg.snapshot.role_state_id


def test_property2_attribute_forward_revocation():
    """Prop.2: revoked user cannot decrypt future segments; historical CT unchanged."""
    wf = HieraStreamWorkflow(owner_id="prop2")
    wf.setup()
    wf.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    wf.provision_user("bob", ["doctor", "cardiology"], ["AttendingPhysician"])
    old = wf.publish(b"before-revoke", targets=["AttendingPhysician"], seg_id="old")
    ct_before = old.ct_aes
    wf.revoke_attribute("doctor", revoked_users=["bob"])
    # Historical payload bytes unchanged (prospective)
    assert wf.segments["old"].ct_aes == ct_before
    # Alice (refreshed) still accesses old + new
    assert wf.access("alice", "old") == b"before-revoke"
    new = wf.publish(b"after-revoke", targets=["AttendingPhysician"], seg_id="new")
    assert wf.access("alice", new.seg_id) == b"after-revoke"
    # Bob lacks refreshed E_ua for doctor under new attrStateId
    with pytest.raises(PermissionError):
        wf.access("bob", new.seg_id)


def test_property3_role_forward_revocation():
    """Prop.3: after demotion, old RK cannot open future role envelopes."""
    wf = HieraStreamWorkflow(owner_id="prop3")
    wf.setup()
    wf.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    wf.provision_user("bob", ["doctor", "cardiology"], ["AttendingPhysician"])
    # Demote bob to Nurse — loses AttendingPhysician RK under new ξ
    wf.reassign_roles({"alice": ["AttendingPhysician"], "bob": ["Nurse"]})
    seg = wf.publish(b"role-future", targets=["AttendingPhysician"], seg_id="rf")
    assert wf.access("alice", seg.seg_id) == b"role-future"
    with pytest.raises(PermissionError):
        wf.access("bob", seg.seg_id)


def test_confidentiality_dual_share_required():
    """IV: both Z^A and Z^R needed — attr-only path insufficient for dual-layer key."""
    from core.crypto.python.kdf_aead import derive_segment_key, aead_decrypt

    c = SegmentCrypto()
    c.ca_setup()
    c.aa_setup(["doctor", "cardiology"])
    c.role_setup(HEALTHCARE_FIXTURE)
    user = c.aa_keygen("u", ["doctor", "cardiology"])
    role = c.ca_role_user("u")
    c.rm_issue_rk("AttendingPhysician", role)
    tree = AND(leaf("doctor"), leaf("cardiology"))
    pt = b"dual-secret"
    seg = c.protect_segment(pt, tree, ["AttendingPhysician"])
    # Recover only ZA via attr path
    Bj = c.outsource_attr_transform(seg.attr_ct, user.to_outsource_keys())
    assert Bj is not None
    ZA = c.user_recover_ZA(seg.attr_ct, Bj, user.usk1)
    # Wrong ZR ⇒ wrong key
    bad_key = derive_segment_key(ZA, c.sample_ZR())
    with pytest.raises(Exception):
        aead_decrypt(bad_key, seg.ct_aes)
    ok = c.recover_segment(seg, user, role, ["AttendingPhysician"])
    assert ok == pt


def test_tamper_evidence_cid_eta():
    """IV: CID / η detect modification of payload or metadata binding."""
    wf = HieraStreamWorkflow(owner_id="tamp")
    wf.setup()
    wf.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    seg = wf.publish(b"honest", targets=["AttendingPhysician"], seg_id="t1")
    rec = wf.fabric.get_segment(wf.owner_id, "t1")
    assert rec is not None
    # Tamper stored payload under same CID key
    wf.ipfs.local._store[rec["CID"]] = b"tampered-bytes"
    with pytest.raises(ValueError, match="CID|tamper|payload"):
        wf.access("alice", "t1")


def test_role_state_canonical_excludes_xi_scalar():
    """Manuscript publishes PK_ri, not scalar ξ — state_id must not hash ξ."""
    lc = AuthorizationLifecycle(owner_id="xi-pub")
    lc.setup()
    lc.provision_user("u", ["doctor", "cardiology"], ["AttendingPhysician"])
    rs = lc.role_by_ver[0]
    can = rs.canonical()
    assert "xi" not in can
    assert "pk" in can and "membership" in can
