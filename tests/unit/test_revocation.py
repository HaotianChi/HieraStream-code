"""Revocation / prospective semantics tests."""

from __future__ import annotations

import pytest

from core.protocol.system import HieraStreamSystem


def test_attribute_revocation_blocks_future_keeps_history():
    sys = HieraStreamSystem()
    sys.setup()
    sys.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    sys.provision_user("bob", ["doctor", "cardiology"], ["AttendingPhysician"])

    seg0 = sys.protect_and_publish(b"historical", targets=["AttendingPhysician"], seg_id="s0")
    hist_bytes = sys.hist_ct_aes["s0"]

    # Revoke bob's doctor attribute (bob loses doctor)
    sys.revoke_attribute("doctor", revoked_users=["bob"])
    # Historical ciphertext bytes unchanged
    assert sys.hist_ct_aes["s0"] == hist_bytes
    # Historical legitimate access still works for alice (old keys + old CT)
    assert sys.access("alice", "s0") == b"historical"
    # Bob still has old E_ua for doctor (not refreshed) — prospective:
    # historical may still work with obsolete components under old ν.
    # Future segment under new state: bob lacks refreshed doctor component
    # and attrs list no longer includes doctor → fail policy.
    seg1 = sys.protect_and_publish(b"future", targets=["AttendingPhysician"], seg_id="s1")
    assert sys.access("alice", "s1") == b"future"
    with pytest.raises(PermissionError):
        sys.access("bob", "s1")


def test_role_reassignment_blocks_future():
    sys = HieraStreamSystem()
    sys.setup()
    sys.provision_user("u", ["doctor", "cardiology"], ["AttendingPhysician"])
    seg0 = sys.protect_and_publish(b"old", targets=["AttendingPhysician"], seg_id="h0")
    assert sys.access("u", "h0") == b"old"

    # Demote to Nurse — refresh xi and RK
    sys.reassign_roles({"u": ["Nurse"]})

    seg1 = sys.protect_and_publish(b"new", targets=["AttendingPhysician"], seg_id="h1")
    with pytest.raises(PermissionError):
        sys.access("u", "h1")
    # Can access nurse-targeted future data
    seg2 = sys.protect_and_publish(b"nurse-ok", targets=["Nurse"], seg_id="h2")
    assert sys.access("u", "h2") == b"nurse-ok"
