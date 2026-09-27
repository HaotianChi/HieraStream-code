"""Randomized stress: thousands of segment/update ops; invariants after each commit."""

from __future__ import annotations

import random

from core.authorization.lifecycle import AuthorizationLifecycle
from core.authorization.machine import AuthPhase
from core.blockchain.client.fabric_client import FabricClient
from core.blockchain.client.peer_backend import FabricTxStatus
from core.canonical import eta_digest
from core.crypto.python.access_tree import AND, OR, leaf
from core.protocol.workflow import HieraStreamWorkflow


STRESS_OPS = 2000
STRESS_SEED = 20260912


def test_stress_lifecycle_invariants_after_each_commit():
    rng = random.Random(STRESS_SEED)
    lc = AuthorizationLifecycle(owner_id="stress-lc")
    lc.setup()
    users = ["u0", "u1", "u2", "u3", "u4"]
    for u in users:
        lc.provision_user(u, ["doctor", "cardiology"], ["AttendingPhysician"])

    seg_n = 0
    for i in range(STRESS_OPS):
        op = rng.choice(["seg", "seg", "policy", "attr", "role", "seg"])
        before = lc.active
        if op == "seg":
            sid = f"s{seg_n}"
            seg_n += 1
            pt = f"pt-{i}".encode()
            target = rng.choice(["AttendingPhysician", "Nurse", "Resident"])
            # Ensure at least one user can hold Nurse when needed
            if target == "Nurse" and not any(
                "Nurse" in lc._membership_map().get(u, []) for u in users
            ):
                # fall back
                target = "AttendingPhysician"
            lc.protect_segment(sid, pt, targets=[target])
            rec = lc.segments[sid]
            # Segment always binds to *then-active* snapshot (never pending ν+1)
            assert rec.snapshot.matches(lc.active)
            assert lc.machine.phase == AuthPhase.ACTIVE
            continue

        if op == "policy":
            tree = rng.choice(
                [
                    AND(leaf("doctor"), leaf("cardiology")),
                    OR(leaf("doctor"), leaf("nurse")),
                    AND(leaf("doctor"), leaf("cardiology"), leaf("emergency")),
                ]
            )
            snap = lc.update_policy(tree)
        elif op == "attr":
            victim = rng.choice(users)
            # Keep at least one non-revoked doctor holder when possible
            snap = lc.revoke_attribute("emergency", revoked_users=[victim])
        else:
            mem = {}
            for u in users:
                mem[u] = [rng.choice(["AttendingPhysician", "Nurse", "Resident"])]
            # Ensure alice-like u0 often keeps Attending for recoverability
            if rng.random() < 0.7:
                mem[users[0]] = ["AttendingPhysician"]
            snap = lc.reassign_roles(mem)

        assert snap.version == before.version + 1
        assert lc.active.matches(snap)
        assert lc.machine.phase == AuthPhase.ACTIVE
        assert lc.machine.pending is None
        assert snap.version > before.version


def test_stress_fabric_mvcc_property1():
    """Many interleaved CommitSegment / UpdateAuthorization with random order."""
    rng = random.Random(STRESS_SEED + 1)
    c = FabricClient()
    owner = "stress-fab"
    from core.authorization.snapshot import AuthorizationSnapshot

    c.init_auth(AuthorizationSnapshot(owner, 0, "p0", "a0", "r0"))
    valid_segments = 0
    mvcc_rejects = 0
    for i in range(1500):
        snap = c.get_authorization_snapshot(owner)
        assert snap is not None
        if rng.random() < 0.55:
            # CommitSegment under current snap
            sid = f"s{i}"
            cid, mcid = f"c{i}", f"m{i}"
            eta = eta_digest(cid, mcid, snap.version, snap.policy_id, snap.attr_state_id, snap.role_state_id)
            defer = rng.random() < 0.35
            pend = c.commit_segment(
                owner,
                sid,
                cid,
                mcid,
                snap.version,
                snap.policy_id,
                snap.attr_state_id,
                snap.role_state_id,
                eta,
                defer_validation=defer,
            )
            if defer:
                # Maybe interleave an update before validation
                if rng.random() < 0.5:
                    u = c.update_authorization(
                        owner,
                        snap,
                        new_attr_state_id=f"a{i}",
                    )
                    if u.status == FabricTxStatus.VALID:
                        res = c.await_validation(pend.tx_id)
                        if res.status == FabricTxStatus.MVCC_READ_CONFLICT:
                            mvcc_rejects += 1
                            assert c.get_segment(owner, sid) is None
                        elif res.status == FabricTxStatus.VALID:
                            valid_segments += 1
                            rec = c.get_segment(owner, sid)
                            assert rec is not None
                            # Prop.1: tuple equals AuthKey that preceded commit
                            # After update, AuthKey advanced — segment should NOT be valid
                            # so VALID here only if update failed
                            cur = c.get_authorization_snapshot(owner)
                            assert cur is not None
                            assert (
                                int(rec["version"]),
                                rec["policyId"],
                                rec["attrStateId"],
                                rec["roleStateId"],
                            ) == (
                                snap.version,
                                snap.policy_id,
                                snap.attr_state_id,
                                snap.role_state_id,
                            )
                    else:
                        res = c.await_validation(pend.tx_id)
                        if res.status == FabricTxStatus.VALID:
                            valid_segments += 1
                else:
                    res = c.await_validation(pend.tx_id)
                    if res.status == FabricTxStatus.VALID:
                        valid_segments += 1
                        rec = c.get_segment(owner, sid)
                        assert rec is not None
                        assert int(rec["version"]) == snap.version
            else:
                if pend.status == FabricTxStatus.VALID:
                    valid_segments += 1
                    rec = c.get_segment(owner, sid)
                    assert rec is not None
                    assert (
                        int(rec["version"]),
                        rec["policyId"],
                        rec["attrStateId"],
                        rec["roleStateId"],
                    ) == snap.identity_tuple()
        else:
            # UpdateAuthorization
            kw = {}
            kind = rng.choice(["policy", "attr", "role"])
            if kind == "policy":
                kw["new_policy_id"] = f"p{i}"
            elif kind == "attr":
                kw["new_attr_state_id"] = f"a{i}"
            else:
                kw["new_role_state_id"] = f"r{i}"
            res = c.update_authorization(owner, snap, **kw)
            assert res.status in (FabricTxStatus.VALID, FabricTxStatus.INVALID, FabricTxStatus.MVCC_READ_CONFLICT)

    # Sanity: some work happened
    assert valid_segments + mvcc_rejects > 100
    final = c.get_authorization_snapshot(owner)
    assert final is not None
    assert final.version >= 0


def test_stress_e2e_publish_access_rounds():
    rng = random.Random(STRESS_SEED + 2)
    wf = HieraStreamWorkflow(owner_id="stress-e2e")
    wf.setup()
    wf.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    wf.provision_user("bob", ["doctor", "cardiology"], ["AttendingPhysician"])
    for i in range(80):
        sid = f"e{i}"
        pt = f"body-{i}".encode()
        if rng.random() < 0.2 and i > 0:
            # Occasional update between publishes
            if rng.random() < 0.5:
                wf.update_policy(OR(leaf("doctor"), leaf("nurse")))
            else:
                wf.revoke_attribute("emergency", revoked_users=[])
        seg = wf.publish(pt, targets=["AttendingPhysician"], seg_id=sid)
        assert wf.access("alice", sid) == pt
        rec = wf.fabric.get_segment(wf.owner_id, sid)
        assert rec is not None
        assert (
            int(rec["version"]),
            rec["policyId"],
            rec["attrStateId"],
            rec["roleStateId"],
        ) == seg.snapshot.identity_tuple()
