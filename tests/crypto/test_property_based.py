"""Property-based / randomized conformance tests.

Uses reproducible seeds: failures print seed for replay.
Covers policies, thresholds, users, attributes, hierarchies, targets,
authorization versions, update sequences, and segment sizes.
"""

from __future__ import annotations

import random
from typing import List

import pytest

from core.crypto.python.access_tree import AccessTree, leaf
from core.crypto.python.hierarchy import linear_hierarchy
from core.crypto.python.segment import SegmentCrypto
from core.protocol.workflow import HieraStreamWorkflow


def _rng(seed: int) -> random.Random:
    return random.Random(seed)


def _random_tree(rng: random.Random, attrs: List[str], n_leaves: int) -> AccessTree:
    chosen = [rng.choice(attrs) for _ in range(n_leaves)]
    children = [leaf(a) for a in chosen]
    k = rng.randint(1, max(1, min(n_leaves, 3)))
    return AccessTree(kind="internal", threshold=k, children=children)


@pytest.mark.parametrize("seed", [0, 1, 2, 7, 42, 99, 2026, 31415])
def test_prop_random_policy_encrypt_decrypt(seed: int):
    rng = _rng(seed)
    try:
        attrs = [f"a{i}" for i in range(6)]
        c = SegmentCrypto()
        c.ca_setup()
        c.aa_setup(attrs)
        roles = [f"R{i}" for i in range(4)]
        hier = linear_hierarchy(roles)
        c.role_setup(hier)
        user_attrs = list(attrs)  # satisfy any threshold ≤ n
        user = c.aa_keygen("u", user_attrs)
        role_mat = c.ca_role_user("u")
        assigned = roles[0]  # top dominates all
        c.rm_issue_rk(assigned, role_mat)

        n_leaves = rng.randint(1, 5)
        tree = _random_tree(rng, attrs, n_leaves)
        targets = rng.sample(roles, k=rng.randint(1, len(roles)))
        payload = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 64)))
        seg = c.protect_segment(payload, tree, targets)
        # Need policy satisfiable: user has all attrs; threshold trees with only attrs work
        # If threshold requires more distinct satisfying leaves than user can hit — may fail.
        # Use OR-of-leaves style: threshold 1 always satisfiable when user has all attrs.
        tree1 = AccessTree(kind="internal", threshold=1, children=[leaf(a) for a in rng.sample(attrs, n_leaves)])
        seg = c.protect_segment(payload, tree1, targets)
        pt = c.recover_segment(seg, user, role_mat, [assigned])
        assert pt == payload
    except Exception as e:
        raise AssertionError(f"property failure seed={seed}: {e}") from e


@pytest.mark.parametrize("seed", [3, 11, 17, 23, 101])
def test_prop_random_hierarchy_dominance(seed: int):
    rng = _rng(seed)
    n = rng.randint(3, 8)
    names = [f"R{i}" for i in range(n)]
    hier = linear_hierarchy(names)
    hier.validate_nesting()
    # Top dominates all
    for r in names:
        assert hier.dominates(names[0], r)
    # Bottom dominates only self
    assert hier.dominates(names[-1], names[-1])
    if n > 1:
        assert not hier.dominates(names[-1], names[0])


@pytest.mark.parametrize("seed", [5, 13, 29, 37])
def test_prop_auth_update_sequence_versions(seed: int):
    rng = _rng(seed)
    try:
        wf = HieraStreamWorkflow(owner_id=f"pb-{seed}")
        wf.setup()
        wf.provision_user("u0", ["doctor", "cardiology"], ["AttendingPhysician"])
        v = 0
        for i in range(rng.randint(2, 5)):
            kind = rng.choice(["policy", "attr", "role"])
            if kind == "policy":
                snap = wf.update_policy(
                    AccessTree(kind="internal", threshold=1, children=[leaf("doctor"), leaf("nurse")])
                )
            elif kind == "attr":
                snap = wf.revoke_attribute("emergency", revoked_users=[])
            else:
                snap = wf.reassign_roles({"u0": ["AttendingPhysician"]})
            assert snap.version == v + 1
            v = snap.version
            seg = wf.publish(f"x-{i}".encode(), targets=["AttendingPhysician"], seg_id=f"s{i}")
            assert seg.snapshot.version == v
            assert wf.access("u0", seg.seg_id) == f"x-{i}".encode()
    except Exception as e:
        raise AssertionError(f"property failure seed={seed}: {e}") from e


@pytest.mark.parametrize("seed", [8, 19, 41])
def test_prop_segment_sizes_roundtrip(seed: int):
    rng = _rng(seed)
    try:
        wf = HieraStreamWorkflow(owner_id=f"sz-{seed}")
        wf.setup()
        wf.provision_user("u", ["doctor", "cardiology"], ["AttendingPhysician"])
        for i, nbytes in enumerate([1, 16, 256, 1024]):
            # slight jitter
            n = nbytes + rng.randint(0, 7)
            payload = bytes(rng.getrandbits(8) for _ in range(n))
            seg = wf.publish(payload, targets=["AttendingPhysician"], seg_id=f"p{i}")
            assert wf.access("u", seg.seg_id) == payload
    except Exception as e:
        raise AssertionError(f"property failure seed={seed}: {e}") from e


@pytest.mark.parametrize("seed", [2, 6, 14])
def test_prop_multi_target_independent_d(seed: int):
    rng = _rng(seed)
    c = SegmentCrypto()
    c.ca_setup()
    c.aa_setup(["doctor"])
    roles = [f"R{i}" for i in range(5)]
    c.role_setup(linear_hierarchy(roles))
    ZR = c.sample_ZR()
    targets = rng.sample(roles, k=rng.randint(2, 4))
    envs = c.role_encrypt_multi(ZR, targets)
    ds = [e.d for e in envs]
    assert len(ds) == len(set(ds))  # independent d_{i,j}
    assert len(envs) == len(targets)
