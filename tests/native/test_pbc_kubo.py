"""Native stack: PBC serialization, backend parity, Kubo CID."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core" / "crypto" / "bindings"))
sys.path.insert(0, str(ROOT / "build" / "core" / "crypto"))

PARAM = str(ROOT / "core" / "crypto" / "params" / "a.param")


def _native():
    try:
        import hierastream_native as n

        return n
    except ImportError:
        pytest.skip("hierastream_native not built — run make build")


def test_pbc_native_ping_and_section_iii():
    n = _native()
    assert n.ping() == "hierastream_native"
    assert n.engine_setup_smoke(PARAM) is True
    out = n.engine_section_iii_roundtrip(PARAM, "native-iii")
    assert out["ok"] is True
    assert out["pt"] == "native-iii"
    assert int(out["key_len"]) == 32


@pytest.mark.parametrize("ty_name", ["ZR", "G", "GT"])
def test_pbc_element_serialize_roundtrip(ty_name):
    n = _native()
    ty = {"ZR": n.ELEM_ZR, "G": n.ELEM_G, "GT": n.ELEM_GT}[ty_name]
    ctx = n.PairingContext(PARAM)
    e = n.Element(ctx, ty)
    e.set_random()
    b1 = e.to_bytes()
    e2 = n.Element(ctx, ty)
    e2.from_bytes(b1)
    b2 = e2.to_bytes()
    assert b1 == b2
    assert e.equals(e2)


def test_pbc_python_segment_protect_recover_revoke():
    from copy import deepcopy

    from core.crypto.python.access_tree import AND, leaf
    from core.crypto.python.hierarchy import HEALTHCARE_FIXTURE
    from core.crypto.python.segment import SegmentCrypto

    c = SegmentCrypto(backend="pbc")
    c.ca_setup()
    c.aa_setup(["doctor", "cardiology", "nurse"])
    c.role_setup(HEALTHCARE_FIXTURE)
    alice = c.aa_keygen("alice", ["doctor", "cardiology"])
    bob = c.aa_keygen("bob", ["doctor", "cardiology"])
    ra = c.ca_role_user("alice")
    rb = c.ca_role_user("bob")
    c.rm_issue_rk("AttendingPhysician", ra)
    c.rm_issue_rk("AttendingPhysician", rb)
    tree = AND(leaf("doctor"), leaf("cardiology"))
    old = c.protect_segment(b"hist-pbc", tree, ["AttendingPhysician"])
    assert c.recover_segment(old, alice, ra, ["AttendingPhysician"]) == b"hist-pbc"
    assert c.recover_segment(old, bob, rb, ["AttendingPhysician"]) == b"hist-pbc"

    bob_hist = deepcopy(bob)  # retain pre-revoke keys for historical CT
    c.aa_revoke_attribute("doctor")
    alice.E_ua["doctor"] = c.aa_refresh_Eua(alice.E_ua["doctor"], "doctor")
    # Prospective: revoked user does not receive refresh; drop attr component
    bob.E_ua.pop("doctor", None)
    bob.attrs = [a for a in bob.attrs if a != "doctor"]

    new = c.protect_segment(b"new-pbc", tree, ["AttendingPhysician"])
    assert c.recover_segment(new, alice, ra, ["AttendingPhysician"]) == b"new-pbc"
    with pytest.raises(PermissionError):
        c.recover_segment(new, bob, rb, ["AttendingPhysician"])
    assert c.recover_segment(old, bob_hist, rb, ["AttendingPhysician"]) == b"hist-pbc"


def test_backend_parity_semantic_outcomes():
    """Algebraic vs PBC: same authorization success/fail, not ciphertext equality."""
    from core.crypto.python.access_tree import AND, leaf
    from core.crypto.python.hierarchy import HEALTHCARE_FIXTURE
    from core.crypto.python.segment import SegmentCrypto

    tree = AND(leaf("doctor"), leaf("cardiology"))
    results = {}
    for backend in ("algebraic", "pbc"):
        c = SegmentCrypto(backend=backend)
        c.ca_setup()
        c.aa_setup(["doctor", "cardiology", "nurse"])
        c.role_setup(HEALTHCARE_FIXTURE)
        good = c.aa_keygen("u", ["doctor", "cardiology"])
        bad = c.aa_keygen("v", ["nurse"])
        role = c.ca_role_user("u")
        c.rm_issue_rk("AttendingPhysician", role)
        role_bad = c.ca_role_user("v")
        c.rm_issue_rk("Nurse", role_bad)
        seg = c.protect_segment(b"parity", tree, ["AttendingPhysician"])
        ok = c.recover_segment(seg, good, role, ["AttendingPhysician"]) == b"parity"
        denied = False
        try:
            c.recover_segment(seg, bad, role_bad, ["Nurse"])
        except PermissionError:
            denied = True
        results[backend] = (ok, denied)
    assert results["algebraic"] == (True, True)
    assert results["pbc"] == (True, True)


def test_kubo_predicted_equals_actual():
    from core.storage.ipfs_client import IPFSClient

    client = IPFSClient(use_local=False)
    if not client._kubo:
        pytest.skip("Kubo daemon not reachable on 127.0.0.1:5001")
    for i in range(12):
        data = os.urandom(80) + f"-meta-{i}".encode()
        predicted = client.only_hash(data)
        cid = client.add(data)
        assert predicted == cid
        assert client.get(cid) == data
        assert client.verify_cid(cid, data)


def test_kubo_publication_order_metadata_after_valid():
    """Encrypt → Kubo CID → predict MCID → Fabric VALID → then Kubo add metadata."""
    from core.blockchain.client.fabric_client import FabricClient
    from core.blockchain.client.peer_backend import FabricTxStatus
    from core.canonical import eta_digest
    from core.crypto.python.access_tree import AND, leaf
    from core.crypto.python.hierarchy import HEALTHCARE_FIXTURE
    from core.crypto.python.segment import SegmentCrypto
    from core.protocol.metadata import metadata_bytes, build_metadata_object
    from core.storage.ipfs_client import IPFSClient

    ipfs = IPFSClient(use_local=False)
    if not ipfs._kubo:
        pytest.skip("Kubo daemon not reachable")

    crypto = SegmentCrypto(backend="pbc")
    crypto.ca_setup()
    crypto.aa_setup(["doctor", "cardiology"])
    crypto.role_setup(HEALTHCARE_FIXTURE)
    tree = AND(leaf("doctor"), leaf("cardiology"))
    seg = crypto.protect_segment(b"pub-order", tree, ["AttendingPhysician"])
    cid = ipfs.add(seg.ct_aes)

    snap_v, pol, attr, role = 0, "pol", "attr", "role"
    mj = build_metadata_object(
        seg.attr_ct, seg.role_envelopes, snap_v, pol, attr, role, ["AttendingPhysician"]
    )
    meta = metadata_bytes(mj)
    mcid_pred = ipfs.only_hash(meta)
    fabric = FabricClient(owner_gateway_id="gw", authority_id="aa")
    from core.authorization.snapshot import AuthorizationSnapshot

    snap = AuthorizationSnapshot("owner-kubo", 0, pol, attr, role)
    assert fabric.init_auth(snap).status == FabricTxStatus.VALID
    eta = eta_digest(cid, mcid_pred, 0, pol, attr, role)
    res = fabric.commit_segment(
        "owner-kubo", "s1", cid, mcid_pred, 0, pol, attr, role, eta, caller="gw"
    )
    assert res.status == FabricTxStatus.VALID
    # ONLY NOW publish metadata
    mcid = ipfs.add(meta)
    assert mcid == mcid_pred
