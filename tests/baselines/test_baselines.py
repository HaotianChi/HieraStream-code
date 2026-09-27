"""Fix test imports for unversioned workflow after API simplification."""

from __future__ import annotations

import pytest


def test_unversioned_commit_has_no_authkey_read():
    from core.authorization.snapshot import AuthorizationSnapshot, auth_key, segment_key
    from core.blockchain.client.fabric_client import FabricClient, _json_bytes
    from core.blockchain.client.peer_backend import FabricTxStatus
    from core.canonical import eta_digest
    import uuid

    client = FabricClient()
    snap = AuthorizationSnapshot("o", 0, "p", "a", "r")
    assert client.init_auth(snap).status == FabricTxStatus.VALID

    cur = client.get_authorization_snapshot("o")
    assert cur is not None
    upd = client.update_authorization("o", cur, new_policy_id="p1", caller="aa")
    assert upd.status == FabricTxStatus.VALID

    eta = eta_digest("c", "m", 0, "p", "a", "r")
    res = client.commit_segment_unversioned("o", "s1", "c", "m", 0, "p", "a", "r", eta)
    assert res.status == FabricTxStatus.VALID

    client2 = FabricClient()
    client2.init_auth(AuthorizationSnapshot("o2", 0, "p", "a", "r"))
    tx_id = str(uuid.uuid4())
    client2.ledger.set_acl("CommitSegmentUnversioned", {"gw", "admin"})
    ctx = client2.ledger.begin(tx_id, "gw", "CommitSegmentUnversioned")
    ctx.put_state(segment_key("o2", "s"), _json_bytes({"unversioned": True}))
    endorsed = ctx.endorse()
    assert auth_key("o2") not in [r.key for r in endorsed.read_set]
    assert client2.ledger.validate_and_commit(endorsed).status == FabricTxStatus.VALID


def test_unversioned_workflow_can_record_stale_success():
    from experiments.baselines.unversioned.workflow import UnversionedWorkflow
    from core.blockchain.client.peer_backend import FabricTxStatus

    wf = UnversionedWorkflow(owner_id="uv-1")
    wf.setup()
    wf.provision_user("u", ["doctor", "cardiology"], ["AttendingPhysician"])
    observed = wf.read_active_snapshot()
    pending = wf.protect_payload("s", b"payload", ["AttendingPhysician"])
    wf.revoke_attribute("emergency", revoked_users=[])
    tree = wf.lifecycle.active_policy_tree()  # type: ignore
    result, meta, mcid, eta = wf.attempt_commit_unversioned(pending, observed, tree)
    assert result.status == FabricTxStatus.VALID
    cur = wf.fabric.get_authorization_snapshot(wf.owner_id)
    assert cur is not None and cur.version > observed.version


def test_historical_algebraic_updates_leaves_not_aes():
    from core.authorization.lifecycle import AuthorizationLifecycle
    from core.crypto.python.access_tree import AND, leaf
    from core.crypto.python.hierarchy import HEALTHCARE_FIXTURE
    from core.crypto.python.segment import SegmentCrypto
    from experiments.baselines.historical_update.baseline import HistoricalUpdateBaseline

    crypto = SegmentCrypto()
    lc = AuthorizationLifecycle(
        owner_id="hist",
        crypto=crypto,
        hierarchy=HEALTHCARE_FIXTURE,
        attr_universe=["doctor", "cardiology", "nurse", "emergency", "researcher"],
    )
    lc.setup(initial_policy=AND(leaf("doctor"), leaf("cardiology")))
    lc.provision_user("u", ["doctor", "cardiology"], ["AttendingPhysician"])
    bl = HistoricalUpdateBaseline(crypto=crypto, lifecycle=lc)
    for i in range(3):
        bl.protect_and_store(f"p-{i}".encode(), ["AttendingPhysician"], f"s{i}")

    aes_before = [e.protected.ct_aes for e in bl.segments]
    ca_before = [{k: v.to_bytes() for k, v in e.protected.attr_ct.C_a.items()} for e in bl.segments]

    stats = bl.revoke_with_historical_update("doctor", revoked_users=[])
    assert stats["aes_payloads_rewritten"] == 0
    assert stats["role_envelopes_rewritten"] == 0
    assert stats["historical_segments_touched"] == 3
    assert stats["leaf_components_updated"] >= 3
    assert [e.protected.ct_aes for e in bl.segments] == aes_before
    for i, e in enumerate(bl.segments):
        for lid, g in e.protected.attr_ct.C_a.items():
            if lid.endswith(":doctor"):
                assert g.to_bytes() != ca_before[i][lid]
            if lid.endswith(":cardiology"):
                assert g.to_bytes() == ca_before[i][lid]


def test_historical_decrypt_after_algebraic_update():
    from core.authorization.lifecycle import AuthorizationLifecycle
    from core.crypto.python.access_tree import AND, leaf
    from core.crypto.python.hierarchy import HEALTHCARE_FIXTURE
    from core.crypto.python.segment import SegmentCrypto
    from experiments.baselines.historical_update.baseline import HistoricalUpdateBaseline

    crypto = SegmentCrypto()
    lc = AuthorizationLifecycle(
        owner_id="hist2",
        crypto=crypto,
        hierarchy=HEALTHCARE_FIXTURE,
        attr_universe=["doctor", "cardiology", "nurse", "emergency", "researcher"],
    )
    lc.setup(initial_policy=AND(leaf("doctor"), leaf("cardiology")))
    lc.provision_user("u", ["doctor", "cardiology"], ["AttendingPhysician"])
    bl = HistoricalUpdateBaseline(crypto=crypto, lifecycle=lc)
    bl.protect_and_store(b"secret-hist", ["AttendingPhysician"], "s0")
    bl.revoke_with_historical_update("doctor", revoked_users=[])

    user_attr = lc.keys.current_attr("u").material  # type: ignore
    role = lc.keys.current_role("u")  # type: ignore
    pt = crypto.recover_segment(
        bl.segments[0].protected,
        user_attr,
        role.material,
        role.assigned_roles,
    )
    assert pt == b"secret-hist"


def test_cpabe_roundtrip_no_role_setup():
    from core.crypto.python.access_tree import AND, leaf
    from experiments.baselines.cpabe.adapter import CPABEBaseline

    b = CPABEBaseline.setup()
    assert b.crypto.hierarchy is None
    user = b.keygen("u", ["doctor", "cardiology"])
    tree = AND(leaf("doctor"), leaf("cardiology"))
    blob = b.encrypt(b"cpabe-pt", tree)
    assert "gateway_partial_attr" in blob["measured_ops"]
    out = b.decrypt(blob, user)
    assert out["plaintext"] == b"cpabe-pt"


def test_cpabe_unauthorized_negative():
    import pytest
    from core.crypto.python.access_tree import AND, leaf
    from experiments.baselines.cpabe.adapter import CPABEBaseline

    b = CPABEBaseline.setup()
    user = b.keygen("u", ["doctor"])  # missing cardiology
    tree = AND(leaf("doctor"), leaf("cardiology"))
    blob = b.encrypt(b"cpabe-pt", tree)
    with pytest.raises(PermissionError):
        b.decrypt(blob, user)


def test_evm_harness_measures_gas_not_manuscript_constants():
    from experiments.baselines.evm.harness import EVMComparisonHarness

    h = EVMComparisonHarness()
    rows = h.run_hierastream_bench(n_policy=3, n_query=2)
    assert len(rows) == 5
    assert all(r["gas_used"] and r["gas_used"] > 0 for r in rows)
    manuscript_gas = {41512, 45617, 52675, 252309, 369409, 551243}
    assert not any(r["gas_used"] in manuscript_gas for r in rows)
    blocked = h.probe_pash_mass()
    assert all(x["status"] == "NOT_AVAILABLE" for x in blocked)


def test_pash_mass_adapters_available():
    from experiments.baselines.mass.adapter import MASSAdapter
    from experiments.baselines.pash.adapter import PASHAdapter

    p = PASHAdapter()
    m = MASSAdapter()
    assert p.available() and m.available()
    assert p.probe()["available"] is True
    assert m.probe()["available"] is True
    p.setup_for_policy_size(5)
    blob = p.encrypt(b"\x01" * 32)
    assert p.decrypt(blob)["plaintext"] == b"\x01" * 32
    m.setup_for_policy_size(5)
    mb = m.encrypt(b"\x02" * 32, doc_id="t")
    assert m.decrypt(mb)["plaintext"] == mb["obj_hash"]
    import pytest

    with pytest.raises(NotImplementedError):
        m.on_chain_policy_op()
