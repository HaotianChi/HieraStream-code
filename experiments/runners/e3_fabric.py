"""E3 — Fabric performance: resource/policy mgmt, CommitSegment, UpdateAuthorization.

live Fabric uses OPEN_LOOP_RATE_CONTROLLED injection with a
bounded outstanding worker pool. PeerMVCC path retains the legacy serial
closed-loop driver for CI / diagnostic continuity.
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any, Dict, List, Optional

from experiments.harness.metrics import latency_summary, percentile
from experiments.harness.open_loop_load import run_open_loop
from experiments.harness.run_context import create_run, load_config


def _is_live() -> bool:
    return os.environ.get("HIERASTREAM_FABRIC_GATEWAY", "").strip() in {"1", "true", "yes"}


def _use_open_loop(cfg: Dict[str, Any]) -> bool:
    model = str(cfg.get("workload_model", "")).strip().lower()
    if model in {"open_loop", "open-loop", "open_loop_rate_controlled"}:
        return True
    if model in {"closed_loop_serial", "serial"}:
        return False
    # Default: live → open-loop; PeerMVCC → serial
    return _is_live()


def run(smoke: bool = False, config_path: Optional[str] = None) -> int:
    cfg = load_config("fabric", config_path)
    if _use_open_loop(cfg):
        return _run_open_loop(smoke=smoke, cfg=cfg)
    return _run_serial(smoke=smoke, cfg=cfg)


def _run_serial(smoke: bool, cfg: Dict[str, Any]) -> int:
    """Legacy CLOSED_LOOP_SERIAL driver (PeerMVCC / explicit serial)."""
    from core.authorization.snapshot import AuthorizationSnapshot
    from core.blockchain.client.fabric_client import FabricClient
    from core.blockchain.client.peer_backend import FabricTxStatus
    from core.canonical import eta_digest

    rates = [10, 50] if smoke else list(cfg.get("rates", [10, 50, 100, 200]))
    ops = list(
        cfg.get(
            "operations",
            ["resource_management", "policy_management", "CommitSegment", "UpdateAuthorization"],
        )
    )
    live = _is_live()
    run_ctx = create_run(
        "fabric",
        {**cfg, "smoke": smoke, "rates": rates, "operations": ops, "live_fabric": live, "workload_model": "CLOSED_LOOP_SERIAL"},
    )

    for rate in rates:
        raw_n = cfg.get("tx_per_rate", rate)
        if smoke:
            n = min(int(rate), 5) if live else min(int(rate), 20)
        else:
            n = int(rate if raw_n is None else raw_n)
            max_tx = int(cfg.get("max_tx_per_cell", 40 if live else n))
            n = min(n, max_tx)
        for op in ops:
            client = FabricClient(owner_gateway_id="gw", authority_id="aa")
            owner = f"owner-e3-{rate}-{op}-{uuid.uuid4().hex[:8]}" if live else "owner-e3"
            snap = AuthorizationSnapshot(owner, 0, "p0", "a0", "r0")
            client.init_auth(snap)
            client.register_owner(owner, "gw")

            latencies: List[float] = []
            statuses: List[str] = []
            submitted = valid = invalid = 0
            t_start = time.perf_counter()

            for i in range(n):
                submitted += 1
                t0 = time.perf_counter()
                if op == "resource_management":
                    res = client.register_owner(f"{owner}-res-{rate}-{i}", "gw")
                elif op == "policy_management":
                    res = client.register_policy_state(f"pol-{owner}-{rate}-{i}", i, {"k": i})
                elif op == "CommitSegment":
                    cur = client.get_authorization_snapshot(owner)
                    assert cur is not None
                    eta = eta_digest(f"c{i}", f"m{i}", cur.version, cur.policy_id, cur.attr_state_id, cur.role_state_id)
                    res = client.commit_segment(
                        owner, f"s-{rate}-{i}", f"c{i}", f"m{i}",
                        cur.version, cur.policy_id, cur.attr_state_id, cur.role_state_id, eta,
                    )
                elif op == "UpdateAuthorization":
                    cur = client.get_authorization_snapshot(owner)
                    assert cur is not None
                    res = client.update_authorization(owner, cur, new_policy_id=f"p{i+1}", caller="aa")
                    if res.status == FabricTxStatus.VALID:
                        client.register_policy_state(f"p{owner}-{i+1}", i + 1, {})
                else:
                    raise ValueError(op)
                dt = time.perf_counter() - t0
                latencies.append(dt)
                st = res.status.value if hasattr(res.status, "value") else str(res.status)
                statuses.append(st)
                if res.status == FabricTxStatus.VALID:
                    valid += 1
                else:
                    invalid += 1
                if not smoke and rate > 0:
                    elapsed = time.perf_counter() - t_start
                    expected = (i + 1) / float(rate)
                    if expected > elapsed:
                        time.sleep(expected - elapsed)

            wall = max(time.perf_counter() - t_start, 1e-9)
            row: Dict[str, Any] = {
                "experiment": "E3",
                "operation": op,
                "offered_tps": rate,
                "target_offered_tps": rate,
                "actual_submission_tps": submitted / wall,
                "submitted": submitted,
                "valid_committed": valid,
                "invalid": invalid,
                "queue_backlog": 0,
                "max_outstanding": 1,
                "workload_model": "CLOSED_LOOP_SERIAL",
                "submitted_tps": submitted / wall,
                "valid_committed_tps": valid / wall,
                "invalid_transaction_rate": invalid / submitted if submitted else 0.0,
                "mean_latency_s": sum(latencies) / len(latencies),
                "p95_latency_s": percentile(latencies, 95),
                "wall_s": wall,
                "clock": "perf_counter",
                "outliers_discarded": False,
                "backend": "live_fabric_gateway" if live else "fabric_peer_statebased_mvcc",
                "fabric_equivalence": "Fabric_statebased_MVCC_Alg1",
                "live_gateway": live,
                "deployment_class": "single-host_local",
                "fabric_topology": "single-org_1peer_1orderer",
                "wan_distributed": False,
                "live_fabric_network": live,
                "ledger_impl": "HyperledgerFabric_CCAAS" if live else "PeerMVCCLedger",
                **latency_summary(latencies, prefix="latency_s"),
            }
            run_ctx.add_row(row)
            for j, lat in enumerate(latencies):
                run_ctx.add_row(
                    {
                        "experiment": "E3",
                        "phase": "per_tx",
                        "operation": op,
                        "offered_tps": rate,
                        "tx_index": j,
                        "latency_s": lat,
                        "status": statuses[j],
                        "live_fabric_network": live,
                        "workload_model": "CLOSED_LOOP_SERIAL",
                    }
                )

    run_ctx.extra = {
        "experiment": "E3",
        "workload_model": "CLOSED_LOOP_SERIAL",
        "backend": "live_fabric_gateway" if live else "fabric_peer_statebased_mvcc",
        "deployment_class": "single-host_local",
        "wan_distributed": False,
        "live_fabric_network": live,
    }
    run_ctx.finish()
    return 0


def _run_open_loop(smoke: bool, cfg: Dict[str, Any]) -> int:
    """OPEN_LOOP_RATE_CONTROLLED live Fabric driver."""
    from core.authorization.snapshot import AuthorizationSnapshot
    from core.blockchain.client.fabric_client import FabricClient
    from core.blockchain.client.peer_backend import FabricTxStatus
    from core.canonical import eta_digest

    rates = [1, 2] if smoke else list(cfg.get("rates", [1, 2, 4, 8]))
    ops = list(
        cfg.get(
            "operations",
            ["resource_management", "policy_management", "CommitSegment", "UpdateAuthorization"],
        )
    )
    live = True
    max_outstanding = int(cfg.get("max_outstanding", 32))
    worker_threads = int(cfg.get("worker_threads", max_outstanding))
    run_ctx = create_run(
        "fabric",
        {
            **cfg,
            "smoke": smoke,
            "rates": rates,
            "operations": ops,
            "live_fabric": live,
            "workload_model": "OPEN_LOOP_RATE_CONTROLLED",
            "max_outstanding": max_outstanding,
        },
    )

    for rate in rates:
        raw_n = cfg.get("tx_per_rate", max(int(rate * 5), 20))
        if smoke:
            n = min(8, max(4, int(rate) * 2))
        else:
            n = int(raw_n if raw_n is not None else max(int(rate * 5), 20))
            max_tx = int(cfg.get("max_tx_per_cell", n))
            n = min(n, max_tx)

        for op in ops:
            cell_tag = f"{rate}-{op}-{uuid.uuid4().hex[:8]}"
            # Key distribution (capacity, not conflict stress):
            # - resource_management: unique Owner/{id} per tx
            # - policy_management: unique PolicyState/{id} per tx
            # - CommitSegment: one AuthKey; unique Segment/{owner}/{seg} per tx
            # - UpdateAuthorization: unique AuthKey per tx (one update each)
            if op == "UpdateAuthorization":
                owners = [f"ua-{cell_tag}-{i}" for i in range(n)]
                for oid in owners:
                    c = FabricClient(owner_gateway_id="gw", authority_id="aa")
                    snap = AuthorizationSnapshot(oid, 0, "p0", "a0", "r0")
                    init = c.init_auth(snap)
                    if init.status != FabricTxStatus.VALID:
                        raise RuntimeError(f"InitAuth {oid}: {init}")
                    reg = c.register_owner(oid, "gw")
                    if reg.status != FabricTxStatus.VALID:
                        raise RuntimeError(f"RegisterOwner {oid}: {reg}")
                # Snapshot frozen at ν=0 for each owner (independent keys)
                snaps = {oid: AuthorizationSnapshot(oid, 0, "p0", "a0", "r0") for oid in owners}

                def worker(i: int, _owners=owners, _snaps=snaps) -> Dict[str, Any]:
                    oid = _owners[i]
                    client = FabricClient(owner_gateway_id="gw", authority_id="aa")
                    res = client.update_authorization(
                        oid, _snaps[oid], new_policy_id=f"p-{oid}-1", caller="aa"
                    )
                    return {
                        "status": res.status.value,
                        "reason": res.reason,
                        "tx_id": res.tx_id,
                    }

                key_dist = "independent_AuthKey_per_tx"
            elif op == "CommitSegment":
                owner = f"cs-{cell_tag}"
                c0 = FabricClient(owner_gateway_id="gw", authority_id="aa")
                snap = AuthorizationSnapshot(owner, 0, "p0", "a0", "r0")
                if c0.init_auth(snap).status != FabricTxStatus.VALID:
                    raise RuntimeError("InitAuth CommitSegment cell failed")
                if c0.register_owner(owner, "gw").status != FabricTxStatus.VALID:
                    raise RuntimeError("RegisterOwner CommitSegment cell failed")
                cur = c0.get_authorization_snapshot(owner)
                assert cur is not None

                def worker(i: int, _owner=owner, _cur=cur) -> Dict[str, Any]:
                    client = FabricClient(owner_gateway_id="gw", authority_id="aa")
                    eta = eta_digest(
                        f"c{i}", f"m{i}", _cur.version, _cur.policy_id, _cur.attr_state_id, _cur.role_state_id
                    )
                    res = client.commit_segment(
                        _owner, f"s-{i}", f"c{i}", f"m{i}",
                        _cur.version, _cur.policy_id, _cur.attr_state_id, _cur.role_state_id, eta,
                    )
                    return {"status": res.status.value, "reason": res.reason, "tx_id": res.tx_id}

                key_dist = "shared_AuthKey_read_unique_Segment_write"
            elif op == "resource_management":

                def worker(i: int, _tag=cell_tag) -> Dict[str, Any]:
                    client = FabricClient(owner_gateway_id="gw", authority_id="aa")
                    res = client.register_owner(f"res-{_tag}-{i}", "gw")
                    return {"status": res.status.value, "reason": res.reason, "tx_id": res.tx_id}

                key_dist = "unique_Owner_key_per_tx"
            elif op == "policy_management":

                def worker(i: int, _tag=cell_tag) -> Dict[str, Any]:
                    client = FabricClient(owner_gateway_id="gw", authority_id="aa")
                    res = client.register_policy_state(f"pol-{_tag}-{i}", i, {"k": i})
                    return {"status": res.status.value, "reason": res.reason, "tx_id": res.tx_id}

                key_dist = "unique_PolicyState_key_per_tx"
            else:
                raise ValueError(op)

            ol = run_open_loop(
                target_offered_tps=float(rate),
                n=n,
                max_outstanding=max_outstanding,
                worker=worker,
                worker_threads=worker_threads,
            )
            completion = [t.completion_latency_s for t in ol.timings]
            e2e = [t.e2e_offered_latency_s for t in ol.timings]
            qdelay = [t.queue_delay_s for t in ol.timings]
            statuses = [t.status for t in ol.timings]
            valid = ol.valid_committed
            invalid = ol.invalid
            submitted = ol.submitted

            # Submission-rate validity vs target (below client generation limit)
            submit_ratio = ol.actual_submission_tps / float(rate) if rate else 0.0

            row: Dict[str, Any] = {
                "experiment": "E3",
                "operation": op,
                "offered_tps": rate,
                "target_offered_tps": rate,
                "actual_submission_tps": ol.actual_submission_tps,
                "submission_ratio_vs_target": submit_ratio,
                "submitted": submitted,
                "valid_committed": valid,
                "invalid": invalid,
                "queue_backlog": 0,
                "max_outstanding_configured": max_outstanding,
                "max_outstanding_observed": ol.max_outstanding_observed,
                "bound_wait_events": ol.bound_wait_events,
                "bound_saturated": ol.bound_saturated,
                "workload_model": "OPEN_LOOP_RATE_CONTROLLED",
                "key_distribution": key_dist,
                "submitted_tps": ol.actual_submission_tps,
                "valid_committed_tps": ol.valid_committed_tps,
                "invalid_transaction_rate": invalid / submitted if submitted else 0.0,
                "mean_latency_s": sum(completion) / len(completion),
                "p50_latency_s": percentile(completion, 50),
                "p95_latency_s": percentile(completion, 95),
                "mean_e2e_offered_latency_s": sum(e2e) / len(e2e),
                "p95_e2e_offered_latency_s": percentile(e2e, 95),
                "mean_queue_delay_s": sum(qdelay) / len(qdelay),
                "wall_s": ol.wall_s,
                "submission_span_s": ol.submission_span_s,
                "clock": "perf_counter",
                "outliers_discarded": False,
                "backend": "live_fabric_gateway",
                "fabric_equivalence": "Fabric_statebased_MVCC_Alg1",
                "live_gateway": True,
                "deployment_class": "single-host_local",
                "fabric_topology": "single-org_1peer_1orderer",
                "wan_distributed": False,
                "live_fabric_network": True,
                "ledger_impl": "HyperledgerFabric_CCAAS",
                "result_class_hint": cfg.get("result_class", "LIVE_FABRIC_CONCURRENT"),
                **latency_summary(completion, prefix="latency_s"),
            }
            run_ctx.add_row(row)
            for t in ol.timings:
                run_ctx.add_row(
                    {
                        "experiment": "E3",
                        "phase": "per_tx",
                        "operation": op,
                        "offered_tps": rate,
                        "target_offered_tps": rate,
                        "tx_index": t.tx_index,
                        "scheduled_submission_s": t.scheduled_submission_s,
                        "actual_submission_s": t.actual_submission_s,
                        "commit_completion_s": t.commit_completion_s,
                        "queue_delay_s": t.queue_delay_s,
                        "latency_s": t.completion_latency_s,
                        "e2e_offered_latency_s": t.e2e_offered_latency_s,
                        "status": t.status,
                        "tx_id": t.tx_id,
                        "live_fabric_network": True,
                        "workload_model": "OPEN_LOOP_RATE_CONTROLLED",
                    }
                )

    run_ctx.extra = {
        "experiment": "E3",
        "workload_model": "OPEN_LOOP_RATE_CONTROLLED",
        "backend": "live_fabric_gateway",
        "deployment_class": "single-host_local",
        "wan_distributed": False,
        "live_fabric_network": True,
        "max_outstanding": max_outstanding,
        "note": (
            "Open-loop rate-controlled live Fabric. "
            "target_offered_tps vs actual_submission_tps must be inspected; "
            "not a WAN/distributed claim."
        ),
    }
    run_ctx.finish()
    return 0
