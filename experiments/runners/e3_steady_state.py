"""E3 steady-state live Fabric runner.

Fixed-duration open-loop + persistent Gateway client.
"""

from __future__ import annotations

import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from experiments.harness.metrics import latency_summary, percentile
from experiments.harness.run_context import create_run, load_config
from experiments.harness.steady_state_load import run_steady_state


def run(smoke: bool = False, config_path: Optional[str] = None) -> int:
    from core.authorization.snapshot import AuthorizationSnapshot
    from core.blockchain.client.persistent_gateway import PersistentGatewayServer
    from core.canonical import eta_digest

    cfg = load_config("fabric", config_path)
    rates = [1.0, 4.0] if smoke else [float(x) for x in cfg.get("rates", [1, 4, 8, 16])]
    ops = list(
        cfg.get(
            "operations",
            ["resource_management", "policy_management", "CommitSegment", "UpdateAuthorization"],
        )
    )
    warmup_s = float(cfg.get("warmup_s", 5))
    measure_s = float(cfg.get("measure_s", 20 if smoke else 30))
    if smoke:
        warmup_s = min(warmup_s, 2.0)
        measure_s = min(measure_s, 5.0)
    max_outstanding = int(cfg.get("max_outstanding", 64))
    worker_threads = int(cfg.get("worker_threads", max_outstanding))

    os.environ["HIERASTREAM_FABRIC_GATEWAY"] = "1"
    os.environ["HIERASTREAM_FABRIC_LIVE"] = "1"

    run_ctx = create_run(
        "fabric",
        {
            **cfg,
            "smoke": smoke,
            "rates": rates,
            "operations": ops,
            "workload_model": "OPEN_LOOP_STEADY_STATE",
            "warmup_s": warmup_s,
            "measure_s": measure_s,
            "max_outstanding": max_outstanding,
            "live_fabric": True,
        },
    )

    server = PersistentGatewayServer()
    client = server.start()
    try:
        # UpdateAuthorization: parallel owner streams (not one owner per tx).
        # Avoids massive InitAuth prep while preventing same-AuthKey MVCC contention.
        ua_n_streams = int(cfg.get("ua_streams", min(256, max_outstanding)))
        ua_streams: List[Dict[str, Any]] = []
        ua_rr = 0
        ua_lock = __import__("threading").Lock()

        def _prep_ua_streams(n: int) -> List[Dict[str, Any]]:
            tag = uuid.uuid4().hex[:8]
            owners = [f"ss-ua-{tag}-{i}" for i in range(n)]

            def one(oid: str) -> Dict[str, Any]:
                r1 = client.invoke("RegisterOwner", [oid, "gw"], identity="aa")
                if not r1.get("ok"):
                    raise RuntimeError(f"RegisterOwner {oid}: {r1}")
                r2 = client.invoke("InitAuth", [oid, "0", "p0", "a0", "r0"], identity="aa")
                if not r2.get("ok"):
                    raise RuntimeError(f"InitAuth {oid}: {r2}")
                return {
                    "owner": oid,
                    "version": 0,
                    "policy": "p0",
                    "lock": __import__("threading").Lock(),
                }

            out: List[Dict[str, Any]] = []
            with ThreadPoolExecutor(max_workers=min(32, max_outstanding)) as pool:
                futs = [pool.submit(one, oid) for oid in owners]
                for f in as_completed(futs):
                    out.append(f.result())
            return out

        if "UpdateAuthorization" in ops:
            print(f"pre-creating {ua_n_streams} UpdateAuthorization streams...", flush=True)
            ua_streams = _prep_ua_streams(ua_n_streams)
            print(f"UA streams ready: {len(ua_streams)}", flush=True)

        for rate in rates:
            for op in ops:
                cell_tag = f"{rate}-{op}-{uuid.uuid4().hex[:8]}"
                print(f"=== cell op={op} rate={rate} ===", flush=True)

                if op == "resource_management":

                    def worker(i: int, _tag=cell_tag) -> Dict[str, Any]:
                        oid = f"res-{_tag}-{i}"
                        r = client.invoke("RegisterOwner", [oid, "gw"], identity="aa")
                        return {
                            "status": r.get("status", "INVALID"),
                            "reason": r.get("error", ""),
                            "code": r.get("code", r.get("status", "")),
                            "tx_id": r.get("tx_id", ""),
                            "owner_key": oid,
                        }

                    key_dist = "unique_Owner_key_per_tx"

                elif op == "policy_management":

                    def worker(i: int, _tag=cell_tag) -> Dict[str, Any]:
                        pid = f"pol-{_tag}-{i}"
                        r = client.invoke(
                            "RegisterPolicyState",
                            [pid, str(i), '{"k":1}'],
                            identity="aa",
                        )
                        return {
                            "status": r.get("status", "INVALID"),
                            "reason": r.get("error", ""),
                            "code": r.get("code", r.get("status", "")),
                            "tx_id": r.get("tx_id", ""),
                            "owner_key": pid,
                        }

                    key_dist = "unique_PolicyState_key_per_tx"

                elif op == "CommitSegment":
                    owner = f"cs-{cell_tag}"
                    r0 = client.invoke("RegisterOwner", [owner, "gw"], identity="aa")
                    if not r0.get("ok"):
                        raise RuntimeError(r0)
                    r1 = client.invoke("InitAuth", [owner, "0", "p0", "a0", "r0"], identity="aa")
                    if not r1.get("ok"):
                        raise RuntimeError(r1)

                    def worker(i: int, _owner=owner) -> Dict[str, Any]:
                        eta = eta_digest(f"c{i}", f"m{i}", 0, "p0", "a0", "r0")
                        r = client.invoke(
                            "CommitSegment",
                            [_owner, f"s-{i}", f"c{i}", f"m{i}", "0", "p0", "a0", "r0", eta],
                            identity="gw",
                        )
                        return {
                            "status": r.get("status", "INVALID"),
                            "reason": r.get("error", ""),
                            "code": r.get("code", r.get("status", "")),
                            "tx_id": r.get("tx_id", ""),
                            "owner_key": _owner,
                        }

                    key_dist = "shared_AuthKey_read_unique_Segment_write"

                elif op == "UpdateAuthorization":

                    def worker(i: int) -> Dict[str, Any]:
                        nonlocal ua_rr
                        with ua_lock:
                            st = ua_streams[ua_rr % len(ua_streams)]
                            ua_rr += 1
                        with st["lock"]:
                            ver = int(st["version"])
                            oid = st["owner"]
                            exp_pol = st.get("policy", "p0")
                            new_pol = f"p-{oid}-{ver + 1}"
                            r = client.invoke(
                                "UpdateAuthorization",
                                [oid, str(ver), exp_pol, "a0", "r0", new_pol, "", ""],
                                identity="aa",
                            )
                            if r.get("ok"):
                                st["version"] = ver + 1
                                st["policy"] = new_pol
                            return {
                                "status": r.get("status", "INVALID"),
                                "reason": r.get("error", ""),
                                "code": r.get("code", r.get("status", "")),
                                "tx_id": r.get("tx_id", ""),
                                "owner_key": oid,
                            }

                    key_dist = f"independent_AuthKey_streams_n={len(ua_streams)}"
                else:
                    raise ValueError(op)

                ss = run_steady_state(
                    target_offered_tps=float(rate),
                    warmup_s=warmup_s,
                    measure_s=measure_s,
                    max_outstanding=max_outstanding,
                    worker=worker,
                    worker_threads=worker_threads,
                )
                lats = ss.measure_latencies()
                delays = ss.measure_sched_delays()
                if not lats:
                    lats = [0.0]
                if not delays:
                    delays = [0.0]

                submit_ratio = ss.actual_submission_tps / float(rate) if rate else 0.0
                # bound_hit ⇒ never pure FABRIC_BOUND
                commit = ss.steady_state_valid_commit_tps
                inv_rate = ss.total_invalid / ss.total_submitted if ss.total_submitted else 0.0
                if ss.bound_hit:
                    if submit_ratio < 0.95:
                        limit = (
                            "CLIENT_BOUND"
                            if commit >= ss.actual_submission_tps * 0.9 and inv_rate < 0.05
                            else "MIXED"
                        )
                    elif commit < float(rate) * 0.85 or inv_rate >= 0.05:
                        limit = "MIXED"
                    else:
                        # Touched outstanding cap but still tracked — treat as client-constrained headroom
                        limit = "CLIENT_BOUND"
                elif submit_ratio >= 0.95 and commit < float(rate) * 0.85:
                    limit = "FABRIC_BOUND"
                elif abs(commit - float(rate)) / max(rate, 1e-9) < 0.15 and inv_rate < 0.05:
                    limit = "NOT_SATURATED"
                else:
                    limit = "INCONCLUSIVE"

                from experiments.harness.invalid_taxonomy import summarize_failures

                inv_sum = summarize_failures(
                    [
                        {
                            "status": t.status,
                            "reason": t.reason,
                            "code": t.code,
                            "invalid_category": t.invalid_category,
                        }
                        for t in ss.timings
                    ]
                )

                row: Dict[str, Any] = {
                    "experiment": "E3",
                    "operation": op,
                    "target_offered_tps": rate,
                    "actual_submission_tps": ss.actual_submission_tps,
                    "steady_state_valid_commit_tps": ss.steady_state_valid_commit_tps,
                    "valid_committed_tps": ss.steady_state_valid_commit_tps,  # alias for plotters
                    "offered_tps": rate,
                    "submission_ratio_vs_target": submit_ratio,
                    "total_submitted": ss.total_submitted,
                    "measure_submitted": ss.measure_submitted,
                    "measure_valid_commits": ss.measure_valid_commits,
                    "total_valid_eventually": ss.total_valid_eventually,
                    "total_invalid": ss.total_invalid,
                    "invalid": ss.total_invalid,
                    "invalid_transaction_rate": (
                        ss.total_invalid / ss.total_submitted if ss.total_submitted else 0.0
                    ),
                    "invalid_taxonomy_counts": inv_sum["counts"],
                    "invalid_taxonomy_rates": inv_sum["rates"],
                    "mean_latency_s": sum(lats) / len(lats),
                    "p50_latency_s": percentile(lats, 50),
                    "p95_latency_s": percentile(lats, 95),
                    "mean_scheduling_delay_s": sum(delays) / len(delays),
                    "max_outstanding_observed": ss.max_outstanding_observed,
                    "configured_max_outstanding": max_outstanding,
                    "configured_worker_threads": worker_threads,
                    "bound_hit": ss.bound_hit,
                    "bound_wait_events": ss.bound_wait_events,
                    "outstanding_at_measurement_end": ss.outstanding_at_measurement_end,
                    "drain_duration_s": ss.drain_duration_s,
                    "warmup_s": warmup_s,
                    "measure_s": measure_s,
                    "measurement_duration_s": measure_s,
                    "workload_model": "OPEN_LOOP_STEADY_STATE",
                    "key_distribution": key_dist,
                    "limiting_factor": limit,
                    "client": "persistent_gateway_http",
                    "live_fabric_network": True,
                    "deployment_class": "single-host_local",
                    "wan_distributed": False,
                    "fabric_topology": "single-org_1peer_1orderer",
                    "ledger_impl": "HyperledgerFabric_CCAAS",
                    "backend": "live_fabric_gateway_persistent",
                    **latency_summary(lats, prefix="latency_s"),
                }
                run_ctx.add_row(row)

                for t in ss.timings:
                    run_ctx.add_row(
                        {
                            "experiment": "E3",
                            "phase": "per_tx",
                            "tx_phase": t.phase,
                            "operation": op,
                            "target_offered_tps": rate,
                            "tx_index": t.tx_index,
                            "scheduled_time": t.scheduled_submission_s,
                            "actual_submit_time": t.actual_submission_s,
                            "commit_time": t.commit_completion_s,
                            "scheduling_delay_s": t.scheduling_delay_s,
                            "latency_s": t.transaction_latency_s,
                            "e2e_offered_latency_s": t.offered_load_e2e_latency_s,
                            "validation_status": t.status,
                            "status": t.status,
                            "reason": t.reason,
                            "code": t.code,
                            "invalid_category": t.invalid_category,
                            "tx_id": t.tx_id,
                            "owner_key": t.owner_key,
                            "live_fabric_network": True,
                            "workload_model": "OPEN_LOOP_STEADY_STATE",
                        }
                    )
                print(
                    f"  submit={ss.actual_submission_tps:.2f} commit={ss.steady_state_valid_commit_tps:.2f} "
                    f"p95={percentile(lats,95):.3f}s drain={ss.drain_duration_s:.2f}s limit={limit}",
                    flush=True,
                )
    finally:
        server.stop()

    run_ctx.extra = {
        "experiment": "E3",
        "workload_model": "OPEN_LOOP_STEADY_STATE",
        "client": "persistent_gateway_http",
        "live_fabric_network": True,
        "deployment_class": "single-host_local",
        "wan_distributed": False,
        "warmup_s": warmup_s,
        "measure_s": measure_s,
        "note": "Steady-state fixed-duration open-loop; drain excluded from primary commit TPS.",
    }
    run_ctx.finish()
    return 0
