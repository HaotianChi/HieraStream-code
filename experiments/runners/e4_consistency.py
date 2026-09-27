"""E4 — Concurrent authorization consistency while publishing segments."""

from __future__ import annotations

import threading
import time
from typing import Any, Dict, List, Optional

from experiments.harness.metrics import latency_summary, percentile
from experiments.harness.run_context import create_run, load_config


def run(smoke: bool = False, config_path: Optional[str] = None) -> int:
    from core.blockchain.client.peer_backend import FabricTxStatus
    from core.crypto.python.access_tree import AND, leaf
    from core.protocol.workflow import HieraStreamWorkflow

    cfg = load_config("consistency", config_path)
    # Authorization updates per second while publishing
    auth_rates = [0.5, 2.0] if smoke else list(cfg.get("auth_update_rates", [0.1, 0.5, 1.0, 2.0, 5.0]))
    segments = 8 if smoke else int(cfg.get("segments_per_rate", 40))
    duration_cap = 2.0 if smoke else float(cfg.get("duration_s", 10.0))

    run_ctx = create_run(
        "consistency",
        {**cfg, "smoke": smoke, "auth_update_rates": auth_rates, "segments_per_rate": segments},
    )

    for rate in auth_rates:
        wf = HieraStreamWorkflow(owner_id=f"owner-e4-{rate}")
        wf.setup(initial_policy=AND(leaf("doctor"), leaf("cardiology")))
        wf.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])

        stop = threading.Event()
        stats = {
            "auth_updates": 0,
            "auth_ok": 0,
            "auth_fail": 0,
        }
        lock = threading.Lock()

        def auth_worker() -> None:
            i = 0
            interval = 1.0 / rate if rate > 0 else 1e9
            next_t = time.perf_counter()
            while not stop.is_set():
                now = time.perf_counter()
                if now < next_t:
                    time.sleep(min(0.01, next_t - now))
                    continue
                next_t += interval
                try:
                    # Alternate policy / attribute / role updates
                    kind = i % 3
                    if kind == 0:
                        wf.update_policy(AND(leaf("doctor"), leaf("cardiology")))
                    elif kind == 1:
                        # Revoke unused attr to avoid locking out alice
                        wf.revoke_attribute("emergency", revoked_users=[])
                    else:
                        wf.reassign_roles({"alice": ["AttendingPhysician"]})
                    with lock:
                        stats["auth_updates"] += 1
                        stats["auth_ok"] += 1
                except Exception:
                    with lock:
                        stats["auth_updates"] += 1
                        stats["auth_fail"] += 1
                i += 1

        th = threading.Thread(target=auth_worker, daemon=True)
        if rate > 0:
            th.start()

        successful = 0
        stale_successful = 0  # must stay 0 under HieraStream
        snapshot_rejects = 0
        mvcc_invalidations = 0
        retries = 0
        regen_latencies: List[float] = []
        pub_latencies: List[float] = []
        t0_all = time.perf_counter()

        for s in range(segments):
            if time.perf_counter() - t0_all > duration_cap and smoke:
                break
            t_pub0 = time.perf_counter()
            # Instrument regenerate path: protect once, then commit loop counts retries
            assert wf.gateway and wf.lifecycle
            from core.actors.gateway.owner import PublishedSegment

            pending = wf.gateway.protect_payload(f"seg-{s}", f"payload-{s}".encode(), ["AttendingPhysician"])
            wf.pendings[pending.seg_id] = pending
            last_status = ""
            attempt = 0
            published = None
            for attempt in range(1, 8):
                tree = wf.lifecycle.active_policy_tree()
                snap = wf.gateway.read_active_snapshot()
                t_reg0 = time.perf_counter()
                result, metadata_obj, mcid, eta = wf.gateway.attempt_commit(pending, snap, tree)
                regen_latencies.append(time.perf_counter() - t_reg0)
                last_status = result.status.value if hasattr(result.status, "value") else str(result.status)
                if result.status == FabricTxStatus.VALID:
                    mcid_pub = wf.gateway.publish_metadata_after_valid(pending, metadata_obj, mcid)
                    published = PublishedSegment(
                        seg_id=pending.seg_id,
                        cid=pending.cid,
                        mcid=mcid_pub,
                        eta=eta,
                        snapshot=snap,
                        ct_aes=pending.ct_aes,
                        metadata_obj=metadata_obj,
                        meta_published=True,
                        targets=list(pending.targets),
                        ZA=pending.ZA,
                        ZR=pending.ZR,
                    )
                    wf.segments[pending.seg_id] = published
                    # Staleness vs AuthKey that validated this tx: segment record's
                    # committed 4-tuple must match the snapshot used at endorsement.
                    # (Do not re-read AuthKey after commit — concurrent updates race.)
                    on_chain = wf.fabric.get_segment(wf.owner_id, pending.seg_id)
                    if on_chain is not None and (
                        int(on_chain["version"]) != published.snapshot.version
                        or on_chain["policyId"] != published.snapshot.policy_id
                        or on_chain["attrStateId"] != published.snapshot.attr_state_id
                        or on_chain["roleStateId"] != published.snapshot.role_state_id
                    ):
                        stale_successful += 1
                    # Under Alg.1 VALID, on-chain tuple equals endorsed snapshot ⇒ stale=0
                    successful += 1
                    break
                if result.status == FabricTxStatus.MVCC_READ_CONFLICT:
                    mvcc_invalidations += 1
                    retries += 1
                    continue
                if result.status == FabricTxStatus.INVALID:
                    snapshot_rejects += 1
                    retries += 1
                    continue
                retries += 1
            pub_latencies.append(time.perf_counter() - t_pub0)
            run_ctx.add_row(
                {
                    "experiment": "E4",
                    "phase": "per_segment",
                    "auth_update_rate": rate,
                    "seg_index": s,
                    "attempts": attempt,
                    "last_status": last_status,
                    "publication_latency_s": pub_latencies[-1],
                    "success": published is not None,
                }
            )

        stop.set()
        if rate > 0:
            th.join(timeout=2.0)

        wall = max(time.perf_counter() - t0_all, 1e-9)
        summary: Dict[str, Any] = {
            "experiment": "E4",
            "phase": "summary",
            "scheme": "HieraStream",
            "auth_update_rate": rate,
            "successful_segment_commits": successful,
            "stale_successful_commits": stale_successful,
            "explicit_snapshot_rejections": snapshot_rejects,
            "mvcc_invalidations": mvcc_invalidations,
            "retry_count": retries,
            "retry_rate": retries / max(1, successful + retries),
            "key_envelope_regeneration_s_mean": sum(regen_latencies) / max(1, len(regen_latencies)),
            "e2e_publication_latency_s_mean": sum(pub_latencies) / max(1, len(pub_latencies)),
            "p95_publication_latency_s": percentile(pub_latencies, 95) if pub_latencies else float("nan"),
            "auth_updates_observed": stats["auth_updates"],
            "wall_s": wall,
            "stale_determination": "ledger_serialization_order_vs_endorsed_snapshot",
            "deployment_class": "single-host_local",
            "wan_distributed": False,
            **latency_summary(pub_latencies, prefix="publication_latency_s"),
            **{f"regen_{k}": v for k, v in latency_summary(regen_latencies, prefix="latency_s").items()},
        }
        run_ctx.add_row(summary)

    # Unversioned baseline: same stack, measure stale successful commits
    from experiments.baselines.unversioned.workflow import UnversionedWorkflow

    for rate in auth_rates[:1] if smoke else auth_rates:
        uv = UnversionedWorkflow(owner_id=f"owner-e4-uv-{rate}")
        uv.setup(initial_policy=AND(leaf("doctor"), leaf("cardiology")))
        uv.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
        stale_ok = success = 0
        for s in range(min(segments, 6) if smoke else segments // 2):
            observed = uv.gateway.read_active_snapshot()  # type: ignore
            pending = uv.gateway.protect_payload(f"uv-{s}", f"p-{s}".encode(), ["AttendingPhysician"])  # type: ignore
            if rate > 0:
                try:
                    uv.revoke_attribute("emergency", revoked_users=[])
                except Exception:
                    pass
            tree = uv.lifecycle.active_policy_tree()  # type: ignore
            result, meta, mcid, eta = uv.gateway.attempt_commit_unversioned(pending, observed, tree)  # type: ignore
            if result.status == FabricTxStatus.VALID:
                success += 1
                uv.gateway.publish_metadata_after_valid(pending, meta, mcid)  # type: ignore
                cur = uv.fabric.get_authorization_snapshot(uv.owner_id)
                if cur is not None and (
                    observed.version != cur.version
                    or observed.policy_id != cur.policy_id
                    or observed.attr_state_id != cur.attr_state_id
                    or observed.role_state_id != cur.role_state_id
                ):
                    stale_ok += 1
        run_ctx.add_row(
            {
                "experiment": "E4",
                "phase": "unversioned_baseline_summary",
                "scheme": "unversioned_publication",
                "auth_update_rate": rate,
                "successful_segment_commits": success,
                "stale_successful_commits": stale_ok,
                "note": "CommitSegmentUnversioned does not read AuthKey; stale commits can succeed",
            }
        )

    run_ctx.extra = {"experiment": "E4", "includes_unversioned_baseline": True}
    run_ctx.finish()
    return 0
