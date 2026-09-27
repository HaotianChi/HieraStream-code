"""E4 paired open-loop auth-consistency experiment.

HieraStream and the unversioned baseline replay identical exogenous
publication and authorization-update schedules. The only intentional
difference is CommitSegment AuthKey MVCC dependency.
"""

from __future__ import annotations

import hashlib
import json
import queue
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from experiments.harness.run_context import create_run, load_config


AuthTuple = Tuple[int, str, str, str]


@dataclass(frozen=True)
class SchedEvent:
    t: float
    kind: str  # "auth" | "publish"
    index: int
    auth_kind: int = 0


def _snap_tuple(snap) -> AuthTuple:
    return (
        int(snap.version),
        str(snap.policy_id),
        str(snap.attr_state_id),
        str(snap.role_state_id),
    )


def _segment_committed_tuple(record: Dict[str, Any]) -> AuthTuple:
    if "version" in record and record["version"] is not None:
        ver = int(record["version"])
    else:
        ver = int(record["observedVersion"])
    return (
        ver,
        str(record["policyId"]),
        str(record["attrStateId"]),
        str(record["roleStateId"]),
    )


def build_schedule(
    *,
    rate: float,
    n_pubs: int,
    pub_interval_s: float,
    auth_horizon_slack_s: float,
    seed: int,
) -> Tuple[List[SchedEvent], str]:
    """Deterministic open-loop schedule. Auth kinds cycle 0/1/2 (policy/attr/role)."""
    events: List[SchedEvent] = []
    for i in range(n_pubs):
        events.append(SchedEvent(t=i * pub_interval_s, kind="publish", index=i))
    horizon = (n_pubs - 1) * pub_interval_s + auth_horizon_slack_s
    if rate > 0:
        # Match historical E4 auth_worker: first update fires immediately at t=0,
        # then every 1/rate until the open-loop horizon (~1 s for 40×0.025 s pubs).
        interval = 1.0 / rate
        k = 0
        t = 0.0
        while t <= horizon + 1e-12:
            events.append(SchedEvent(t=t, kind="auth", index=k, auth_kind=k % 3))
            k += 1
            t += interval
    # At equal timestamps, auth precedes publish (same as starting auth_worker first).
    events.sort(key=lambda e: (e.t, 0 if e.kind == "auth" else 1, e.index))
    payload = [
        {"t": e.t, "kind": e.kind, "index": e.index, "auth_kind": e.auth_kind} for e in events
    ]
    digest = hashlib.sha256(
        json.dumps({"seed": seed, "rate": rate, "events": payload}, sort_keys=True).encode()
    ).hexdigest()
    return events, digest


def _apply_auth(wf, auth_kind: int, leaf, AND) -> None:
    if auth_kind == 0:
        wf.update_policy(AND(leaf("doctor"), leaf("cardiology")))
    elif auth_kind == 1:
        wf.revoke_attribute("emergency", revoked_users=[])
    else:
        wf.reassign_roles({"alice": ["AttendingPhysician"]})


def _run_scheme(
    *,
    scheme: str,
    schedule: Sequence[SchedEvent],
    schedule_hash: str,
    rate: float,
    seed: int,
    rep: int,
    owner_id: str,
) -> Dict[str, Any]:
    from core.blockchain.client.peer_backend import FabricTxStatus
    from core.crypto.python.access_tree import AND, leaf
    from core.protocol.workflow import HieraStreamWorkflow
    from experiments.baselines.unversioned.workflow import UnversionedWorkflow

    if scheme == "HieraStream":
        wf: Any = HieraStreamWorkflow(owner_id=owner_id)
    else:
        wf = UnversionedWorkflow(owner_id=owner_id)
    wf.setup(initial_policy=AND(leaf("doctor"), leaf("cardiology")))
    wf.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])

    # lifecycle_lock protects AuthorizationLifecycle local state only.
    # Do NOT hold it across crypto prepare or ledger commit — PeerMVCC
    # AuthKey races must remain possible (historical E4 concurrent design).
    lifecycle_lock = threading.RLock()
    auth_events_applied: List[Dict[str, Any]] = []
    pub_events_started: List[Dict[str, Any]] = []

    initial = wf.fabric.get_authorization_snapshot(wf.owner_id)
    assert initial is not None
    initial_tuple = _snap_tuple(initial)

    counters = {
        "source_publications": 0,
        "commit_attempts": 0,
        "valid_commits": 0,
        "failed_attempts": 0,
        "stale_preparations": 0,
        "stale_valid_commits": 0,
        "retry_events": 0,
        "auth_updates_applied": 0,
        "auth_update_failures": 0,
        "mvcc_invalidations": 0,
        "explicit_snapshot_rejections": 0,
    }
    per_seg: List[Dict[str, Any]] = []
    row_lock = threading.Lock()

    def _is_stale(committed: AuthTuple, auth_at_or_before_commit: AuthTuple) -> bool:
        """Identical semantic for both schemes: committed snap precedes AuthKey."""
        return committed != auth_at_or_before_commit

    def apply_auth_event(ev: SchedEvent, fired_at: float) -> None:
        with lifecycle_lock:
            _apply_auth(wf, ev.auth_kind, leaf, AND)
            snap = wf.fabric.get_authorization_snapshot(wf.owner_id)
        with row_lock:
            auth_events_applied.append(
                {
                    "index": ev.index,
                    "auth_kind": ev.auth_kind,
                    "sched_t": ev.t,
                    "fired_at": fired_at,
                    "tuple": list(_snap_tuple(snap)) if snap else None,
                }
            )
            counters["auth_updates_applied"] += 1

    def publish_one(ev: SchedEvent, started_at: float) -> None:
        from core.actors.gateway.owner import PublishedSegment

        with row_lock:
            counters["source_publications"] += 1
            pub_events_started.append(
                {"index": ev.index, "sched_t": ev.t, "started_at": started_at}
            )
        seg_id = f"p-{seed}-{rep}-{ev.index}"
        payload = f"payload-{seed}-{rep}-{ev.index}".encode()
        targets = ["AttendingPhysician"]

        t0 = time.perf_counter()
        attempts = 0
        retries = 0
        stale_preps = 0
        published = False
        stale_valid = False
        last_status = ""
        max_attempts = 8 if scheme == "HieraStream" else 1

        if scheme == "HieraStream":
            assert wf.gateway and wf.lifecycle
            pending = wf.gateway.protect_payload(seg_id, payload, targets)
            wf.pendings[pending.seg_id] = pending
            for attempts in range(1, max_attempts + 1):
                with lifecycle_lock:
                    tree = wf.lifecycle.active_policy_tree()
                    snap = wf.gateway.read_active_snapshot()
                prep_tuple = _snap_tuple(snap)
                with row_lock:
                    counters["commit_attempts"] += 1
                # Prepare crypto/metadata first (race window), then sample AuthKey
                # immediately before the ledger write — same gate point as UV.
                prepared = wf.gateway.prepare_commit_artifacts(pending, snap, tree)
                auth_gate = wf.fabric.get_authorization_snapshot(wf.owner_id)
                auth_gate_tuple = _snap_tuple(auth_gate) if auth_gate else prep_tuple
                wf.gateway.unpublished_predictions[pending.seg_id] = prepared.mcid
                result = wf.fabric.commit_segment(
                    wf.owner_id,
                    pending.seg_id,
                    pending.cid,
                    prepared.mcid,
                    snap.version,
                    snap.policy_id,
                    snap.attr_state_id,
                    snap.role_state_id,
                    prepared.eta,
                    caller=wf.gateway.caller_id,
                )
                metadata_obj, mcid, eta = prepared.metadata_obj, prepared.mcid, prepared.eta
                last_status = (
                    result.status.value if hasattr(result.status, "value") else str(result.status)
                )
                if result.status == FabricTxStatus.VALID:
                    mcid_pub = wf.gateway.publish_metadata_after_valid(
                        pending, metadata_obj, mcid
                    )
                    on_chain = wf.fabric.get_segment(wf.owner_id, pending.seg_id)
                    assert on_chain is not None
                    committed = _segment_committed_tuple(on_chain)
                    stale_valid = _is_stale(committed, auth_gate_tuple)
                    if committed != prep_tuple:
                        stale_valid = True
                    wf.segments[pending.seg_id] = PublishedSegment(
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
                    published = True
                    with row_lock:
                        counters["valid_commits"] += 1
                        if stale_valid:
                            counters["stale_valid_commits"] += 1
                    break
                with row_lock:
                    counters["failed_attempts"] += 1
                    retries += 1
                    counters["retry_events"] += 1
                    if prep_tuple != auth_gate_tuple:
                        stale_preps += 1
                        counters["stale_preparations"] += 1
                    if result.status == FabricTxStatus.MVCC_READ_CONFLICT:
                        counters["mvcc_invalidations"] += 1
                    elif result.status == FabricTxStatus.INVALID:
                        counters["explicit_snapshot_rejections"] += 1
        else:
            # Unversioned: snap → crypto prepare → AuthKey gate → ledger write.
            # No forced update between snapshot and commit.
            assert wf.lifecycle
            with lifecycle_lock:
                snap = wf.gateway.read_active_snapshot()  # type: ignore[attr-defined]
                tree = wf.lifecycle.active_policy_tree()
            prep_tuple = _snap_tuple(snap)
            pending = wf.gateway.protect_payload(seg_id, payload, targets)  # type: ignore[attr-defined]
            attempts = 1
            with row_lock:
                counters["commit_attempts"] += 1
            meta, mcid, eta = wf.gateway.prepare_unversioned_artifacts(  # type: ignore[attr-defined]
                pending, snap, tree
            )
            auth_gate = wf.fabric.get_authorization_snapshot(wf.owner_id)
            auth_gate_tuple = _snap_tuple(auth_gate) if auth_gate else prep_tuple
            result = wf.gateway.commit_prepared_unversioned(pending, snap, mcid, eta)  # type: ignore[attr-defined]
            last_status = (
                result.status.value if hasattr(result.status, "value") else str(result.status)
            )
            if result.status == FabricTxStatus.VALID:
                wf.gateway.publish_metadata_after_valid(pending, meta, mcid)  # type: ignore[attr-defined]
                on_chain = wf.fabric.get_segment(wf.owner_id, pending.seg_id)
                assert on_chain is not None
                committed = _segment_committed_tuple(on_chain)
                stale_valid = _is_stale(committed, auth_gate_tuple)
                with row_lock:
                    if prep_tuple != auth_gate_tuple:
                        stale_preps += 1
                        counters["stale_preparations"] += 1
                    published = True
                    counters["valid_commits"] += 1
                    if stale_valid:
                        counters["stale_valid_commits"] += 1
            else:
                with row_lock:
                    counters["failed_attempts"] += 1

        with row_lock:
            per_seg.append(
                {
                    "experiment": "E4_paired",
                    "phase": "per_segment",
                    "scheme": scheme,
                    "auth_update_rate": rate,
                    "seed": seed,
                    "repetition": rep,
                    "schedule_hash": schedule_hash,
                    "seg_index": ev.index,
                    "sched_t": ev.t,
                    "attempts": attempts,
                    "retry_events_seg": retries,
                    "stale_preparations_seg": stale_preps,
                    "stale_valid": stale_valid,
                    "success": published,
                    "last_status": last_status,
                    "publication_latency_s": time.perf_counter() - t0,
                }
            )

    # Open-loop dispatcher + single auth worker (matches historical E4
    # auth_worker: one updater thread, concurrent with publication worker).
    # Auth events are applied sequentially with short MVCC retries so both
    # schemes observe the same exogenous update counts.
    pub_q: queue.Queue[Optional[SchedEvent]] = queue.Queue()
    auth_q: queue.Queue[Optional[Tuple[SchedEvent, float]]] = queue.Queue()
    errors: List[BaseException] = []

    def publisher() -> None:
        while True:
            item = pub_q.get()
            if item is None:
                pub_q.task_done()
                break
            try:
                publish_one(item, time.perf_counter())
            except BaseException as exc:  # noqa: BLE001 — surface in parent
                errors.append(exc)
            finally:
                pub_q.task_done()

    def auth_worker() -> None:
        while True:
            item = auth_q.get()
            if item is None:
                auth_q.task_done()
                break
            ev, fired = item
            try:
                # Retry transient AuthKey MVCC conflicts so schedule cardinality matches.
                for _ in range(8):
                    try:
                        apply_auth_event(ev, fired)
                        break
                    except Exception:
                        time.sleep(0.001)
                else:
                    with row_lock:
                        counters["auth_update_failures"] += 1
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)
            finally:
                auth_q.task_done()

    pub_thread = threading.Thread(target=publisher, name=f"pub-{scheme}", daemon=True)
    auth_thread = threading.Thread(target=auth_worker, name=f"auth-{scheme}", daemon=True)
    pub_thread.start()
    auth_thread.start()

    t0 = time.perf_counter()
    for ev in schedule:
        target = t0 + ev.t
        now = time.perf_counter()
        if now < target:
            time.sleep(target - now)
        fired = time.perf_counter()
        if ev.kind == "auth":
            auth_q.put((ev, fired))
        else:
            pub_q.put(ev)

    auth_q.put(None)
    pub_q.put(None)
    auth_q.join()
    pub_q.join()
    auth_thread.join(timeout=30.0)
    pub_thread.join(timeout=30.0)
    if errors:
        raise errors[0]

    valid = counters["valid_commits"]
    retries = counters["retry_events"]
    summary = {
        "experiment": "E4_paired",
        "phase": "summary",
        "scheme": scheme,
        "auth_update_rate": rate,
        "seed": seed,
        "repetition": rep,
        "schedule_hash": schedule_hash,
        "initial_auth_tuple": list(initial_tuple),
        "source_publications": counters["source_publications"],
        "commit_attempts": counters["commit_attempts"],
        "successful_segment_commits": valid,
        "valid_commits": valid,
        "failed_attempts": counters["failed_attempts"],
        "stale_preparations": counters["stale_preparations"],
        "stale_successful_commits": counters["stale_valid_commits"],
        "stale_valid_commits": counters["stale_valid_commits"],
        "retry_count": retries,
        "retry_events": retries,
        "stale_success_ratio": (counters["stale_valid_commits"] / valid) if valid else 0.0,
        "retry_rate": retries / max(1, valid + retries),
        "mvcc_invalidations": counters["mvcc_invalidations"],
        "explicit_snapshot_rejections": counters["explicit_snapshot_rejections"],
        "auth_updates_applied": counters["auth_updates_applied"],
        "auth_update_failures": counters["auth_update_failures"],
        "n_auth_schedule": sum(1 for e in schedule if e.kind == "auth"),
        "n_pub_schedule": sum(1 for e in schedule if e.kind == "publish"),
        "auth_events_applied_json": json.dumps(auth_events_applied),
        "pub_events_started_json": json.dumps(pub_events_started),
        "stale_determination": "committed_tuple_vs_AuthKey_after_crypto_prepare_before_ledger_write",
        "deployment_class": "single-host_local",
        "wan_distributed": False,
        "design": "paired_open_loop",
    }
    return {"summary": summary, "per_segment": per_seg}


def run(smoke: bool = False, config_path: Optional[str] = None) -> int:
    cfg = load_config("consistency_paired", config_path)
    # Prefer paired FINAL yaml when caller passes it; also accept defaults.
    auth_rates = (
        [0.5, 2.0] if smoke else list(cfg.get("auth_update_rates", [0.5, 1.0, 2.0, 5.0, 10.0]))
    )
    n_pubs = 8 if smoke else int(cfg.get("segments_per_rate", 40))
    n_reps = 2 if smoke else int(cfg.get("paired_repetitions", 10))
    base_seed = int(cfg.get("base_seed", 20260928))
    pub_interval = float(cfg.get("publication_interval_s", 0.025))
    auth_slack = float(cfg.get("auth_horizon_slack_s", 0.05))

    run_ctx = create_run(
        "E4_paired",
        {
            **cfg,
            "smoke": smoke,
            "auth_update_rates": auth_rates,
            "segments_per_rate": n_pubs,
            "paired_repetitions": n_reps,
            "base_seed": base_seed,
            "publication_interval_s": pub_interval,
            "auth_horizon_slack_s": auth_slack,
            "design": "paired_open_loop",
        },
    )

    schedule_rows: List[Dict[str, Any]] = []
    for rate in auth_rates:
        for rep in range(n_reps):
            seed = base_seed + int(rate * 1000) + rep
            schedule, digest = build_schedule(
                rate=float(rate),
                n_pubs=n_pubs,
                pub_interval_s=pub_interval,
                auth_horizon_slack_s=auth_slack,
                seed=seed,
            )
            schedule_rows.append(
                {
                    "experiment": "E4_paired",
                    "phase": "schedule",
                    "auth_update_rate": rate,
                    "seed": seed,
                    "repetition": rep,
                    "schedule_hash": digest,
                    "n_auth": sum(1 for e in schedule if e.kind == "auth"),
                    "n_pub": sum(1 for e in schedule if e.kind == "publish"),
                    "schedule_json": json.dumps(
                        [
                            {
                                "t": e.t,
                                "kind": e.kind,
                                "index": e.index,
                                "auth_kind": e.auth_kind,
                            }
                            for e in schedule
                        ]
                    ),
                }
            )
            # Identical schedule → both schemes.
            hs = _run_scheme(
                scheme="HieraStream",
                schedule=schedule,
                schedule_hash=digest,
                rate=float(rate),
                seed=seed,
                rep=rep,
                owner_id=f"owner-hs-{seed}-{rep}",
            )
            uv = _run_scheme(
                scheme="unversioned_publication",
                schedule=schedule,
                schedule_hash=digest,
                rate=float(rate),
                seed=seed,
                rep=rep,
                owner_id=f"owner-uv-{seed}-{rep}",
            )
            if hs["summary"]["schedule_hash"] != uv["summary"]["schedule_hash"]:
                raise RuntimeError("schedule hash divergence between schemes")
            if hs["summary"]["n_auth_schedule"] != uv["summary"]["n_auth_schedule"]:
                raise RuntimeError("auth schedule count divergence")
            if hs["summary"]["stale_valid_commits"] != 0:
                raise RuntimeError(
                    f"HieraStream produced stale valid commits: {hs['summary']}"
                )
            run_ctx.add_row(schedule_rows[-1])
            for row in hs["per_segment"]:
                run_ctx.add_row(row)
            for row in uv["per_segment"]:
                run_ctx.add_row(row)
            run_ctx.add_row(hs["summary"])
            run_ctx.add_row(uv["summary"])

    # Aggregate across repetitions for plotting convenience.
    for rate in auth_rates:
        for scheme in ("HieraStream", "unversioned_publication"):
            reps = [
                r
                for r in run_ctx.rows
                if r.get("phase") == "summary"
                and r.get("scheme") == scheme
                and float(r["auth_update_rate"]) == float(rate)
            ]
            if not reps:
                continue

            def _mean(key: str) -> float:
                return sum(float(r[key]) for r in reps) / len(reps)

            def _std(key: str) -> float:
                xs = [float(r[key]) for r in reps]
                mu = sum(xs) / len(xs)
                if len(xs) < 2:
                    return 0.0
                return (sum((x - mu) ** 2 for x in xs) / (len(xs) - 1)) ** 0.5

            sum_valid = sum(int(r["valid_commits"]) for r in reps)
            sum_stale = sum(int(r["stale_valid_commits"]) for r in reps)
            sum_retry = sum(int(r["retry_events"]) for r in reps)
            pooled_stale = (sum_stale / sum_valid) if sum_valid else 0.0
            pooled_retry = sum_retry / max(1, sum_valid + sum_retry)

            run_ctx.add_row(
                {
                    "experiment": "E4_paired",
                    "phase": "aggregate",
                    "scheme": scheme,
                    "auth_update_rate": rate,
                    "paired_repetitions": len(reps),
                    "source_publications_mean": _mean("source_publications"),
                    "commit_attempts_mean": _mean("commit_attempts"),
                    "valid_commits_mean": _mean("valid_commits"),
                    "failed_attempts_mean": _mean("failed_attempts"),
                    "stale_preparations_mean": _mean("stale_preparations"),
                    "stale_valid_commits_mean": _mean("stale_valid_commits"),
                    "retry_events_mean": _mean("retry_events"),
                    "stale_valid_commits_total": sum_stale,
                    "valid_commits_total": sum_valid,
                    "retry_events_total": sum_retry,
                    "stale_success_ratio": pooled_stale,
                    "stale_success_ratio_std": _std("stale_success_ratio"),
                    "retry_rate": pooled_retry,
                    "retry_rate_std": _std("retry_rate"),
                    # Plot-facing aliases matching historical column names.
                    "successful_segment_commits": sum_valid,
                    "stale_successful_commits": sum_stale,
                    "ratio_definition": "stale_valid_commits / valid_commits (pooled)",
                    "retry_rate_definition": "retry_events / (valid_commits + retry_events) (pooled)",
                    "design": "paired_open_loop",
                }
            )

    run_ctx.extra = {
        "experiment": "E4_paired",
        "design": "paired_open_loop",
        "includes_unversioned_baseline": True,
    }
    run_ctx.finish()
    return 0
