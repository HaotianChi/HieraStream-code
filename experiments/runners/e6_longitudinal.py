"""E6 — Longitudinal streaming scalability (VitalDB high-rate stress)."""

from __future__ import annotations

import itertools
import time
from typing import Any, Dict, Iterator, Optional

from experiments.harness.run_context import create_run, load_config, resource_snapshot


def run(smoke: bool = False, config_path: Optional[str] = None) -> int:
    from core.protocol.workflow import HieraStreamWorkflow
    from data.adapters.registry import iter_workload, prepare_dataset
    from data.replay.engine import OfflineReplayEngine, ReplayConfig, ReplayMode
    from data.replay.segmenter import PRESETS, SegmentPolicy

    cfg = load_config("longitudinal", config_path)
    prepare_dataset("vitaldb", smoke=smoke)

    rates = [50, 200] if smoke else list(cfg.get("replay_rates_eps", [10, 50, 100, 500, 1000]))
    max_events = 30 if smoke else int(cfg.get("max_events", 500))
    policy_name = cfg.get("segment_policy", "records_10")
    policy = PRESETS.get(policy_name) or SegmentPolicy.from_dict(
        cfg.get("segment_policy_dict", {"name": policy_name, "target_records": 10})
    )

    run_ctx = create_run(
        "longitudinal",
        {
            **cfg,
            "smoke": smoke,
            "dataset": "vitaldb",
            "segment_policy": policy.to_dict(),
            "replay_rates_eps": rates,
            "max_events": max_events,
        },
    )

    for rate in rates:
        wf = HieraStreamWorkflow(owner_id=f"owner-e6-{rate}")
        wf.setup()
        wf.provision_user("u", ["doctor", "cardiology"], ["AttendingPhysician"])

        events = itertools.islice(iter_workload("vitaldb", smoke=smoke), max_events)

        pub_latencies = []
        seg_count = 0
        backlog_samples = []

        def on_segment(batch) -> None:
            nonlocal seg_count
            t0 = time.perf_counter()
            wf.publish(batch.payload, targets=["AttendingPhysician"], seg_id=f"e6-{rate}-{batch.segment_index}")
            pub_latencies.append(time.perf_counter() - t0)
            seg_count += 1

        # Smoke: ASAP (no sleep). Full: pace to offered events/sec.
        mode = ReplayMode.AS_FAST_AS_POSSIBLE if smoke else ReplayMode.TARGET_EVENTS_PER_SEC
        engine = OfflineReplayEngine(
            ReplayConfig(
                mode=mode,
                target_events_per_sec=float(rate),
                segment_policy=policy,
            ),
            max_backlog=None,
        )
        rs0 = resource_snapshot()
        t0 = time.perf_counter()
        stats = engine.run(events, on_segment=on_segment, sleep=not smoke)
        wall = max(time.perf_counter() - t0, 1e-9)
        rs1 = resource_snapshot()

        sustained = stats.accepted_events / wall
        # Saturation heuristic: sustained << offered OR backlog grew
        saturated = sustained < 0.5 * rate or stats.queue_backlog > 0

        row: Dict[str, Any] = {
            "experiment": "E6",
            "dataset": "vitaldb",
            "offered_events_per_sec": rate,
            "sustained_throughput_eps": sustained,
            "sustained_throughput_seg_s": seg_count / wall,
            "segment_completion_rate": seg_count / wall,
            "segments_created": stats.segments_created,
            "input_events": stats.input_events,
            "accepted_events": stats.accepted_events,
            "dropped_events": stats.dropped_events,
            "queue_backlog": stats.queue_backlog,
            "wall_s": wall,
            "segment_policy": policy.name,
            "saturated": saturated,
            "cpu_percent_end": rs1.get("cpu_percent"),
            "rss_bytes_end": rs1.get("rss_bytes"),
            "ru_maxrss_kb_end": rs1.get("ru_maxrss_kb"),
            "ru_utime_delta_s": (rs1.get("ru_utime_s") or 0) - (rs0.get("ru_utime_s") or 0),
            "mean_segment_publish_s": sum(pub_latencies) / max(1, len(pub_latencies)),
            "deployment_class": "single-host_local",
            "wan_distributed": False,
            "crypto_backend": getattr(wf.crypto, "backend", None),
            "ipfs_backend": getattr(wf.ipfs, "backend", None),
        }
        run_ctx.add_row(row)
        for i, lat in enumerate(pub_latencies):
            run_ctx.add_row(
                {
                    "experiment": "E6",
                    "phase": "per_segment",
                    "offered_events_per_sec": rate,
                    "seg_index": i,
                    "publish_latency_s": lat,
                }
            )

    # Identify saturation point from measured rows only
    summaries = [r for r in run_ctx.rows if r.get("experiment") == "E6" and "saturated" in r]
    sat_rates = [r["offered_events_per_sec"] for r in summaries if r.get("saturated")]
    run_ctx.extra = {
        "experiment": "E6",
        "saturation_point_eps": min(sat_rates) if sat_rates else None,
        "dominant_bottleneck_note": "Inferred from measured sustained<<offered or backlog; see raw rows",
    }
    run_ctx.finish()
    return 0
