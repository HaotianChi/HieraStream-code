"""E9 — Four-dataset end-to-end (identical crypto/system params).

Claim boundary: system compatibility / generalization across heterogeneous
healthcare traces. NOT clinical validation, epidemiology, or ML evaluation.
"""

from __future__ import annotations

import itertools
import time
from typing import Any, Dict, Optional

from experiments.harness.run_context import create_run, load_config


DATASETS = ["uci_heart_failure", "hf_remote_monitoring", "hm3_synthetic", "vitaldb"]

CLAIM_BOUNDARY = (
    "system_compatibility_generalization_only — "
    "not clinical validation, epidemiology, or predictive-model evaluation"
)


def run(smoke: bool = False, config_path: Optional[str] = None) -> int:
    from core.blockchain.client.peer_backend import FabricTxStatus
    from core.protocol.metadata import metadata_bytes
    from core.protocol.workflow import HieraStreamWorkflow
    from data.adapters.registry import iter_workload, prepare_dataset
    from data.replay.engine import OfflineReplayEngine, ReplayConfig, ReplayMode
    from data.replay.segmenter import PRESETS, SegmentPolicy

    cfg = load_config("datasets", config_path)
    datasets = list(cfg.get("datasets", DATASETS))
    replay_rate = float(cfg.get("replay_rate_eps", 50 if not smoke else 100))
    max_events_default = 8 if smoke else int(cfg.get("max_events_per_dataset", 80))
    policy_name = cfg.get("segment_policy", "records_1")
    policy = PRESETS.get(policy_name) or SegmentPolicy(name="records_1", target_records=1)

    run_ctx = create_run(
        "datasets",
        {
            **cfg,
            "smoke": smoke,
            "datasets": datasets,
            "replay_rate_eps": replay_rate,
            "segment_policy": policy.to_dict(),
            "max_events_per_dataset": max_events_default,
            "claim_boundary": CLAIM_BOUNDARY,
            "note": (
                "Identical cryptographic and system parameters; only replay trace changes. "
                + CLAIM_BOUNDARY
            ),
        },
    )

    for ds in datasets:
        # Formal UCI: always attempt public download (never synthesize).
        prepare_dataset(ds, smoke=smoke, download=(not smoke and ds == "uci_heart_failure"))
        scale_meta: Dict[str, Any] = {}
        subjects = None
        paper_patients = None
        try:
            from pathlib import Path
            import json as _json

            man = Path(__file__).resolve().parents[2] / "data" / "manifests" / f"{ds}.json"
            if man.exists():
                scale_meta = _json.loads(man.read_text(encoding="utf-8"))
                subjects = scale_meta.get("subjects_represented") or scale_meta.get("subjects")
                paper_patients = scale_meta.get("paper_description_patients")
                apf = scale_meta.get("actual_public_files") or {}
                if isinstance(apf, dict):
                    files = apf.get("files") or {}
                    if isinstance(files, dict) and files:
                        subj_vals = [
                            int(v.get("subjects_represented"))
                            for v in files.values()
                            if isinstance(v, dict) and v.get("subjects_represented") is not None
                        ]
                        if subj_vals:
                            subjects = max(subj_vals)
                    if paper_patients is None:
                        paper_patients = apf.get("paper_description_patients")
                if paper_patients is None:
                    paper_patients = scale_meta.get("paper_description_patients")
        except Exception:
            scale_meta = {}

        # UCI: consume the full staged public set (299); others keep frozen cap.
        if ds == "uci_heart_failure" and not smoke:
            max_events = int(scale_meta.get("records") or scale_meta.get("expected_full_uci_records") or 299)
            expected = int(scale_meta.get("expected_full_uci_records") or 299)
            integrity = scale_meta.get("integrity_check")
            if integrity not in (None, "PASS") or int(scale_meta.get("records") or 0) < 290:
                raise RuntimeError(
                    f"E9 UCI incomplete: records={scale_meta.get('records')} "
                    f"integrity={integrity} expected={expected}"
                )
        else:
            max_events = max_events_default

        wf = HieraStreamWorkflow(owner_id=f"owner-e9-{ds}")
        wf.setup()
        wf.provision_user("u", ["doctor", "cardiology"], ["AttendingPhysician"])

        e2e: list[float] = []
        payload_bytes = 0
        meta_bytes_total = 0
        segs = 0

        def on_segment(batch) -> None:
            nonlocal payload_bytes, meta_bytes_total, segs
            assert wf.gateway and wf.lifecycle
            t0 = time.perf_counter()
            pending = wf.gateway.protect_payload(
                f"e9-{ds}-{batch.segment_index}",
                batch.payload,
                ["AttendingPhysician"],
            )
            snap = wf.gateway.read_active_snapshot()
            tree = wf.lifecycle.active_policy_tree()
            result, metadata_obj, mcid, _eta = wf.gateway.attempt_commit(pending, snap, tree)
            if result.status == FabricTxStatus.VALID:
                wf.gateway.publish_metadata_after_valid(pending, metadata_obj, mcid)
            e2e.append(time.perf_counter() - t0)
            payload_bytes += batch.nbytes
            meta_bytes_total += len(metadata_bytes(metadata_obj))
            segs += 1

        events = itertools.islice(iter_workload(ds, smoke=smoke), max_events)
        engine = OfflineReplayEngine(
            ReplayConfig(
                mode=ReplayMode.TARGET_EVENTS_PER_SEC if not smoke else ReplayMode.AS_FAST_AS_POSSIBLE,
                target_events_per_sec=replay_rate,
                segment_policy=policy,
            )
        )
        t0 = time.perf_counter()
        stats = engine.run(events, on_segment=on_segment, sleep=not smoke)
        wall = max(time.perf_counter() - t0, 1e-9)

        if ds == "uci_heart_failure" and not smoke and stats.accepted_events < 290:
            raise RuntimeError(
                f"E9 UCI accepted_events={stats.accepted_events} < 290 — incomplete public set"
            )

        row: Dict[str, Any] = {
            "experiment": "E9",
            "dataset": ds,
            "segment_size_policy": policy.name,
            "segment_target_records": policy.target_records,
            "segment_target_bytes": policy.target_bytes,
            "replay_rate_eps": replay_rate,
            "throughput_seg_s": segs / wall,
            "throughput_eps": stats.accepted_events / wall,
            "e2e_latency_s_mean": sum(e2e) / max(1, len(e2e)),
            "metadata_overhead": meta_bytes_total / max(1, payload_bytes),
            "segments": segs,
            "payload_bytes": payload_bytes,
            "metadata_bytes": meta_bytes_total,
            "wall_s": wall,
            "max_events_requested": max_events,
            "accepted_events": stats.accepted_events,
            "dataset_kind": scale_meta.get("kind"),
            "dataset_synthetic": bool(
                scale_meta.get("synthetic")
                or "synthetic" in ds
                or "synthetic" in str(scale_meta.get("kind", "")).lower()
            ),
            "subjects_represented": subjects,
            "paper_description_patients": paper_patients,
            "smoke_records_in_manifest": scale_meta.get("smoke_records"),
            "dataset_source": scale_meta.get("source"),
            "dataset_records_staged": scale_meta.get("records"),
            "dataset_integrity_check": scale_meta.get("integrity_check"),
            "claim_boundary": CLAIM_BOUNDARY,
            "deployment_class": "single-host_local",
            "ipfs_backend": getattr(wf.ipfs, "backend", None),
            "crypto_backend": getattr(wf.crypto, "backend", None),
        }
        run_ctx.add_row(row)
        for i, lat in enumerate(e2e):
            run_ctx.add_row(
                {
                    "experiment": "E9",
                    "phase": "per_segment",
                    "dataset": ds,
                    "seg_index": i,
                    "e2e_latency_s": lat,
                }
            )

    run_ctx.extra = {
        "experiment": "E9",
        "table": "Table II",
        "claim_boundary": CLAIM_BOUNDARY,
    }
    run_ctx.finish()
    return 0
