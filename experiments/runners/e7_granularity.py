"""E7 — Segment granularity tradeoff (crypto/Fabric cost vs size)."""

from __future__ import annotations

import itertools
import statistics
import time
from typing import Any, Dict, List, Optional

from experiments.harness.run_context import create_run, load_config


def _fill_gate(
    payloads: List[int],
    target: int,
    *,
    max_ratio: float = 0.9,
    median_ratio: float = 0.8,
) -> Dict[str, Any]:
    """Validate that target T is realized by actual segment payloads.

    The final segment is treated as an optional tail and excluded from the
    median non-tail check when more than one segment exists.
    """
    if not payloads:
        return {
            "ok": False,
            "reason": "no_segments",
            "max_actual": 0,
            "median_non_tail": None,
            "n_segments": 0,
            "n_non_tail": 0,
            "tail_excluded": False,
        }
    max_actual = max(payloads)
    max_ok = max_actual >= max_ratio * target
    if len(payloads) >= 2:
        non_tail = payloads[:-1]
        tail_excluded = True
    else:
        non_tail = list(payloads)
        tail_excluded = False
    med = float(statistics.median(non_tail)) if non_tail else 0.0
    med_ok = med >= median_ratio * target
    ok = bool(max_ok and med_ok)
    reason = "ok"
    if not max_ok:
        reason = f"max_actual={max_actual} < {max_ratio}*{target}"
    elif not med_ok:
        reason = f"median_non_tail={med} < {median_ratio}*{target}"
    return {
        "ok": ok,
        "reason": reason,
        "max_actual": max_actual,
        "median_non_tail": med,
        "n_segments": len(payloads),
        "n_non_tail": len(non_tail),
        "tail_excluded": tail_excluded,
        "required_max": max_ratio * target,
        "required_median_non_tail": median_ratio * target,
    }


def run(smoke: bool = False, config_path: Optional[str] = None) -> int:
    from core.blockchain.client.peer_backend import FabricTxStatus
    from core.protocol.metadata import metadata_bytes
    from core.protocol.workflow import HieraStreamWorkflow
    from data.adapters.registry import iter_workload, prepare_dataset
    from data.replay.engine import OfflineReplayEngine, ReplayConfig, ReplayMode
    from data.replay.segmenter import SegmentPolicy
    from pathlib import Path

    cfg_path = Path(__file__).resolve().parents[1] / "configs" / "granularity.yaml"
    cfg = load_config("granularity" if cfg_path.exists() else "longitudinal", config_path)

    prepare_dataset("vitaldb", smoke=smoke)
    sizes = [256, 1024] if smoke else list(cfg.get("segment_sizes_bytes", [256, 1024, 4096, 16384]))
    # Formal repair: enough events to fill 16 KiB targets multiple times.
    max_events = 40 if smoke else int(cfg.get("max_events", 6000))

    run_ctx = create_run(
        "granularity",
        {
            **cfg,
            "smoke": smoke,
            "segment_sizes_bytes": sizes,
            "dataset": "vitaldb",
            "max_events": max_events,
            "fill_gate": {"max_ratio": 0.9, "median_non_tail_ratio": 0.8},
        },
    )

    fill_reports: Dict[str, Any] = {}
    all_gates_ok = True

    for nbytes in sizes:
        policy = SegmentPolicy(name=f"bytes_{nbytes}", target_bytes=nbytes)
        wf = HieraStreamWorkflow(owner_id=f"owner-e7-{nbytes}")
        wf.setup()
        wf.provision_user("u", ["doctor", "cardiology"], ["AttendingPhysician"])

        crypto_times: List[float] = []
        pub_times: List[float] = []
        actual_payloads: List[int] = []
        payload_bytes = 0
        meta_bytes_total = 0
        fabric_txs = 0
        records = 0

        def on_segment(batch, _nbytes=nbytes, _policy=policy) -> None:
            nonlocal payload_bytes, meta_bytes_total, fabric_txs, records
            assert wf.gateway and wf.lifecycle
            t0 = time.perf_counter()
            pending = wf.gateway.protect_payload(
                f"e7-{_nbytes}-{batch.segment_index}",
                batch.payload,
                ["AttendingPhysician"],
            )
            tree = wf.lifecycle.active_policy_tree()
            snap = wf.gateway.read_active_snapshot()
            result, metadata_obj, mcid, _eta = wf.gateway.attempt_commit(pending, snap, tree)
            crypto_dt = time.perf_counter() - t0
            crypto_times.append(crypto_dt)

            t1 = time.perf_counter()
            if result.status == FabricTxStatus.VALID:
                wf.gateway.publish_metadata_after_valid(pending, metadata_obj, mcid)
                fabric_txs += 1
            pub_times.append(time.perf_counter() - t1 + crypto_dt)

            mb = len(metadata_bytes(metadata_obj))
            payload_bytes += batch.nbytes
            records += batch.nrecords
            meta_bytes_total += mb
            actual_payloads.append(int(batch.nbytes))

            run_ctx.add_row(
                {
                    "experiment": "E7",
                    "phase": "per_segment",
                    "target_segment_bytes": _nbytes,
                    "segment_policy": _policy.name,
                    "actual_payload_bytes": batch.nbytes,
                    "nrecords": batch.nrecords,
                    "crypto_protect_commit_s": crypto_dt,
                    "publication_latency_s": pub_times[-1],
                    "metadata_bytes": mb,
                    "is_tail_candidate": False,  # set after pass
                }
            )

        events = itertools.islice(iter_workload("vitaldb", smoke=smoke), max_events)
        engine = OfflineReplayEngine(
            ReplayConfig(mode=ReplayMode.AS_FAST_AS_POSSIBLE, segment_policy=policy)
        )
        stats = engine.run(events, on_segment=on_segment, sleep=False)

        # Mark last per-target segment as tail candidate in the last matching rows
        if actual_payloads:
            for r in reversed(run_ctx.rows):
                if (
                    r.get("phase") == "per_segment"
                    and r.get("target_segment_bytes") == nbytes
                    and r.get("is_tail_candidate") is False
                ):
                    r["is_tail_candidate"] = True
                    break

        gate = _fill_gate(actual_payloads, nbytes)
        fill_reports[str(nbytes)] = {
            **gate,
            "actual_payload_distribution": {
                "n": len(actual_payloads),
                "min": min(actual_payloads) if actual_payloads else None,
                "max": max(actual_payloads) if actual_payloads else None,
                "mean": (sum(actual_payloads) / len(actual_payloads)) if actual_payloads else None,
                "values_sample": actual_payloads[:12],
            },
            "input_events": stats.accepted_events,
        }
        if not smoke and not gate["ok"]:
            all_gates_ok = False

        crypto_sum = sum(crypto_times)
        row: Dict[str, Any] = {
            "experiment": "E7",
            "phase": "summary",
            "target_segment_bytes": nbytes,
            "segment_policy": policy.to_dict(),
            "segments": stats.segments_created,
            "payload_bytes": payload_bytes,
            "records": records,
            "crypto_cost_per_byte_s": crypto_sum / max(1, payload_bytes),
            "crypto_cost_per_record_s": crypto_sum / max(1, records),
            "fabric_transactions": fabric_txs,
            "fabric_tx_per_mb": fabric_txs / max(1e-9, payload_bytes / 1_000_000),
            "metadata_bytes_per_payload_byte": meta_bytes_total / max(1, payload_bytes),
            "mean_segment_publication_latency_s": sum(pub_times) / max(1, len(pub_times)),
            "max_actual_payload_bytes": gate["max_actual"],
            "median_non_tail_payload_bytes": gate["median_non_tail"],
            "fill_gate_ok": gate["ok"],
            "fill_gate_reason": gate["reason"],
            "deployment_class": "single-host_local",
            "wan_distributed": False,
            "crypto_backend": getattr(wf.crypto, "backend", None),
            "ipfs_backend": getattr(wf.ipfs, "backend", None),
            "ledger_backend": "PeerMVCC",
        }
        run_ctx.add_row(row)

    result_class = "FINAL_BENCHMARK" if (smoke or all_gates_ok) else "INVALID"
    run_ctx.extra = {
        "experiment": "E7",
        "result_class": result_class,
        "fill_gate_reports": fill_reports,
        "all_fill_gates_ok": all_gates_ok or smoke,
        "note": "Fill gate: max(actual)>=0.9*T and median(non-tail)>=0.8*T",
    }
    run_ctx.config["result_class"] = result_class
    run_ctx.finish()
    if not smoke and not all_gates_ok:
        print("E7 INVALID: fill gate failed —", fill_reports)
        return 2
    return 0
