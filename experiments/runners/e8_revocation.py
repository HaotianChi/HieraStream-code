"""E8 — Revocation vs accumulated history (HieraStream vs historical-update baseline)."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from experiments.harness.run_context import create_run, load_config


def run(smoke: bool = False, config_path: Optional[str] = None) -> int:
    from experiments.baselines.historical_update.baseline import HistoricalUpdateBaseline
    from core.authorization.lifecycle import AuthorizationLifecycle
    from core.crypto.python.access_tree import AND, leaf
    from core.crypto.python.hierarchy import HEALTHCARE_FIXTURE
    from core.crypto.python.segment import SegmentCrypto
    from core.protocol.workflow import HieraStreamWorkflow

    cfg = load_config("revocation", config_path)
    hist = [5, 10] if smoke else list(cfg.get("history_sizes", [10, 50, 100, 500]))

    run_ctx = create_run("revocation", {**cfg, "smoke": smoke, "history_sizes": hist})

    for h in hist:
        # --- HieraStream prospective ---
        wf = HieraStreamWorkflow(owner_id=f"owner-e8-hs-{h}")
        wf.setup()
        wf.provision_user("u", ["doctor", "cardiology"], ["AttendingPhysician"])
        stored = []
        for i in range(h):
            seg = wf.publish(f"hist-{i}".encode(), targets=["AttendingPhysician"], seg_id=f"h{i}")
            stored.append(seg)

        before = {s.seg_id: s.ct_aes for s in stored}
        # Prospective revocation — historical AES/metadata CT unchanged
        t0 = time.perf_counter()
        wf.revoke_attribute("doctor", revoked_users=[])
        hs_s = time.perf_counter() - t0
        hist_modified = sum(1 for s in stored if before[s.seg_id] != s.ct_aes)
        run_ctx.add_row(
            {
                "experiment": "E8",
                "scheme": "HieraStream",
                "historical_segments": h,
                "revocation_latency_s": hs_s,
                "bytes_communicated": 0,
                "historical_ciphertexts_modified": hist_modified,
                "current_auth_users_fixed": 1,
                "revoked_attr": "doctor",
            }
        )

        # --- Historical algebraic ciphertext-update baseline ---
        crypto = SegmentCrypto()
        lc = AuthorizationLifecycle(
            owner_id=f"owner-e8-hist-{h}",
            crypto=crypto,
            hierarchy=HEALTHCARE_FIXTURE,
            attr_universe=["doctor", "cardiology", "nurse", "emergency", "researcher"],
        )
        lc.setup(initial_policy=AND(leaf("doctor"), leaf("cardiology")))
        lc.provision_user("u", ["doctor", "cardiology"], ["AttendingPhysician"])
        baseline = HistoricalUpdateBaseline(crypto=crypto, lifecycle=lc)
        for i in range(h):
            baseline.protect_and_store(f"hist-{i}".encode(), ["AttendingPhysician"], seg_id=f"b{i}")

        t0 = time.perf_counter()
        result = baseline.revoke_with_historical_update("doctor", revoked_users=[])
        hist_s = time.perf_counter() - t0
        run_ctx.add_row(
            {
                "experiment": "E8",
                "scheme": "historical_ciphertext_update",
                "historical_segments": h,
                "revocation_latency_s": hist_s,
                "bytes_communicated": result["bytes_communicated"],
                "historical_ciphertexts_modified": result["ciphertexts_modified"],
                "leaf_components_updated": result.get("leaf_components_updated"),
                "bytes_read": result.get("bytes_read"),
                "bytes_written": result.get("bytes_written"),
                "metadata_storage_update_work": result.get("metadata_storage_update_work"),
                "aes_payloads_rewritten": result.get("aes_payloads_rewritten"),
                "current_auth_users_fixed": 1,
                "revoked_attr": "doctor",
            }
        )

    run_ctx.extra = {"experiment": "E8"}
    run_ctx.finish()
    return 0
