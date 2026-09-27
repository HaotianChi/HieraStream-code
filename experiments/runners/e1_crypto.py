"""E1 — Attribute cryptographic cost vs policy leaves (+ batched outsourced decryption)."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from experiments.harness.metrics import latency_summary
from experiments.harness.run_context import create_run, load_config


def _policy_tree(n_leaves: int, attrs: List[str]):
    from core.crypto.python.access_tree import AccessTree, leaf

    chosen = (attrs * ((n_leaves // len(attrs)) + 1))[:n_leaves]
    children = [leaf(a) for a in chosen]
    # threshold min(2,n) matches prior smoke; scales with leaves for encryption path
    return AccessTree(kind="internal", threshold=max(1, min(2, n_leaves)), children=children)


def run(smoke: bool = False, config_path: Optional[str] = None) -> int:
    from core.crypto.python.segment import SegmentCrypto

    cfg = load_config("crypto", config_path)
    sizes = [2, 4] if smoke else list(cfg.get("policy_sizes", [2, 4, 8, 16, 32]))
    warmup = 0 if smoke else int(cfg.get("warmup", 1))
    repeats = 2 if smoke else int(cfg.get("repeats", 5))
    batch_sizes = [1, 2] if smoke else list(cfg.get("batch_sizes", [1, 2, 4, 8, 16]))
    payload = b"e1-attr-bench-payload"

    crypto = SegmentCrypto()
    attrs = ["doctor", "cardiology", "nurse", "emergency", "researcher"]
    crypto.ca_setup()
    crypto.aa_setup(attrs)
    from core.crypto.python.hierarchy import HEALTHCARE_FIXTURE

    crypto.role_setup(HEALTHCARE_FIXTURE)
    user = crypto.aa_keygen("u0", attrs)

    run_ctx = create_run("crypto", {**cfg, "smoke": smoke, "policy_sizes": sizes, "repeats": repeats})
    rows: List[Dict[str, Any]] = []

    def _once(n: int) -> Dict[str, float]:
        tree = _policy_tree(n, attrs)
        ZA = crypto.sample_ZA()
        t0 = time.perf_counter()
        partial = crypto.gateway_partial_attr(ZA)
        t_gate = time.perf_counter() - t0

        t0 = time.perf_counter()
        ct = crypto.outsource_policy_encrypt(partial, tree)
        t_out_enc = time.perf_counter() - t0

        t0 = time.perf_counter()
        Bj = crypto.outsource_attr_transform(ct, user)
        t_out_dec = time.perf_counter() - t0
        assert Bj is not None

        t0 = time.perf_counter()
        crypto.user_recover_ZA(ct, Bj, user.usk1)
        t_user = time.perf_counter() - t0
        return {
            "gateway_partial_s": t_gate,
            "outsourced_enc_s": t_out_enc,
            "outsourced_dec_s": t_out_dec,
            "user_final_dec_s": t_user,
            "leaf_components": float(len(ct.C_a)),
        }

    for n in sizes:
        for _ in range(warmup):
            _once(n)
        samples = {k: [] for k in ("gateway_partial_s", "outsourced_enc_s", "outsourced_dec_s", "user_final_dec_s")}
        leaf_n = 0
        for i in range(repeats):
            m = _once(n)
            leaf_n = int(m["leaf_components"])
            for k in samples:
                samples[k].append(m[k])
            row = {
                "experiment": "E1",
                "phase": "policy_leaves",
                "policy_leaves": n,
                "repeat": i,
                "leaf_components": leaf_n,
                **{k: m[k] for k in samples},
            }
            rows.append(row)
            run_ctx.add_row(row)

        # Aggregated operation stats (still derived from measured samples)
        for op, vals in samples.items():
            agg = {
                "experiment": "E1",
                "phase": "policy_leaves_summary",
                "policy_leaves": n,
                "operation": op,
                "leaf_components": leaf_n,
                **latency_summary(vals, prefix="latency_s"),
            }
            rows.append(agg)
            run_ctx.add_row(agg)

    # Batched / concurrent outsourced decryption vs number of user requests
    tree = _policy_tree(max(sizes), attrs)
    ZA = crypto.sample_ZA()
    partial = crypto.gateway_partial_attr(ZA)
    ct = crypto.outsource_policy_encrypt(partial, tree)

    for b in batch_sizes:
        users = [crypto.aa_keygen(f"batch-{i}", attrs) for i in range(b)]
        for _ in range(warmup):
            with ThreadPoolExecutor(max_workers=b) as ex:
                list(ex.map(lambda u: crypto.outsource_attr_transform(ct, u), users))

        latencies: List[float] = []
        for i in range(repeats):
            t0 = time.perf_counter()
            with ThreadPoolExecutor(max_workers=b) as ex:
                outs = list(ex.map(lambda u: crypto.outsource_attr_transform(ct, u), users))
            dt = time.perf_counter() - t0
            assert all(o is not None for o in outs)
            latencies.append(dt)
            row = {
                "experiment": "E1",
                "phase": "batched_outsourced_dec",
                "batch_size": b,
                "repeat": i,
                "batch_wall_s": dt,
                "per_request_s": dt / b,
            }
            rows.append(row)
            run_ctx.add_row(row)
        agg = {
            "experiment": "E1",
            "phase": "batched_outsourced_dec_summary",
            "batch_size": b,
            **latency_summary(latencies, prefix="batch_wall_s"),
        }
        run_ctx.add_row(agg)

    run_ctx.extra = {"experiment": "E1", "payload_note": payload.decode(), "n_raw_rows": len(rows)}
    run_ctx.finish()
    return 0
