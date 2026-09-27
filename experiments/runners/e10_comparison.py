"""E10 — Comparison: HieraStream vs conventional CP-ABE vs PASH vs MASS.

PASH/MASS adapters report availability status; unavailable paths are not
replaced with invented timings.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from experiments.harness.metrics import latency_summary
from experiments.harness.run_context import create_run, load_config


def run(smoke: bool = False, config_path: Optional[str] = None) -> int:
    from core.crypto.python.access_tree import AccessTree, leaf
    from core.crypto.python.hierarchy import HEALTHCARE_FIXTURE
    from core.crypto.python.segment import SegmentCrypto
    from experiments.baselines.cpabe.adapter import CPABEBaseline
    from experiments.baselines.mass.adapter import MASSAdapter
    from experiments.baselines.pash.adapter import PASHAdapter

    cfg = load_config("comparison", config_path)
    sizes = [2, 4] if smoke else list(cfg.get("policy_sizes", [2, 4, 8, 16]))
    warmup = 0 if smoke else int(cfg.get("warmup", 1))
    repeats = 2 if smoke else int(cfg.get("repeats", 5))
    payload = b"e10-comparison-payload"
    evm_n_policy = 2 if smoke else int(cfg.get("evm_policy_ops", 20))
    evm_n_query = 2 if smoke else int(cfg.get("evm_query_ops", 20))
    evm_rates = None if smoke else list(cfg.get("evm_offered_tps") or [])

    run_ctx = create_run("comparison", {**cfg, "smoke": smoke, "policy_sizes": sizes, "repeats": repeats})

    # --- HieraStream (dual-layer) ---
    for n in sizes:
        crypto = SegmentCrypto()
        attrs = ["doctor", "cardiology", "nurse", "emergency", "researcher"]
        crypto.ca_setup()
        crypto.aa_setup(attrs)
        crypto.role_setup(HEALTHCARE_FIXTURE)
        user_attr = crypto.aa_keygen("u", attrs)
        role_mat = crypto.ca_role_user("u")
        for r in ["AttendingPhysician"]:
            crypto.rm_issue_rk(r, role_mat)

        chosen = (attrs * ((n // len(attrs)) + 1))[:n]
        tree = AccessTree(kind="internal", threshold=max(1, min(2, n)), children=[leaf(a) for a in chosen])

        for _ in range(warmup):
            seg = crypto.protect_segment(payload, tree, ["AttendingPhysician"])
            assert crypto.recover_segment(seg, user_attr, role_mat, ["AttendingPhysician"]) == payload

        enc_s: List[float] = []
        dec_s: List[float] = []
        for i in range(repeats):
            t0 = time.perf_counter()
            seg = crypto.protect_segment(payload, tree, ["AttendingPhysician"])
            e = time.perf_counter() - t0
            enc_s.append(e)
            t0 = time.perf_counter()
            pt = crypto.recover_segment(seg, user_attr, role_mat, ["AttendingPhysician"])
            d = time.perf_counter() - t0
            dec_s.append(d)
            assert pt == payload
            run_ctx.add_row(
                {
                    "experiment": "E10",
                    "scheme": "HieraStream",
                    "status": "measured",
                    "reproducibility_class": "REPRODUCIBLE",
                    "policy_leaves": n,
                    "repeat": i,
                    "encrypt_s": e,
                    "decrypt_s": d,
                    "crypto_backend": getattr(crypto, "backend", None),
                }
            )
        run_ctx.add_row(
            {
                "experiment": "E10",
                "scheme": "HieraStream",
                "phase": "summary",
                "policy_leaves": n,
                **latency_summary(enc_s, prefix="encrypt_s"),
                **{f"decrypt_{k}": v for k, v in latency_summary(dec_s, prefix="latency_s").items()},
            }
        )

    # --- Conventional CP-ABE ---
    cpabe = CPABEBaseline.setup()
    user = cpabe.keygen("u", cpabe.attrs)
    for n in sizes:
        chosen = (cpabe.attrs * ((n // len(cpabe.attrs)) + 1))[:n]
        tree = AccessTree(kind="internal", threshold=max(1, min(2, n)), children=[leaf(a) for a in chosen])
        for _ in range(warmup):
            blob = cpabe.encrypt(payload, tree)
            assert cpabe.decrypt(blob, user)["plaintext"] == payload
        enc_s = []
        dec_s = []
        for i in range(repeats):
            blob = cpabe.encrypt(payload, tree)
            enc_s.append(blob["encrypt_s"])
            out = cpabe.decrypt(blob, user)
            dec_s.append(out["decrypt_s"])
            assert out["plaintext"] == payload
            run_ctx.add_row(
                {
                    "experiment": "E10",
                    "scheme": "CP-ABE",
                    "status": "measured",
                    "reproducibility_class": "REPRODUCIBLE_WITH_DOCUMENTED_ASSUMPTIONS",
                    "policy_leaves": n,
                    "repeat": i,
                    "encrypt_s": blob["encrypt_s"],
                    "decrypt_s": out["decrypt_s"],
                    "leaf_components": blob["leaf_components"],
                    "crypto_backend": getattr(cpabe.crypto, "backend", None),
                }
            )
        run_ctx.add_row(
            {
                "experiment": "E10",
                "scheme": "CP-ABE",
                "phase": "summary",
                "policy_leaves": n,
                **latency_summary(enc_s, prefix="encrypt_s"),
                **{f"decrypt_{k}": v for k, v in latency_summary(dec_s, prefix="latency_s").items()},
            }
        )

    # --- PASH / MASS: adapters only ---
    for adapter in (PASHAdapter(), MASSAdapter()):
        probe = adapter.probe()
        run_ctx.add_row(
            {
                "experiment": "E10",
                "scheme": probe["scheme"],
                "status": probe["status"],
                "available": probe["available"],
                "reproducibility_class": probe.get("reproducibility_class"),
                "citation": probe["citation"],
                "missing_information": probe["missing_information"],
                "note": probe["note"],
            }
        )

    # --- EVM / Ganache comparison (separate from Fabric) ---
    from experiments.baselines.evm.harness import EVMComparisonHarness

    evm = EVMComparisonHarness()
    for row in evm.run_hierastream_bench(
        n_policy=evm_n_policy,
        n_query=evm_n_query,
        offered_tps_list=evm_rates or None,
    ):
        run_ctx.add_row({"experiment": "E10", "phase": "evm", **row})
    for row in evm.probe_pash_mass():
        run_ctx.add_row(
            {
                "experiment": "E10",
                "phase": "evm",
                "reproducibility_class": "NOT_FAITHFULLY_REPRODUCIBLE",
                **row,
            }
        )

    run_ctx.extra = {
        "experiment": "E10",
        "evm_backend": evm.backend,
        "ganache_note": "Live Ganache via HIERASTREAM_GANACHE_URL when set; else in-process schedule.",
        "gas_note": "Gas is independent of offered TPS; latency may vary with load.",
    }
    run_ctx.finish()
    return 0
