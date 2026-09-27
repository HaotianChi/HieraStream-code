"""E2 — Hierarchical role-protection cost: target roles × ancestor-path size."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from experiments.harness.metrics import latency_summary
from experiments.harness.run_context import create_run, load_config


def _envelope_serialized_bytes(env) -> int:
    from core.protocol.metadata import serialize_role_envelope

    return len(json.dumps(serialize_role_envelope(env), sort_keys=True, separators=(",", ":")).encode())


def run(smoke: bool = False, config_path: Optional[str] = None) -> int:
    from core.crypto.python.hierarchy import linear_hierarchy
    from core.crypto.python.segment import SegmentCrypto

    cfg = load_config("role", config_path)
    warmup = 0 if smoke else int(cfg.get("warmup", 1))
    repeats = 2 if smoke else int(cfg.get("repeats", 5))

    # Fig.4a: vary targets, fixed ancestor-path size
    fixed_path = 4 if smoke else int(cfg.get("fixed_ancestor_path", 30))
    # Fig.4b: fix targets=5, vary ancestor path
    fixed_targets = 2 if smoke else int(cfg.get("fixed_targets", 5))

    target_counts = [1, 2] if smoke else list(cfg.get("target_counts", [1, 2, 4, 8, 16]))
    path_sizes = [2, 4] if smoke else list(cfg.get("ancestor_path_sizes", [5, 10, 20, 30, 40]))

    run_ctx = create_run(
        "role",
        {
            **cfg,
            "smoke": smoke,
            "fixed_ancestor_path": fixed_path,
            "fixed_targets": fixed_targets,
            "target_counts": target_counts,
            "ancestor_path_sizes": path_sizes,
        },
    )

    def _bench(n_roles_total: int, n_targets: int, label: str, x_value: int) -> None:
        names = [f"R{i}" for i in range(n_roles_total)]
        hier = linear_hierarchy(names)
        # Targets: deepest roles so H(ri) uses ancestor path
        targets = names[-n_targets:] if n_targets <= len(names) else names
        crypto = SegmentCrypto()
        crypto.ca_setup()
        crypto.aa_setup(["doctor"])
        crypto.role_setup(hier)

        # Warmup
        ZR = crypto.sample_ZR()
        for _ in range(warmup):
            crypto.role_encrypt_multi(ZR, targets)

        latencies: List[float] = []
        for i in range(repeats):
            ZR = crypto.sample_ZR()
            t0 = time.perf_counter()
            envs = crypto.role_encrypt_multi(ZR, targets)
            dt = time.perf_counter() - t0
            latencies.append(dt)
            comp = sum(1 + len(e.C3) for e in envs)  # Ci + C3 path components (+C1/C2 counted below)
            # Count ciphertext components: C1,C2,Ci + |C3| per envelope
            ct_components = sum(3 + len(e.C3) for e in envs)
            ser = sum(_envelope_serialized_bytes(e) for e in envs)
            path_lens = [len(hier.H(t)) for t in targets]
            row = {
                "experiment": "E2",
                "phase": label,
                "x": x_value,
                "num_targets": len(targets),
                "hierarchy_size": n_roles_total,
                "ancestor_path_sizes": path_lens,
                "mean_H_size": sum(path_lens) / max(1, len(path_lens)),
                "role_encryption_s": dt,
                "ciphertext_component_count": ct_components,
                "serialized_envelope_bytes": ser,
                "role_envelope_count": len(envs),
                "repeat": i,
            }
            run_ctx.add_row(row)
        agg = {
            "experiment": "E2",
            "phase": f"{label}_summary",
            "x": x_value,
            "num_targets": len(targets),
            "hierarchy_size": n_roles_total,
            **latency_summary(latencies, prefix="role_encryption_s"),
        }
        run_ctx.add_row(agg)

    # 4a: vary targets; hold hierarchy so deepest target has ~fixed_path ancestors in H
    # Build hierarchy of size fixed_path+1 so H for deepest leaf grows with depth
    hier_size_a = max(fixed_path, max(target_counts) + 1)
    for nt in target_counts:
        _bench(hier_size_a, nt, "vary_targets", nt)

    # 4b: fix targets; vary hierarchy / ancestor path size
    for ps in path_sizes:
        _bench(max(ps, fixed_targets), fixed_targets, "vary_ancestor_path", ps)

    run_ctx.extra = {"experiment": "E2"}
    run_ctx.finish()
    return 0
