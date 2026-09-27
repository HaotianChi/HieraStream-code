"""Experiment runner registry (E1–E10)."""

from __future__ import annotations

import os
from typing import Callable, Dict, List, Optional

from experiments.harness.timing import shuffled_order


EXPERIMENT_ALIASES = {
    "e1": "crypto",
    "crypto": "crypto",
    "e2": "role",
    "role": "role",
    "e3": "fabric",
    "fabric": "fabric",
    "e4": "consistency_paired",
    "consistency_paired": "consistency_paired",
    "consistency": "consistency",
    "e5": "rekey",
    "rekey": "rekey",
    "e6": "longitudinal",
    "longitudinal": "longitudinal",
    "e7": "granularity",
    "granularity": "granularity",
    "e8": "revocation",
    "revocation": "revocation",
    "e9": "datasets",
    "datasets": "datasets",
    "e10": "comparison",
    "comparison": "comparison",
    "system_baselines": "system_baselines",
}

ALL_ORDER = [
    "crypto",
    "role",
    "fabric",
    "consistency_paired",
    "rekey",
    "longitudinal",
    "granularity",
    "revocation",
    "datasets",
    "comparison",
]


def _runners() -> Dict[str, Callable[..., int]]:
    from experiments.runners import (
        e1_crypto,
        e2_role,
        e3_fabric,
        e4_consistency,
        e4_consistency_paired,
        e5_rekey,
        e6_longitudinal,
        e7_granularity,
        e8_revocation,
        e9_datasets,
        e10_comparison,
        system_baselines,
    )

    return {
        "crypto": e1_crypto.run,
        "role": e2_role.run,
        "fabric": e3_fabric.run,
        "consistency": e4_consistency.run,
        "consistency_paired": e4_consistency_paired.run,
        "rekey": e5_rekey.run,
        "longitudinal": e6_longitudinal.run,
        "granularity": e7_granularity.run,
        "revocation": e8_revocation.run,
        "datasets": e9_datasets.run,
        "comparison": e10_comparison.run,
        "system_baselines": system_baselines.run,
    }


def run_experiment(
    name: str,
    smoke: bool = False,
    config: Optional[str] = None,
    profile: Optional[str] = None,
) -> int:
    if profile:
        os.environ["HIERASTREAM_BENCH_PROFILE"] = profile
        os.environ.setdefault("HIERASTREAM_PLATFORM_TAG", profile)

    if name == "all":
        from experiments.harness.run_context import load_profile

        prof = load_profile(profile)
        order: List[str] = shuffled_order(
            ALL_ORDER,
            seed=int(prof.get("seed", 20260311)),
            enabled=bool(prof.get("shuffle_experiment_order", False))
            or os.environ.get("HIERASTREAM_SHUFFLE_EXPERIMENTS", "").strip()
            in {"1", "true", "yes"},
        )
        rc = 0
        for n in order:
            print(
                f"\n######## running {n} (smoke={smoke}, profile={prof.get('profile')}) ########"
            )
            rc |= run_experiment(n, smoke=smoke, config=config, profile=profile)
        return rc

    key = EXPERIMENT_ALIASES.get(name)
    if key is None:
        raise KeyError(
            f"unknown experiment: {name}; choose from {sorted(set(EXPERIMENT_ALIASES)) + ['all']}"
        )
    return _runners()[key](smoke=smoke, config_path=config)
