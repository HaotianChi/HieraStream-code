#!/usr/bin/env python3
"""System-level HieraStream / Droplet / TimeCrypt microbenchmarks.

Writes under the local run root; does not rewrite `results/` by default.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import statistics
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]
OUT_ROOT = ROOT / "experiments" / "raw" / "system_baselines"

PAYLOADS = [256, 1024, 4096, 16384]
RATES = [50, 100, 200, 400, 800, 1600]
# Extra low rates for full native-PBC HieraStream (saturates well below 50 eps).
HIERASTREAM_EXTRA_RATES = [1, 2, 5, 10, 20, 40]
FROZEN_RUN = "20260919T181630Z"


def _stats(xs: List[float]) -> Dict[str, float]:
    if not xs:
        return {"mean": None, "median": None, "p95": None, "std": None}
    s = sorted(xs)
    p95 = s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]
    return {
        "mean": statistics.fmean(xs),
        "median": statistics.median(xs),
        "p95": p95,
        "std": statistics.pstdev(xs) if len(xs) > 1 else 0.0,
    }


# Opaque seed string embedded in frozen results/data/fig8; keep unchanged.
PAYLOAD_SEED = b"hierastream-round2-payload-v1"


def _payload(n: int, salt: int = 0) -> bytes:
    """Deterministic high-entropy bytes. Same logical payload for every scheme."""
    out = bytearray()
    counter = 0
    while len(out) < n:
        block = hashlib.sha256(
            PAYLOAD_SEED
            + n.to_bytes(4, "little")
            + salt.to_bytes(8, "little")
            + counter.to_bytes(4, "little")
        ).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:n])


def _one_e2e(adapter, payload: bytes) -> Dict[str, Any]:
    t0 = time.perf_counter()
    prot = adapter.protect_and_store(payload)
    rec = adapter.retrieve_and_recover(prot["object_id"])
    e2e = (time.perf_counter() - t0) * 1000.0
    got = rec["payload"]
    if got != payload and got[: len(payload)] != payload:
        raise RuntimeError("correctness mismatch")
    if got != payload:
        # TimeCrypt trims in Java; still require exact
        if got != payload:
            raise RuntimeError(f"len {len(got)} != {len(payload)}")
    return {
        "protect_latency_ms": prot["protect_latency_ms"],
        "recover_latency_ms": rec["recover_latency_ms"],
        "e2e_latency_ms": e2e,
        "protected_payload_bytes": prot.get("encrypted_payload_bytes", prot["protected_bytes"]),
        "metadata_or_aux_bytes": prot.get("metadata_bytes"),
        "crypto_metadata_bytes": prot.get("crypto_metadata_bytes"),
        "other_serialized_metadata_bytes": prot.get("other_serialized_metadata_bytes"),
        "total_bytes": prot["total_bytes"],
        "post_zlib_bytes": prot.get("post_zlib_bytes"),
        "success": True,
    }


def run_latency(adapter, scheme: str, status: str, reps: int, reps_4k: int, warmup: int) -> List[Dict[str, Any]]:
    rows = []
    for n in PAYLOADS:
        nrep = reps_4k if n == 4096 else reps
        for _ in range(warmup):
            _one_e2e(adapter, _payload(n))
        for i in range(nrep):
            sample = _one_e2e(adapter, _payload(n, i))
            rows.append(
                {
                    "scheme": scheme,
                    "baseline_status": status,
                    "experiment": "B1",
                    "payload_size": n,
                    "repetition": i,
                    **sample,
                }
            )
    return rows


def run_throughput(
    adapter,
    scheme: str,
    status: str,
    duration: float,
    warmup: float,
    *,
    rates: List[int] | None = None,
) -> List[Dict[str, Any]]:
    payload = _payload(4096)
    rows = []
    offered_rates = list(rates) if rates is not None else list(RATES)
    t_end = time.perf_counter() + warmup
    while time.perf_counter() < t_end:
        _one_e2e(adapter, payload)
    for rate in offered_rates:
        interval = 1.0 / rate
        start = time.perf_counter()
        next_t = start
        deadline = start + duration
        lats: List[float] = []
        ok = fail = offered = 0
        first_error = None
        while time.perf_counter() < deadline:
            now = time.perf_counter()
            if now < next_t:
                time.sleep(min(0.002, next_t - now))
                continue
            offered += 1
            t0 = time.perf_counter()
            try:
                _one_e2e(adapter, payload)
                lats.append((time.perf_counter() - t0) * 1000.0)
                ok += 1
            except Exception as exc:
                fail += 1
                if first_error is None:
                    first_error = repr(exc)
            next_t += interval
            if next_t < time.perf_counter():
                next_t = time.perf_counter()
        wall = max(time.perf_counter() - start, 1e-9)
        st = _stats(lats)
        rows.append(
            {
                "scheme": scheme,
                "baseline_status": status,
                "experiment": "B3",
                "payload_size": 4096,
                "offered_tps": rate,
                "offered_attempts": offered,
                "successes": ok,
                "failures": fail,
                "first_error": first_error,
                "sustained_throughput": ok / wall,
                "e2e_mean": st["mean"],
                "e2e_p95": st["p95"],
                "duration_s": wall,
            }
        )
    return rows


def _load_frozen_non_hs(run_id: str = FROZEN_RUN) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Reuse Droplet/TimeCrypt rows from the frozen system-baseline inputs."""
    if run_id == "20260919T173812Z":
        raise RuntimeError("refusing superseded system baseline data")
    candidates = [
        ROOT / "results" / "data" / "fig8",
        OUT_ROOT / run_id,
    ]
    base = next((p for p in candidates if (p / "raw_latency.jsonl").is_file()), None)
    if base is None:
        raise RuntimeError("missing Droplet/TimeCrypt rows under results/data/fig8")
    lat_path = base / "raw_latency.jsonl"
    tp_path = base / "raw_throughput.jsonl"
    if not tp_path.is_file():
        raise RuntimeError(f"missing throughput rows under {base}")
    latency = [
        json.loads(line)
        for line in lat_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and json.loads(line).get("scheme") != "HieraStream"
    ]
    throughput = [
        json.loads(line)
        for line in tp_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and json.loads(line).get("scheme") != "HieraStream"
    ]
    return latency, throughput


def write_composite_preview(out: Path, latency_rows: List[Dict[str, Any]], tp_rows: List[Dict[str, Any]], *, suffix: str = "_v3") -> None:
    colors = {"HieraStream": "#1f77b4", "Droplet": "#ff7f0e", "TimeCrypt": "#2ca02c"}
    fig, axes = plt.subplots(1, 3, figsize=(9.0, 2.6))
    e2e = [r for r in latency_rows if r["payload_size"] == 4096]
    for sch, col in colors.items():
        xs = sorted(r["e2e_latency_ms"] for r in e2e if r["scheme"] == sch)
        if not xs:
            continue
        ys = [(i + 1) / len(xs) for i in range(len(xs))]
        axes[0].plot(xs, ys, label=sch, color=col)
    axes[0].set_xlabel("End-to-end latency (ms)")
    axes[0].set_ylabel("ECDF")
    axes[0].legend(frameon=False, fontsize=7)
    for sch, col in colors.items():
        pts = []
        for n in PAYLOADS:
            subset = [r for r in latency_rows if r["scheme"] == sch and r["payload_size"] == n]
            if subset:
                pts.append((n / 1024.0, subset[0]["total_bytes"] / 1024.0))
        if pts:
            axes[1].plot([p[0] for p in pts], [p[1] for p in pts], marker="o", label=sch, color=col)
    axes[1].set_xlabel("Logical payload size (KiB)")
    axes[1].set_ylabel("Size (KiB)")
    axes[1].legend(frameon=False, fontsize=7)
    for sch, col in colors.items():
        subset = sorted(
            (r for r in tp_rows if r["scheme"] == sch and int(r.get("failures", 0)) == 0),
            key=lambda r: r["offered_tps"],
        )
        # Prefer original Fig.8 rates for the composite when present.
        subset = [r for r in subset if int(r["offered_tps"]) in RATES] or subset
        if subset:
            axes[2].plot(
                [r["offered_tps"] for r in subset],
                [r["sustained_throughput"] for r in subset],
                marker="o",
                label=sch,
                color=col,
            )
    axes[2].set_xlabel("Offered rate (events/s)")
    axes[2].set_ylabel("Sustained throughput (events/s)")
    axes[2].legend(frameon=False, fontsize=7)
    for ax in axes:
        ax.grid(False)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
    fig.tight_layout()
    fig.savefig(out / f"system_baseline_comparison_preview{suffix}.pdf")
    fig.savefig(out / f"system_baseline_comparison_preview{suffix}.png")
    plt.close(fig)


def write_plots(out: Path, latency_rows: List[Dict[str, Any]], tp_rows: List[Dict[str, Any]], *, suffix: str = "_v2", plot_throughput: bool = False) -> None:
    plt.rcParams.update({"font.family": "Times New Roman", "font.size": 9, "pdf.fonttype": 42})
    colors = {"HieraStream": "#1f77b4", "Droplet": "#ff7f0e", "TimeCrypt": "#2ca02c"}
    e2e = [r for r in latency_rows if r["payload_size"] == 4096]
    fig, ax = plt.subplots(figsize=(4.2, 3.0))
    for sch in colors:
        xs = sorted(r["e2e_latency_ms"] for r in e2e if r["scheme"] == sch)
        if not xs:
            continue
        ys = [(i + 1) / len(xs) for i in range(len(xs))]
        ax.plot(xs, ys, label=sch, color=colors[sch])
    ax.set_xlabel("End-to-end latency (ms)")
    ax.set_ylabel("ECDF")
    ax.legend(frameon=False)
    ax.grid(False)
    fig.tight_layout()
    fig.savefig(out / f"system_baseline_latency_ecdf{suffix}.pdf")
    fig.savefig(out / f"system_baseline_latency_ecdf{suffix}.png")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(4.2, 3.0))
    data, labels = [], []
    for sch in colors:
        xs = [r["e2e_latency_ms"] for r in e2e if r["scheme"] == sch]
        if xs:
            data.append(xs)
            labels.append(sch)
    if data:
        ax.violinplot(data, showmedians=True)
        ax.set_xticks(range(1, len(labels) + 1))
        ax.set_xticklabels(labels)
    ax.set_ylabel("End-to-end latency (ms)")
    ax.grid(False)
    fig.tight_layout()
    fig.savefig(out / f"system_baseline_latency_violin{suffix}.pdf")
    fig.savefig(out / f"system_baseline_latency_violin{suffix}.png")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(4.2, 3.0))
    for sch, col in colors.items():
        pts = []
        for n in PAYLOADS:
            subset = [r for r in latency_rows if r["scheme"] == sch and r["payload_size"] == n]
            if subset:
                pts.append((n, subset[0]["total_bytes"]))
        if pts:
            ax.plot([p[0] for p in pts], [p[1] for p in pts], marker="o", label=sch, color=col)
    ax.set_xlabel("Plaintext bytes")
    ax.set_ylabel("Total serialized protected bytes")
    ax.legend(frameon=False)
    ax.grid(False)
    fig.tight_layout()
    fig.savefig(out / f"system_baseline_size_scaling{suffix}.pdf")
    fig.savefig(out / f"system_baseline_size_scaling{suffix}.png")
    plt.close(fig)

    if plot_throughput:
        fig, ax = plt.subplots(figsize=(4.2, 3.0))
        for sch, col in colors.items():
            subset = [r for r in tp_rows if r["scheme"] == sch and r.get("failures", 0) == 0]
            if subset:
                ax.plot(
                    [r["offered_tps"] for r in subset],
                    [r["sustained_throughput"] for r in subset],
                    marker="o",
                    label=sch,
                    color=col,
                )
        ax.set_xlabel("Offered rate (events/s)")
        ax.set_ylabel("Sustained throughput (events/s)")
        ax.legend(frameon=False)
        ax.grid(False)
        fig.tight_layout()
        fig.savefig(out / f"system_baseline_throughput{suffix}.pdf")
        fig.savefig(out / f"system_baseline_throughput{suffix}.png")
        plt.close(fig)

    fig, ax = plt.subplots(figsize=(4.2, 3.0))
    for sch, col in colors.items():
        subset = [r for r in latency_rows if r["scheme"] == sch and r["payload_size"] == 4096]
        tp = [r for r in tp_rows if r["scheme"] == sch and r["offered_tps"] == 100]
        if not subset:
            continue
        e2e_mean = statistics.fmean(r["e2e_latency_ms"] for r in subset)
        total = subset[0]["total_bytes"]
        ax.scatter([e2e_mean], [total], color=col, label=sch)
        ax.annotate(sch, (e2e_mean, total), fontsize=8)
    ax.set_xlabel("Mean end-to-end latency (ms)")
    ax.set_ylabel("Serialized protected bytes")
    ax.grid(False)
    fig.tight_layout()
    fig.savefig(out / f"system_baseline_tradeoff{suffix}.pdf")
    fig.savefig(out / f"system_baseline_tradeoff{suffix}.png")
    plt.close(fig)


def aggregate(latency_rows, tp_rows) -> List[Dict[str, Any]]:
    out = []
    schemes = sorted({r["scheme"] for r in latency_rows})
    for sch in schemes:
        status = next(r["baseline_status"] for r in latency_rows if r["scheme"] == sch)
        for n in PAYLOADS:
            sub = [r for r in latency_rows if r["scheme"] == sch and r["payload_size"] == n]
            if not sub:
                continue
            p = _stats([r["protect_latency_ms"] for r in sub])
            rec = _stats([r["recover_latency_ms"] for r in sub])
            e = _stats([r["e2e_latency_ms"] for r in sub])
            tp = [r for r in tp_rows if r["scheme"] == sch]
            sustained = max((r["sustained_throughput"] for r in tp), default=None)
            out.append(
                {
                    "scheme": sch,
                    "baseline_status": status,
                    "payload_size": n,
                    "protect_mean": p["mean"],
                    "protect_p95": p["p95"],
                    "recover_mean": rec["mean"],
                    "recover_p95": rec["p95"],
                    "e2e_mean": e["mean"],
                    "e2e_p95": e["p95"],
                    "plaintext_bytes": n,
                    "encrypted_payload_bytes": sub[0]["protected_payload_bytes"],
                    "crypto_metadata_bytes": sub[0].get("crypto_metadata_bytes"),
                    "other_serialized_metadata_bytes": sub[0].get("other_serialized_metadata_bytes"),
                    "protected_bytes": sub[0]["protected_payload_bytes"],
                    "metadata_bytes": sub[0]["metadata_or_aux_bytes"],
                    "post_zlib_bytes": sub[0].get("post_zlib_bytes"),
                    "expansion_ratio": (sub[0]["total_bytes"] / n) if sub[0]["total_bytes"] else None,
                    "sustained_throughput": sustained if n == 4096 else None,
                }
            )
    return out


def run(smoke: bool = False, config_path=None) -> int:
    """CLI/registry entry point."""
    del config_path  # no YAML; parameters are env-driven
    if smoke:
        os.environ.setdefault("SB_WARMUP", "1")
        os.environ.setdefault("SB_REPS", "2")
        os.environ.setdefault("SB_REPS_4K", "2")
        os.environ.setdefault("SB_DURATION", "2")
        os.environ.setdefault("SB_TP_WARMUP", "0")
        os.environ.setdefault("SB_SCHEMES", "HieraStream")
    return main()


def main() -> int:
    warmup = int(os.environ.get("SB_WARMUP", "5"))
    reps = int(os.environ.get("SB_REPS", "30"))
    reps_4k = int(os.environ.get("SB_REPS_4K", "200"))
    duration = float(os.environ.get("SB_DURATION", "30"))
    tp_warm = float(os.environ.get("SB_TP_WARMUP", "5"))
    schemes_filter = {
        s.strip()
        for s in os.environ.get("SB_SCHEMES", "HieraStream,Droplet,TimeCrypt").split(",")
        if s.strip()
    }
    merge_frozen = os.environ.get("SB_MERGE_FROZEN", os.environ.get("SB_MERGE_ROUND2", "0")) == "1" or schemes_filter == {
        "HieraStream"
    }
    plot_suffix = os.environ.get("SB_PLOT_SUFFIX", "_v3" if merge_frozen else "_v2")

    from experiments.baselines.droplet.adapter import BASELINE_STATUS as DSTAT
    from experiments.baselines.droplet.adapter import DropletLocalAdapter
    from experiments.baselines.system_common.hierastream_adapter import BASELINE_STATUS as HSTAT
    from experiments.baselines.system_common.hierastream_adapter import HieraStreamLocalAdapter
    from experiments.baselines.timecrypt.adapter import BASELINE_STATUS as TSTAT
    from experiments.baselines.timecrypt.adapter import TimeCryptLocalAdapter

    adapters: List[tuple] = [
        ("HieraStream", HSTAT, HieraStreamLocalAdapter),
        ("Droplet", DSTAT, DropletLocalAdapter),
        ("TimeCrypt", TSTAT, TimeCryptLocalAdapter),
    ]
    adapters = [a for a in adapters if a[0] in schemes_filter]

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = OUT_ROOT / run_id
    out.mkdir(parents=True, exist_ok=True)
    latency_rows: List[Dict[str, Any]] = []
    tp_rows: List[Dict[str, Any]] = []
    failures = []
    stage_diag: Dict[str, Any] = {}
    hs_config: Dict[str, Any] = {}

    for name, status, cls in adapters:
        adapter = cls()
        try:
            adapter.setup()
            if name == "HieraStream" and hasattr(adapter, "config"):
                hs_config = dict(adapter.config)
            probe = _payload(128)
            got = adapter.retrieve_and_recover(adapter.protect_and_store(probe)["object_id"])["payload"]
            if got != probe:
                raise RuntimeError(f"{name} correctness failed")
            if name == "HieraStream" and hasattr(adapter, "run_stage_diagnostics"):
                # Warm one diagnostic then record a fresh timed stage pass.
                adapter.run_stage_diagnostics(_payload(4096, salt=999001))
                stage_diag = adapter.run_stage_diagnostics(_payload(4096, salt=999002))
            latency_rows.extend(run_latency(adapter, name, status, reps, reps_4k, warmup))
            rates = None
            if name == "HieraStream":
                rates = list(HIERASTREAM_EXTRA_RATES) + list(RATES)
            tp_rows.extend(run_throughput(adapter, name, status, duration, tp_warm, rates=rates))
        except Exception as exc:
            failures.append({"scheme": name, "error": repr(exc)})
        finally:
            try:
                adapter.teardown()
            except Exception:
                pass

    if merge_frozen:
        frozen_lat, frozen_tp = _load_frozen_non_hs(FROZEN_RUN)
        latency_rows.extend(frozen_lat)
        tp_rows.extend(frozen_tp)

    with (out / "raw_latency.jsonl").open("w") as f:
        for r in latency_rows:
            f.write(json.dumps(r) + "\n")
    with (out / "raw_throughput.jsonl").open("w") as f:
        for r in tp_rows:
            f.write(json.dumps(r) + "\n")
    if stage_diag:
        (out / "hierastream_stage_diagnostics.json").write_text(
            json.dumps(stage_diag, indent=2), encoding="utf-8"
        )
    agg = aggregate(latency_rows, tp_rows)
    if agg:
        with (out / "aggregate.csv").open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(agg[0].keys()))
            w.writeheader()
            w.writerows(agg)
    if latency_rows:
        tp_ok = bool(tp_rows) and all(
            r.get("failures", 0) == 0 for r in tp_rows if r.get("scheme") == "HieraStream" or int(r.get("offered_tps", 0)) in RATES
        )
        # Throughput plot always useful for v3 even if high rates miss offered load.
        write_plots(out, latency_rows, tp_rows, suffix=plot_suffix, plot_throughput=True)
        write_composite_preview(out, latency_rows, tp_rows, suffix=plot_suffix)
    env = {
        "macos": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "hierastream_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "droplet_commit": "5c2dbac90aa3bde837ed4989ecd78235e5d9ef8e",
        "timecrypt_commit": "f97d72adb9e22017cb2992c1b233ab9aa0562b8e",
        "failures": failures,
        "reps": reps,
        "reps_4k": reps_4k,
        "duration_s": duration,
        "payload_seed": PAYLOAD_SEED.decode("ascii"),
        "schemes_run": sorted(schemes_filter),
        "merged_frozen_droplet_timecrypt": merge_frozen,
        "frozen_run": FROZEN_RUN if merge_frozen else None,
        "hierastream_config": hs_config,
        "hierastream_stage_diagnostics_4kib": stage_diag,
        "plot_suffix": plot_suffix,
        "hierastream_throughput_rates": list(HIERASTREAM_EXTRA_RATES) + list(RATES)
        if "HieraStream" in schemes_filter
        else list(RATES),
    }
    (out / "environment.json").write_text(json.dumps(env, indent=2), encoding="utf-8")
    print(json.dumps({"out": str(out), "n_latency": len(latency_rows), "failures": failures}, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
