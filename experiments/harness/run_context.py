"""Per-run output directory under experiments/raw/<experiment>/<run-id>/."""

from __future__ import annotations

import csv
import json
import os
import resource
import subprocess
import sys
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, TextIO

import yaml

ROOT = Path(__file__).resolve().parents[2]
RAW_ROOT = ROOT / "experiments" / "raw"
PROCESSED_ROOT = ROOT / "experiments" / "processed"
FIGURES_ROOT = ROOT / "experiments" / "figures"
PROFILES_DIR = ROOT / "experiments" / "configs" / "profiles"


class _Tee:
    def __init__(self, *streams: TextIO) -> None:
        self._streams = streams

    def write(self, data: str) -> int:
        for s in self._streams:
            s.write(data)
            s.flush()
        return len(data)

    def flush(self) -> None:
        for s in self._streams:
            s.flush()


@dataclass
class ExperimentRun:
    experiment: str
    run_id: str
    path: Path
    config: Dict[str, Any] = field(default_factory=dict)
    rows: List[Dict[str, Any]] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)
    _stdout_f: Optional[TextIO] = None
    _stderr_f: Optional[TextIO] = None
    _old_out: Any = None
    _old_err: Any = None

    def add_row(self, row: Dict[str, Any]) -> None:
        self.rows.append(row)

    def add_rows(self, rows: Iterable[Dict[str, Any]]) -> None:
        self.rows.extend(rows)

    def finish(self) -> Path:
        """Write all artifacts (run directory is unique)."""
        (self.path / "config.yaml").write_text(
            yaml.safe_dump(self.config, sort_keys=True), encoding="utf-8"
        )
        from experiments.harness.environment import capture_environment

        (self.path / "environment.json").write_text(
            json.dumps(capture_environment(), indent=2, sort_keys=True), encoding="utf-8"
        )
        (self.path / "git_commit.txt").write_text(_git_commit(), encoding="utf-8")

        with (self.path / "raw.jsonl").open("w", encoding="utf-8") as f:
            for r in self.rows:
                f.write(json.dumps(r, sort_keys=True, default=str) + "\n")

        if self.rows:
            keys: List[str] = []
            seen = set()
            for r in self.rows:
                for k in r.keys():
                    if k not in seen:
                        seen.add(k)
                        keys.append(k)
            with (self.path / "raw.csv").open("w", encoding="utf-8", newline="") as f:
                w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
                w.writeheader()
                for r in self.rows:
                    w.writerow({k: r.get(k, "") for k in keys})

        if self.extra:
            (self.path / "summary.json").write_text(
                json.dumps(self.extra, indent=2, sort_keys=True, default=str),
                encoding="utf-8",
            )
        self._close_logs()
        print(f"raw results → {self.path}")
        return self.path

    def _close_logs(self) -> None:
        if self._old_out is not None:
            sys.stdout = self._old_out
            self._old_out = None
        if self._old_err is not None:
            sys.stderr = self._old_err
            self._old_err = None
        if self._stdout_f is not None:
            self._stdout_f.close()
            self._stdout_f = None
        if self._stderr_f is not None:
            self._stderr_f.close()
            self._stderr_f = None


def create_run(experiment: str, config: Optional[Dict[str, Any]] = None) -> ExperimentRun:
    """Create a unique run directory under output_root (does not overwrite).

    Default root: ``experiments/raw/``.
    Override with ``config['output_root']`` or ``HIERASTREAM_OUTPUT_ROOT``.
    """
    cfg = dict(config or {})
    root = Path(
        str(
            os.environ.get("HIERASTREAM_OUTPUT_ROOT")
            or cfg.get("output_root")
            or RAW_ROOT
        )
    )
    if not root.is_absolute():
        root = ROOT / root
    root.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    path = root / experiment / run_id
    path.mkdir(parents=True, exist_ok=False)

    tag = str(
        cfg.get("platform_tag")
        or os.environ.get("HIERASTREAM_PLATFORM_TAG")
        or os.environ.get("HIERASTREAM_BENCH_PROFILE")
        or "development"
    )
    cfg.setdefault("platform_tag", tag)
    if str(cfg.get("result_class", "")).upper() in {"FINAL_V1_CONFIG", "FINAL_V1"}:
        cfg.pop("result_class", None)
    if cfg.get("pilot") or str(cfg.get("result_class", "")).upper() == "PILOT":
        cfg["result_class"] = "PILOT"
        cfg["pilot"] = True
    else:
        cfg.setdefault(
            "result_class",
            "FINAL_BENCHMARK"
            if tag.lower() in {"ubuntu_final", "final", "formal", "formal_single_host", "production"}
            else "DEVELOPMENT",
        )
    cfg.setdefault("outliers_discarded", False)
    cfg["output_root"] = str(root)

    run = ExperimentRun(experiment=experiment, run_id=run_id, path=path, config=cfg)
    run._stdout_f = (path / "stdout.log").open("w", encoding="utf-8")
    run._stderr_f = (path / "stderr.log").open("w", encoding="utf-8")
    run._old_out, run._old_err = sys.stdout, sys.stderr
    sys.stdout = _Tee(run._old_out, run._stdout_f)  # type: ignore[assignment]
    sys.stderr = _Tee(run._old_err, run._stderr_f)  # type: ignore[assignment]
    print(f"=== experiment={experiment} run_id={run_id} result_class={cfg['result_class']} ===")
    return run


@contextmanager
def run_experiment_ctx(experiment: str, config: Optional[Dict[str, Any]] = None):
    run = create_run(experiment, config)
    try:
        yield run
        run.finish()
    except Exception:
        try:
            run.extra.setdefault("error", True)
            run.finish()
        except Exception:
            run._close_logs()
        raise


def load_profile(profile: Optional[str] = None) -> Dict[str, Any]:
    name = (
        profile
        or os.environ.get("HIERASTREAM_BENCH_PROFILE")
        or os.environ.get("HIERASTREAM_PLATFORM_TAG")
        or "development"
    )
    path = PROFILES_DIR / f"{name}.yaml"
    if not path.exists():
        # Fall back to development
        path = PROFILES_DIR / "development.yaml"
    if path.exists():
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {"profile": name, "platform_tag": "development"}


def load_defaults() -> Dict[str, Any]:
    path = ROOT / "experiments" / "configs" / "experiments.yaml"
    if path.exists():
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return dict(data.get("experiment_defaults") or {})
    return {}


# Short runner names → manuscript configs under configs/final/.
_DEFAULT_CONFIG_FILES = {
    "crypto": "final/E1_crypto.yaml",
    "role": "final/E2_role.yaml",
    "fabric": "final/E3_fabric_live_steady_state_final.yaml",
    "consistency": "consistency.yaml",
    "consistency_paired": "final/E4_consistency_paired.yaml",
    "rekey": "final/E5_rekey.yaml",
    "longitudinal": "final/E6_longitudinal.yaml",
    "granularity": "final/E7_segment.yaml",
    "revocation": "final/E8_history.yaml",
    "datasets": "final/E9_datasets.yaml",
    "comparison": "final/E10_comparison.yaml",
}


def load_config(
    name: str,
    config_path: Optional[str] = None,
    profile: Optional[str] = None,
) -> Dict[str, Any]:
    """Merge experiment_defaults ← profile ← experiment YAML (later wins)."""
    merged: Dict[str, Any] = {}
    merged.update(load_defaults())
    prof = load_profile(profile)
    merged.update(prof)
    if config_path:
        path = Path(config_path)
    else:
        rel = _DEFAULT_CONFIG_FILES.get(name, f"{name}.yaml")
        path = ROOT / "experiments" / "configs" / rel
    if path.exists():
        exp = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        merged.update(exp)
    else:
        merged.setdefault("experiment", name)
    # Propagate env for backends if profile sets them
    if merged.get("crypto_backend") and not os.environ.get("HIERASTREAM_CRYPTO_BACKEND"):
        os.environ.setdefault("HIERASTREAM_CRYPTO_BACKEND", str(merged["crypto_backend"]))
    if merged.get("platform_tag"):
        os.environ.setdefault("HIERASTREAM_PLATFORM_TAG", str(merged["platform_tag"]))
    return merged


def resource_snapshot() -> Dict[str, Any]:
    """Lightweight CPU/memory sample (no external deps required)."""
    ru = resource.getrusage(resource.RUSAGE_SELF)
    out: Dict[str, Any] = {
        "ru_maxrss_kb": ru.ru_maxrss,  # macOS: bytes; Linux: KiB — recorded raw
        "ru_utime_s": ru.ru_utime,
        "ru_stime_s": ru.ru_stime,
        "thread_count": threading.active_count(),
    }
    try:
        import psutil  # type: ignore

        p = psutil.Process()
        out["cpu_percent"] = p.cpu_percent(interval=0.05)
        out["rss_bytes"] = p.memory_info().rss
        out["vms_bytes"] = p.memory_info().vms
    except Exception:
        out["cpu_percent"] = None
        out["rss_bytes"] = None
    return out


def _git_commit() -> str:
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(ROOT), stderr=subprocess.DEVNULL
        ).decode().strip()
        dirty = subprocess.call(["git", "diff", "--quiet"], cwd=str(ROOT)) != 0
        porcelain = subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=str(ROOT), stderr=subprocess.DEVNULL
        ).decode()
        if porcelain.strip():
            dirty = True
        return commit + (" DIRTY" if dirty else "")
    except Exception:
        return "NO_GIT"
