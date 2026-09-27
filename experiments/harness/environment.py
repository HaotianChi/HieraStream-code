"""Full environment capture for reproducible experiment runs."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parents[2]
PAIRING_PARAM = ROOT / "core" / "crypto" / "params" / "a.param"


def _run(cmd: list[str], timeout: float = 5.0) -> Optional[str]:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout)
        return out.decode("utf-8", errors="replace").strip()
    except Exception:
        return None


def _pkg_config(mod: str) -> Optional[str]:
    return _run(["pkg-config", "--modversion", mod])


def _sha256_file(path: Path) -> Optional[str]:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _cpu_model() -> str:
    # macOS
    brand = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
    if brand:
        return brand
    # Linux
    try:
        text = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "unknown"


def _ram_bytes() -> Optional[int]:
    try:
        import psutil  # type: ignore

        return int(psutil.virtual_memory().total)
    except Exception:
        pass
    # macOS
    mem = _run(["sysctl", "-n", "hw.memsize"])
    if mem and mem.isdigit():
        return int(mem)
    # Linux
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                parts = line.split()
                return int(parts[1]) * 1024  # kB → bytes
    except Exception:
        pass
    return None


def _compiler() -> Dict[str, Optional[str]]:
    return {
        "cc": _run(["cc", "--version"]),
        "c++": _run(["c++", "--version"]),
        "clang": _run(["clang", "--version"]),
        "gcc": _run(["gcc", "--version"]),
    }


def _go_version() -> Optional[str]:
    return _run(["go", "version"])


def _ipfs_version() -> Optional[str]:
    v = _run(["ipfs", "version"])
    if v:
        return v
    # Docker-compose Kubo often not on PATH; note compose service
    return None


def _fabric_version() -> Optional[str]:
    # peer binary if present
    return _run(["peer", "version"]) or os.environ.get("HIERASTREAM_FABRIC_VERSION")


def _caliper_version() -> Optional[str]:
    # Record Node only if explicitly configured or already on PATH.
    env_v = os.environ.get("HIERASTREAM_CALIPER_VERSION")
    if env_v:
        return env_v
    if shutil.which("caliper"):
        return _run(["caliper", "--version"])
    return None


def _ganache_note() -> Dict[str, Any]:
    url = os.environ.get("HIERASTREAM_GANACHE_URL")
    return {
        "configured_url": url,
        "used": bool(url),
        "note": "Recorded only when HIERASTREAM_GANACHE_URL is set for EVM baseline.",
    }


def _git_state() -> Dict[str, Any]:
    commit = _run(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    dirty = None
    if commit:
        dirty = (
            subprocess.call(
                ["git", "-C", str(ROOT), "diff", "--quiet"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            != 0
        )
        # also untracked? keep dirty for tracked diffs; note status porcelain
        porcelain = _run(["git", "-C", str(ROOT), "status", "--porcelain"])
        if porcelain:
            dirty = True
    return {
        "commit": commit or "NO_GIT",
        "dirty": dirty,
        "clean": (dirty is False) if dirty is not None else None,
        "branch": _run(["git", "-C", str(ROOT), "rev-parse", "--abbrev-ref", "HEAD"]),
    }


def _kdf_aead_config() -> Dict[str, Any]:
    return {
        "kdf": "HKDF-SHA-256",
        "kdf_domains": [
            "HieraStream-Attribute-v1",
            "HieraStream-Role-v1",
        ],
        "aead": "AES-256-GCM",
        "payload_version": 1,
        "nonce_bytes": 12,
        "key_bytes": 32,
        "source": "core/crypto/python/kdf_aead.py",
    }


def capture_environment(
    *,
    resource: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Record every field required for reproducibility."""
    from experiments.harness.run_context import resource_snapshot

    platform_tag = os.environ.get(
        "HIERASTREAM_PLATFORM_TAG",
        os.environ.get("HIERASTREAM_BENCH_PROFILE", "development"),
    )
    git = _git_state()
    pairing_sha = _sha256_file(PAIRING_PARAM)
    env: Dict[str, Any] = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "git": git,
        "git_commit": git["commit"] + (" DIRTY" if git.get("dirty") else ""),
        "repo_dirty": git.get("dirty"),
        "os": platform.platform(),
        "os_system": platform.system(),
        "os_release": platform.release(),
        "kernel": platform.release(),
        "kernel_version": platform.version(),
        "cpu_model": _cpu_model(),
        "cpu_architecture": platform.machine(),
        "cpu_count_logical": os.cpu_count(),
        "ram_bytes": _ram_bytes(),
        "compiler": _compiler(),
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
        },
        "go": _go_version(),
        "pbc": _pkg_config("pbc") or os.environ.get("HIERASTREAM_PBC_VERSION"),
        "gmp": _pkg_config("gmp") or _pkg_config("libgmp"),
        "openssl": _pkg_config("openssl") or _run(["openssl", "version"]),
        "fabric": _fabric_version(),
        "caliper": _caliper_version(),
        "ipfs_kubo": _ipfs_version(),
        "ganache": _ganache_note(),
        "pairing_parameter_filename": str(PAIRING_PARAM.relative_to(ROOT))
        if PAIRING_PARAM.exists()
        else None,
        "pairing_parameter_sha256": pairing_sha,
        "kdf_aead": _kdf_aead_config(),
        "crypto_backend": os.environ.get("HIERASTREAM_CRYPTO_BACKEND", "python_algebraic"),
        "fabric_backend": (
            "fabric_gateway"
            if os.environ.get("HIERASTREAM_FABRIC_GATEWAY", "").strip() in {"1", "true", "yes"}
            else os.environ.get("HIERASTREAM_FABRIC_BACKEND", "peer_mvcc")
        ),
        "platform_tag": platform_tag,
        "bench_profile": os.environ.get("HIERASTREAM_BENCH_PROFILE", platform_tag),
        "result_class": _result_class(platform_tag),
        "hostname": platform.node(),
        "resource": resource if resource is not None else resource_snapshot(),
        "paths": {
            "root": str(ROOT),
            "cc": shutil.which("cc"),
            "go": shutil.which("go"),
            "ipfs": shutil.which("ipfs"),
        },
    }
    return env


def _result_class(platform_tag: str) -> str:
    tag = (platform_tag or "").lower()
    if tag in {"ubuntu_final", "final", "formal", "formal_single_host", "production"}:
        return "FINAL_BENCHMARK"
    return "DEVELOPMENT"


def assert_required_env_fields(env: Dict[str, Any]) -> None:
    required = [
        "git_commit",
        "repo_dirty",
        "os",
        "kernel",
        "cpu_model",
        "cpu_architecture",
        "ram_bytes",
        "compiler",
        "python",
        "go",
        "pbc",
        "gmp",
        "openssl",
        "fabric",
        "caliper",
        "ipfs_kubo",
        "ganache",
        "pairing_parameter_filename",
        "pairing_parameter_sha256",
        "kdf_aead",
        "platform_tag",
        "result_class",
    ]
    missing = [k for k in required if k not in env]
    if missing:
        raise AssertionError(f"environment.json missing keys: {missing}")
