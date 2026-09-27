"""Live Hyperledger Fabric Gateway adapter.

Enable with:
  HIERASTREAM_FABRIC_GATEWAY=1
  HIERASTREAM_FABRIC_LIVE=1

Shells out to hs-gateway-cli with per-identity configs under
  core/blockchain/network/gateway/{gateway,authority,admin}.json
"""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from pathlib import Path
from typing import List, Optional, Tuple

from core.blockchain.client.peer_backend import FabricTxStatus, TxResult

_NETWORK = Path(__file__).resolve().parents[1] / "network"
_GATEWAY_DIR = _NETWORK / "gateway"
_DEFAULT_CLI = _NETWORK / "bin" / "hs-gateway-cli"


def _profile_path() -> Path:
    return Path(os.environ.get("HIERASTREAM_FABRIC_PROFILE", str(_GATEWAY_DIR / "connection.json")))


def _cli_bin() -> Path:
    profile = _profile_path()
    if profile.exists():
        try:
            hs = json.loads(profile.read_text()).get("hierastream") or {}
            if hs.get("cli_bin"):
                return Path(hs["cli_bin"])
        except (OSError, json.JSONDecodeError):
            pass
    return Path(os.environ.get("HIERASTREAM_FABRIC_CLI", str(_DEFAULT_CLI)))


def _identity_config(identity: str) -> Path:
    """Map logical caller ids to Fabric identity configs."""
    low = (identity or "").strip().lower()
    if low in {"gw", "gateway", "owner", "owner_gateway"} or low.startswith("gateway"):
        name = "gateway"
    elif low in {"aa", "authority", "rm", "ca", "admin_authority"} or low.startswith("authority"):
        name = "authority"
    elif low in {"admin"}:
        name = "admin"
    elif low in {"unauthorized", "user3", "intruder"}:
        # Reuse gateway cert but ACL will deny authority-only ops when called as gateway;
        # for CommitSegment denial use authority identity attempting CommitSegment.
        name = os.environ.get("HIERASTREAM_UNAUTHORIZED_IDENTITY", "authority")
    else:
        # Default: treat unknown as gateway for CommitSegment callers like "gw1"
        name = "gateway"
    path = _GATEWAY_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"missing identity config: {path}")
    return path


def _status_from_raw(status: str, code: str = "") -> FabricTxStatus:
    blob = f"{status} {code}".upper()
    if "MVCC" in blob:
        return FabricTxStatus.MVCC_READ_CONFLICT
    if "ACL" in blob or "DENIED" in blob:
        return FabricTxStatus.ACL_DENIED
    if status.upper() == "VALID" or status.upper() == "SUCCESS":
        return FabricTxStatus.VALID
    if status.upper() == "PENDING":
        return FabricTxStatus.PENDING
    return FabricTxStatus.INVALID


def _run_cli(mode: str, fn: str, args: List[str], identity: str) -> dict:
    live = os.environ.get("HIERASTREAM_FABRIC_LIVE", "").strip() in {"1", "true", "yes"}
    if not live:
        return {
            "ok": False,
            "status": "INVALID",
            "error": (
                f"live Fabric Gateway not connected (fn={fn}, identity={identity}). "
                "Set HIERASTREAM_FABRIC_LIVE=1 after chaincode commit."
            ),
            "tx_id": str(uuid.uuid4()),
        }
    if not _profile_path().exists():
        return {
            "ok": False,
            "status": "INVALID",
            "error": f"missing Fabric connection profile: {_profile_path()}",
            "tx_id": str(uuid.uuid4()),
        }
    cli = _cli_bin()
    if not cli.exists():
        return {
            "ok": False,
            "status": "INVALID",
            "error": f"missing hs-gateway-cli: {cli}",
            "tx_id": str(uuid.uuid4()),
        }
    cfg = _identity_config(identity)
    cmd = [str(cli), str(cfg), mode, fn, *[str(a) for a in args]]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=float(os.environ.get("HIERASTREAM_FABRIC_TIMEOUT", "120")),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "status": "INVALID",
            "error": f"gateway timeout: {exc}",
            "tx_id": str(uuid.uuid4()),
        }
    out = (proc.stdout or "").strip().splitlines()
    payload = {}
    for line in reversed(out):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                payload = json.loads(line)
                break
            except json.JSONDecodeError:
                continue
    if not payload:
        err = (proc.stderr or proc.stdout or f"exit={proc.returncode}").strip()
        return {
            "ok": False,
            "status": "INVALID",
            "error": err[:2000],
            "tx_id": str(uuid.uuid4()),
        }
    return payload


def gateway_invoke(fn: str, args: List[str], identity: str = "aa") -> TxResult:
    raw = _run_cli("submit", fn, args, identity)
    status = _status_from_raw(str(raw.get("status", "INVALID")), str(raw.get("code", "")))
    if raw.get("ok") and status == FabricTxStatus.VALID:
        return TxResult(str(raw.get("tx_id") or uuid.uuid4()), FabricTxStatus.VALID, "")
    reason = str(raw.get("error") or raw.get("code") or raw.get("status") or "gateway invoke failed")
    # Surface ACL denials from chaincode endorsement errors
    if "ACL denied" in reason or "ACL_DENIED" in reason.upper():
        status = FabricTxStatus.ACL_DENIED
    return TxResult(str(raw.get("tx_id") or uuid.uuid4()), status, reason)


def gateway_query(fn: str, args: List[str], identity: str = "gateway") -> Optional[str]:
    raw = _run_cli("evaluate", fn, args, identity)
    if not raw.get("ok"):
        return None
    payload = raw.get("payload")
    return None if payload is None else str(payload)


def gateway_endorse(fn: str, args: List[str], identity: str = "gw") -> Tuple[TxResult, Optional[str]]:
    """Endorse only; returns (PENDING TxResult, path to endorsed bytes)."""
    raw = _run_cli("endorse", fn, args, identity)
    path = str(raw.get("payload") or "") or None
    status = _status_from_raw(str(raw.get("status", "INVALID")), str(raw.get("code", "")))
    if raw.get("ok") and path:
        return TxResult(str(raw.get("tx_id") or uuid.uuid4()), FabricTxStatus.PENDING, path), path
    reason = str(raw.get("error") or "endorse failed")
    return TxResult(str(raw.get("tx_id") or uuid.uuid4()), status, reason), None


def gateway_submit_endorsed(endorsed_path: str, identity: str = "gw") -> TxResult:
    """Submit a previously endorsed transaction (Property-1 Case A)."""
    # CLI: submit_endorsed <dummy-fn> <path>
    raw = _run_cli("submit_endorsed", "_", [endorsed_path], identity)
    status = _status_from_raw(str(raw.get("status", "INVALID")), str(raw.get("code", "")))
    reason = str(raw.get("error") or raw.get("code") or "")
    if raw.get("ok") and status == FabricTxStatus.VALID:
        return TxResult(str(raw.get("tx_id") or uuid.uuid4()), FabricTxStatus.VALID, "")
    return TxResult(str(raw.get("tx_id") or uuid.uuid4()), status, reason)
