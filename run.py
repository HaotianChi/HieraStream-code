#!/usr/bin/env python3
"""Command-line entry point for HieraStream."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def cmd_test(args: argparse.Namespace) -> int:
    cmd = [sys.executable, "-m", "pytest", "tests/unit", "-q"]
    if args.k:
        cmd.extend(["-k", args.k])
    return subprocess.call(cmd, cwd=str(ROOT))


def cmd_demo(args: argparse.Namespace) -> int:
    from core.crypto.python.factory import create_segment_crypto, resolve_backend
    from core.protocol.workflow import HieraStreamWorkflow
    from core.storage.ipfs_client import IPFSClient

    native = bool(getattr(args, "native", False))
    backend = "pbc" if native else resolve_backend()
    use_local_ipfs = not native

    if native:
        os.environ["HIERASTREAM_CRYPTO_BACKEND"] = "pbc"

    crypto = create_segment_crypto(backend=backend)
    ipfs = IPFSClient(use_local=use_local_ipfs)
    if native and not ipfs._kubo:
        print("ERROR: --native requires Kubo at http://127.0.0.1:5001")
        return 1

    wf = HieraStreamWorkflow(owner_id="owner-1", crypto=crypto, ipfs=ipfs)
    snap = wf.setup()
    print(f"setup ok: version={snap.version} crypto={crypto.backend} ipfs={ipfs.backend}")
    wf.provision_user("alice", ["doctor", "cardiology"], ["AttendingPhysician"])
    wf.provision_user("bob", ["nurse"], ["Nurse"])
    seg = wf.publish(b"demo-ehr-payload", targets=["Resident", "Nurse"], seg_id="demo1")
    print(f"published segment {seg.seg_id} CID={seg.cid[:18]}... MCID={seg.mcid[:18]}...")
    pt = wf.access("alice", seg.seg_id)
    print(f"alice access ok: {pt!r}")
    try:
        wf.access("bob", seg.seg_id)
        print("ERROR: bob should fail attribute policy")
        return 1
    except PermissionError as e:
        print(f"bob correctly denied: {e}")

    if native:
        wf.provision_user("carol", ["doctor", "cardiology"], ["AttendingPhysician"])
        wf.publish(b"before-revoke", targets=["AttendingPhysician"], seg_id="nr0")
        wf.revoke_attribute("doctor", revoked_users=["carol"])
        wf.publish(b"after-revoke", targets=["AttendingPhysician"], seg_id="nr1")
        assert wf.access("alice", "nr0") == b"before-revoke"
        assert wf.access("carol", "nr0") == b"before-revoke"
        assert wf.access("alice", "nr1") == b"after-revoke"
        try:
            wf.access("carol", "nr1")
            print("ERROR: carol should fail after revoke")
            return 1
        except PermissionError:
            print("carol correctly denied on new segment after attribute revoke")
        print(f"native demo complete (PBC={crypto.backend} Kubo={ipfs.backend})")
    else:
        print("demo complete")
    return 0


def cmd_data_prepare(args: argparse.Namespace) -> int:
    from data.adapters.registry import prepare_dataset

    return prepare_dataset(args.dataset, smoke=args.quick, download=args.download)


def cmd_experiment(args: argparse.Namespace) -> int:
    from experiments.runners.registry import run_experiment

    return run_experiment(args.name, smoke=args.quick, config=args.config, profile=args.profile)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="run.py", description="HieraStream")
    sub = p.add_subparsers(dest="command", required=True)

    t = sub.add_parser("test", help="Run unit tests")
    t.add_argument("-k", default=None, help="pytest -k expression")
    t.set_defaults(func=cmd_test)

    d = sub.add_parser("demo", help="End-to-end demo")
    d.add_argument(
        "--native",
        action="store_true",
        help="Use PBC crypto + Kubo IPFS (requires make build and a Kubo daemon)",
    )
    d.set_defaults(func=cmd_demo)

    data = sub.add_parser("data", help="Dataset preparation")
    data_sub = data.add_subparsers(dest="data_cmd", required=True)
    prep = data_sub.add_parser("prepare")
    prep.add_argument(
        "dataset",
        choices=["uci_heart_failure", "hf_remote_monitoring", "hm3_synthetic", "vitaldb", "all"],
    )
    prep.add_argument("--quick", action="store_true", help="Use a small local subset")
    prep.add_argument("--download", action="store_true", help="Fetch corpora into data/datasets/*/raw/")
    prep.set_defaults(func=cmd_data_prepare)

    exp = sub.add_parser("experiment", help="Run evaluation experiments (E1–E10)")
    exp.add_argument(
        "name",
        choices=[
            "crypto",
            "e1",
            "role",
            "e2",
            "fabric",
            "e3",
            "consistency",
            "e4",
            "rekey",
            "e5",
            "longitudinal",
            "e6",
            "granularity",
            "e7",
            "revocation",
            "e8",
            "datasets",
            "e9",
            "comparison",
            "e10",
            "all",
        ],
    )
    exp.add_argument("--quick", action="store_true", help="Short workload for local checks")
    exp.add_argument("--config", default=None, help="Override YAML config path")
    exp.add_argument(
        "--profile",
        default=None,
        help="Bench profile: formal_single_host | ubuntu_final",
    )
    exp.set_defaults(func=cmd_experiment)

    plot = sub.add_parser("plot", help="Process raw experiment outputs into figures")
    plot.add_argument("experiment", help="Experiment name or 'all'")
    plot.add_argument("--run-id", default=None)
    plot.add_argument("--process-only", action="store_true")

    def cmd_plot(a: argparse.Namespace) -> int:
        from experiments.plots.plot_from_raw import main as plot_main

        argv = [a.experiment]
        if a.run_id:
            argv.extend(["--run-id", a.run_id])
        if a.process_only:
            argv.append("--process-only")
        return plot_main(argv)

    plot.set_defaults(func=cmd_plot)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
