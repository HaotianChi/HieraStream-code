#!/usr/bin/env python3
"""Compile HieraStreamPolicy.sol → experiments/baselines/evm/build/HieraStreamPolicy.json"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CONTRACT = ROOT / "experiments/baselines/evm/contracts/HieraStreamPolicy.sol"
OUT = ROOT / "experiments/baselines/evm/build"
OUT.mkdir(parents=True, exist_ok=True)


def main() -> int:
    # Prefer solc via npx solc
    cmd = [
        "npx",
        "--yes",
        "solc@0.8.19",
        "--optimize",
        "--bin",
        "--abi",
        str(CONTRACT),
    ]
    print("compiling:", " ".join(cmd))
    p = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    if p.returncode != 0:
        print(p.stdout)
        print(p.stderr)
        return p.returncode

    # solc prints ======= sections
    text = p.stdout + "\n" + p.stderr
    abi = None
    bytecode = None
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("======= ") and "HieraStreamPolicy" in line and line.strip().endswith("======="):
            # next non-empty may be Binary: or Contract JSON
            pass
        if line.strip() == "Binary:":
            i += 1
            while i < len(lines) and not lines[i].strip():
                i += 1
            if i < len(lines):
                bytecode = "0x" + lines[i].strip()
        if line.strip() == "Contract JSON ABI":
            i += 1
            while i < len(lines) and not lines[i].strip():
                i += 1
            if i < len(lines):
                abi = json.loads(lines[i].strip())
        i += 1

    if not abi or not bytecode:
        # Fallback: write combined output for debug
        (OUT / "solc_stdout.txt").write_text(text, encoding="utf-8")
        print("failed to parse solc output; see build/solc_stdout.txt")
        return 1

    art = {"abi": abi, "bytecode": bytecode, "contractName": "HieraStreamPolicy"}
    path = OUT / "HieraStreamPolicy.json"
    path.write_text(json.dumps(art, indent=2), encoding="utf-8")
    print("wrote", path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
