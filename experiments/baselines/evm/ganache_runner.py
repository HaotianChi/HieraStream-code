"""Optional live Ganache/Web3 runner for HieraStreamPolicy.sol.

Requires: web3.py and a node at HIERASTREAM_GANACHE_URL (e.g. http://127.0.0.1:8545).
If unavailable, callers fall back to the in-process gas harness.

Gas is a property of executed contract logic — independent of offered TPS.
Latency may vary with load; gas_used must not be presented as scaling with TPS.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


CONTRACT_DIR = Path(__file__).resolve().parent / "contracts"


def run_ganache_hierastream(
    url: str,
    n_policy: int = 10,
    n_query: int = 10,
    offered_tps_list: Optional[List[float]] = None,
) -> List[Dict[str, Any]]:
    from web3 import Web3

    w3 = Web3(Web3.HTTPProvider(url))
    if not w3.is_connected():
        raise RuntimeError(f"cannot connect to ganache at {url}")

    artifact = Path(__file__).resolve().parent / "build" / "HieraStreamPolicy.json"
    if not artifact.exists():
        raise RuntimeError(
            "HieraStreamPolicy.json artifact missing — run "
            "experiments/baselines/evm/compile_contract.py, "
            "or unset HIERASTREAM_GANACHE_URL to use in-process harness"
        )
    art = json.loads(artifact.read_text(encoding="utf-8"))
    acct = w3.eth.accounts[0]
    Contract = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
    tx_hash = Contract.constructor().transact({"from": acct})
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    c = w3.eth.contract(address=receipt.contractAddress, abi=art["abi"])

    owner = w3.keccak(text="owner-1")
    c.functions.initAuth(owner, w3.keccak(text="p0"), w3.keccak(text="a0"), w3.keccak(text="r0")).transact(
        {"from": acct}
    )

    rows: List[Dict[str, Any]] = []
    rates = list(offered_tps_list or [None])

    for offered in rates:
        # Fresh version sequence per rate bucket (same contract)
        # Measure n_policy updates with optional pacing toward offered TPS.
        ver = int(c.functions.queryAccess(owner).call()[0])
        t_start = time.perf_counter()
        gas_samples: List[int] = []
        lat_samples: List[float] = []
        for i in range(n_policy):
            ver += 1
            t0 = time.perf_counter()
            tx = c.functions.policyUpdate(
                owner, ver, w3.keccak(text=f"p{ver}"), w3.keccak(text=f"a{ver}"), w3.keccak(text=f"r{ver}")
            ).transact({"from": acct})
            rcpt = w3.eth.wait_for_transaction_receipt(tx)
            dt = time.perf_counter() - t0
            gas = int(rcpt["gasUsed"])
            gas_samples.append(gas)
            lat_samples.append(dt)
            rows.append(
                {
                    "scheme": "HieraStream",
                    "operation": "policyUpdate",
                    "gas_used": gas,
                    "latency_s": dt,
                    "status": "ok",
                    "backend": "ganache",
                    "offered_tps": offered,
                    "gas_independent_of_tps": True,
                    "tx_index": i,
                }
            )
            if offered and offered > 0:
                elapsed = time.perf_counter() - t_start
                expected = (i + 1) / float(offered)
                if expected > elapsed:
                    time.sleep(expected - elapsed)

        # Query/access calls (eth_call) — latency only; estimateGas for view ops
        for j in range(n_query):
            t0 = time.perf_counter()
            c.functions.queryAccess(owner).call()
            dt = time.perf_counter() - t0
            try:
                gas_est = int(c.functions.queryAccess(owner).estimate_gas({"from": acct}))
            except Exception:
                gas_est = None
            rows.append(
                {
                    "scheme": "HieraStream",
                    "operation": "queryAccess",
                    "gas_used": gas_est,
                    "latency_s": dt,
                    "status": "ok",
                    "backend": "ganache",
                    "offered_tps": offered,
                    "gas_independent_of_tps": True,
                    "tx_index": j,
                }
            )

        if gas_samples:
            rows.append(
                {
                    "scheme": "HieraStream",
                    "operation": "policyUpdate_summary",
                    "phase": "evm_summary",
                    "backend": "ganache",
                    "offered_tps": offered,
                    "gas_used_mean": sum(gas_samples) / len(gas_samples),
                    "gas_used_min": min(gas_samples),
                    "gas_used_max": max(gas_samples),
                    "latency_s_mean": sum(lat_samples) / len(lat_samples),
                    "n": len(gas_samples),
                    "gas_independent_of_tps": True,
                    "note": "Gas determined by contract logic; must not be plotted as a function of TPS",
                }
            )

    # PASH/MASS never fabricated here
    rows.append(
        {
            "scheme": "PASH",
            "operation": "evm_comparison",
            "status": "NOT_AVAILABLE",
            "gas_used": None,
            "latency_s": None,
            "backend": "ganache",
            "reproducibility_class": "NOT_FAITHFULLY_REPRODUCIBLE",
        }
    )
    rows.append(
        {
            "scheme": "MASS",
            "operation": "evm_comparison",
            "status": "NOT_AVAILABLE",
            "gas_used": None,
            "latency_s": None,
            "backend": "ganache",
            "reproducibility_class": "NOT_FAITHFULLY_REPRODUCIBLE",
        }
    )
    return rows
