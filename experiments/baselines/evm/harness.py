"""In-process EVM gas harness for cross-scheme comparison contracts.

Models London schedule costs for the storage operations performed by
HieraStreamPolicy.sol. Optional live Ganache via ganache_runner.py.

Completely separate from Fabric PeerMVCCLedger.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# London gas schedule (subset)
GAS_SLOAD = 2100
GAS_SSTORE_SET = 20000  # zero → nonzero
GAS_SSTORE_RESET = 2900  # nonzero → nonzero
GAS_CALLBASE = 21000
GAS_TXDATA_ZERO = 4
GAS_TXDATA_NONZERO = 16


def _b32(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


@dataclass
class AuthSnap:
    version: int = 0
    policy_id: bytes = field(default_factory=lambda: b"\x00" * 32)
    attr_state_id: bytes = field(default_factory=lambda: b"\x00" * 32)
    role_state_id: bytes = field(default_factory=lambda: b"\x00" * 32)
    exists: bool = False


@dataclass
class TxMeasurement:
    scheme: str
    operation: str
    gas_used: int
    latency_s: float
    status: str = "ok"
    backend: str = "in_process_london_schedule"


@dataclass
class EVMComparisonHarness:
    """HieraStream policy contract simulator + PASH/MASS unavailable probes."""

    backend: str = "in_process"
    auth: Dict[bytes, AuthSnap] = field(default_factory=dict)
    measurements: List[TxMeasurement] = field(default_factory=list)

    def __post_init__(self) -> None:
        url = os.environ.get("HIERASTREAM_GANACHE_URL", "").strip()
        if url:
            self.backend = "ganache"
            self._ganache_url = url
        else:
            self._ganache_url = ""

    def init_hierastream(self, owner: str = "owner-1") -> TxMeasurement:
        oid = _b32(owner)
        t0 = time.perf_counter()
        gas = GAS_CALLBASE
        if oid in self.auth and self.auth[oid].exists:
            raise RuntimeError("Auth exists")
        # 5 SSTORE sets: version, policy, attr, role, exists
        gas += 5 * GAS_SSTORE_SET
        self.auth[oid] = AuthSnap(
            version=0,
            policy_id=_b32("p0"),
            attr_state_id=_b32("a0"),
            role_state_id=_b32("r0"),
            exists=True,
        )
        m = TxMeasurement("HieraStream", "initAuth", gas, time.perf_counter() - t0, backend=self._backend_tag())
        self.measurements.append(m)
        return m

    def policy_update(self, owner: str = "owner-1") -> TxMeasurement:
        oid = _b32(owner)
        t0 = time.perf_counter()
        gas = GAS_CALLBASE
        s = self.auth[oid]
        gas += GAS_SLOAD  # load exists/version
        gas += 4 * GAS_SSTORE_RESET  # version + 3 ids
        s.version += 1
        s.policy_id = _b32(f"p{s.version}")
        s.attr_state_id = _b32(f"a{s.version}")
        s.role_state_id = _b32(f"r{s.version}")
        m = TxMeasurement(
            "HieraStream",
            "policyUpdate",
            gas,
            time.perf_counter() - t0,
            backend=self._backend_tag(),
        )
        self.measurements.append(m)
        return m

    def query_access(self, owner: str = "owner-1") -> TxMeasurement:
        oid = _b32(owner)
        t0 = time.perf_counter()
        gas = GAS_CALLBASE
        s = self.auth[oid]
        gas += 4 * GAS_SLOAD
        _ = (s.version, s.policy_id, s.attr_state_id, s.role_state_id)
        m = TxMeasurement(
            "HieraStream",
            "queryAccess",
            gas,
            time.perf_counter() - t0,
            backend=self._backend_tag(),
        )
        self.measurements.append(m)
        return m

    def run_hierastream_bench(
        self,
        n_policy: int = 10,
        n_query: int = 10,
        offered_tps_list: Optional[List[float]] = None,
    ) -> List[Dict[str, Any]]:
        if self.backend == "ganache":
            try:
                from experiments.baselines.evm.ganache_runner import run_ganache_hierastream

                return run_ganache_hierastream(
                    self._ganache_url,
                    n_policy=n_policy,
                    n_query=n_query,
                    offered_tps_list=offered_tps_list,
                )
            except Exception as exc:  # noqa: BLE001
                # Fall back to in-process with note
                self.backend = "in_process"
                note = f"ganache_unavailable:{exc}"
            else:
                note = None
        else:
            note = None

        self.init_hierastream()
        rows: List[Dict[str, Any]] = []
        for offered in offered_tps_list or [None]:
            for _ in range(n_policy):
                m = self.policy_update()
                rows.append(
                    {
                        **m.__dict__,
                        "note": note,
                        "offered_tps": offered,
                        "gas_independent_of_tps": True,
                    }
                )
            for _ in range(n_query):
                m = self.query_access()
                rows.append(
                    {
                        **m.__dict__,
                        "note": note,
                        "offered_tps": offered,
                        "gas_independent_of_tps": True,
                    }
                )
        return rows

    def probe_pash_mass(self) -> List[Dict[str, Any]]:
        from experiments.baselines.mass.adapter import MASSAdapter
        from experiments.baselines.pash.adapter import PASHAdapter

        out = []
        for ad in (PASHAdapter(), MASSAdapter()):
            p = ad.probe()
            out.append(
                {
                    "scheme": p["scheme"],
                    "operation": "evm_comparison",
                    "status": "NOT_AVAILABLE",
                    "gas_used": None,
                    "latency_s": None,
                    "missing_information": p["missing_information"],
                    "backend": "none",
                }
            )
        return out

    def _backend_tag(self) -> str:
        return "ganache" if self.backend == "ganache" else "in_process_london_schedule"
