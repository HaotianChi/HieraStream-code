"""Fabric peer state-based MVCC backend (port of core/blockchain/peerval).

This IS the paper-faithful Fabric validation path for research CI:

  Fabric peers apply state-based validation (statebasedval):
    for each key in read-set:
        if ledger_version(key) != endorsed_version(key) → MVCC_READ_CONFLICT

CommitSegment and UpdateAuthorization both GetState(AuthKey(ownerId)), so
concurrent updates exercise this path exactly as on a live peer.

Equivalence claim (evaluation §III-C / Property 1):
  PeerMVCCLedger implements the same read-set version check as Hyperledger
  Fabric's state-based MVCC. It is NOT an application-level fake of VALID.
  Live gRPC Gateway is optional (HIERASTREAM_FABRIC_GATEWAY=1) for deployment
  TPS; concurrency correctness for Alg.1 does not require Docker.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set


class FabricTxStatus(str, Enum):
    VALID = "VALID"
    MVCC_READ_CONFLICT = "MVCC_READ_CONFLICT"
    INVALID = "INVALID"
    ACL_DENIED = "ACL_DENIED"
    PENDING = "PENDING"


@dataclass
class _Ver:
    value: bytes
    version: int


@dataclass
class ReadEntry:
    key: str
    version: int
    exists: bool


@dataclass
class EndorsedTx:
    tx_id: str
    caller: str
    function: str
    read_set: List[ReadEntry]
    write_set: Dict[str, bytes]
    app_reject: bool = False
    app_reason: str = ""


@dataclass
class TxResult:
    tx_id: str
    status: FabricTxStatus
    reason: str = ""


@dataclass
class PeerMVCCLedger:
    """In-process Fabric peer validator for research / CI without Docker."""

    _state: Dict[str, _Ver] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)
    history: List[TxResult] = field(default_factory=list)
    acl: Dict[str, Set[str]] = field(default_factory=dict)
    pending: Dict[str, EndorsedTx] = field(default_factory=dict)

    def set_acl(self, function: str, callers: Set[str]) -> None:
        self.acl[function] = set(callers)

    def bootstrap_put(self, key: str, value: bytes) -> None:
        with self._lock:
            ver = 1 if key not in self._state else self._state[key].version + 1
            self._state[key] = _Ver(value=value, version=ver)

    def get(self, key: str) -> Optional[bytes]:
        with self._lock:
            vv = self._state.get(key)
            return None if vv is None else vv.value

    def begin(self, tx_id: str, caller: str, function: str) -> "EndorseCtx":
        return EndorseCtx(self, tx_id, caller, function)

    def submit_endorsed(self, tx: EndorsedTx) -> None:
        """Queue endorsed tx as PENDING (await_validation)."""
        self.pending[tx.tx_id] = tx

    def validate_and_commit(self, tx: EndorsedTx) -> TxResult:
        with self._lock:
            allowed = self.acl.get(tx.function)
            if allowed is not None and tx.caller not in allowed:
                res = TxResult(tx.tx_id, FabricTxStatus.ACL_DENIED, "ACL")
                self.history.append(res)
                return res
            if tx.app_reject:
                res = TxResult(tx.tx_id, FabricTxStatus.INVALID, tx.app_reason)
                self.history.append(res)
                return res
            for r in tx.read_set:
                cur = self._state.get(r.key)
                if not r.exists:
                    if cur is not None:
                        res = TxResult(
                            tx.tx_id,
                            FabricTxStatus.MVCC_READ_CONFLICT,
                            f"key={r.key} expectedAbsent gotVer={cur.version}",
                        )
                        self.history.append(res)
                        return res
                    continue
                if cur is None or cur.version != r.version:
                    got = 0 if cur is None else cur.version
                    res = TxResult(
                        tx.tx_id,
                        FabricTxStatus.MVCC_READ_CONFLICT,
                        f"key={r.key} endorsedVer={r.version} ledgerVer={got}",
                    )
                    self.history.append(res)
                    return res
            for k, v in tx.write_set.items():
                ver = 1 if k not in self._state else self._state[k].version + 1
                self._state[k] = _Ver(value=v, version=ver)
            res = TxResult(tx.tx_id, FabricTxStatus.VALID)
            self.history.append(res)
            return res

    def await_validation(self, tx_id: str) -> TxResult:
        tx = self.pending.pop(tx_id, None)
        if tx is None:
            for h in reversed(self.history):
                if h.tx_id == tx_id:
                    return h
            return TxResult(tx_id, FabricTxStatus.INVALID, "unknown tx")
        return self.validate_and_commit(tx)


class EndorseCtx:
    def __init__(self, ledger: PeerMVCCLedger, tx_id: str, caller: str, function: str) -> None:
        self.ledger = ledger
        self.tx_id = tx_id
        self.caller = caller
        self.function = function
        self.reads: Dict[str, ReadEntry] = {}
        self.writes: Dict[str, bytes] = {}
        self.app_reject = False
        self.app_reason = ""

    def get_state(self, key: str) -> Optional[bytes]:
        with self.ledger._lock:
            vv = self.ledger._state.get(key)
            if vv is None:
                self.reads[key] = ReadEntry(key=key, version=0, exists=False)
                return None
            self.reads[key] = ReadEntry(key=key, version=vv.version, exists=True)
            return vv.value

    def put_state(self, key: str, value: bytes) -> None:
        self.writes[key] = value

    def reject(self, reason: str) -> None:
        self.app_reject = True
        self.app_reason = reason

    def endorse(self) -> EndorsedTx:
        return EndorsedTx(
            tx_id=self.tx_id,
            caller=self.caller,
            function=self.function,
            read_set=list(self.reads.values()),
            write_set=dict(self.writes),
            app_reject=self.app_reject,
            app_reason=self.app_reason,
        )
