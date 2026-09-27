"""Fabric-faithful MVCC world-state simulator for research tests.

Models endorsement read-set / write-set validation:
- GetState adds key to read-set with version observed at endorsement time.
- PutState stages write.
- On commit, if any read-set key's ledger version changed since endorsement,
  the transaction is INVALID (MVCC_READ_CONFLICT).

This is NOT a wall-clock consistency mechanism — serialization order only.
"""

from __future__ import annotations

import copy
import json
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class TxStatus(str, Enum):
    VALID = "VALID"
    MVCC_READ_CONFLICT = "MVCC_READ_CONFLICT"
    REJECT = "REJECT"  # application-level reject (e.g. snapshot mismatch)
    ACL_DENIED = "ACL_DENIED"


@dataclass
class VersionedValue:
    value: bytes
    version: int  # monotonically increasing per key


@dataclass
class EndorsedTx:
    tx_id: str
    caller: str
    read_set: Dict[str, int]  # key -> version observed
    write_set: Dict[str, bytes]
    app_reject: bool = False
    app_reason: str = ""


@dataclass
class CommitResult:
    tx_id: str
    status: TxStatus
    reason: str = ""


@dataclass
class MVCCLedger:
    """In-process Fabric MVCC stand-in for correctness / concurrency tests."""

    _state: Dict[str, VersionedValue] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock)
    _seq: int = 0
    history: List[CommitResult] = field(default_factory=list)
    # ACL: function -> allowed callers
    acl: Dict[str, Set[str]] = field(default_factory=dict)

    def set_acl(self, function: str, callers: Set[str]) -> None:
        self.acl[function] = set(callers)

    def get_state(self, key: str) -> Optional[bytes]:
        with self._lock:
            vv = self._state.get(key)
            return None if vv is None else vv.value

    def get_version(self, key: str) -> Optional[int]:
        with self._lock:
            vv = self._state.get(key)
            return None if vv is None else vv.version

    def put_state_direct(self, key: str, value: bytes) -> None:
        """Genesis / test bootstrap only — bypasses MVCC."""
        with self._lock:
            cur = self._state.get(key)
            ver = 0 if cur is None else cur.version + 1
            self._state[key] = VersionedValue(value=value, version=ver)

    def begin(self, tx_id: str, caller: str) -> "TxContext":
        return TxContext(self, tx_id, caller)

    def commit(self, endorsed: EndorsedTx, function: str) -> CommitResult:
        with self._lock:
            allowed = self.acl.get(function)
            if allowed is not None and endorsed.caller not in allowed:
                res = CommitResult(endorsed.tx_id, TxStatus.ACL_DENIED, "ACL")
                self.history.append(res)
                return res
            if endorsed.app_reject:
                res = CommitResult(endorsed.tx_id, TxStatus.REJECT, endorsed.app_reason)
                self.history.append(res)
                return res
            # MVCC validation
            for key, observed in endorsed.read_set.items():
                cur = self._state.get(key)
                cur_ver = -1 if cur is None else cur.version
                if cur_ver != observed:
                    res = CommitResult(
                        endorsed.tx_id,
                        TxStatus.MVCC_READ_CONFLICT,
                        f"key={key} observed={observed} current={cur_ver}",
                    )
                    self.history.append(res)
                    return res
            for key, value in endorsed.write_set.items():
                cur = self._state.get(key)
                ver = 0 if cur is None else cur.version + 1
                self._state[key] = VersionedValue(value=value, version=ver)
            self._seq += 1
            res = CommitResult(endorsed.tx_id, TxStatus.VALID)
            self.history.append(res)
            return res


class TxContext:
    def __init__(self, ledger: MVCCLedger, tx_id: str, caller: str) -> None:
        self.ledger = ledger
        self.tx_id = tx_id
        self.caller = caller
        self.read_set: Dict[str, int] = {}
        self.write_set: Dict[str, bytes] = {}
        self.app_reject = False
        self.app_reason = ""

    def get_state(self, key: str) -> Optional[bytes]:
        # Observe version at endorsement time
        with self.ledger._lock:
            vv = self.ledger._state.get(key)
            if vv is None:
                self.read_set[key] = -1
                return None
            self.read_set[key] = vv.version
            return vv.value

    def put_state(self, key: str, value: bytes) -> None:
        self.write_set[key] = value

    def reject(self, reason: str) -> None:
        self.app_reject = True
        self.app_reason = reason

    def endorse(self) -> EndorsedTx:
        return EndorsedTx(
            tx_id=self.tx_id,
            caller=self.caller,
            read_set=dict(self.read_set),
            write_set=dict(self.write_set),
            app_reject=self.app_reject,
            app_reason=self.app_reason,
        )


def json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
