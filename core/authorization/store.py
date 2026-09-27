"""In-memory and file-backed authorization ledger (Fabric-independent).

Simulates AuthKey(ownerId) world-state updates for prepare/commit/activate
orchestration tests without a live Fabric network.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

from core.authorization.snapshot import AuthKeyRecord, AuthorizationSnapshot, auth_key
from core.canonical import canonical_json_dumps


class CommitRejected(Exception):
    """Simulated / local ledger rejection of UpdateAuthorization."""


@dataclass
class LocalAuthLedger:
    """Per-process AuthKey store with optional durable JSON backend."""

    path: Optional[Path] = None
    records: Dict[str, AuthKeyRecord] = field(default_factory=dict)
    # Force next UpdateAuthorization to fail (test hook)
    fail_next_commit: bool = False
    # Append-only audit of public commit payloads (never ratios)
    commit_log: list = field(default_factory=list)

    def load(self) -> None:
        if self.path is None or not self.path.exists():
            return
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        # canonical_json_dumps wraps as {_schema, data}
        data = raw.get("data", raw) if isinstance(raw, dict) else raw
        self.records = {
            k: AuthKeyRecord.from_dict(v) for k, v in data.get("records", {}).items()
        }

    def persist(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        blob = {
            "records": {k: v.to_dict() for k, v in self.records.items()},
        }
        # Write via canonical bytes then decode for readable UTF-8 JSON file
        raw = canonical_json_dumps(blob)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_bytes(raw)
        os.replace(tmp, self.path)

    def get(self, owner_id: str) -> Optional[AuthKeyRecord]:
        return self.records.get(auth_key(owner_id))

    def bootstrap(self, snap: AuthorizationSnapshot) -> AuthKeyRecord:
        if snap.version != 0:
            raise ValueError("bootstrap requires version 0")
        key = auth_key(snap.owner_id)
        if key in self.records:
            raise RuntimeError("auth already bootstrapped")
        rec = AuthKeyRecord.from_snapshot(snap)
        self.records[key] = rec
        self.persist()
        return rec

    def update_authorization(
        self,
        owner_id: str,
        expected: AuthKeyRecord,
        next_rec: AuthKeyRecord,
        public_payload: Optional[dict] = None,
    ) -> AuthKeyRecord:
        """Atomic AuthKey overwrite with ν -> ν+1 (local orchestration)."""
        if self.fail_next_commit:
            self.fail_next_commit = False
            raise CommitRejected("forced commit failure")

        key = auth_key(owner_id)
        cur = self.records.get(key)
        if cur is None:
            raise CommitRejected("missing AuthKey")
        if cur.version != expected.version:
            raise CommitRejected("expectedVersion mismatch")
        if (
            cur.policy_id != expected.policy_id
            or cur.attr_state_id != expected.attr_state_id
            or cur.role_state_id != expected.role_state_id
        ):
            raise CommitRejected("expected current state mismatch")
        if next_rec.version != cur.version + 1:
            raise CommitRejected("version must increment by exactly one")

        # Public audit only
        if public_payload is not None:
            # Defense: refuse payloads that look like they carry ratios
            _assert_no_ratio_leak(public_payload)
            self.commit_log.append({"ownerId": owner_id, "payload": public_payload})

        self.records[key] = next_rec
        self.persist()
        return next_rec


_FORBIDDEN_KEYS = {
    "ratio",
    "updateRatio",
    "update_ratio",
    "t_old",
    "t_new",
    "t_a_ratio",
    "tOld",
    "tNew",
}


def _assert_no_ratio_leak(obj: object) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k) in _FORBIDDEN_KEYS or "ratio" in str(k).lower():
                raise ValueError(f"forbidden secret field in commit payload: {k}")
            _assert_no_ratio_leak(v)
    elif isinstance(obj, list):
        for x in obj:
            _assert_no_ratio_leak(x)
