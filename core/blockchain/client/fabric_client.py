"""Python Fabric client wrapper for HieraStream (Section III-C).

Provides:
  get_authorization_snapshot, commit_segment, update_authorization,
  get_segment, await_validation, inspect transaction status.

Backends:
  - peer (default): Fabric peer MVCC validator (peer_backend) — used for
    automated concurrency Cases 1–5 without requiring Docker.
  - gateway: Hyperledger Fabric Gateway gRPC against a live network
    (HIERASTREAM_FABRIC_GATEWAY=1 + connection profile).

MVCC_READ_CONFLICT and INVALID are first-class statuses for experiments.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from core.authorization.snapshot import AuthKeyRecord, AuthorizationSnapshot, auth_key, segment_key
from core.blockchain.client.peer_backend import (
    EndorsedTx,
    FabricTxStatus,
    PeerMVCCLedger,
    TxResult,
)
from core.canonical import eta_digest


def _json_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class FabricClient:
    """Client library used by the experiment framework."""

    owner_gateway_id: str = "gw"
    authority_id: str = "aa"
    backend: str = "peer"  # peer | gateway
    ledger: PeerMVCCLedger = field(default_factory=PeerMVCCLedger)
    _results: Dict[str, TxResult] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if os.environ.get("HIERASTREAM_FABRIC_GATEWAY", "").strip() in {"1", "true", "yes"}:
            self.backend = "gateway"
        if self.backend == "peer":
            self.ledger.set_acl("CommitSegment", {self.owner_gateway_id, "admin"})
            self.ledger.set_acl(
                "UpdateAuthorization",
                {self.authority_id, "authority", "aa", "rm", "ca", "admin"},
            )
            self.ledger.set_acl("RegisterOwner", {self.authority_id, "admin", "aa"})
            self.ledger.set_acl("RegisterPolicyState", {self.authority_id, "admin", "aa"})
            self.ledger.set_acl("RegisterAttributeState", {self.authority_id, "admin", "aa"})
            self.ledger.set_acl("RegisterRoleState", {self.authority_id, "admin", "aa"})

    # ---- management ----

    def register_owner(self, owner_id: str, gateway_id: str = "") -> TxResult:
        if self.backend == "gateway":
            return self._gateway_invoke("RegisterOwner", [owner_id, gateway_id or self.owner_gateway_id])
        tx_id = str(uuid.uuid4())
        ctx = self.ledger.begin(tx_id, self.authority_id, "RegisterOwner")
        ctx.put_state(
            f"Owner/{owner_id}",
            _json_bytes({"ownerId": owner_id, "gatewayId": gateway_id or self.owner_gateway_id, "active": True}),
        )
        return self._commit(ctx.endorse())

    def register_policy_state(self, policy_id: str, version: int, payload: Dict[str, Any]) -> TxResult:
        if self.backend == "gateway":
            return self._gateway_invoke(
                "RegisterPolicyState",
                [policy_id, str(version), json.dumps(payload, sort_keys=True, separators=(",", ":"))],
                identity=self.authority_id,
            )
        tx_id = str(uuid.uuid4())
        ctx = self.ledger.begin(tx_id, self.authority_id, "RegisterPolicyState")
        ctx.put_state(
            f"PolicyState/{policy_id}",
            _json_bytes({"policyId": policy_id, "version": version, "payload": payload}),
        )
        return self._commit(ctx.endorse())

    def register_attribute_state(self, attr_state_id: str, version: int, payload: Dict[str, Any]) -> TxResult:
        if self.backend == "gateway":
            return self._gateway_invoke(
                "RegisterAttributeState",
                [attr_state_id, str(version), json.dumps(payload, sort_keys=True, separators=(",", ":"))],
                identity=self.authority_id,
            )
        tx_id = str(uuid.uuid4())
        ctx = self.ledger.begin(tx_id, self.authority_id, "RegisterAttributeState")
        ctx.put_state(
            f"AttributeState/{attr_state_id}",
            _json_bytes({"attrStateId": attr_state_id, "version": version, "payload": payload}),
        )
        return self._commit(ctx.endorse())

    def register_role_state(self, role_state_id: str, version: int, payload: Dict[str, Any]) -> TxResult:
        if self.backend == "gateway":
            return self._gateway_invoke(
                "RegisterRoleState",
                [role_state_id, str(version), json.dumps(payload, sort_keys=True, separators=(",", ":"))],
                identity=self.authority_id,
            )
        tx_id = str(uuid.uuid4())
        ctx = self.ledger.begin(tx_id, self.authority_id, "RegisterRoleState")
        ctx.put_state(
            f"RoleState/{role_state_id}",
            _json_bytes({"roleStateId": role_state_id, "version": version, "payload": payload}),
        )
        return self._commit(ctx.endorse())

    def init_auth(self, snap: AuthorizationSnapshot) -> TxResult:
        if self.backend == "gateway":
            return self._gateway_invoke(
                "InitAuth",
                [
                    snap.owner_id,
                    str(snap.version),
                    snap.policy_id,
                    snap.attr_state_id,
                    snap.role_state_id,
                ],
            )
        key = auth_key(snap.owner_id)
        if self.ledger.get(key) is not None:
            return TxResult("init", FabricTxStatus.INVALID, "AuthKey exists")
        self.ledger.bootstrap_put(key, _json_bytes(AuthKeyRecord.from_snapshot(snap).to_dict()))
        res = TxResult("init", FabricTxStatus.VALID)
        self._results[res.tx_id] = res
        return res

    # ---- queries ----

    def get_authorization_snapshot(self, owner_id: str) -> Optional[AuthorizationSnapshot]:
        if self.backend == "gateway":
            raw = self._gateway_query("GetAuthorization", [owner_id])
            if raw is None:
                return None
            d = json.loads(raw)
            return AuthorizationSnapshot(
                owner_id=owner_id,
                version=int(d["version"]),
                policy_id=d["policyId"],
                attr_state_id=d["attrStateId"],
                role_state_id=d["roleStateId"],
            )
        raw = self.ledger.get(auth_key(owner_id))
        if raw is None:
            return None
        rec = AuthKeyRecord.from_dict(json.loads(raw.decode("utf-8")))
        return rec.snapshot(owner_id)

    def get_segment(self, owner_id: str, seg_id: str) -> Optional[Dict[str, Any]]:
        if self.backend == "gateway":
            raw = self._gateway_query("GetSegment", [owner_id, seg_id])
            return None if raw is None else json.loads(raw)
        raw = self.ledger.get(segment_key(owner_id, seg_id))
        if raw is None:
            return None
        return json.loads(raw.decode("utf-8"))

    # ---- transactions ----

    def commit_segment(
        self,
        owner_id: str,
        seg_id: str,
        cid: str,
        mcid: str,
        version: int,
        policy_id: str,
        attr_state_id: str,
        role_state_id: str,
        eta: str,
        *,
        caller: Optional[str] = None,
        defer_validation: bool = False,
    ) -> TxResult:
        """Algorithm 1. GetState(AuthKey) creates the Fabric MVCC read dependency."""
        if self.backend == "gateway":
            return self._gateway_invoke(
                "CommitSegment",
                [
                    owner_id,
                    seg_id,
                    cid,
                    mcid,
                    str(version),
                    policy_id,
                    attr_state_id,
                    role_state_id,
                    eta,
                ],
                identity=caller or self.owner_gateway_id,
            )

        tx_id = str(uuid.uuid4())
        ctx = self.ledger.begin(tx_id, caller or self.owner_gateway_id, "CommitSegment")
        raw = ctx.get_state(auth_key(owner_id))
        if raw is None:
            ctx.reject("AuthKey missing")
            return self._finish(ctx.endorse(), defer_validation)

        auth = AuthKeyRecord.from_dict(json.loads(raw.decode("utf-8")))
        expected = AuthorizationSnapshot(
            owner_id=owner_id,
            version=version,
            policy_id=policy_id,
            attr_state_id=attr_state_id,
            role_state_id=role_state_id,
        )
        if not auth.snapshot(owner_id).matches(expected):
            ctx.reject("authorization snapshot mismatch")
            return self._finish(ctx.endorse(), defer_validation)

        if eta_digest(cid, mcid, version, policy_id, attr_state_id, role_state_id) != eta:
            ctx.reject("eta mismatch")
            return self._finish(ctx.endorse(), defer_validation)

        record = {
            "CID": cid,
            "MCID": mcid,
            "version": version,
            "policyId": policy_id,
            "attrStateId": attr_state_id,
            "roleStateId": role_state_id,
            "eta": eta,
        }
        ctx.put_state(segment_key(owner_id, seg_id), _json_bytes(record))
        return self._finish(ctx.endorse(), defer_validation)

    def commit_segment_unversioned(
        self,
        owner_id: str,
        seg_id: str,
        cid: str,
        mcid: str,
        observed_version: int,
        policy_id: str,
        attr_state_id: str,
        role_state_id: str,
        eta: str,
        *,
        caller: Optional[str] = None,
    ) -> TxResult:
        """Baseline commit: write Segment WITHOUT GetState(AuthKey).

        Creates no Fabric MVCC read dependency on AuthKey(ownerId). Observed
        authorization fields are recorded for stale-commit measurement only.
        """
        if self.backend == "gateway":
            return TxResult(
                str(uuid.uuid4()),
                FabricTxStatus.INVALID,
                "unversioned commit not exposed on live gateway path in this prototype",
            )

        tx_id = str(uuid.uuid4())
        # Distinct function name so ACL can allow it; still gateway-only.
        self.ledger.set_acl("CommitSegmentUnversioned", {self.owner_gateway_id, "admin", "gw"})
        ctx = self.ledger.begin(tx_id, caller or self.owner_gateway_id, "CommitSegmentUnversioned")
        # Intentionally NO ctx.get_state(auth_key(...))
        record = {
            "CID": cid,
            "MCID": mcid,
            "observedVersion": observed_version,
            "policyId": policy_id,
            "attrStateId": attr_state_id,
            "roleStateId": role_state_id,
            "eta": eta,
            "unversioned": True,
        }
        ctx.put_state(segment_key(owner_id, seg_id), _json_bytes(record))
        return self._finish(ctx.endorse(), False)

    def update_authorization(
        self,
        owner_id: str,
        expected: AuthorizationSnapshot,
        *,
        new_policy_id: str = "",
        new_attr_state_id: str = "",
        new_role_state_id: str = "",
        caller: Optional[str] = None,
        defer_validation: bool = False,
    ) -> TxResult:
        """Read SAME AuthKey; carry forward unchanged refs; ν → ν+1."""
        if self.backend == "gateway":
            return self._gateway_invoke(
                "UpdateAuthorization",
                [
                    owner_id,
                    str(expected.version),
                    expected.policy_id,
                    expected.attr_state_id,
                    expected.role_state_id,
                    new_policy_id,
                    new_attr_state_id,
                    new_role_state_id,
                ],
                identity=caller or self.authority_id,
            )

        tx_id = str(uuid.uuid4())
        ctx = self.ledger.begin(tx_id, caller or self.authority_id, "UpdateAuthorization")
        raw = ctx.get_state(auth_key(owner_id))
        if raw is None:
            ctx.reject("AuthKey missing")
            return self._finish(ctx.endorse(), defer_validation)

        auth = AuthKeyRecord.from_dict(json.loads(raw.decode("utf-8")))
        # Explicit expectedVersion guard (manuscript UpdateAuthorization).
        if auth.version != expected.version:
            ctx.reject("expectedVersion mismatch")
            return self._finish(ctx.endorse(), defer_validation)
        if not auth.snapshot(owner_id).matches(expected):
            ctx.reject("expected current state mismatch")
            return self._finish(ctx.endorse(), defer_validation)

        # Increment from stored auth.version; write complete nextRefs (carry unchanged).
        next_rec = AuthKeyRecord(
            version=auth.version + 1,
            policy_id=new_policy_id or auth.policy_id,
            attr_state_id=new_attr_state_id or auth.attr_state_id,
            role_state_id=new_role_state_id or auth.role_state_id,
        )
        ctx.put_state(auth_key(owner_id), _json_bytes(next_rec.to_dict()))
        return self._finish(ctx.endorse(), defer_validation)

    def endorse_commit_segment_only(
        self,
        owner_id: str,
        seg_id: str,
        cid: str,
        mcid: str,
        version: int,
        policy_id: str,
        attr_state_id: str,
        role_state_id: str,
        eta: str,
        *,
        caller: Optional[str] = None,
    ) -> EndorsedTx:
        """Endorse without validating — for concurrency Case 1."""
        if self.backend == "gateway":
            import tempfile

            from core.blockchain.client.gateway_adapter import gateway_endorse

            # Unique endorsed-bytes path per tx (avoid collisions across Case A/B).
            os.environ["HIERASTREAM_ENDORSED_TX_PATH"] = tempfile.mktemp(
                prefix="hs-endorsed-", suffix=".bin"
            )
            res, path = gateway_endorse(
                "CommitSegment",
                [
                    owner_id,
                    seg_id,
                    cid,
                    mcid,
                    str(version),
                    policy_id,
                    attr_state_id,
                    role_state_id,
                    eta,
                ],
                identity=caller or self.owner_gateway_id,
            )
            self._results[res.tx_id] = res
            # Store endorsed path in pending map via a lightweight EndorsedTx shim
            tx = EndorsedTx(
                tx_id=res.tx_id,
                caller=caller or self.owner_gateway_id,
                function="CommitSegment",
                read_set=[],
                write_set={},
            )
            # Stash path on reason field of PENDING result; live submit uses path
            self._results[res.tx_id] = TxResult(res.tx_id, FabricTxStatus.PENDING, path or res.reason)
            self.ledger.pending[res.tx_id] = tx
            return tx

        res = self.commit_segment(
            owner_id,
            seg_id,
            cid,
            mcid,
            version,
            policy_id,
            attr_state_id,
            role_state_id,
            eta,
            caller=caller,
            defer_validation=True,
        )
        # retrieve pending
        tx = self.ledger.pending.get(res.tx_id)
        assert tx is not None
        return tx

    def submit_endorsed_commit(self, tx_id: str) -> TxResult:
        """Submit a previously endorsed CommitSegment (live Gateway Property-1)."""
        if self.backend != "gateway":
            return self.await_validation(tx_id)
        from pathlib import Path as _Path

        from core.blockchain.client.gateway_adapter import gateway_submit_endorsed

        pending = self._results.get(tx_id)
        # reason holds endorsed bytes path from gateway_endorse
        path = pending.reason if pending else ""
        if not path:
            return TxResult(tx_id, FabricTxStatus.INVALID, "missing endorsed path")
        if not _Path(path).exists():
            return TxResult(tx_id, FabricTxStatus.INVALID, f"endorsed path missing: {path}")
        res = gateway_submit_endorsed(path, identity=self.owner_gateway_id)
        self._results[tx_id] = res
        self.ledger.pending.pop(tx_id, None)
        return res

    def await_validation(self, tx_id: str) -> TxResult:
        if self.backend == "gateway" and tx_id in self._results:
            pending = self._results[tx_id]
            if pending.status == FabricTxStatus.PENDING and pending.reason:
                return self.submit_endorsed_commit(tx_id)
        if tx_id in self.ledger.pending:
            res = self.ledger.await_validation(tx_id)
            self._results[tx_id] = res
            return res
        if tx_id in self._results and self._results[tx_id].status != FabricTxStatus.PENDING:
            return self._results[tx_id]
        for h in reversed(self.ledger.history):
            if h.tx_id == tx_id:
                return h
        return TxResult(tx_id, FabricTxStatus.INVALID, "unknown tx")

    def inspect_transaction_status(self, tx_id: str) -> Optional[TxResult]:
        if tx_id in self._results:
            return self._results[tx_id]
        for h in reversed(self.ledger.history):
            if h.tx_id == tx_id:
                return h
        if tx_id in self.ledger.pending:
            return TxResult(tx_id, FabricTxStatus.PENDING)
        return None

    def read_set_keys(self, tx: EndorsedTx) -> List[str]:
        return [r.key for r in tx.read_set]

    # ---- internals ----

    def _finish(self, tx: EndorsedTx, defer: bool) -> TxResult:
        if defer:
            self.ledger.submit_endorsed(tx)
            res = TxResult(tx.tx_id, FabricTxStatus.PENDING)
            self._results[tx.tx_id] = res
            return res
        return self._commit(tx)

    def _commit(self, tx: EndorsedTx) -> TxResult:
        res = self.ledger.validate_and_commit(tx)
        self._results[tx.tx_id] = res
        return res

    def _gateway_invoke(self, fn: str, args: Sequence[str], identity: str = "") -> TxResult:
        try:
            from core.blockchain.client.gateway_adapter import gateway_invoke

            return gateway_invoke(fn, list(args), identity=identity or self.authority_id)
        except Exception as exc:  # noqa: BLE001
            return TxResult(str(uuid.uuid4()), FabricTxStatus.INVALID, f"gateway: {exc}")

    def _gateway_query(self, fn: str, args: Sequence[str]) -> Optional[str]:
        try:
            from core.blockchain.client.gateway_adapter import gateway_query

            return gateway_query(fn, list(args))
        except Exception:
            return None
