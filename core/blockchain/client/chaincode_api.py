"""Chaincode logic shared by simulator client and Go port (Algorithm 1)."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple

from core.authorization.snapshot import AuthKeyRecord, AuthorizationSnapshot, auth_key, segment_key
from core.blockchain.client.ledger import MVCCLedger, TxStatus, json_bytes
from core.canonical import eta_digest


def commit_segment(
    ledger: MVCCLedger,
    tx_id: str,
    caller: str,
    owner_id: str,
    seg_id: str,
    cid: str,
    mcid: str,
    version: int,
    policy_id: str,
    attr_state_id: str,
    role_state_id: str,
    eta: str,
) -> Tuple[Any, ...]:
    """Algorithm 1: COMMIT SEGMENT on AuthKey(ownerId)."""
    ctx = ledger.begin(tx_id, caller)
    raw = ctx.get_state(auth_key(owner_id))
    if raw is None:
        ctx.reject("AuthKey missing")
        return ledger.commit(ctx.endorse(), "CommitSegment")

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
        return ledger.commit(ctx.endorse(), "CommitSegment")

    eta_prime = eta_digest(cid, mcid, version, policy_id, attr_state_id, role_state_id)
    if eta_prime != eta:
        ctx.reject("eta mismatch")
        return ledger.commit(ctx.endorse(), "CommitSegment")

    record = {
        "CID": cid,
        "MCID": mcid,
        "version": version,
        "policyId": policy_id,
        "attrStateId": attr_state_id,
        "roleStateId": role_state_id,
        "eta": eta,
    }
    ctx.put_state(segment_key(owner_id, seg_id), json_bytes(record))
    return ledger.commit(ctx.endorse(), "CommitSegment")


def update_authorization(
    ledger: MVCCLedger,
    tx_id: str,
    caller: str,
    owner_id: str,
    expected: AuthorizationSnapshot,
    new_record: AuthKeyRecord,
) -> Any:
    """UPDATE AUTHORIZATION — same AuthKey(ownerId) as CommitSegment."""
    ctx = ledger.begin(tx_id, caller)
    raw = ctx.get_state(auth_key(owner_id))
    if raw is None:
        ctx.reject("AuthKey missing")
        return ledger.commit(ctx.endorse(), "UpdateAuthorization")

    auth = AuthKeyRecord.from_dict(json.loads(raw.decode("utf-8")))
    if auth.version != expected.version:
        ctx.reject("expectedVersion mismatch")
        return ledger.commit(ctx.endorse(), "UpdateAuthorization")
    if not auth.snapshot(owner_id).matches(expected):
        ctx.reject("expected current state mismatch")
        return ledger.commit(ctx.endorse(), "UpdateAuthorization")

    if new_record.version != auth.version + 1:
        ctx.reject("version must increment by exactly one")
        return ledger.commit(ctx.endorse(), "UpdateAuthorization")

    ctx.put_state(auth_key(owner_id), json_bytes(new_record.to_dict()))
    return ledger.commit(ctx.endorse(), "UpdateAuthorization")


def bootstrap_auth(ledger: MVCCLedger, owner_id: str, record: AuthKeyRecord) -> None:
    ledger.put_state_direct(auth_key(owner_id), json_bytes(record.to_dict()))


# Unversioned baseline: commits WITHOUT reading AuthKey (no MVCC dependency).
def commit_segment_unversioned(
    ledger: MVCCLedger,
    tx_id: str,
    caller: str,
    owner_id: str,
    seg_id: str,
    cid: str,
    mcid: str,
    observed_version: int,
    policy_id: str,
    attr_state_id: str,
    role_state_id: str,
    eta: str,
) -> Any:
    ctx = ledger.begin(tx_id, caller)
    # Intentionally does NOT GetState(AuthKey) — baseline difference.
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
    ctx.put_state(segment_key(owner_id, seg_id), json_bytes(record))
    return ledger.commit(ctx.endorse(), "CommitSegment")
