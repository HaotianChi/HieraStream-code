"""Selective stale-retry preparation (authorization-bound envelopes only).

Shared by OwnerGateway production path and Step-23/23R ablation timing.

Decision rule (from authorization-state identifiers, not ν alone):

  need_attr  ⇔  prior is None OR policyId changed OR attrStateId changed
  need_role  ⇔  prior is None OR roleStateId changed

Version-only (ν changes; policy/attr/role ids unchanged) regenerates neither
envelope; metadata / MCID / η are still rebuilt under Θ_new.

Does not resample ZA/ZR or re-encrypts CTAES.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence, Tuple

from core.authorization.snapshot import AuthorizationSnapshot
from core.canonical import eta_digest
from core.crypto.python.access_tree import AccessTree
from core.crypto.python.segment import AttrCT, RoleEnvelope, SegmentCrypto
from core.protocol.metadata import build_metadata_object, metadata_bytes


@dataclass(frozen=True)
class SelectiveRegenDecision:
    need_attr: bool
    need_role: bool
    reason: str


@dataclass(frozen=True)
class SelectiveRetryDiagnostics:
    """Lightweight structured diagnostics for one prepare/retry attempt."""

    attr_envelope_regenerated: bool
    role_envelope_regenerated: bool
    payload_reencrypted: bool
    ZA_reused: bool
    ZR_reused: bool
    metadata_rebuilt: bool
    decision_reason: str
    prior_version: Optional[int]
    new_version: int
    prior_policy_id: Optional[str]
    prior_attr_state_id: Optional[str]
    prior_role_state_id: Optional[str]
    new_policy_id: str
    new_attr_state_id: str
    new_role_state_id: str


@dataclass
class PreparedCommitArtifacts:
    attr_ct: AttrCT
    role_envelopes: List[RoleEnvelope]
    metadata_obj: dict
    meta_bytes: bytes
    mcid: str
    eta: str
    diagnostics: SelectiveRetryDiagnostics


def decide_envelope_regeneration(
    prior: Optional[AuthorizationSnapshot],
    new: AuthorizationSnapshot,
) -> SelectiveRegenDecision:
    """Return which authorization envelopes must be regenerated for Θ_new."""
    if prior is None:
        return SelectiveRegenDecision(True, True, "initial_prepare")

    need_attr = prior.policy_id != new.policy_id or prior.attr_state_id != new.attr_state_id
    need_role = prior.role_state_id != new.role_state_id

    if not need_attr and not need_role:
        if prior.version != new.version:
            reason = "version_only"
        elif prior.matches(new):
            reason = "identical_snapshot"
        else:
            reason = "unchanged_auth_ids"
        return SelectiveRegenDecision(False, False, reason)

    if need_attr and need_role:
        reason = "joint"
    elif need_attr:
        reason = "attribute"
    else:
        reason = "role"
    return SelectiveRegenDecision(need_attr, need_role, reason)


def regenerate_attr_envelope(crypto: SegmentCrypto, ZA, tree: AccessTree) -> AttrCT:
    partial = crypto.gateway_partial_attr(ZA)
    return crypto.outsource_policy_encrypt(partial.to_outsource_view(), tree)


def regenerate_role_envelopes(
    crypto: SegmentCrypto, ZR, targets: Sequence[str]
) -> List[RoleEnvelope]:
    return crypto.role_encrypt_multi(ZR, list(targets))


def prepare_for_authorization_snapshot(
    crypto: SegmentCrypto,
    *,
    ZA,
    ZR,
    cid: str,
    targets: Sequence[str],
    snap: AuthorizationSnapshot,
    tree: AccessTree,
    prior_snap: Optional[AuthorizationSnapshot],
    prior_attr: Optional[AttrCT],
    prior_roles: Optional[List[RoleEnvelope]],
    mcid_fn: Callable[[bytes], str],
    force_attr: Optional[bool] = None,
    force_role: Optional[bool] = None,
) -> PreparedCommitArtifacts:
    """Rebuild envelopes selectively + metadata/MCID/η for Θ_new.

    CTAES/ZA/ZR are inputs only (never resampled here).
    ``force_attr`` / ``force_role`` override the decision (ablation FULL_*).
    """
    decision = decide_envelope_regeneration(prior_snap, snap)
    need_attr = decision.need_attr if force_attr is None else bool(force_attr)
    need_role = decision.need_role if force_role is None else bool(force_role)

    if need_attr:
        attr_ct = regenerate_attr_envelope(crypto, ZA, tree)
    else:
        if prior_attr is None:
            raise RuntimeError("cannot reuse attribute envelope: none cached")
        attr_ct = prior_attr

    if need_role:
        role_envelopes = regenerate_role_envelopes(crypto, ZR, targets)
    else:
        if prior_roles is None:
            raise RuntimeError("cannot reuse role envelopes: none cached")
        role_envelopes = prior_roles

    metadata_obj = build_metadata_object(
        attr_ct,
        role_envelopes,
        snap.version,
        snap.policy_id,
        snap.attr_state_id,
        snap.role_state_id,
        list(targets),
    )
    meta_b = metadata_bytes(metadata_obj)
    mcid = mcid_fn(meta_b)
    eta = eta_digest(
        cid,
        mcid,
        snap.version,
        snap.policy_id,
        snap.attr_state_id,
        snap.role_state_id,
    )

    reason = decision.reason
    if force_attr is not None or force_role is not None:
        reason = f"{decision.reason}+forced(attr={need_attr},role={need_role})"

    diag = SelectiveRetryDiagnostics(
        attr_envelope_regenerated=need_attr,
        role_envelope_regenerated=need_role,
        payload_reencrypted=False,
        ZA_reused=True,
        ZR_reused=True,
        metadata_rebuilt=True,
        decision_reason=reason,
        prior_version=None if prior_snap is None else prior_snap.version,
        new_version=snap.version,
        prior_policy_id=None if prior_snap is None else prior_snap.policy_id,
        prior_attr_state_id=None if prior_snap is None else prior_snap.attr_state_id,
        prior_role_state_id=None if prior_snap is None else prior_snap.role_state_id,
        new_policy_id=snap.policy_id,
        new_attr_state_id=snap.attr_state_id,
        new_role_state_id=snap.role_state_id,
    )
    return PreparedCommitArtifacts(
        attr_ct=attr_ct,
        role_envelopes=role_envelopes,
        metadata_obj=metadata_obj,
        meta_bytes=meta_b,
        mcid=mcid,
        eta=eta,
        diagnostics=diag,
    )
