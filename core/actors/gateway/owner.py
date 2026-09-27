"""Owner gateway — segment protection, envelopes, CommitSegment, IPFS publish."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from core.authorization.snapshot import AuthorizationSnapshot
from core.blockchain.client.fabric_client import FabricClient
from core.blockchain.client.peer_backend import FabricTxStatus, TxResult
from core.crypto.python.access_tree import AccessTree
from core.crypto.python.groups import GTElement
from core.crypto.python.kdf_aead import aead_encrypt, derive_segment_key
from core.crypto.python.segment import AttrCT, RoleEnvelope, SegmentCrypto
from core.protocol.metadata import metadata_bytes
from core.protocol.selective_retry import (
    PreparedCommitArtifacts,
    SelectiveRetryDiagnostics,
    prepare_for_authorization_snapshot,
)
from core.storage.ipfs_client import IPFSClient


@dataclass
class PendingProtection:
    """Immutable payload shares retained across stale authorization retries.

    Envelope caches are updated after each prepare attempt so a subsequent
    stale retry can reuse unaffected authorization envelopes.
    """

    seg_id: str
    ZA: GTElement
    ZR: GTElement
    key: bytes
    ct_aes: bytes
    cid: str
    targets: List[str]
    plaintext_aad: bytes = b""
    # Cached envelopes from the last prepare under ``envelope_snap``
    attr_ct: Optional[AttrCT] = None
    role_envelopes: Optional[List[RoleEnvelope]] = None
    envelope_snap: Optional[AuthorizationSnapshot] = None


@dataclass
class PublishedSegment:
    seg_id: str
    cid: str
    mcid: str
    eta: str
    snapshot: AuthorizationSnapshot
    ct_aes: bytes
    metadata_obj: dict
    meta_published: bool
    targets: List[str]
    # Retained for retry tests (not on-chain)
    ZA: GTElement
    ZR: GTElement


@dataclass
class OwnerGateway:
    owner_id: str
    crypto: SegmentCrypto
    fabric: FabricClient
    ipfs: IPFSClient
    caller_id: str = "gw"
    # Track whether metadata CIDs were published (for test 13)
    published_mcids: Dict[str, str] = field(default_factory=dict)
    unpublished_predictions: Dict[str, str] = field(default_factory=dict)
    # Last prepare diagnostics (overwritten each attempt_commit)
    last_prepare_diagnostics: Optional[SelectiveRetryDiagnostics] = None
    prepare_diagnostics_log: List[SelectiveRetryDiagnostics] = field(default_factory=list)

    def read_active_snapshot(self) -> AuthorizationSnapshot:
        snap = self.fabric.get_authorization_snapshot(self.owner_id)
        if snap is None:
            raise RuntimeError("no active AuthKey on Fabric")
        return snap

    def protect_payload(
        self,
        seg_id: str,
        plaintext: bytes,
        targets: Sequence[str],
        aad: bytes = b"",
    ) -> PendingProtection:
        """Sample Z^A, Z^R once; encrypt; upload CT_AES → CID. Do not redo on retry."""
        ZA = self.crypto.sample_ZA()
        ZR = self.crypto.sample_ZR()
        key = derive_segment_key(ZA, ZR)
        ct_aes = aead_encrypt(key, plaintext, aad=aad)
        cid = self.ipfs.add(ct_aes)
        return PendingProtection(
            seg_id=seg_id,
            ZA=ZA,
            ZR=ZR,
            key=key,
            ct_aes=ct_aes,
            cid=cid,
            targets=list(targets),
            plaintext_aad=aad,
        )

    def build_envelopes(
        self, pending: PendingProtection, tree: AccessTree
    ) -> Tuple[AttrCT, List[RoleEnvelope]]:
        """Full (non-selective) envelope build — used by tests/baselines only."""
        from core.protocol.selective_retry import (
            regenerate_attr_envelope,
            regenerate_role_envelopes,
        )

        attr_ct = regenerate_attr_envelope(self.crypto, pending.ZA, tree)
        envelopes = regenerate_role_envelopes(self.crypto, pending.ZR, pending.targets)
        return attr_ct, envelopes

    def prepare_commit_artifacts(
        self,
        pending: PendingProtection,
        snap: AuthorizationSnapshot,
        tree: AccessTree,
        *,
        force_attr: Optional[bool] = None,
        force_role: Optional[bool] = None,
    ) -> PreparedCommitArtifacts:
        """Selective envelope prepare + metadata/MCID/η (no Fabric commit)."""
        prepared = prepare_for_authorization_snapshot(
            self.crypto,
            ZA=pending.ZA,
            ZR=pending.ZR,
            cid=pending.cid,
            targets=pending.targets,
            snap=snap,
            tree=tree,
            prior_snap=pending.envelope_snap,
            prior_attr=pending.attr_ct,
            prior_roles=pending.role_envelopes,
            mcid_fn=self.ipfs.only_hash,
            force_attr=force_attr,
            force_role=force_role,
        )
        # Cache for subsequent selective retries; payload shares unchanged.
        pending.attr_ct = prepared.attr_ct
        pending.role_envelopes = prepared.role_envelopes
        pending.envelope_snap = snap
        self.last_prepare_diagnostics = prepared.diagnostics
        self.prepare_diagnostics_log.append(prepared.diagnostics)
        return prepared

    def attempt_commit(
        self,
        pending: PendingProtection,
        snap: AuthorizationSnapshot,
        tree: AccessTree,
        *,
        defer_validation: bool = False,
    ) -> Tuple[TxResult, dict, str, str]:
        """Selective prepare M_j / MCID / η, then CommitSegment. Does NOT publish M_j yet."""
        prepared = self.prepare_commit_artifacts(pending, snap, tree)
        self.unpublished_predictions[pending.seg_id] = prepared.mcid
        result = self.fabric.commit_segment(
            self.owner_id,
            pending.seg_id,
            pending.cid,
            prepared.mcid,
            snap.version,
            snap.policy_id,
            snap.attr_state_id,
            snap.role_state_id,
            prepared.eta,
            caller=self.caller_id,
            defer_validation=defer_validation,
        )
        return result, prepared.metadata_obj, prepared.mcid, prepared.eta

    def publish_metadata_after_valid(
        self, pending: PendingProtection, metadata_obj: dict, mcid: str
    ) -> str:
        meta_bytes_val = metadata_bytes(metadata_obj)
        actual = self.ipfs.add(meta_bytes_val)
        if actual != mcid:
            raise RuntimeError(f"MCID invariant failed: predicted={mcid} actual={actual}")
        self.published_mcids[pending.seg_id] = actual
        return actual

    def metadata_was_published(self, seg_id: str) -> bool:
        return seg_id in self.published_mcids
