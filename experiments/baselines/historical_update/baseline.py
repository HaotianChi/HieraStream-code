"""Algebraic historical ciphertext-update baseline (E8).

After attribute a changes t_old → t_new, update each historical leaf component
associated with a:

  C_a' = C_a ^{t_new / t_old} = g^{t_new · q}

so that refreshed user keys E_ua' = g^{β r_u / t_new} still pair correctly:
  e(E_ua', C_a') = e(g,g)^{β r_u q} = e(E_ua, C_a).

AES payloads and role envelopes are NOT re-encrypted — this baseline represents
approaches that must process accumulated historical CP-ABE leaf ciphertexts
after revocation, distinct from HieraStream prospective semantics.
"""

from __future__ import annotations

import json
import time
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from core.authorization.lifecycle import AuthorizationLifecycle
from core.crypto.python.field import Zp
from core.crypto.python.segment import AttrCT, ProtectedSegmentCrypto, SegmentCrypto
from core.protocol.metadata import serialize_attr_ct


@dataclass
class StoredHistoricalSegment:
    seg_id: str
    targets: List[str]
    protected: ProtectedSegmentCrypto
    attr_ct_bytes: int
    # plaintext retained only for optional decrypt tests — never used in update path
    plaintext: bytes = b""


@dataclass
class HistoricalUpdateStats:
    historical_segments_touched: int = 0
    leaf_components_updated: int = 0
    cryptographic_update_s: float = 0.0
    bytes_read: int = 0
    bytes_written: int = 0
    metadata_storage_update_work: int = 0  # serialized attr-CT rewrite bytes
    aes_payloads_rewritten: int = 0  # must remain 0 for algebraic path
    role_envelopes_rewritten: int = 0  # must remain 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "historical_segments_touched": self.historical_segments_touched,
            "leaf_components_updated": self.leaf_components_updated,
            "cryptographic_update_s": self.cryptographic_update_s,
            "bytes_read": self.bytes_read,
            "bytes_written": self.bytes_written,
            "metadata_storage_update_work": self.metadata_storage_update_work,
            "aes_payloads_rewritten": self.aes_payloads_rewritten,
            "role_envelopes_rewritten": self.role_envelopes_rewritten,
            # E8 harness aliases
            "ciphertexts_modified": self.historical_segments_touched,
            "bytes_communicated": self.bytes_written,
        }


@dataclass
class HistoricalUpdateBaseline:
    """Retroactive algebraic leaf update — separate from HieraStream prospective path."""

    crypto: SegmentCrypto
    lifecycle: AuthorizationLifecycle
    segments: List[StoredHistoricalSegment] = field(default_factory=list)
    baseline_id: str = "historical_ciphertext_update_algebraic"
    last_stats: Optional[HistoricalUpdateStats] = None

    def protect_and_store(
        self, plaintext: bytes, targets: Sequence[str], seg_id: str
    ) -> StoredHistoricalSegment:
        tree = self.lifecycle.active_policy_tree()
        prot = self.crypto.protect_segment(plaintext, tree, targets)
        ser = len(json.dumps(serialize_attr_ct(prot.attr_ct), sort_keys=True).encode())
        entry = StoredHistoricalSegment(
            seg_id=seg_id,
            targets=list(targets),
            protected=prot,
            attr_ct_bytes=ser,
            plaintext=plaintext,
        )
        self.segments.append(entry)
        return entry

    def revoke_with_historical_update(
        self, attr: str, revoked_users: Sequence[str]
    ) -> Dict[str, Any]:
        """Current-state revoke + algebraic rewrite of historical leaves for `attr`."""
        assert self.crypto.secrets
        aa = self.crypto.secrets.aa
        if attr not in aa.t_a:
            raise KeyError(f"unknown attribute {attr}")
        t_old = aa.t_a[attr]

        # Prospective current-state update (same AA path as HieraStream)
        self.lifecycle.revoke_attribute(attr, revoked_users)
        t_new = aa.t_a[attr]
        # Leaf exponent scale: t_new / t_old  (inverse of key-refresh ratio t_old/t_new)
        leaf_scale = t_new * t_old.inv()

        stats = HistoricalUpdateStats()
        t0 = time.perf_counter()
        for entry in self.segments:
            before = json.dumps(serialize_attr_ct(entry.protected.attr_ct), sort_keys=True).encode()
            stats.bytes_read += len(before) + len(entry.protected.ct_aes)

            ct = entry.protected.attr_ct
            new_ca = dict(ct.C_a)
            touched = 0
            for lid, g_el in list(new_ca.items()):
                # Leaf ids are "path:attr" — update only matching attribute leaves
                leaf_attr = lid.rsplit(":", 1)[-1]
                if leaf_attr == attr:
                    new_ca[lid] = g_el.pow(leaf_scale)
                    touched += 1

            if touched == 0:
                # Policy tree does not contain this attribute — no CT rewrite
                continue

            new_ct = AttrCT(
                tree=deepcopy(ct.tree),
                C_tilde=ct.C_tilde,
                C_prime=ct.C_prime,
                C_tilde_prime=ct.C_tilde_prime,
                C_tilde_dprime=ct.C_tilde_dprime,
                C_a=new_ca,
            )
            # Preserve AES + role envelopes (algebraic leaf-only update)
            entry.protected = ProtectedSegmentCrypto(
                ZA=entry.protected.ZA,
                ZR=entry.protected.ZR,
                key=entry.protected.key,
                ct_aes=entry.protected.ct_aes,
                attr_ct=new_ct,
                role_envelopes=entry.protected.role_envelopes,
                targets=list(entry.protected.targets),
            )
            after = json.dumps(serialize_attr_ct(new_ct), sort_keys=True).encode()
            entry.attr_ct_bytes = len(after)
            stats.historical_segments_touched += 1
            stats.leaf_components_updated += touched
            stats.bytes_written += len(after)
            stats.metadata_storage_update_work += len(after)

        stats.cryptographic_update_s = time.perf_counter() - t0
        # Do not export t_old/t_new/ratio
        del t_old, t_new, leaf_scale
        self.last_stats = stats
        return stats.to_dict()
