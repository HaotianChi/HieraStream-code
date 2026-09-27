"""Canonical segment metadata M_j serialization (Section III-B / III-C).

M_j = {
  CT_j^A,
  CT_j^R,
  nu,
  policyId,
  attrStateId,
  roleStateId,
  targetRoles
}

Encoding rules (explicit, order-independent for maps):
- Schema version: hierastream-metadata-v1 (wrapped by canonical_json_dumps)
- Group elements: lowercase hex of to_bytes()
- Access trees: AccessTree.to_dict()
- CTR list: ordered by targetRoles list order (not dict iteration)
- C_a / C3 maps: keys sorted lexicographically in JSON (sort_keys=True)
- Do not include test-only fields (e.g. RoleEnvelope.d)
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence

from core.canonical import canonical_json_dumps
from core.crypto.python.access_tree import AccessTree
from core.crypto.python.groups import GElement, GTElement
from core.crypto.python.segment import AttrCT, RoleEnvelope

METADATA_KIND = "HieraStream-Mj"
METADATA_VERSION = 1


def _g_hex(g: GElement) -> str:
    return g.to_bytes().hex()


def _gt_hex(g: GTElement) -> str:
    return g.to_bytes().hex()


def _g_from_hex(h: str, GElementCls=GElement) -> GElement:
    return GElementCls.from_bytes(bytes.fromhex(h))


def _gt_from_hex(h: str, GTElementCls=GTElement) -> GTElement:
    return GTElementCls.from_bytes(bytes.fromhex(h))


def serialize_attr_ct(ct: AttrCT) -> Dict[str, Any]:
    # Sort leaf map keys for stable encoding
    c_a = {k: _g_hex(v) for k, v in sorted(ct.C_a.items())}
    return {
        "C_a": c_a,
        "C_dprime": _g_hex(ct.C_tilde_dprime),  # kept for clarity alias below
        "C_prime": _g_hex(ct.C_prime),
        "C_tilde": _gt_hex(ct.C_tilde),
        "C_tilde_dprime": _g_hex(ct.C_tilde_dprime),
        "C_tilde_prime": _g_hex(ct.C_tilde_prime),
        "tree": ct.tree.to_dict(),
    }


def deserialize_attr_ct(
    d: Dict[str, Any],
    *,
    GElementCls=GElement,
    GTElementCls=GTElement,
) -> AttrCT:
    return AttrCT(
        tree=AccessTree.from_dict(d["tree"]),
        C_tilde=_gt_from_hex(d["C_tilde"], GTElementCls),
        C_prime=_g_from_hex(d["C_prime"], GElementCls),
        C_tilde_prime=_g_from_hex(d["C_tilde_prime"], GElementCls),
        C_tilde_dprime=_g_from_hex(d["C_tilde_dprime"], GElementCls),
        C_a={k: _g_from_hex(v, GElementCls) for k, v in d["C_a"].items()},
    )


def serialize_role_envelope(env: RoleEnvelope) -> Dict[str, Any]:
    c3 = {k: _g_hex(v) for k, v in sorted(env.C3.items())}
    return {
        "C1": _gt_hex(env.C1),
        "C2": _g_hex(env.C2),
        "C3": c3,
        "Ci": _g_hex(env.Ci),
        "target": env.target_role,
        # d intentionally omitted
    }


def deserialize_role_envelope(
    d: Dict[str, Any],
    *,
    GElementCls=GElement,
    GTElementCls=GTElement,
    ZpCls=None,
) -> RoleEnvelope:
    from core.crypto.python.field import Zp as AlgebraicZp

    ZpT = ZpCls or AlgebraicZp
    return RoleEnvelope(
        target_role=d["target"],
        C1=_gt_from_hex(d["C1"], GTElementCls),
        C2=_g_from_hex(d["C2"], GElementCls),
        C3={k: _g_from_hex(v, GElementCls) for k, v in d["C3"].items()},
        Ci=_g_from_hex(d["Ci"], GElementCls),
        d=ZpT.one(),  # placeholder; not used in decryption
    )


def build_metadata_object(
    attr_ct: AttrCT,
    envelopes: Sequence[RoleEnvelope],
    version: int,
    policy_id: str,
    attr_state_id: str,
    role_state_id: str,
    target_roles: Sequence[str],
) -> Dict[str, Any]:
    """Build M_j dict with fixed top-level field set.

    Field names follow manuscript: CT^A, CT^R, ν, ids, R^tar.
    JSON key order is normalized by canonical_json_dumps(sort_keys=True).
    """
    # Order CTR by explicit target_roles sequence
    by_target = {e.target_role: e for e in envelopes}
    ctr = [serialize_role_envelope(by_target[t]) for t in target_roles]
    return {
        "CTA": serialize_attr_ct(attr_ct),
        "CTR": ctr,
        "attrStateId": attr_state_id,
        "kind": METADATA_KIND,
        "metaVersion": METADATA_VERSION,
        "nu": int(version),
        "policyId": policy_id,
        "roleStateId": role_state_id,
        "targetRoles": list(target_roles),
    }


def metadata_bytes(metadata_obj: Dict[str, Any]) -> bytes:
    return canonical_json_dumps(metadata_obj)


def parse_metadata(raw: bytes) -> Dict[str, Any]:
    import json

    wrapper = json.loads(raw.decode("utf-8"))
    if isinstance(wrapper, dict) and "data" in wrapper:
        return wrapper["data"]
    return wrapper
