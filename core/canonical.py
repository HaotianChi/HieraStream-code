"""Canonical serialization for hashed / content-addressed objects.

Schema version: hierastream-canonical-v1

Rules (cross-platform):
- UTF-8 encoding
- JSON object keys sorted lexicographically
- No insignificant whitespace (separators=(',', ':'))
- Integers as JSON numbers (no floats for protocol fields)
- Bytes / group elements as lowercase hex with even length
- Lists preserve explicit caller order (role lists must be sorted by caller
  when order is semantically unordered)
- Endianness for integer-to-bytes helpers: big-endian
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


SCHEMA_VERSION = "hierastream-canonical-v1"


def canonical_json_dumps(obj: Any) -> bytes:
    payload = {"_schema": SCHEMA_VERSION, "data": obj}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_id(obj: Any) -> str:
    """Stable content identifier for authorization-state objects."""
    return "cid:" + sha256_hex(canonical_json_dumps(obj))


def eta_digest(
    cid: str,
    mcid: str,
    version: int,
    policy_id: str,
    attr_state_id: str,
    role_state_id: str,
) -> str:
    """η_j = H_c(CID || MCID || ν || policyId || attrStateId || roleStateId).

    Canonical concatenation uses 0x1F unit separators between UTF-8 fields.
    Integers encoded as decimal ASCII.
    """
    parts = [
        cid.encode("utf-8"),
        mcid.encode("utf-8"),
        str(version).encode("ascii"),
        policy_id.encode("utf-8"),
        attr_state_id.encode("utf-8"),
        role_state_id.encode("utf-8"),
    ]
    blob = b"\x1f".join(parts)
    return sha256_hex(blob)
