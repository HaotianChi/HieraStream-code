"""Droplet local data-path adapter.

Status: ADAPTED_OFFICIAL_ARTIFACT

Uses official `create_cloud_chunk` / `get_chunk_data_from_cloud_chunk`
(AES-GCM + zlib + ECDSA) from droplet-engine chunkdata.py after the
Python 3 compatibility layer in `upstream/chunkdata_compat.py`.

Storage is an in-process key-value map standing in for LevelDB
(`TalosLevelDBStorage` put/get of encoded chunk bytes). No AWS, no
Bitcoin virtualchain. Authorization confirmation is NOT included.
"""

from __future__ import annotations

import struct
import sys
import time
from pathlib import Path
from typing import Any, Dict

_UP = Path(__file__).resolve().parent / "upstream"
if str(_UP) not in sys.path:
    sys.path.insert(0, str(_UP))

import chunkdata_compat as droplet  # noqa: E402
from cryptography.hazmat.backends import default_backend  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

BASELINE_STATUS = "ADAPTED_OFFICIAL_ARTIFACT"
SCHEME = "Droplet"


def _payload_to_ints(payload: bytes) -> list:
    pad = (4 - (len(payload) % 4)) % 4
    blob = payload + b"\x00" * pad
    n = len(blob) // 4
    return list(struct.unpack("<" + "I" * n, blob))


def _ints_to_payload(values: list, nbytes: int) -> bytes:
    blob = struct.pack("<" + "I" * len(values), *[int(v) for v in values])
    return blob[:nbytes]


class DropletLocalAdapter:
    def setup(self) -> None:
        self._sk = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self._key = b"D" * 32  # 32-byte AES-GCM key (official API)
        self._ident = droplet.DataStreamIdentifier(
            owner="droplet-owner",
            streamid=1,
            nonce=b"local-nonce-16b!",
            txid_create_policy="ab" * 32,
        )
        self._store: Dict[str, bytes] = {}
        self._meta: Dict[str, Dict[str, Any]] = {}
        self._n = 0

    def protect_and_store(self, payload: bytes, stream_context: Dict[str, Any] | None = None) -> Dict[str, Any]:
        t0 = time.perf_counter()
        meta = struct.pack("<I", len(payload))
        entry = droplet.MultiIntegerEntry(self._n, meta, _payload_to_ints(payload))
        chunk = droplet.ChunkData([entry], max_size=1)
        cloud = droplet.create_cloud_chunk(
            self._ident,
            self._n,
            self._sk,
            0,
            self._key,
            chunk,
            use_compression=True,
        )
        encoded = cloud.encode()
        enc_ct = len(cloud.encrypted_data) - 12
        crypto_meta = 12 + 16 + len(cloud.signature)
        other = len(encoded) - enc_ct - crypto_meta
        post_zlib = len(droplet.compress_data(chunk.encode()))
        oid = f"d-{self._n}"
        self._store[oid] = encoded
        self._meta[oid] = {
            "plaintext_bytes": len(payload),
            "protected_bytes": enc_ct,
            "encrypted_payload_bytes": enc_ct,
            "crypto_metadata_bytes": crypto_meta,
            "other_serialized_metadata_bytes": other,
            "metadata_bytes": crypto_meta + other,
            "total_bytes": len(encoded),
            "post_zlib_bytes": post_zlib,
        }
        self._n += 1
        ms = (time.perf_counter() - t0) * 1000.0
        return {"object_id": oid, "protect_latency_ms": ms, **self._meta[oid], "success": True}

    def retrieve_and_recover(self, object_id: str, access_context: Dict[str, Any] | None = None) -> Dict[str, Any]:
        t0 = time.perf_counter()
        raw = self._store[object_id]
        cloud = droplet.CloudChunk.decode(raw)
        plain_chunk = droplet.get_chunk_data_from_cloud_chunk(cloud, self._key, True)
        entry = plain_chunk.entries[0]
        nbytes = struct.unpack("<I", entry.metadata)[0]
        payload = _ints_to_payload(list(entry.values), nbytes)
        ms = (time.perf_counter() - t0) * 1000.0
        return {"payload": payload, "recover_latency_ms": ms, "success": True}

    def protected_size(self, object_id: str) -> int:
        return int(self._meta[object_id]["protected_bytes"])

    def metadata_size(self, object_id: str) -> int:
        return int(self._meta[object_id]["metadata_bytes"])

    def teardown(self) -> None:
        self._store.clear()
