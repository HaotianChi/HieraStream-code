"""Content-addressed storage: Kubo IPFS or deterministic local fallback.

CID parameters (must match only-hash and add):
  - CID version: 1
  - multicodec: raw (0x55)
  - multihash: sha2-256 (0x12), digest length 32
  - multibase: base16 lowercase ('f' prefix) preferred; Kubo may return base32
  - chunking: raw-leaves / no wrap
  - no UnixFS wrapping when using raw codec

Predicted only_hash(bytes) MUST equal add(bytes) for identical bytes
when both use the same backend and CID options.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Dict, Optional


def cid_v1_raw_sha256(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    mh = bytes([0x12, 32]) + digest  # sha2-256
    cid = bytes([0x01, 0x55]) + mh  # version 1, raw
    return "f" + cid.hex()


@dataclass
class LocalContentAddressedStore:
    _store: Dict[str, bytes]

    def __init__(self) -> None:
        self._store = {}

    def only_hash(self, data: bytes) -> str:
        return cid_v1_raw_sha256(data)

    def add(self, data: bytes) -> str:
        cid = self.only_hash(data)
        self._store[cid] = data
        return cid

    def get(self, cid: str) -> bytes:
        if cid not in self._store:
            raise KeyError(cid)
        return self._store[cid]

    def has(self, cid: str) -> bool:
        return cid in self._store

    def verify_cid(self, cid: str, data: bytes) -> bool:
        return self.only_hash(data) == cid


def _multipart(data: bytes, filename: str = "blob") -> tuple[bytes, str]:
    boundary = "----HieraStreamBoundary"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode("utf-8") + data + f"\r\n--{boundary}--\r\n".encode("utf-8")
    return body, boundary


class IPFSClient:
    """Prefer Kubo HTTP API when use_local=False and daemon is reachable."""

    ADD_OPTS = "cid-version=1&raw-leaves=true&hash=sha2-256&pin=false"

    def __init__(self, api_url: Optional[str] = None, use_local: bool = True) -> None:
        self.api_url = (api_url or os.environ.get("HIERASTREAM_IPFS_API") or "http://127.0.0.1:5001").rstrip(
            "/"
        )
        self.local = LocalContentAddressedStore()
        # Formal / native runs: HIERASTREAM_IPFS_BACKEND=kubo forces real daemon when reachable.
        env_backend = (os.environ.get("HIERASTREAM_IPFS_BACKEND") or "").strip().lower()
        if env_backend in {"kubo", "ipfs", "daemon"}:
            use_local = False
        self.use_local = use_local
        self._kubo = False
        # Mirror of Kubo-published blobs for get() when daemon is source of truth
        self._kubo_cache: Dict[str, bytes] = {}
        if not use_local:
            self._try_kubo()
            if env_backend in {"kubo", "ipfs", "daemon"} and not self._kubo:
                raise RuntimeError(
                    f"HIERASTREAM_IPFS_BACKEND={env_backend} but Kubo unreachable at {self.api_url}"
                )

    @property
    def backend(self) -> str:
        if self._kubo:
            return "kubo"
        return "local"

    def _try_kubo(self) -> None:
        try:
            req = urllib.request.Request(self.api_url + "/api/v0/version", method="POST")
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status == 200:
                    self._kubo = True
        except Exception:
            self._kubo = False

    def _kubo_post_add(self, data: bytes, *, only_hash: bool) -> str:
        import time as _time

        body, boundary = _multipart(data)
        q = self.ADD_OPTS
        if only_hash:
            q = "only-hash=true&" + q
        url = f"{self.api_url}/api/v0/add?{q}"
        last_err: Exception | None = None
        for attempt in range(5):
            req = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    payload = json.loads(resp.read().decode("utf-8"))
                cid = payload.get("Hash") or payload.get("Cid")
                if not cid:
                    raise RuntimeError(f"Kubo add returned no CID: {payload}")
                return str(cid)
            except urllib.error.HTTPError as e:
                last_err = e
                # Transient daemon errors after restart / load spikes
                if e.code in {500, 502, 503} and attempt < 4:
                    _time.sleep(0.25 * (2**attempt))
                    continue
                raise
            except (urllib.error.URLError, TimeoutError) as e:
                last_err = e
                if attempt < 4:
                    _time.sleep(0.25 * (2**attempt))
                    continue
                raise
        raise RuntimeError(f"Kubo add failed after retries: {last_err}")

    def only_hash(self, data: bytes) -> str:
        if self._kubo:
            return self._kubo_post_add(data, only_hash=True)
        return self.local.only_hash(data)

    def add(self, data: bytes) -> str:
        if self._kubo:
            cid = self._kubo_post_add(data, only_hash=False)
            self._kubo_cache[cid] = data
            # Also keep local mirror for offline verify helpers
            self.local._store[cid] = data
            return cid
        return self.local.add(data)

    def get(self, cid: str) -> bytes:
        if cid in self._kubo_cache:
            return self._kubo_cache[cid]
        if cid in self.local._store:
            return self.local.get(cid)
        if self._kubo:
            url = f"{self.api_url}/api/v0/cat?arg={cid}"
            req = urllib.request.Request(url, method="POST")
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            self._kubo_cache[cid] = data
            return data
        return self.local.get(cid)

    def has(self, cid: str) -> bool:
        if cid in self._kubo_cache or self.local.has(cid):
            return True
        if not self._kubo:
            return False
        try:
            self.get(cid)
            return True
        except Exception:
            return False

    def verify_cid(self, cid: str, data: bytes) -> bool:
        try:
            return self.only_hash(data) == cid
        except Exception:
            return False
