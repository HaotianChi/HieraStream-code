"""Persistent Fabric Gateway benchmark client (/ 20.3).

Talks to hs-gateway-bench over HTTP with a keep-alive connection pool
so high outstanding depth does not open one TCP socket per transaction.
"""

from __future__ import annotations

import http.client
import json
import os
import queue
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

_NETWORK = Path(__file__).resolve().parents[1] / "network"
_DEFAULT_BIN = _NETWORK / "bin" / "hs-gateway-bench"
_DEFAULT_CFG = _NETWORK / "gateway"


class _HTTPPool:
    """Thread-safe keep-alive HTTP/1.1 connection pool to a single host:port."""

    def __init__(self, host: str, port: int, size: int = 64, timeout: float = 120.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._q: queue.Queue[http.client.HTTPConnection] = queue.Queue(maxsize=size)
        for _ in range(size):
            self._q.put(self._new())

    def _new(self) -> http.client.HTTPConnection:
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def request(self, method: str, path: str, body: bytes, headers: Dict[str, str]) -> tuple[int, bytes]:
        try:
            conn = self._q.get(timeout=self.timeout)
        except queue.Empty as exc:
            raise TimeoutError("HTTP connection pool exhausted") from exc
        try:
            try:
                conn.request(method, path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
                status = resp.status
            except (http.client.HTTPException, OSError):
                try:
                    conn.close()
                except Exception:
                    pass
                conn = self._new()
                conn.request(method, path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
                status = resp.status
            return status, data
        finally:
            self._q.put(conn)

    def close(self) -> None:
        while True:
            try:
                c = self._q.get_nowait()
            except queue.Empty:
                break
            try:
                c.close()
            except Exception:
                pass


class PersistentGatewayClient:
    def __init__(self, base_url: str, pool_size: int = 128):
        self.base_url = base_url.rstrip("/")
        parsed = urllib.parse.urlparse(self.base_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 80
        timeout = float(os.environ.get("HIERASTREAM_FABRIC_TIMEOUT", "120"))
        pool_size = int(os.environ.get("HIERASTREAM_HTTP_POOL", str(pool_size)))
        self._pool = _HTTPPool(host, port, size=max(8, pool_size), timeout=timeout)
        self._lock = threading.Lock()

    def invoke(self, fn: str, args: List[str], identity: str = "aa", mode: str = "submit") -> Dict[str, Any]:
        body = json.dumps(
            {"identity": identity, "fn": fn, "args": [str(a) for a in args], "mode": mode}
        ).encode()
        headers = {"Content-Type": "application/json", "Connection": "keep-alive"}
        try:
            status, data = self._pool.request("POST", "/invoke", body, headers)
            if status >= 400:
                return {
                    "ok": False,
                    "status": "HTTP_ERROR",
                    "code": f"HTTP_{status}",
                    "error": data.decode(errors="replace")[:500],
                }
            return json.loads(data.decode())
        except TimeoutError as exc:
            return {"ok": False, "status": "TIMEOUT", "code": "POOL_TIMEOUT", "error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            msg = str(exc)
            st = "CLIENT_ERROR"
            code = "CLIENT_ERROR"
            low = msg.lower()
            if "timed out" in low or "timeout" in low or "deadline" in low:
                st, code = "TIMEOUT", "TIMEOUT"
            elif any(x in low for x in ("reset", "refused", "broken pipe", "assign requested")):
                st, code = "CONNECTION_ERROR", "CONNECTION_ERROR"
            return {"ok": False, "status": st, "code": code, "error": msg}

    def health(self) -> Dict[str, Any]:
        status, data = self._pool.request("GET", "/health", b"", {})
        if status >= 400:
            raise RuntimeError(f"health HTTP {status}")
        return json.loads(data.decode())

    def close(self) -> None:
        self._pool.close()


class PersistentGatewayServer:
    """Manage hs-gateway-bench subprocess lifecycle."""

    def __init__(
        self,
        config_dir: Optional[Path] = None,
        bin_path: Optional[Path] = None,
        addr: str = "127.0.0.1:0",
        http_pool_size: int = 128,
    ):
        self.config_dir = Path(config_dir or os.environ.get("HIERASTREAM_FABRIC_GATEWAY_DIR", str(_DEFAULT_CFG)))
        self.bin_path = Path(bin_path or os.environ.get("HIERASTREAM_FABRIC_BENCH", str(_DEFAULT_BIN)))
        self.addr_arg = addr
        self.http_pool_size = http_pool_size
        self.proc: Optional[subprocess.Popen] = None
        self.base_url: Optional[str] = None
        self._client: Optional[PersistentGatewayClient] = None

    def start(self) -> "PersistentGatewayClient":
        if not self.bin_path.exists():
            raise FileNotFoundError(f"missing bench binary: {self.bin_path}")
        self.proc = subprocess.Popen(
            [str(self.bin_path), "-config-dir", str(self.config_dir), "-addr", self.addr_arg],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        deadline = time.time() + 30
        assert self.proc.stdout is not None
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line and self.proc.poll() is not None:
                raise RuntimeError("hs-gateway-bench exited early")
            if line.startswith("READY "):
                listen = line.strip().split(" ", 1)[1]
                self.base_url = f"http://{listen}"
                break
        if not self.base_url:
            raise RuntimeError("timed out waiting for READY from hs-gateway-bench")
        pool = int(os.environ.get("HIERASTREAM_HTTP_POOL", str(self.http_pool_size)))
        client = PersistentGatewayClient(self.base_url, pool_size=pool)
        self._client = client
        for _ in range(20):
            try:
                client.health()
                return client
            except Exception:
                time.sleep(0.1)
        return client

    def stop(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None
