"""TimeCrypt official client driver (in-memory server).

Status: ADAPTED_OFFICIAL_ARTIFACT
- Maven build without aesni-native (Apple Silicon).
- protobuf protoc classifier osx-x86_64.
- maven-assembly-plugin 2.4.1 -> 3.7.1 (Maven 3.9).
- Positive stream ids only (upstream KeyUtil splits on '-' and breaks for negative ids).
- Payload bytes packed into native long DataPoints.
- PROTECT does not fetch the ciphertext. Byte accounting is one ACCOUNT
  per payload length, outside later timed samples.
- HEAC digest is measured from getStatisticalData (SUM/COUNT/SQUARE, LONG).
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional

BASELINE_STATUS = "ADAPTED_OFFICIAL_ARTIFACT"
SCHEME = "TimeCrypt"

_JAVA = "/Library/Java/JavaVirtualMachines/zulu-21.jdk/Contents/Home/bin/java"
_TC_ROOT = Path("/tmp/hs-baseline-timecrypt")
_CLIENT_JAR = _TC_ROOT / "timecrypt-client/target/timecrypt-client-jar-with-dependencies.jar"
_SERVER_JAR = _TC_ROOT / "timecrypt-server/target/timecrypt-server-jar-with-dependencies.jar"
_CLASSES = Path("/tmp/tc-bench")
_PORT = 15040


class TimeCryptLocalAdapter:
    def setup(self) -> None:
        if not _SERVER_JAR.is_file() or not _CLIENT_JAR.is_file():
            raise RuntimeError("TimeCrypt jars missing; build failed")
        env = os.environ.copy()
        env["TIMECRYPT_IN_MEMORY"] = "true"
        env["TIMECRYPT_PORT"] = str(_PORT)
        env["JAVA_HOME"] = str(Path(_JAVA).parents[1])
        self._server = subprocess.Popen(
            [_JAVA, "-Xmx2g", "-cp", str(_SERVER_JAR), "ch.ethz.dsg.timecrypt.Server"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1.5)
        cp = f"{_CLASSES}:{_CLIENT_JAR}"
        self._proc = subprocess.Popen(
            [
                _JAVA,
                "-Dlogback.configurationFile=/tmp/logback-quiet.xml",
                "-cp",
                cp,
                "ch.ethz.dsg.timecrypt.bench.LocalMicrobench",
                "127.0.0.1",
                str(_PORT),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self._cmd("SETUP")
        self._meta: Dict[str, Dict[str, Any]] = {}
        self._size_by_len: Dict[int, Dict[str, int]] = {}

    def _cmd(self, line: str) -> str:
        assert self._proc.stdin and self._proc.stdout
        self._proc.stdin.write(line + "\n")
        self._proc.stdin.flush()
        out = self._proc.stdout.readline().strip()
        if not out.startswith("OK"):
            raise RuntimeError(out or "empty TimeCrypt response")
        return out

    def protect_and_store(self, payload: bytes, stream_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        t0 = time.perf_counter()
        out = self._cmd("PROTECT " + payload.hex())
        wall = (time.perf_counter() - t0) * 1000.0
        _ok, ms, oid, _enc, _iv, _tag, _heac, _other, _ser = out.split()
        n = len(payload)
        if n not in self._size_by_len:
            acc = self._cmd("ACCOUNT")
            _a, enc, heac, other, serialized = acc.split()
            enc_i, heac_i, other_i, ser_i = map(int, (enc, heac, other, serialized))
            self._size_by_len[n] = {
                "encrypted_payload_bytes": enc_i,
                "crypto_metadata_bytes": 12 + 16 + heac_i,
                "other_serialized_metadata_bytes": other_i,
                "heac_bytes": heac_i,
                "total_bytes": ser_i,
            }
        sizes = self._size_by_len[n]
        self._meta[oid] = {
            "plaintext_bytes": n,
            "protected_bytes": sizes["encrypted_payload_bytes"],
            "metadata_bytes": sizes["crypto_metadata_bytes"] + sizes["other_serialized_metadata_bytes"],
            **sizes,
        }
        return {
            "object_id": oid,
            "protect_latency_ms": float(ms),
            "wall_ms": wall,
            **self._meta[oid],
            "success": True,
        }

    def retrieve_and_recover(self, object_id: str, access_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        out = self._cmd("RECOVER " + object_id)
        _ok, ms, hx = out.split()
        return {"payload": bytes.fromhex(hx), "recover_latency_ms": float(ms), "success": True}

    def protected_size(self, object_id: str) -> int:
        return int(self._meta[object_id]["protected_bytes"])

    def metadata_size(self, object_id: str):
        return self._meta[object_id]["metadata_bytes"]

    def teardown(self) -> None:
        try:
            if self._proc.stdin:
                self._proc.stdin.write("QUIT\n")
                self._proc.stdin.flush()
            self._proc.wait(timeout=5)
        except Exception:
            self._proc.kill()
        self._server.terminate()
