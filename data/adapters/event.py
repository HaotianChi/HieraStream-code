"""Common longitudinal event model (Section V) — no clinical ML."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterator, Optional, Union


Payload = Union[bytes, str, Dict[str, Any]]


@dataclass(frozen=True)
class Event:
    """Normalized workload event.

    ⟨user, stream, timestamp, payload⟩ plus explicit payload_type.
    """

    user_id: str
    stream_id: str
    timestamp: float  # seconds since epoch (or dataset-relative seconds)
    payload: bytes
    payload_type: str  # e.g. static_record | remote_vitals | lvad_synthetic | vitaldb_track

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "stream_id": self.stream_id,
            "timestamp": self.timestamp,
            "payload": self.payload.hex() if isinstance(self.payload, (bytes, bytearray)) else self.payload,
            "payload_type": self.payload_type,
            "payload_encoding": "hex",
        }

    @staticmethod
    def from_fields(
        user_id: str,
        stream_id: str,
        timestamp: float,
        payload: Payload,
        payload_type: str,
    ) -> "Event":
        if isinstance(payload, bytes):
            blob = payload
        elif isinstance(payload, str):
            blob = payload.encode("utf-8")
        else:
            import json

            blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return Event(
            user_id=str(user_id),
            stream_id=str(stream_id),
            timestamp=float(timestamp),
            payload=blob,
            payload_type=payload_type,
        )


def encode_kv_payload(**fields: Any) -> bytes:
    """Compact key=value;... payload for numeric telemetry."""
    parts = []
    for k in sorted(fields.keys()):
        v = fields[k]
        if v is None:
            continue
        parts.append(f"{k}={v}")
    return ";".join(parts).encode("utf-8")
