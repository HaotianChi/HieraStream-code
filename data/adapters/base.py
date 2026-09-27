"""Dataset adapter protocol and shared helpers."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

from data.adapters.event import Event

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
DATASETS = DATA / "datasets"


class DatasetAdapter(ABC):
    name: str

    @abstractmethod
    def prepare(self, *, smoke: bool = False, download: bool = False) -> Dict[str, Any]:
        """Download/import as needed; write manifest; return meta dict."""

    @abstractmethod
    def iter_events(self, *, smoke: bool = False) -> Iterator[Event]:
        """Streaming iterator over prepared events."""

    def write_manifest(self, meta: Dict[str, Any]) -> Path:
        out = DATA / "manifests" / f"{self.name}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
        return out


def write_jsonl_event(path: Path, event: Event) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        row = {
            "user_id": event.user_id,
            "stream_id": event.stream_id,
            "timestamp": event.timestamp,
            "payload": event.payload.decode("utf-8", errors="replace"),
            "payload_type": event.payload_type,
        }
        f.write(json.dumps(row, sort_keys=True) + "\n")
