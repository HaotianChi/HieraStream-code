"""HF remote monitoring adapter (Zenodo DOI:10.5281/zenodo.6951625).

Public package files used by this adapter:
  - bank.csv
  - non_bank.csv

Place downloads under ``data/datasets/hf_remote_monitoring/raw/``.
"""

from __future__ import annotations

import csv
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator

from data.adapters.base import DATASETS, DatasetAdapter
from data.adapters.event import Event, encode_kv_payload

ZENODO_FILES = {
    "bank.csv": "https://zenodo.org/api/records/6951625/files/bank.csv/content",
    "non_bank.csv": "https://zenodo.org/api/records/6951625/files/non_bank.csv/content",
}


class HFRemoteMonitoringAdapter(DatasetAdapter):
    name = "hf_remote_monitoring"

    def __init__(self) -> None:
        self.root = DATASETS / self.name
        self.raw = self.root / "raw"
        self.samples = self.root / "samples"
        self.normalized = self.root / "normalized"

    def prepare(self, *, smoke: bool = False, download: bool = False) -> Dict[str, Any]:
        self.samples.mkdir(parents=True, exist_ok=True)
        self.raw.mkdir(parents=True, exist_ok=True)
        smoke_path = self.samples / "fixture.jsonl"
        if not smoke_path.exists():
            with smoke_path.open("w", encoding="utf-8") as f:
                for i in range(5):
                    f.write(
                        json.dumps(
                            {
                                "user_id": "hf-01",
                                "stream_id": "remote",
                                "timestamp": float(i * 86400),
                                "payload": f"weight={80 + i * 0.01}",
                                "payload_type": "remote_vitals",
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )

        if download and not smoke:
            for name, url in ZENODO_FILES.items():
                dest = self.raw / name
                if not dest.exists():
                    with urllib.request.urlopen(url, timeout=120) as resp:
                        dest.write_bytes(resp.read())

        if (self.raw / "bank.csv").exists() and not smoke:
            out = self.normalized / "events.jsonl"
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("w", encoding="utf-8") as f:
                for ev in self._iter_from_raw():
                    f.write(
                        json.dumps(
                            {
                                "user_id": ev.user_id,
                                "stream_id": ev.stream_id,
                                "timestamp": ev.timestamp,
                                "payload": ev.payload.decode("utf-8"),
                                "payload_type": ev.payload_type,
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )

        meta = {
            "dataset": self.name,
            "kind": "longitudinal_low_rate",
            "citation": "https://doi.org/10.5281/zenodo.6951625",
            "fixture_records": sum(1 for _ in smoke_path.open(encoding="utf-8")),
        }
        self.write_manifest(meta)
        return meta

    def iter_events(self, *, smoke: bool = False) -> Iterator[Event]:
        if smoke or not (self.raw / "bank.csv").exists():
            path = self.samples / "fixture.jsonl"
            with path.open(encoding="utf-8") as f:
                for line in f:
                    obj = json.loads(line)
                    yield Event.from_fields(
                        obj["user_id"],
                        obj["stream_id"],
                        float(obj["timestamp"]),
                        obj["payload"],
                        obj.get("payload_type", "remote_vitals"),
                    )
            return
        yield from self._iter_from_raw()

    def _iter_from_raw(self) -> Iterator[Event]:
        for fname, stream in (("bank.csv", "remote_bank"), ("non_bank.csv", "remote_non_bank")):
            path = self.raw / fname
            if not path.exists():
                continue
            with path.open(newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    ts = datetime.strptime(row["dates"], "%Y-%m-%d").timestamp()
                    yield Event.from_fields(
                        user_id=f"hf-{row['ID']}",
                        stream_id=stream,
                        timestamp=ts,
                        payload=encode_kv_payload(
                            weight=row.get("WEIGHT"),
                            subj_int=row.get("subj_int"),
                            resid=row.get("resid"),
                        ),
                        payload_type="remote_vitals",
                    )
