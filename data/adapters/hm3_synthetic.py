"""HM3 / LVAD synthetic trace adapter (Zenodo 10.5281/zenodo.8307993).

The Zenodo package provides synthetic LVAD flow and power traces.
Events use payload_type=lvad_synthetic with synthetic=true metadata.
"""

from __future__ import annotations

import csv
import json
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List

from data.adapters.base import DATASETS, DatasetAdapter
from data.adapters.event import Event, encode_kv_payload

ZENODO_ZIP = "https://zenodo.org/api/records/8307993/files/data.zip/content"


class HM3SyntheticAdapter(DatasetAdapter):
    name = "hm3_synthetic"

    def __init__(self) -> None:
        self.root = DATASETS / self.name
        self.raw = self.root / "raw"
        self.samples = self.root / "samples"
        self.normalized = self.root / "normalized"
        self.extracted = self.raw / "extracted" / "data"

    def prepare(self, *, smoke: bool = False, download: bool = False) -> Dict[str, Any]:
        self.samples.mkdir(parents=True, exist_ok=True)
        self.raw.mkdir(parents=True, exist_ok=True)
        smoke_path = self.samples / "fixture.jsonl"
        if not smoke_path.exists():
            with smoke_path.open("w", encoding="utf-8") as f:
                for i in range(10):
                    f.write(
                        json.dumps(
                            {
                                "user_id": "hm3-synth-01",
                                "stream_id": "lvad",
                                "timestamp": float(i),
                                "payload": f"flow={4.0 + i * 0.01};power={5.0 + i * 0.02}",
                                "payload_type": "lvad_synthetic",
                                "synthetic": True,
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )

        if download and not smoke:
            zpath = self.raw / "data.zip"
            if not zpath.exists():
                with urllib.request.urlopen(ZENODO_ZIP, timeout=180) as resp:
                    zpath.write_bytes(resp.read())
            if not self.extracted.exists():
                with zipfile.ZipFile(zpath) as zf:
                    zf.extractall(self.raw / "extracted")

        file_stats = self._scan_extracted()
        if file_stats and not smoke:
            out = self.normalized / "events.jsonl"
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("w", encoding="utf-8") as f:
                for ev in self._iter_from_extracted(prefer_syn_only=True):
                    f.write(
                        json.dumps(
                            {
                                "user_id": ev.user_id,
                                "stream_id": ev.stream_id,
                                "timestamp": ev.timestamp,
                                "payload": ev.payload.decode("utf-8"),
                                "payload_type": ev.payload_type,
                                "synthetic": True,
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )

        meta = {
            "dataset": self.name,
            "kind": "lvad_synthetic",
            "citation": "https://doi.org/10.5281/zenodo.8307993",
            "note": (
                "Synthetic LVAD traces from the public Zenodo package "
                "(not raw clinical data from 120 patients)."
            ),
            "synthetic": True,
            "uses": ["pump_flow", "motor_power", "timestamps"],
            "files": file_stats,
            "smoke_records": sum(1 for _ in smoke_path.open(encoding="utf-8")),
        }
        self.write_manifest(meta)
        return meta

    def iter_events(self, *, smoke: bool = False) -> Iterator[Event]:
        if smoke or not self.extracted.exists():
            path = self.samples / "fixture.jsonl"
            with path.open(encoding="utf-8") as f:
                for line in f:
                    obj = json.loads(line)
                    yield Event.from_fields(
                        obj["user_id"],
                        obj["stream_id"],
                        float(obj["timestamp"]),
                        obj["payload"],
                        "lvad_synthetic",
                    )
            return
        yield from self._iter_from_extracted(prefer_syn_only=True)

    def _iter_from_extracted(self, *, prefer_syn_only: bool) -> Iterator[Event]:
        files = sorted(self.extracted.glob("*.csv"))
        for path in files:
            # Prefer explicitly synthetic files; still mark ALL as synthetic
            if prefer_syn_only and not path.name.startswith("syn_data_"):
                # Include example_stable_patient as synthetic longitudinal volume
                if path.name not in {"example_stable_patient.csv"}:
                    continue
            stream = "lvad_" + path.stem
            with path.open(newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                if "Flow" not in (reader.fieldnames or []) and "Motor_power" not in (
                    reader.fieldnames or []
                ):
                    continue
                for row in reader:
                    pid = row.get("ID") or "unknown"
                    dt = row.get("Datetime") or "1970-01-01"
                    try:
                        ts = datetime.strptime(dt[:10], "%Y-%m-%d").timestamp()
                    except ValueError:
                        ts = 0.0
                    yield Event.from_fields(
                        user_id=f"hm3-synth-{pid}",
                        stream_id=stream,
                        timestamp=ts,
                        payload=encode_kv_payload(
                            flow=row.get("Flow"),
                            power=row.get("Motor_power"),
                            norm_speed=row.get("norm_speed"),
                            stored_speed=row.get("Stored_speed"),
                            hct=row.get("HCT"),
                            synthetic=True,
                        ),
                        payload_type="lvad_synthetic",
                    )

    def _scan_extracted(self) -> Dict[str, Any]:
        if not self.extracted.exists():
            return {}
        out: Dict[str, Any] = {}
        for path in sorted(self.extracted.glob("*.csv")):
            with path.open(newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            subjects = sorted(
                {r["ID"] for r in rows if r.get("ID")},
                key=lambda x: int(x) if str(x).isdigit() else 0,
            )
            out[path.name] = {
                "rows": len(rows),
                "subjects": len(subjects),
                "fields": list(rows[0].keys()) if rows else [],
                "synthetic_filename": path.name.startswith("syn_data_")
                or "example" in path.name,
                "label": "SYNTHETIC/SIMULATED",
            }
        return out
