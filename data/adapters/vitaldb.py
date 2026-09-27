"""VitalDB adapter — configurable case subsets (no full-corpus requirement for smoke).

Supports:
  - case subset manifests
  - numeric track events
  - waveform-style dense samples (optional resampling)
  - smoke fixtures without downloading VitalDB

Full API download is optional via vitaldb Python package when available.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence

from data.adapters.base import DATASETS, DatasetAdapter
from data.adapters.event import Event, encode_kv_payload


class VitalDBAdapter(DatasetAdapter):
    name = "vitaldb"

    def __init__(self) -> None:
        self.root = DATASETS / self.name
        self.raw = self.root / "raw"
        self.samples = self.root / "samples"
        self.normalized = self.root / "normalized"
        self.subset_manifest = self.root / "case_subset.json"

    def prepare(
        self,
        *,
        smoke: bool = False,
        download: bool = False,
        case_ids: Optional[Sequence[int]] = None,
        tracks: Optional[Sequence[str]] = None,
        resample_hz: Optional[float] = None,
    ) -> Dict[str, Any]:
        self.samples.mkdir(parents=True, exist_ok=True)
        self.raw.mkdir(parents=True, exist_ok=True)
        smoke_path = self.samples / "fixture.jsonl"
        # Non-smoke local subset sized for longitudinal / segment-fill workloads
        # without requiring the full VitalDB download.
        n_records = 100 if smoke else 8000
        need_rewrite = True
        if smoke_path.exists():
            existing = sum(1 for _ in smoke_path.open(encoding="utf-8"))
            need_rewrite = existing < n_records
        if need_rewrite:
            with smoke_path.open("w", encoding="utf-8") as f:
                for i in range(n_records):
                    f.write(
                        json.dumps(
                            {
                                "user_id": "vital-case-1",
                                "stream_id": "art",
                                "timestamp": i / 100.0,
                                "payload": f"art={80 + (i % 20)};i={i}",
                                "payload_type": "vitaldb_track",
                                "track_kind": "numeric",
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )

        subset = {
            "case_ids": list(case_ids or [1]),
            "tracks": list(tracks or ["ART", "ECG_II", "PLETH"]),
            "resample_hz": resample_hz,
            "note": "Smoke/subset only — full VitalDB (6388 cases) not required for unit tests.",
        }
        self.subset_manifest.write_text(json.dumps(subset, indent=2, sort_keys=True), encoding="utf-8")

        downloaded_cases: List[int] = []
        if download and not smoke:
            downloaded_cases = self._try_download_subset(subset)

        meta = {
            "dataset": self.name,
            "kind": "high_rate_physio",
            "citation": "Lee et al., Scientific Data 2022 (VitalDB)",
            "case_subset": subset,
            "downloaded_cases": downloaded_cases,
            "smoke_records": sum(1 for _ in smoke_path.open(encoding="utf-8")),
            "supports": {
                "numeric_tracks": True,
                "waveform_tracks": True,
                "configurable_resampling": True,
            },
            "note": (
                "Local subset for longitudinal/granularity sweeps when the full "
                "VitalDB corpus is unavailable (not a 6388-case download)."
            ),
        }
        self.write_manifest(meta)
        return meta

    def iter_events(
        self,
        *,
        smoke: bool = False,
        resample_hz: Optional[float] = None,
    ) -> Iterator[Event]:
        # Prefer normalized subset if present
        norm = self.normalized / "events.jsonl"
        if not smoke and norm.exists():
            with norm.open(encoding="utf-8") as f:
                for line in f:
                    obj = json.loads(line)
                    yield Event.from_fields(
                        obj["user_id"],
                        obj["stream_id"],
                        float(obj["timestamp"]),
                        obj["payload"],
                        obj.get("payload_type", "vitaldb_track"),
                    )
            return

        path = self.samples / "fixture.jsonl"
        events = []
        with path.open(encoding="utf-8") as f:
            for line in f:
                obj = json.loads(line)
                events.append(
                    Event.from_fields(
                        obj["user_id"],
                        obj["stream_id"],
                        float(obj["timestamp"]),
                        obj["payload"],
                        "vitaldb_track",
                    )
                )
        if resample_hz and resample_hz > 0 and len(events) >= 2:
            # Simple uniform re-index in time for smoke waveform replay
            t0, t1 = events[0].timestamp, events[-1].timestamp
            n = max(2, int((t1 - t0) * resample_hz) + 1)
            for i in range(n):
                t = t0 + i / resample_hz
                # nearest neighbor
                src = min(events, key=lambda e: abs(e.timestamp - t))
                yield Event.from_fields(src.user_id, src.stream_id, t, src.payload, src.payload_type)
            return
        yield from events

    def _try_download_subset(self, subset: Dict[str, Any]) -> List[int]:
        """Optional VitalDB API pull for configured case ids."""
        try:
            import vitaldb  # type: ignore
        except Exception:
            return []
        out_path = self.normalized / "events.jsonl"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        got: List[int] = []
        with out_path.open("w", encoding="utf-8") as f:
            for cid in subset["case_ids"]:
                try:
                    vals = vitaldb.load_case(int(cid), subset["tracks"], 1 / float(subset.get("resample_hz") or 1))
                except Exception:
                    continue
                got.append(int(cid))
                # vals: ndarray [samples, tracks]
                for i, row in enumerate(vals):
                    payload = encode_kv_payload(
                        **{str(t): float(row[j]) if row[j] == row[j] else None for j, t in enumerate(subset["tracks"])}
                    )
                    ev = Event.from_fields(
                        user_id=f"vital-case-{cid}",
                        stream_id="multi",
                        timestamp=float(i) / float(subset.get("resample_hz") or 1),
                        payload=payload,
                        payload_type="vitaldb_track",
                    )
                    f.write(
                        json.dumps(
                            {
                                "user_id": ev.user_id,
                                "stream_id": ev.stream_id,
                                "timestamp": ev.timestamp,
                                "payload": ev.payload.decode("utf-8"),
                                "payload_type": ev.payload_type,
                                "track_kind": "numeric",
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )
        return got
