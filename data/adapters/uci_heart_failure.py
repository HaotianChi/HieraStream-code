"""UCI Heart Failure clinical records — static one-segment compatibility workload.

Source: https://doi.org/10.24432/C5Z89R (299 records in the public UCI set).
No ML / diagnosis — records are treated as opaque payloads.
"""

from __future__ import annotations

import csv
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from data.adapters.base import DATASETS, DatasetAdapter
from data.adapters.event import Event, encode_kv_payload

UCI_URL = (
    "https://archive.ics.uci.edu/ml/machine-learning-databases/"
    "00519/heart_failure_clinical_records_dataset.csv"
)
EXPECTED_FULL_RECORDS = 299
# Accept small header/row variance; substantially fewer ⇒ incomplete.
MIN_ACCEPTABLE_RECORDS = 290


class UCIHeartFailureAdapter(DatasetAdapter):
    name = "uci_heart_failure"

    def __init__(self) -> None:
        self.root = DATASETS / self.name
        self.raw = self.root / "raw"
        self.samples = self.root / "samples"
        self.normalized = self.root / "normalized"

    def prepare(self, *, smoke: bool = False, download: bool = False) -> Dict[str, Any]:
        self.samples.mkdir(parents=True, exist_ok=True)
        self.raw.mkdir(parents=True, exist_ok=True)
        smoke_path = self.samples / "fixture.csv"
        if not smoke_path.exists():
            smoke_path.write_text(
                "age,anaemia,creatinine_phosphokinase,diabetes,ejection_fraction,"
                "high_blood_pressure,platelets,serum_creatinine,serum_sodium,sex,smoking,time,DEATH_EVENT\n"
                "55,0,200,0,30,1,200000,1.1,137,1,0,10,0\n"
                "62,1,180,1,40,0,180000,0.9,140,0,1,20,0\n",
                encoding="utf-8",
            )

        source = "smoke"
        n_records = 2
        fields: List[str] = []
        integrity = "not_checked"
        raw_csv = self.raw / "heart_failure_clinical_records_dataset.csv"

        # Non-smoke: stage the public full CSV when available.
        if not smoke and (download or not raw_csv.exists()):
            try:
                self._download(raw_csv)
                source = "uci_download"
            except Exception as exc:  # noqa: BLE001
                source = f"download_failed:{exc}"
                integrity = "EXTERNAL_DATA_UNAVAILABLE"

        if raw_csv.exists() and not smoke:
            rows = list(self._iter_csv(raw_csv))
            n_records = len(rows)
            fields = list(rows[0].keys()) if rows else []
            if source.startswith("download_failed"):
                pass
            else:
                source = "uci_download"
            if n_records >= MIN_ACCEPTABLE_RECORDS:
                integrity = "PASS"
            elif n_records == EXPECTED_FULL_RECORDS:
                integrity = "PASS"
            else:
                integrity = "INCOMPLETE"
            out = self.normalized / "events.jsonl"
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("w", encoding="utf-8") as f:
                for i, row in enumerate(rows):
                    ev = self._row_to_event(i, row)
                    f.write(
                        f'{{"user_id":"{ev.user_id}","stream_id":"{ev.stream_id}",'
                        f'"timestamp":{ev.timestamp},"payload":"{ev.payload.decode()}","payload_type":"{ev.payload_type}"}}\n'
                    )
        else:
            rows = list(self._iter_csv(smoke_path))
            n_records = len(rows)
            fields = list(rows[0].keys()) if rows else []
            if not smoke:
                integrity = (
                    integrity if integrity == "EXTERNAL_DATA_UNAVAILABLE" else "SMOKE_SUBSET"
                )

        meta = {
            "dataset": self.name,
            "kind": "static_ehr",
            "workload": "conventional_static_one_segment",
            "source": source,
            "citation": "https://doi.org/10.24432/C5Z89R",
            "records": n_records,
            "expected_full_uci_records": EXPECTED_FULL_RECORDS,
            "min_acceptable_records": MIN_ACCEPTABLE_RECORDS,
            "integrity_check": integrity,
            "fields": fields,
            "note": "Static-record / one-segment compatibility case (not clinical evaluation).",
        }
        self.write_manifest(meta)
        if not smoke and integrity not in {"PASS"}:
            raise RuntimeError(
                f"UCI Heart Failure prepare incomplete: records={n_records} "
                f"expected={EXPECTED_FULL_RECORDS} integrity={integrity} source={source}"
            )
        return meta

    def iter_events(self, *, smoke: bool = False) -> Iterator[Event]:
        raw_csv = self.raw / "heart_failure_clinical_records_dataset.csv"
        path = self.samples / "fixture.csv" if smoke or not raw_csv.exists() else raw_csv
        for i, row in enumerate(self._iter_csv(path)):
            yield self._row_to_event(i, row)

    def _row_to_event(self, idx: int, row: Dict[str, str]) -> Event:
        # Prefer clinical field names when present; else smoke payload column
        if "payload" in row and "age" not in row:
            return Event.from_fields(
                user_id=row.get("user_id", f"uci-{idx+1}"),
                stream_id=row.get("stream_id", "static"),
                timestamp=float(row.get("timestamp", 0)),
                payload=row["payload"],
                payload_type="static_record",
            )
        fields = {
            k: row[k]
            for k in (
                "age",
                "ejection_fraction",
                "platelets",
                "serum_creatinine",
                "serum_sodium",
                "time",
            )
            if k in row
        }
        return Event.from_fields(
            user_id=f"uci-{idx+1}",
            stream_id="static",
            timestamp=float(row.get("time", idx)),
            payload=encode_kv_payload(**fields) if fields else encode_kv_payload(row=str(row)),
            payload_type="static_record",
        )

    def _download(self, dest: Path) -> None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(UCI_URL, timeout=120) as resp:
            data = resp.read()
        dest.write_bytes(data)

    @staticmethod
    def _iter_csv(path: Path) -> Iterator[Dict[str, str]]:
        with path.open(newline="", encoding="utf-8") as f:
            yield from csv.DictReader(f)
