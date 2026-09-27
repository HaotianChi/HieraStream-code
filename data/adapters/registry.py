"""Dataset adapters — workload normalization only (no clinical ML).

Facade over per-dataset adapters + streaming Event iterators.
"""

from __future__ import annotations

from typing import Dict, Iterator, Optional

from data.adapters.event import Event
from data.adapters.hf_remote_monitoring import HFRemoteMonitoringAdapter
from data.adapters.hm3_synthetic import HM3SyntheticAdapter
from data.adapters.uci_heart_failure import UCIHeartFailureAdapter
from data.adapters.vitaldb import VitalDBAdapter

ADAPTERS = {
    "uci_heart_failure": UCIHeartFailureAdapter,
    "hf_remote_monitoring": HFRemoteMonitoringAdapter,
    "hm3_synthetic": HM3SyntheticAdapter,
    "vitaldb": VitalDBAdapter,
}


def prepare_dataset(name: str, smoke: bool = False, download: bool = False) -> int:
    if name == "all":
        rc = 0
        for n in ADAPTERS:
            rc |= prepare_dataset(n, smoke=smoke, download=download)
        return rc
    if name not in ADAPTERS:
        raise KeyError(f"unknown dataset: {name}")
    adapter = ADAPTERS[name]()
    meta = adapter.prepare(smoke=smoke, download=download)
    print(f"prepared {name}: {meta.get('kind')} records/source noted in manifests/{name}.json")
    return 0


def iter_workload(dataset: str, *, smoke: bool = True) -> Iterator[Event]:
    """Common replay interface yielding Event objects (streaming)."""
    if dataset not in ADAPTERS:
        raise KeyError(dataset)
    yield from ADAPTERS[dataset]().iter_events(smoke=smoke)


# Backward-compatible dict iterator used by older experiment runners
def iter_workload_dicts(dataset: str, *, smoke: bool = True) -> Iterator[Dict]:
    for ev in iter_workload(dataset, smoke=smoke):
        yield {
            "user_id": ev.user_id,
            "stream_id": ev.stream_id,
            "timestamp": ev.timestamp,
            "payload": ev.payload,
            "payload_type": ev.payload_type,
        }
