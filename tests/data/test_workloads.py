"""Dataset adapters, segmenter, replay, and auth-event tests."""

from __future__ import annotations

import json
from pathlib import Path

from data.adapters.event import Event
from data.adapters.registry import iter_workload, prepare_dataset
from data.auth_events import AuthEventGenerator, AuthEventKind
from data.replay import (
    OfflineReplayEngine,
    PRESETS,
    ReplayConfig,
    ReplayMode,
    SegmentPolicy,
    Segmenter,
)

ROOT = Path(__file__).resolve().parents[2]


def test_event_model_and_streaming():
    prepare_dataset("all", smoke=True)
    for name in ["uci_heart_failure", "hf_remote_monitoring", "hm3_synthetic", "vitaldb"]:
        n = 0
        for ev in iter_workload(name, smoke=True):
            assert isinstance(ev, Event)
            assert ev.user_id and ev.stream_id and ev.payload_type
            assert isinstance(ev.payload, (bytes, bytearray))
            n += 1
            if n >= 3:
                break
        assert n >= 1


def test_uci_static_one_segment_policy():
    prepare_dataset("uci_heart_failure", smoke=True)
    events = list(iter_workload("uci_heart_failure", smoke=True))
    batches = list(Segmenter(PRESETS["records_1"]).segment(iter(events)))
    assert len(batches) == len(events)
    assert all(b.nrecords == 1 for b in batches)
    assert batches[0].policy.name == "records_1"


def test_hm3_marked_synthetic():
    prepare_dataset("hm3_synthetic", smoke=True)
    for ev in iter_workload("hm3_synthetic", smoke=True):
        assert ev.payload_type == "lvad_synthetic"
        break
    man = json.loads((ROOT / "data/manifests/hm3_synthetic.json").read_text())
    assert man.get("synthetic") is True


def test_vitaldb_subset_no_full_download():
    from data.adapters.vitaldb import VitalDBAdapter

    meta = VitalDBAdapter().prepare(smoke=True, download=False)
    assert "6388" in meta["case_subset"]["note"] or "not required" in meta["case_subset"]["note"]
    events = list(VitalDBAdapter().iter_events(smoke=True, resample_hz=10.0))
    assert len(events) >= 2


def test_segmenter_byte_and_time_policies():
    evs = [Event.from_fields("u", "s", float(i), b"x" * 50, "t") for i in range(20)]
    by_bytes = list(Segmenter(SegmentPolicy("b", target_bytes=120)).segment(iter(evs)))
    assert len(by_bytes) >= 1
    by_time = list(
        Segmenter(SegmentPolicy("t", time_window_sec=5.0)).segment(
            iter(Event.from_fields("u", "s", float(i), b"y", "t") for i in range(20))
        )
    )
    assert len(by_time) >= 2


def test_replay_engine_rates_and_zero_drops():
    events = (Event.from_fields("u", "s", float(i), b"abc", "t") for i in range(50))
    eng = OfflineReplayEngine(
        ReplayConfig(
            mode=ReplayMode.AS_FAST_AS_POSSIBLE,
            segment_policy=SegmentPolicy("r10", target_records=10),
        )
    )
    segments = []
    stats = eng.run(events, on_segment=segments.append, sleep=False)
    assert stats.dropped_events == 0
    assert stats.input_events == 50
    assert stats.accepted_events == 50
    assert stats.segments_created == 5
    assert stats.input_rate_eps > 0
    assert stats.to_dict()["segment_policy"]["name"] == "r10"


def test_replay_events_per_sec_mode():
    events = (Event.from_fields("u", "s", float(i), b"z", "t") for i in range(5))
    eng = OfflineReplayEngine(
        ReplayConfig(
            mode=ReplayMode.TARGET_EVENTS_PER_SEC,
            target_events_per_sec=1000.0,
            segment_policy=PRESETS["records_1"],
        )
    )
    stats = eng.run(events, sleep=False)
    assert stats.accepted_events == 5
    assert stats.dropped_events == 0


def test_auth_event_generator_deterministic_and_kinds():
    g1 = AuthEventGenerator(seed=2026)
    g2 = AuthEventGenerator(seed=2026)
    a = g1.generate_count(12)
    b = g2.generate_count(12)
    assert [x.to_dict() for x in a] == [x.to_dict() for x in b]
    kinds = {e.kind for e in a}
    assert AuthEventKind.POLICY_UPDATE in kinds
    assert AuthEventKind.ATTRIBUTE_REVOCATION in kinds
    assert AuthEventKind.ROLE_REASSIGNMENT in kinds
    scripted = g1.scripted(
        [
            {
                "kind": "role_reassignment",
                "timestamp": 1.0,
                "details": {"membership": {"alice": ["Nurse"]}, "change": "demotion"},
            }
        ]
    )
    assert scripted[0].kind == AuthEventKind.ROLE_REASSIGNMENT


def test_auth_rate_controlled_independent_of_clinical():
    gen = AuthEventGenerator(seed=7)
    events = list(gen.generate_rate_controlled(duration_sec=10.0, updates_per_sec=0.5))
    assert len(events) == 5
    assert all("payload" not in e.details for e in events)
