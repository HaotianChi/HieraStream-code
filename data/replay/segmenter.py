"""Configurable segmentation policies for longitudinal replay (Fig. 6b)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence

from data.adapters.event import Event


@dataclass(frozen=True)
class SegmentPolicy:
    """Explicit policy recorded in experiment configuration."""

    name: str
    target_bytes: Optional[int] = None
    target_records: Optional[int] = None
    time_window_sec: Optional[float] = None
    split_on_identity: bool = True  # False → allow multi-user static aggregate

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "SegmentPolicy":
        return SegmentPolicy(
            name=str(d.get("name", "custom")),
            target_bytes=d.get("target_bytes"),
            target_records=d.get("target_records"),
            time_window_sec=d.get("time_window_sec"),
            split_on_identity=bool(d.get("split_on_identity", True)),
        )


# Named presets used by experiments
PRESETS = {
    "bytes_256": SegmentPolicy(name="bytes_256", target_bytes=256),
    "bytes_1024": SegmentPolicy(name="bytes_1024", target_bytes=1024),
    "bytes_4096": SegmentPolicy(name="bytes_4096", target_bytes=4096),
    "records_1": SegmentPolicy(name="records_1", target_records=1),
    "records_10": SegmentPolicy(name="records_10", target_records=10),
    "records_100": SegmentPolicy(name="records_100", target_records=100),
    "time_60s": SegmentPolicy(name="time_60s", time_window_sec=60.0),
    "time_3600s": SegmentPolicy(name="time_3600s", time_window_sec=3600.0),
    "static_one_segment": SegmentPolicy(
        name="static_one_segment",
        target_records=10**9,
        split_on_identity=False,
    ),
}


@dataclass
class SegmentBatch:
    segment_index: int
    user_id: str
    stream_id: str
    t_start: float
    t_end: float
    events: List[Event]
    policy: SegmentPolicy

    @property
    def payload(self) -> bytes:
        # Concatenate event payloads with length prefixes for byte-accurate sizing
        parts: List[bytes] = []
        for ev in self.events:
            parts.append(len(ev.payload).to_bytes(4, "big") + ev.payload)
        return b"".join(parts)

    @property
    def nbytes(self) -> int:
        return len(self.payload)

    @property
    def nrecords(self) -> int:
        return len(self.events)


class Segmenter:
    """Stream events → SegmentBatch under an explicit policy."""

    def __init__(self, policy: SegmentPolicy) -> None:
        self.policy = policy

    def segment(self, events: Iterator[Event]) -> Iterator[SegmentBatch]:
        buf: List[Event] = []
        nbytes = 0
        seg_idx = 0
        window_start: Optional[float] = None

        def flush() -> Optional[SegmentBatch]:
            nonlocal buf, nbytes, seg_idx, window_start
            if not buf:
                return None
            batch = SegmentBatch(
                segment_index=seg_idx,
                user_id=buf[0].user_id,
                stream_id=buf[0].stream_id,
                t_start=buf[0].timestamp,
                t_end=buf[-1].timestamp,
                events=list(buf),
                policy=self.policy,
            )
            seg_idx += 1
            buf = []
            nbytes = 0
            window_start = None
            return batch

        for ev in events:
            # Flush on user/stream change to keep segments coherent
            if buf and (ev.user_id != buf[0].user_id or ev.stream_id != buf[0].stream_id):
                out = flush()
                if out:
                    yield out

            if window_start is None:
                window_start = ev.timestamp
            buf.append(ev)
            nbytes += 4 + len(ev.payload)

            should = False
            if self.policy.target_records is not None and len(buf) >= self.policy.target_records:
                should = True
            if self.policy.target_bytes is not None and nbytes >= self.policy.target_bytes:
                should = True
            if (
                self.policy.time_window_sec is not None
                and window_start is not None
                and (ev.timestamp - window_start) >= self.policy.time_window_sec
            ):
                should = True
            if should:
                out = flush()
                if out:
                    yield out

        out = flush()
        if out:
            yield out
