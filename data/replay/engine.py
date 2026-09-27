"""Offline longitudinal replay engine with controllable rates (Fig. 6a)."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterator, List, Optional

from data.adapters.event import Event
from data.replay.segmenter import SegmentBatch, SegmentPolicy, Segmenter


class ReplayMode(str, Enum):
    ORIGINAL_TIMING = "original_timing"
    ACCELERATED = "accelerated"
    TARGET_EVENTS_PER_SEC = "events_per_sec"
    TARGET_BYTES_PER_SEC = "bytes_per_sec"
    AS_FAST_AS_POSSIBLE = "asap"


@dataclass
class ReplayConfig:
    mode: ReplayMode = ReplayMode.AS_FAST_AS_POSSIBLE
    accelerate_factor: float = 1.0  # for ORIGINAL_TIMING / ACCELERATED
    target_events_per_sec: Optional[float] = None
    target_bytes_per_sec: Optional[float] = None
    segment_policy: SegmentPolicy = field(
        default_factory=lambda: SegmentPolicy(name="records_10", target_records=10)
    )


@dataclass
class ReplayStats:
    input_events: int = 0
    accepted_events: int = 0
    input_bytes: int = 0
    accepted_bytes: int = 0
    segments_created: int = 0
    queue_backlog: int = 0
    dropped_events: int = 0
    wall_time_sec: float = 0.0
    input_rate_eps: float = 0.0
    accepted_rate_eps: float = 0.0
    input_rate_bps: float = 0.0
    accepted_rate_bps: float = 0.0
    policy: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_events": self.input_events,
            "accepted_events": self.accepted_events,
            "input_bytes": self.input_bytes,
            "accepted_bytes": self.accepted_bytes,
            "segments_created": self.segments_created,
            "queue_backlog": self.queue_backlog,
            "dropped_events": self.dropped_events,
            "wall_time_sec": self.wall_time_sec,
            "input_rate_eps": self.input_rate_eps,
            "accepted_rate_eps": self.accepted_rate_eps,
            "input_rate_bps": self.input_rate_bps,
            "accepted_rate_bps": self.accepted_rate_bps,
            "segment_policy": self.policy,
        }


OnSegment = Callable[[SegmentBatch], None]


class OfflineReplayEngine:
    """Replay Event streams into segments under rate control.

    Dropped events should normally remain zero (research prototype default:
    unbounded queue; backlog is tracked but not dropped unless max_backlog set).
    """

    def __init__(self, config: ReplayConfig, max_backlog: Optional[int] = None) -> None:
        self.config = config
        self.max_backlog = max_backlog
        self.stats = ReplayStats(policy=config.segment_policy.to_dict())
        self._queue: List[Event] = []

    def run(
        self,
        events: Iterator[Event],
        on_segment: Optional[OnSegment] = None,
        *,
        sleep: bool = True,
    ) -> ReplayStats:
        t0 = time.perf_counter()
        segmenter = Segmenter(self.config.segment_policy)
        paced = self._pace(events, sleep=sleep)

        def queued() -> Iterator[Event]:
            for ev in paced:
                self.stats.input_events += 1
                self.stats.input_bytes += len(ev.payload)
                if self.max_backlog is not None and len(self._queue) >= self.max_backlog:
                    self.stats.dropped_events += 1
                    self.stats.queue_backlog = len(self._queue)
                    continue
                self._queue.append(ev)
                self.stats.queue_backlog = len(self._queue)
                self.stats.accepted_events += 1
                self.stats.accepted_bytes += len(ev.payload)
                yield self._queue.pop(0)
                self.stats.queue_backlog = len(self._queue)

        for batch in segmenter.segment(queued()):
            self.stats.segments_created += 1
            if on_segment is not None:
                on_segment(batch)

        elapsed = max(time.perf_counter() - t0, 1e-9)
        self.stats.wall_time_sec = elapsed
        self.stats.input_rate_eps = self.stats.input_events / elapsed
        self.stats.accepted_rate_eps = self.stats.accepted_events / elapsed
        self.stats.input_rate_bps = self.stats.input_bytes / elapsed
        self.stats.accepted_rate_bps = self.stats.accepted_bytes / elapsed
        return self.stats

    def _pace(self, events: Iterator[Event], *, sleep: bool) -> Iterator[Event]:
        mode = self.config.mode
        if mode == ReplayMode.AS_FAST_AS_POSSIBLE:
            yield from events
            return

        if mode in (ReplayMode.ORIGINAL_TIMING, ReplayMode.ACCELERATED):
            factor = max(self.config.accelerate_factor, 1e-9)
            if mode == ReplayMode.ACCELERATED:
                # accelerate_factor > 1 means faster than real time
                scale = 1.0 / factor
            else:
                scale = 1.0 / max(factor, 1e-9)
            t_data0: Optional[float] = None
            t_wall0 = time.perf_counter()
            for ev in events:
                if t_data0 is None:
                    t_data0 = ev.timestamp
                target = (ev.timestamp - t_data0) * scale
                delay = target - (time.perf_counter() - t_wall0)
                if sleep and delay > 0:
                    time.sleep(delay)
                yield ev
            return

        if mode == ReplayMode.TARGET_EVENTS_PER_SEC:
            rate = max(self.config.target_events_per_sec or 1.0, 1e-9)
            interval = 1.0 / rate
            next_t = time.perf_counter()
            for ev in events:
                now = time.perf_counter()
                if sleep and now < next_t:
                    time.sleep(next_t - now)
                next_t = max(next_t + interval, time.perf_counter())
                yield ev
            return

        if mode == ReplayMode.TARGET_BYTES_PER_SEC:
            rate = max(self.config.target_bytes_per_sec or 1.0, 1e-9)
            budget_t0 = time.perf_counter()
            sent = 0
            for ev in events:
                sent += len(ev.payload)
                elapsed = time.perf_counter() - budget_t0
                expected = sent / rate
                if sleep and expected > elapsed:
                    time.sleep(expected - elapsed)
                yield ev
            return

        yield from events
