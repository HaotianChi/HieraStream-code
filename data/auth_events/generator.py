"""Synthetic authorization-event generator — independent of clinical content.

Events: policy_update | attribute_revocation | role_reassignment
(promotion/demotion = membership changes).

Deterministic under fixed seeds; supports rate control and scripted sequences.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Iterator, List, Optional, Sequence


class AuthEventKind(str, Enum):
    POLICY_UPDATE = "policy_update"
    ATTRIBUTE_REVOCATION = "attribute_revocation"
    ROLE_REASSIGNMENT = "role_reassignment"


@dataclass(frozen=True)
class AuthEvent:
    kind: AuthEventKind
    timestamp: float
    owner_id: str
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "timestamp": self.timestamp,
            "owner_id": self.owner_id,
            "details": self.details,
        }


@dataclass
class AuthEventGenerator:
    """Deterministic authorization trace generator."""

    seed: int = 2026
    owner_id: str = "owner-1"
    users: List[str] = field(default_factory=lambda: ["alice", "bob", "carol"])
    attributes: List[str] = field(
        default_factory=lambda: ["doctor", "cardiology", "nurse", "emergency"]
    )
    roles: List[str] = field(
        default_factory=lambda: [
            "ChiefMedicalOfficer",
            "AttendingPhysician",
            "Resident",
            "NurseManager",
            "Nurse",
        ]
    )

    def _rng(self, counter: int) -> int:
        h = hashlib.sha256(f"{self.seed}:{counter}".encode("utf-8")).digest()
        return int.from_bytes(h[:8], "big")

    def scripted(self, sequence: Sequence[Dict[str, Any]]) -> List[AuthEvent]:
        """Explicit scripted event sequence (timestamps absolute)."""
        out: List[AuthEvent] = []
        for item in sequence:
            out.append(
                AuthEvent(
                    kind=AuthEventKind(item["kind"]),
                    timestamp=float(item["timestamp"]),
                    owner_id=str(item.get("owner_id", self.owner_id)),
                    details=dict(item.get("details", {})),
                )
            )
        return out

    def generate_rate_controlled(
        self,
        *,
        duration_sec: float,
        updates_per_sec: float,
        start_time: float = 0.0,
    ) -> Iterator[AuthEvent]:
        """Emit authorization updates at a controlled average rate."""
        if updates_per_sec <= 0:
            return
        interval = 1.0 / updates_per_sec
        n = max(1, int(duration_sec * updates_per_sec))
        t = start_time
        for i in range(n):
            yield self._synthetic_at(i, t)
            t += interval

    def generate_count(self, n: int, *, start_time: float = 0.0, dt: float = 1.0) -> List[AuthEvent]:
        return [self._synthetic_at(i, start_time + i * dt) for i in range(n)]

    def _synthetic_at(self, i: int, t: float) -> AuthEvent:
        r = self._rng(i)
        kind_idx = r % 3
        if kind_idx == 0:
            return AuthEvent(
                kind=AuthEventKind.POLICY_UPDATE,
                timestamp=t,
                owner_id=self.owner_id,
                details={
                    "policy_expr": {
                        "kind": "internal",
                        "threshold": 2,
                        "children": [
                            {"kind": "leaf", "attr": self.attributes[r % len(self.attributes)]},
                            {
                                "kind": "leaf",
                                "attr": self.attributes[(r >> 3) % len(self.attributes)],
                            },
                        ],
                    }
                },
            )
        if kind_idx == 1:
            attr = self.attributes[r % len(self.attributes)]
            revoked = [self.users[r % len(self.users)]]
            return AuthEvent(
                kind=AuthEventKind.ATTRIBUTE_REVOCATION,
                timestamp=t,
                owner_id=self.owner_id,
                details={"attribute": attr, "revoked_users": revoked},
            )
        # role reassignment / promotion / demotion as membership change
        user = self.users[r % len(self.users)]
        role = self.roles[(r >> 2) % len(self.roles)]
        return AuthEvent(
            kind=AuthEventKind.ROLE_REASSIGNMENT,
            timestamp=t,
            owner_id=self.owner_id,
            details={
                "membership": {user: [role]},
                "change": "promotion" if (r & 1) == 0 else "demotion",
            },
        )
