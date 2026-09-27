"""Historical authorization objects for prospective revocation.

Do not overwrite historical:
  - t_a values
  - attribute key versions
  - xi values
  - role-user key versions
  - policy definitions
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

from core.authorization.states import (
    AttributePublicState,
    HistoricalAttrSecrets,
    HistoricalRoleSecrets,
    PolicyState,
    RoleState,
)
from core.authorization.snapshot import AuthorizationSnapshot


@dataclass
class HistoricalAuthorizationArchive:
    """Immutable archive keyed by authorization version ν."""

    owner_id: str
    policies: Dict[int, PolicyState] = field(default_factory=dict)
    attrs: Dict[int, AttributePublicState] = field(default_factory=dict)
    roles: Dict[int, RoleState] = field(default_factory=dict)
    snapshots: Dict[int, AuthorizationSnapshot] = field(default_factory=dict)
    attr_secrets: HistoricalAttrSecrets = field(default_factory=HistoricalAttrSecrets)
    role_secrets: HistoricalRoleSecrets = field(default_factory=HistoricalRoleSecrets)

    def store_policy(self, state: PolicyState) -> None:
        if state.version in self.policies:
            if self.policies[state.version].state_id() != state.state_id():
                raise ValueError(f"policy version {state.version} already archived with different content")
            return
        self.policies[state.version] = state

    def store_attr(self, state: AttributePublicState) -> None:
        if state.version in self.attrs:
            if self.attrs[state.version].state_id() != state.state_id():
                raise ValueError(f"attr version {state.version} already archived with different content")
            return
        self.attrs[state.version] = state

    def store_role(self, state: RoleState) -> None:
        if state.version in self.roles:
            if self.roles[state.version].state_id() != state.state_id():
                raise ValueError(f"role version {state.version} already archived with different content")
            return
        self.roles[state.version] = state

    def store_snapshot(self, snap: AuthorizationSnapshot) -> None:
        if snap.owner_id != self.owner_id:
            raise ValueError("owner mismatch")
        existing = self.snapshots.get(snap.version)
        if existing is not None and not existing.matches(snap):
            raise ValueError(f"snapshot version {snap.version} already archived differently")
        self.snapshots[snap.version] = snap

    def policy_at(self, version: int) -> Optional[PolicyState]:
        return self.policies.get(version)

    def attr_at(self, version: int) -> Optional[AttributePublicState]:
        return self.attrs.get(version)

    def role_at(self, version: int) -> Optional[RoleState]:
        return self.roles.get(version)

    def snapshot_at(self, version: int) -> Optional[AuthorizationSnapshot]:
        return self.snapshots.get(version)
