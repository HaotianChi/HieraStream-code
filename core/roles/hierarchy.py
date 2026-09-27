"""Fixed hierarchical role topology (Section III-A).

The DAG topology is FROZEN. Membership / reassignment may change;
structural reconstruction of the DAG is not implemented here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Set


@dataclass(frozen=True)
class RoleHierarchy:
    """Partial order over roles with cryptographic authorization paths A(r_i).

    Convention: ancestors dominate descendants (rx ⪰ ri means rx is an
    ancestor-or-equal of ri and can inherit ri's authorizations).
    """

    # role_id -> immediate parents (more privileged)
    parents: Dict[str, List[str]]
    # topological order from most privileged to least (stable)
    role_order: List[str]

    def roles(self) -> List[str]:
        return list(self.role_order)

    def ancestors_including_self(self, role: str) -> Set[str]:
        """Walk UP toward roots (more privileged)."""
        out: Set[str] = set()
        stack = [role]
        while stack:
            r = stack.pop()
            if r in out:
                continue
            out.add(r)
            stack.extend(self.parents.get(r, []))
        return out

    def descendants_including_self(self, role: str) -> Set[str]:
        """Walk DOWN toward leaves (less privileged)."""
        children: Dict[str, List[str]] = {r: [] for r in self.role_order}
        for child, pars in self.parents.items():
            for p in pars:
                children.setdefault(p, []).append(child)
        out: Set[str] = set()
        stack = [role]
        while stack:
            r = stack.pop()
            if r in out:
                continue
            out.add(r)
            stack.extend(children.get(r, []))
        return out

    def dominates(self, rx: str, ri: str) -> bool:
        """True iff rx ⪰ ri (rx is ancestor-or-equal of ri).

        rx ⪰ ri ⇔ ri ∈ descendants_including_self(rx)
               ⇔ rx ∈ ancestors_including_self(ri).
        """
        return rx in self.ancestors_including_self(ri)

    def is_authorized_ancestor(self, assigned: str, target: str) -> bool:
        """assigned ⪰ target."""
        return self.dominates(assigned, target)

    def auth_path(self, role: str) -> List[str]:
        """A(r_i): cryptographic authorization path — Eq.(5) nesting.

        Defined so that rx ⪰ ri ⇒ A(ri) ⊆ A(rx).
        Instantiation: A(ri) = descendants(ri) ∪ {ri} (roles covered by ri).
        Then s_i = Σ_{rk ∈ A(ri)} h_k aggregates covered role scalars.
        """
        covered = self.descendants_including_self(role)
        return [r for r in self.role_order if r in covered]

    def auth_paths(self) -> Dict[str, List[str]]:
        return {r: self.auth_path(r) for r in self.role_order}

    def H(self, target: str) -> List[str]:
        """H(ri) = ∪_{rx ⪰ ri} (A(rx) \\ A(ri))  — Eq.(18)."""
        A_ri = set(self.auth_path(target))
        extra: Set[str] = set()
        for rx in self.role_order:
            if self.is_authorized_ancestor(rx, target):
                A_rx = set(self.auth_path(rx))
                extra |= A_rx - A_ri
        return [r for r in self.role_order if r in extra]

    def Gamma(self, assigned: str, target: str) -> List[str]:
        """Γ(rx, ri) = A(rx) \\ A(ri)  — Eq.(29)."""
        if not self.is_authorized_ancestor(assigned, target):
            raise PermissionError(f"role {assigned} does not dominate target {target}")
        A_rx = set(self.auth_path(assigned))
        A_ri = set(self.auth_path(target))
        return [r for r in self.role_order if r in (A_rx - A_ri)]


# Default fixed healthcare DAG used by demos / smoke tests.
# ChiefMedicalOfficer ⪰ AttendingPhysician ⪰ Resident
# ChiefMedicalOfficer ⪰ NurseManager ⪰ Nurse
DEFAULT_HEALTHCARE_HIERARCHY = RoleHierarchy(
    parents={
        "ChiefMedicalOfficer": [],
        "AttendingPhysician": ["ChiefMedicalOfficer"],
        "Resident": ["AttendingPhysician"],
        "NurseManager": ["ChiefMedicalOfficer"],
        "Nurse": ["NurseManager"],
    },
    role_order=[
        "ChiefMedicalOfficer",
        "AttendingPhysician",
        "Resident",
        "NurseManager",
        "Nurse",
    ],
)


def validate_dominates_fix(h: RoleHierarchy) -> None:
    """Sanity: A(ri) ⊆ A(rx) whenever rx ⪰ ri."""
    for ri in h.role_order:
        for rx in h.role_order:
            if h.is_authorized_ancestor(rx, ri):
                assert set(h.auth_path(ri)).issubset(set(h.auth_path(rx)))
