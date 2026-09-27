"""Fixed role hierarchy topology + authorization paths (Section III-A)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set


@dataclass(frozen=True)
class RoleHierarchy:
    """Fixed DAG. Membership may change; topology may not.

    A(r_i) instantiated as descendants∪{self} so that
    rx ⪰ ri ⇒ A(ri) ⊆ A(rx) (Eq. 5 nesting).
    """

    parents: Dict[str, List[str]]
    role_order: List[str]

    def roles(self) -> List[str]:
        return list(self.role_order)

    def ancestors_including_self(self, role: str) -> Set[str]:
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
        """rx ⪰ ri."""
        return rx in self.ancestors_including_self(ri)

    def auth_path(self, role: str) -> List[str]:
        covered = self.descendants_including_self(role)
        return [r for r in self.role_order if r in covered]

    def auth_paths(self) -> Dict[str, List[str]]:
        return {r: self.auth_path(r) for r in self.role_order}

    def H(self, target: str) -> List[str]:
        """H(ri) = ∪_{rx ⪰ ri} (A(rx) \\ A(ri)) — Eq.(18)."""
        A_ri = set(self.auth_path(target))
        extra: Set[str] = set()
        for rx in self.role_order:
            if self.dominates(rx, target):
                extra |= set(self.auth_path(rx)) - A_ri
        return [r for r in self.role_order if r in extra]

    def Gamma(self, assigned: str, target: str) -> List[str]:
        """Γ(rx, ri) = A(rx) \\ A(ri) — Eq.(29)."""
        if not self.dominates(assigned, target):
            raise PermissionError(f"{assigned} does not dominate {target}")
        diff = set(self.auth_path(assigned)) - set(self.auth_path(target))
        return [r for r in self.role_order if r in diff]

    def validate_nesting(self) -> None:
        for ri in self.role_order:
            for rx in self.role_order:
                if self.dominates(rx, ri):
                    assert set(self.auth_path(ri)).issubset(set(self.auth_path(rx)))


HEALTHCARE_FIXTURE = RoleHierarchy(
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


def linear_hierarchy(names: List[str]) -> RoleHierarchy:
    """Deterministic chain: names[0] ⪰ names[1] ⪰ ... ⪰ names[-1]."""
    parents: Dict[str, List[str]] = {names[0]: []}
    for i in range(1, len(names)):
        parents[names[i]] = [names[i - 1]]
    return RoleHierarchy(parents=parents, role_order=list(names))
