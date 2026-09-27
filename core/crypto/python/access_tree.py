"""Generic threshold access trees for CP-ABE (k-of-n)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AccessTree:
    kind: str  # "leaf" | "internal"
    attr: Optional[str] = None
    threshold: int = 1
    children: List["AccessTree"] = field(default_factory=list)
    index: int = 1  # child index under parent (1-based)

    def to_dict(self) -> Dict[str, Any]:
        if self.kind == "leaf":
            return {"kind": "leaf", "attr": self.attr}
        return {
            "kind": "internal",
            "threshold": self.threshold,
            "children": [c.to_dict() for c in self.children],
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "AccessTree":
        if d["kind"] == "leaf":
            return leaf(d["attr"])
        children = [AccessTree.from_dict(c) for c in d["children"]]
        # Restore 1-based child indices used by share assignment / Lagrange
        for i, child in enumerate(children):
            child.index = i + 1
        return AccessTree(
            kind="internal",
            threshold=int(d["threshold"]),
            children=children,
        )


def leaf(attr: str) -> AccessTree:
    return AccessTree(kind="leaf", attr=attr)


def gate(threshold: int, *children: AccessTree) -> AccessTree:
    if threshold < 1 or threshold > len(children):
        raise ValueError("invalid threshold")
    return AccessTree(kind="internal", threshold=threshold, children=list(children))


def AND(*children: AccessTree) -> AccessTree:
    return gate(len(children), *children)


def OR(*children: AccessTree) -> AccessTree:
    return gate(1, *children)
