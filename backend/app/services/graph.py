"""Attack-path engine.

Builds a directed, weighted graph of AD principals and abusable relationships,
then answers "who can reach Tier-0?" with Dijkstra (cheapest / most likely
abuse chain) and BFS (shortest hop count).

Weights encode operational difficulty: a group membership is free, an ACL
abuse that requires tooling and a reset is expensive. Lower total cost =
more likely to be used by a real adversary = higher risk.
"""

from __future__ import annotations

import heapq
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from app.connectors.base import ADEdge, ADPrincipal, EdgeType

# Cost model (lower == easier for an attacker).
EDGE_COST: dict[EdgeType, float] = {
    EdgeType.MEMBER_OF: 0.5,
    EdgeType.ADMIN_TO: 1.0,
    EdgeType.SESSION: 1.5,
    EdgeType.HAS_DCSYNC: 1.0,
    EdgeType.GENERIC_ALL: 2.0,
    EdgeType.GENERIC_WRITE: 2.5,
    EdgeType.WRITE_DACL: 3.0,
    EdgeType.WRITE_OWNER: 3.0,
    EdgeType.ADD_MEMBER: 2.0,
    EdgeType.FORCE_CHANGE_PASSWORD: 2.5,
    EdgeType.ALLOWED_TO_DELEGATE: 3.5,
    EdgeType.GP_LINK: 3.0,
    EdgeType.CAN_RDP: 2.0,
}
DEFAULT_COST = 4.0

# Names that define Tier-0 (crown jewels) when no explicit targets are given.
TIER0_NAMES = {
    "domain admins",
    "enterprise admins",
    "administrators",
    "schema admins",
    "account operators",
    "backup operators",
    "domain controllers",
}


@dataclass(frozen=True, slots=True)
class PathStep:
    source_sid: str
    source_name: str
    target_sid: str
    target_name: str
    edge_type: EdgeType
    cost: float


@dataclass(frozen=True, slots=True)
class AttackPath:
    source_sid: str
    source_name: str
    target_sid: str
    target_name: str
    steps: tuple[PathStep, ...]
    total_cost: float

    @property
    def hops(self) -> int:
        return len(self.steps)

    @property
    def severity(self) -> str:
        if self.total_cost <= 2.0:
            return "critical"
        if self.total_cost <= 5.0:
            return "high"
        if self.total_cost <= 9.0:
            return "medium"
        return "low"


@dataclass(slots=True)
class AttackGraph:
    principals: dict[str, ADPrincipal] = field(default_factory=dict)
    adjacency: dict[str, list[ADEdge]] = field(default_factory=lambda: defaultdict(list))
    reverse: dict[str, list[ADEdge]] = field(default_factory=lambda: defaultdict(list))

    # --- construction --------------------------------------------------
    @classmethod
    def build(cls, principals: Iterable[ADPrincipal], edges: Iterable[ADEdge]) -> "AttackGraph":
        graph = cls()
        for p in principals:
            graph.principals[p.object_sid] = p
        for e in edges:
            if e.source_sid not in graph.principals or e.target_sid not in graph.principals:
                continue  # never trust dangling references from collection
            graph.adjacency[e.source_sid].append(e)
            graph.reverse[e.target_sid].append(e)
        return graph

    def name(self, sid: str) -> str:
        p = self.principals.get(sid)
        return p.sam_account_name if p else sid

    def tier0_sids(self) -> list[str]:
        out = []
        for sid, p in self.principals.items():
            if p.is_domain_controller or p.sam_account_name.lower() in TIER0_NAMES:
                out.append(sid)
        return out

    # --- traversal -------------------------------------------------------
    def cheapest_path(self, source_sid: str, target_sid: str) -> AttackPath | None:
        """Dijkstra over the abuse-cost model."""
        if source_sid == target_sid or source_sid not in self.principals:
            return None

        dist: dict[str, float] = {source_sid: 0.0}
        prev: dict[str, ADEdge] = {}
        seen: set[str] = set()
        heap: list[tuple[float, str]] = [(0.0, source_sid)]

        while heap:
            cost, node = heapq.heappop(heap)
            if node in seen:
                continue
            seen.add(node)
            if node == target_sid:
                break
            for edge in self.adjacency.get(node, []):
                w = EDGE_COST.get(edge.edge_type, DEFAULT_COST)
                nxt = cost + w
                if nxt < dist.get(edge.target_sid, float("inf")):
                    dist[edge.target_sid] = nxt
                    prev[edge.target_sid] = edge
                    heapq.heappush(heap, (nxt, edge.target_sid))

        if target_sid not in dist:
            return None
        return self._materialize(source_sid, target_sid, prev, dist[target_sid])

    def shortest_path(self, source_sid: str, target_sid: str) -> AttackPath | None:
        """BFS - fewest hops, ignoring cost."""
        if source_sid == target_sid or source_sid not in self.principals:
            return None
        prev: dict[str, ADEdge] = {}
        visited = {source_sid}
        queue: deque[str] = deque([source_sid])
        while queue:
            node = queue.popleft()
            if node == target_sid:
                break
            for edge in self.adjacency.get(node, []):
                if edge.target_sid in visited:
                    continue
                visited.add(edge.target_sid)
                prev[edge.target_sid] = edge
                queue.append(edge.target_sid)
        if target_sid not in visited:
            return None
        total = 0.0
        cursor = target_sid
        while cursor in prev:
            total += EDGE_COST.get(prev[cursor].edge_type, DEFAULT_COST)
            cursor = prev[cursor].source_sid
        return self._materialize(source_sid, target_sid, prev, total)

    def paths_to_tier0(
        self, source_sid: str, targets: Sequence[str] | None = None, limit: int = 10
    ) -> list[AttackPath]:
        found = [
            path
            for target in (targets or self.tier0_sids())
            if (path := self.cheapest_path(source_sid, target)) is not None
        ]
        found.sort(key=lambda p: (p.total_cost, p.hops))
        return found[:limit]

    def blast_radius(self, sid: str) -> set[str]:
        """Everything reachable from a principal (what they can compromise)."""
        seen: set[str] = set()
        queue: deque[str] = deque([sid])
        while queue:
            node = queue.popleft()
            for edge in self.adjacency.get(node, []):
                if edge.target_sid not in seen:
                    seen.add(edge.target_sid)
                    queue.append(edge.target_sid)
        seen.discard(sid)
        return seen

    def exposure(self, sid: str) -> set[str]:
        """Everyone who can reach this principal (who threatens it)."""
        seen: set[str] = set()
        queue: deque[str] = deque([sid])
        while queue:
            node = queue.popleft()
            for edge in self.reverse.get(node, []):
                if edge.source_sid not in seen:
                    seen.add(edge.source_sid)
                    queue.append(edge.source_sid)
        seen.discard(sid)
        return seen

    def all_tier0_paths(self, limit_per_source: int = 3, limit: int = 50) -> list[AttackPath]:
        tier0 = set(self.tier0_sids())
        paths: list[AttackPath] = []
        for sid, p in self.principals.items():
            if sid in tier0 or not p.enabled:
                continue
            paths.extend(self.paths_to_tier0(sid, list(tier0), limit=limit_per_source))
        paths.sort(key=lambda p: (p.total_cost, p.hops))
        return paths[:limit]

    # --- internals -------------------------------------------------------
    def _materialize(
        self, source_sid: str, target_sid: str, prev: dict[str, ADEdge], total: float
    ) -> AttackPath:
        steps: list[PathStep] = []
        cursor = target_sid
        while cursor in prev:
            edge = prev[cursor]
            steps.append(
                PathStep(
                    source_sid=edge.source_sid,
                    source_name=self.name(edge.source_sid),
                    target_sid=edge.target_sid,
                    target_name=self.name(edge.target_sid),
                    edge_type=edge.edge_type,
                    cost=EDGE_COST.get(edge.edge_type, DEFAULT_COST),
                )
            )
            cursor = edge.source_sid
        steps.reverse()
        return AttackPath(
            source_sid=source_sid,
            source_name=self.name(source_sid),
            target_sid=target_sid,
            target_name=self.name(target_sid),
            steps=tuple(steps),
            total_cost=round(total, 2),
        )
