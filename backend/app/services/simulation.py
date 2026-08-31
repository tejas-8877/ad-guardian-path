"""Attack-Path Remediation Simulator.

Answers "how much risk disappears if we remove this relationship?" by
rebuilding a *temporary* AttackGraph without the selected edges and
re-running the existing attack-path + risk engines.

Hard guarantees:
  * Active Directory is never modified - this module performs no writes.
  * The persistent snapshot / source graph is never mutated: every
    simulation builds a fresh AttackGraph from copies of the edge list.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable, Sequence

from app.connectors.base import ADEdge, ADPrincipal, EdgeType
from app.services.findings import Finding, SEVERITY_WEIGHT
from app.services.graph import AttackGraph, AttackPath

log = logging.getLogger("adshield.simulation")

SIMULATION_NOTICE = "SIMULATION - No Active Directory changes were performed."


def edge_id(edge: ADEdge) -> str:
    """Stable, URL-safe identifier for a graph edge."""
    return f"{edge.source_sid}|{edge.edge_type.value}|{edge.target_sid}"


def parse_edge_id(value: str) -> tuple[str, str, str]:
    parts = value.split("|")
    if len(parts) != 3 or not all(parts):
        raise ValueError("edge_id must be '<source_sid>|<EdgeType>|<target_sid>'")
    return parts[0], parts[1], parts[2]


@dataclass(frozen=True, slots=True)
class GraphMetrics:
    risk_score: int
    attack_paths: int
    tier0_exposure: int
    reachable_privileged: int
    average_path_cost: float
    shortest_path_hops: int | None


@dataclass(frozen=True, slots=True)
class SimulationResult:
    before: GraphMetrics
    after: GraphMetrics
    removed_edges: list[dict[str, str]]
    reason: str
    risk_reduction: int
    risk_reduction_pct: float
    paths_eliminated: int
    tier0_exposure_reduction: int
    eliminated_paths: list[AttackPath] = field(default_factory=list)
    remaining_paths: list[AttackPath] = field(default_factory=list)
    notice: str = SIMULATION_NOTICE


# --- metrics -----------------------------------------------------------
def graph_risk_score(
    graph: AttackGraph, findings: Sequence[Finding], principal_count: int
) -> int:
    """Extends the existing findings-based score with graph exposure.

    Base component (unchanged semantics from findings.risk_score) is blended
    with a graph component so that remediating a relationship - which removes
    no finding - still visibly lowers risk.
    """
    if principal_count <= 0:
        return 0
    finding_component = sum(SEVERITY_WEIGHT[f.severity] for f in findings) / principal_count * 12

    paths = graph.all_tier0_paths(limit=500)
    exposed = {p.source_sid for p in paths}
    # Cheaper paths are more dangerous: weight by inverse cost.
    path_component = sum(6.0 / max(p.total_cost, 0.5) for p in paths)
    exposure_component = len(exposed) * 3.0

    raw = finding_component * 0.55 + path_component * 0.9 + exposure_component
    return max(0, min(100, round(raw)))


def measure(
    graph: AttackGraph, findings: Sequence[Finding], principal_count: int
) -> GraphMetrics:
    paths = graph.all_tier0_paths(limit=500)
    tier0 = set(graph.tier0_sids())
    reachable_privileged = len(
        {
            sid
            for source in {p.source_sid for p in paths}
            for sid in graph.blast_radius(source)
            if sid in tier0
        }
    )
    costs = [p.total_cost for p in paths]
    hops = [p.hops for p in paths]
    return GraphMetrics(
        risk_score=graph_risk_score(graph, findings, principal_count),
        attack_paths=len(paths),
        tier0_exposure=len({p.source_sid for p in paths}),
        reachable_privileged=reachable_privileged,
        average_path_cost=round(sum(costs) / len(costs), 2) if costs else 0.0,
        shortest_path_hops=min(hops) if hops else None,
    )


# --- simulation --------------------------------------------------------
def removable_edges(principals: Iterable[ADPrincipal], edges: Iterable[ADEdge]) -> list[dict]:
    """Catalogue of relationships an analyst may simulate removing."""
    names = {p.object_sid: p.sam_account_name for p in principals}
    out: list[dict] = []
    for e in edges:
        if e.source_sid not in names or e.target_sid not in names:
            continue
        out.append(
            {
                "edge_id": edge_id(e),
                "source_sid": e.source_sid,
                "source_name": names[e.source_sid],
                "target_sid": e.target_sid,
                "target_name": names[e.target_sid],
                "edge_type": e.edge_type.value,
                "note": e.note,
            }
        )
    return out


def _matches(edge: ADEdge, target: tuple[str, str, str]) -> bool:
    src, kind, dst = target
    return edge.source_sid == src and edge.edge_type.value == kind and edge.target_sid == dst


def simulate_removal(
    principals: Sequence[ADPrincipal],
    edges: Sequence[ADEdge],
    findings: Sequence[Finding],
    edge_ids: Sequence[str],
    reason: str = "Remove excessive privilege",
) -> SimulationResult:
    """Recalculate posture with `edge_ids` removed. Never mutates inputs."""
    if not edge_ids:
        raise ValueError("At least one edge_id is required")

    targets = [parse_edge_id(v) for v in edge_ids]
    source_graph = AttackGraph.build(principals, edges)

    kept: list[ADEdge] = []
    removed: list[ADEdge] = []
    for e in edges:
        (removed if any(_matches(e, t) for t in targets) else kept).append(e)

    if not removed:
        raise LookupError("No matching relationship found for the requested edge_id(s)")

    simulated_graph = AttackGraph.build(principals, kept)

    before = measure(source_graph, findings, len(principals))
    after = measure(simulated_graph, findings, len(principals))

    before_paths = source_graph.all_tier0_paths(limit=500)
    after_paths = simulated_graph.all_tier0_paths(limit=500)
    after_keys = {(p.source_sid, p.target_sid) for p in after_paths}
    eliminated = [p for p in before_paths if (p.source_sid, p.target_sid) not in after_keys]

    reduction = before.risk_score - after.risk_score
    pct = round(reduction / before.risk_score * 100, 1) if before.risk_score else 0.0

    log.info(
        "simulation.run edges=%s before_risk=%s after_risk=%s paths=%s->%s",
        len(removed), before.risk_score, after.risk_score,
        before.attack_paths, after.attack_paths,
    )

    names = {p.object_sid: p.sam_account_name for p in principals}
    return SimulationResult(
        before=before,
        after=after,
        removed_edges=[
            {
                "edge_id": edge_id(e),
                "source_name": names.get(e.source_sid, e.source_sid),
                "target_name": names.get(e.target_sid, e.target_sid),
                "edge_type": e.edge_type.value,
                "label": (
                    f"{names.get(e.source_sid, e.source_sid)} "
                    f"--{e.edge_type.value}--> {names.get(e.target_sid, e.target_sid)}"
                ),
            }
            for e in removed
        ],
        reason=reason,
        risk_reduction=reduction,
        risk_reduction_pct=pct,
        paths_eliminated=max(before.attack_paths - after.attack_paths, 0),
        tier0_exposure_reduction=max(before.tier0_exposure - after.tier0_exposure, 0),
        eliminated_paths=eliminated[:25],
        remaining_paths=after_paths[:25],
    )


def compare_remediations(
    principals: Sequence[ADPrincipal],
    edges: Sequence[ADEdge],
    findings: Sequence[Finding],
    candidates: Sequence[Sequence[str]],
) -> list[SimulationResult]:
    """Run several candidate remediations against the same pristine graph."""
    results = [
        simulate_removal(principals, edges, findings, list(c)) for c in candidates if c
    ]
    results.sort(key=lambda r: (-r.risk_reduction, -r.paths_eliminated))
    return results


DANGEROUS_EDGE_TYPES = {
    EdgeType.GENERIC_ALL,
    EdgeType.GENERIC_WRITE,
    EdgeType.WRITE_DACL,
    EdgeType.WRITE_OWNER,
    EdgeType.ADD_MEMBER,
    EdgeType.FORCE_CHANGE_PASSWORD,
    EdgeType.HAS_DCSYNC,
    EdgeType.ALLOWED_TO_DELEGATE,
}
