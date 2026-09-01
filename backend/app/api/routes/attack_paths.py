"""Attack-path analysis and graph export."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from app.api.deps import RequireAttackPaths
from app.schemas.domain import (
    AttackPathOut,
    GraphEdge,
    GraphMetricsOut,
    GraphNode,
    GraphOut,
    PathStepOut,
    RemovableEdgeOut,
    SimulationCompareRequest,
    SimulationOut,
    SimulationRequest,
)
from app.services import simulation, state
from app.services.graph import AttackPath

router = APIRouter(prefix="/attack-paths", tags=["attack-paths"])


def _to_out(path: AttackPath) -> AttackPathOut:
    return AttackPathOut(
        source_sid=path.source_sid,
        source_name=path.source_name,
        target_sid=path.target_sid,
        target_name=path.target_name,
        hops=path.hops,
        total_cost=path.total_cost,
        severity=path.severity,
        steps=[
            PathStepOut(
                source_sid=s.source_sid,
                source_name=s.source_name,
                target_sid=s.target_sid,
                target_name=s.target_name,
                edge_type=s.edge_type.value,
                cost=s.cost,
            )
            for s in path.steps
        ],
    )


@router.get("", response_model=list[AttackPathOut])
def list_paths(
    _user: RequireAttackPaths,
    limit: int = Query(25, ge=1, le=100),
) -> list[AttackPathOut]:
    return [_to_out(p) for p in state.current().graph.all_tier0_paths(limit=limit)]


@router.get("/from/{source_sid}", response_model=list[AttackPathOut])
def paths_from(
    source_sid: str,
    _user: RequireAttackPaths,
    target_sid: str | None = None,
    limit: int = Query(10, ge=1, le=50),
) -> list[AttackPathOut]:
    graph = state.current().graph
    if source_sid not in graph.principals:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Source principal not found")
    targets = [target_sid] if target_sid else None
    return [_to_out(p) for p in graph.paths_to_tier0(source_sid, targets, limit=limit)]


@router.get("/blast-radius/{sid}", response_model=dict)
def blast_radius(sid: str, _user: RequireAttackPaths) -> dict:
    graph = state.current().graph
    if sid not in graph.principals:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Principal not found")
    downstream = graph.blast_radius(sid)
    upstream = graph.exposure(sid)
    return {
        "sid": sid,
        "name": graph.name(sid),
        "can_compromise": sorted(graph.name(s) for s in downstream),
        "compromised_by": sorted(graph.name(s) for s in upstream),
    }


@router.get("/graph", response_model=GraphOut)
def graph_export(_user: RequireAttackPaths) -> GraphOut:
    snapshot = state.current()
    tier0 = set(snapshot.graph.tier0_sids())
    return GraphOut(
        nodes=[
            GraphNode(
                id=p.object_sid,
                label=p.sam_account_name,
                type=p.principal_type.value,
                tier0=p.object_sid in tier0,
                enabled=p.enabled,
            )
            for p in snapshot.principals
        ],
        edges=[
            GraphEdge(
                id=simulation.edge_id(e),
                source=e.source_sid,
                target=e.target_sid,
                type=e.edge_type.value,
            )
            for e in snapshot.edges
        ],
    )


@router.get("/edges", response_model=list[RemovableEdgeOut])
def list_edges(_user: RequireAttackPaths) -> list[RemovableEdgeOut]:
    """Relationships an analyst can select in the Remediation Simulator."""
    snap = state.current()
    return [RemovableEdgeOut(**e) for e in simulation.removable_edges(snap.principals, snap.edges)]


def _metrics(m: simulation.GraphMetrics) -> GraphMetricsOut:
    return GraphMetricsOut(**vars(m))


def _simulation_out(result: simulation.SimulationResult) -> SimulationOut:
    return SimulationOut(
        before=_metrics(result.before),
        after=_metrics(result.after),
        simulation={
            "removed_edges": result.removed_edges,
            "removed_edge": result.removed_edges[0]["label"] if result.removed_edges else None,
            "action": "remove",
            "reason": result.reason,
        },
        risk_reduction=result.risk_reduction,
        risk_reduction_pct=result.risk_reduction_pct,
        paths_eliminated=result.paths_eliminated,
        tier0_exposure_reduction=result.tier0_exposure_reduction,
        eliminated_paths=[_to_out(p) for p in result.eliminated_paths],
        remaining_paths=[_to_out(p) for p in result.remaining_paths],
        notice=result.notice,
    )


@router.post("/simulate-remediation", response_model=SimulationOut)
def simulate_remediation(payload: SimulationRequest, _user: RequireAttackPaths) -> SimulationOut:
    """SIMULATION ONLY - the directory and the stored graph are never modified."""
    snap = state.current()
    try:
        result = simulation.simulate_removal(
            snap.principals, snap.edges, snap.findings, payload.targets(), payload.reason
        )
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None
    return _simulation_out(result)


@router.post("/compare-remediations", response_model=list[SimulationOut])
def compare_remediations(
    payload: SimulationCompareRequest, _user: RequireAttackPaths
) -> list[SimulationOut]:
    snap = state.current()
    if not payload.candidates:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "No candidates supplied")
    try:
        results = simulation.compare_remediations(
            snap.principals, snap.edges, snap.findings, payload.candidates
        )
    except (LookupError, ValueError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None
    return [_simulation_out(r) for r in results]
