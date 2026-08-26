"""Attack-path analysis and graph export."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from app.api.deps import RequireAttackPaths
from app.schemas.domain import AttackPathOut, GraphEdge, GraphNode, GraphOut, PathStepOut
from app.services import state
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
            GraphEdge(source=e.source_sid, target=e.target_sid, type=e.edge_type.value)
            for e in snapshot.edges
        ],
    )
