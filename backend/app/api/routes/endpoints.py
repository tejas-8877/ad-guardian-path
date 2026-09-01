"""Compromise Impact Analysis: endpoint -> identity -> AD blast radius."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.deps import RequireAttackPaths
from app.api.routes.attack_paths import _to_out
from app.schemas.domain import BlastRadiusOut, CompromiseImpactOut, EndpointOut
from app.services import correlation, state

router = APIRouter(prefix="/endpoints", tags=["compromise-impact"])


class WhatIfRequest(BaseModel):
    identity: str = Field(min_length=1, max_length=128)
    status: str = Field(default="compromised", pattern="^(unknown|clean|suspicious|malicious|compromised)$")


def _to_impact(impact: correlation.CompromiseImpact) -> CompromiseImpactOut:
    return CompromiseImpactOut(
        endpoint=impact.endpoint,
        endpoint_sid=impact.endpoint_sid,
        status=impact.status,
        identity=impact.identity,
        identity_sid=impact.identity_sid,
        identity_source=impact.identity_source,
        risk=impact.risk,
        risk_score=impact.risk_score,
        blast_radius=BlastRadiusOut(**vars(impact.blast_radius)),
        tier0_exposed=impact.tier0_exposed,
        attack_path_count=impact.attack_path_count,
        shortest_path=impact.shortest_path,
        shortest_path_hops=impact.shortest_path_hops,
        paths=[_to_out(p) for p in impact.paths],
        notes=impact.notes,
    )


@router.get("", response_model=list[EndpointOut])
def list_endpoints(_user: RequireAttackPaths) -> list[EndpointOut]:
    snap = state.current()
    return [EndpointOut(**e) for e in correlation.list_endpoints(snap.principals, snap.edges)]


@router.get("/{endpoint_id}/compromise-impact", response_model=CompromiseImpactOut)
def compromise_impact(
    endpoint_id: str,
    _user: RequireAttackPaths,
    status_hint: str = Query("suspicious", alias="status"),
    logged_on_user: str | None = Query(None, max_length=128),
) -> CompromiseImpactOut:
    snap = state.current()
    principal = snap.graph.principals.get(endpoint_id)
    hostname = principal.display_name if principal else endpoint_id
    if principal is None and not any(
        correlation.find_computer(snap.principals, hostname) for _ in (0,)
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Endpoint not found")

    impact = correlation.analyze_endpoint(
        snap.graph, snap.principals, hostname, status_hint, logged_on_user
    )
    return _to_impact(impact)


@router.post("/what-if", response_model=CompromiseImpactOut)
def what_if_identity(payload: WhatIfRequest, _user: RequireAttackPaths) -> CompromiseImpactOut:
    """Analytical only: 'what if this identity were compromised?'."""
    snap = state.current()
    needle = payload.identity.strip().lower()
    principal = next(
        (p for p in snap.principals if p.sam_account_name.lower() == needle), None
    )
    if principal is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Identity not found")

    impact = correlation.analyze_endpoint(
        snap.graph,
        snap.principals,
        hostname=principal.sam_account_name,
        status=payload.status,
        logged_on_user=principal.sam_account_name,
    )
    return _to_impact(impact)
