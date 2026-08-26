"""Aggregated SOC dashboard metrics."""

from __future__ import annotations

from collections import Counter

from fastapi import APIRouter

from app.api.deps import RequireFindings
from app.api.routes.attack_paths import _to_out
from app.connectors.base import PrincipalType
from app.schemas.domain import DashboardOut, SeverityCount
from app.services import state

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("", response_model=DashboardOut)
def dashboard(_user: RequireFindings) -> DashboardOut:
    snap = state.current()
    types = Counter(p.principal_type for p in snap.principals)
    severities = Counter(f.severity for f in snap.findings)
    rules = Counter(f.rule for f in snap.findings)
    paths = snap.graph.all_tier0_paths(limit=5)

    return DashboardOut(
        domain=snap.domain,
        risk_score=snap.risk_score,
        collected_at=snap.collected_at,
        users=types[PrincipalType.USER],
        groups=types[PrincipalType.GROUP],
        computers=types[PrincipalType.COMPUTER],
        gpos=types[PrincipalType.GPO],
        findings_by_severity=SeverityCount(
            critical=severities["critical"],
            high=severities["high"],
            medium=severities["medium"],
            low=severities["low"],
        ),
        tier0_exposed_principals=len({p.source_sid for p in snap.graph.all_tier0_paths(limit=500)}),
        critical_paths=[_to_out(p) for p in paths],
        top_rules=[{"rule": r, "count": c} for r, c in rules.most_common(6)],
    )
