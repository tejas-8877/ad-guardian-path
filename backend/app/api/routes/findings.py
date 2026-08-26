"""Misconfiguration findings + per-user hygiene view."""

from __future__ import annotations

from fastapi import APIRouter, Query

from app.api.deps import CurrentUserDep, RequireFindings, RequireSecurityAdmin
from app.schemas.domain import FindingOut, FindingPage
from app.services import state

router = APIRouter(tags=["findings"])


@router.get("/findings", response_model=FindingPage)
def list_findings(
    _user: RequireFindings,
    severity: str | None = Query(None, pattern="^(critical|high|medium|low)$"),
    rule: str | None = Query(None, max_length=64),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
) -> FindingPage:
    items = state.current().findings
    if severity:
        items = [f for f in items if f.severity == severity]
    if rule:
        items = [f for f in items if f.rule == rule]
    start = (page - 1) * page_size
    return FindingPage(
        total=len(items),
        page=page,
        page_size=page_size,
        items=[FindingOut(**vars(f)) for f in items[start : start + page_size]],
    )


@router.get("/me/hygiene", response_model=list[FindingOut])
def my_hygiene(user: CurrentUserDep) -> list[FindingOut]:
    """Every role may see findings about *their own* account only."""
    return [
        FindingOut(**vars(f))
        for f in state.current().findings
        if f.principal_sid == user.object_sid
    ]


@router.post("/scan", response_model=dict)
def run_scan(_user: RequireSecurityAdmin) -> dict:
    snapshot = state.collect()
    return {
        "collected_at": snapshot.collected_at,
        "principals": len(snapshot.principals),
        "edges": len(snapshot.edges),
        "findings": len(snapshot.findings),
        "risk_score": snapshot.risk_score,
    }
