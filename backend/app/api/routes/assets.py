"""Directory inventory: users, groups, computers, GPOs."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from app.api.deps import RequireAssets
from app.schemas.domain import PrincipalOut, PrincipalPage
from app.services import state

router = APIRouter(prefix="/assets", tags=["assets"])


def _to_out(p) -> PrincipalOut:  # noqa: ANN001 - ADPrincipal
    return PrincipalOut(
        object_sid=p.object_sid,
        dn=p.dn,
        sam_account_name=p.sam_account_name,
        display_name=p.display_name,
        principal_type=p.principal_type.value,
        enabled=p.enabled,
        is_admin_count=p.is_admin_count,
        is_domain_controller=p.is_domain_controller,
        spns=list(p.spns),
        password_last_set=p.password_last_set,
        last_logon=p.last_logon,
        operating_system=p.operating_system,
        description=p.description,
    )


@router.get("", response_model=PrincipalPage)
def list_assets(
    _user: RequireAssets,
    type: str | None = Query(None, pattern="^(user|group|computer|gpo|ou)$"),
    q: str | None = Query(None, max_length=128),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
) -> PrincipalPage:
    items = state.current().principals
    if type:
        items = [p for p in items if p.principal_type.value == type]
    if q:
        needle = q.lower()
        items = [
            p
            for p in items
            if needle in p.sam_account_name.lower() or needle in p.display_name.lower()
        ]
    start = (page - 1) * page_size
    return PrincipalPage(
        total=len(items),
        page=page,
        page_size=page_size,
        items=[_to_out(p) for p in items[start : start + page_size]],
    )


@router.get("/{object_sid}", response_model=PrincipalOut)
def get_asset(object_sid: str, _user: RequireAssets) -> PrincipalOut:
    principal = state.current().graph.principals.get(object_sid)
    if principal is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Principal not found")
    return _to_out(principal)
