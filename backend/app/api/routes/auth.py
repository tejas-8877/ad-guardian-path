"""Domain authentication: LDAP bind -> role resolution -> JWT issuance."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request, status

from app.api.deps import ConnectorDep, CurrentUserDep, SettingsDep
from app.connectors.base import ADAuthenticationError, ADConnectionError
from app.core.rbac import ROLE_PERMISSIONS, resolve_role
from app.core.security import create_access_token
from app.schemas.auth import LoginRequest, LoginResponse, UserProfile

router = APIRouter(prefix="/auth", tags=["auth"])
log = logging.getLogger("adshield.auth")


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    connector: ConnectorDep,
    settings: SettingsDep,
) -> LoginResponse:
    client_ip = request.client.host if request.client else "unknown"
    try:
        identity = connector.authenticate(payload.username, payload.password)
    except ADAuthenticationError:
        # Never log the password or distinguish "bad user" from "bad password".
        log.warning("auth.failed user=%s ip=%s", payload.username, client_ip)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid domain credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except ADConnectionError:
        log.error("auth.directory_unreachable ip=%s", client_ip)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Directory service unavailable."
        ) from None

    role = resolve_role(identity.group_dns, settings)
    token, expires_at = create_access_token(
        subject_sid=identity.object_sid,
        sam_account_name=identity.sam_account_name,
        display_name=identity.display_name,
        role=role,
        settings=settings,
    )
    log.info("auth.success user=%s role=%s ip=%s", identity.sam_account_name, role.value, client_ip)

    return LoginResponse(
        access_token=token,
        expires_at=expires_at,
        user=UserProfile(
            object_sid=identity.object_sid,
            sam_account_name=identity.sam_account_name,
            display_name=identity.display_name,
            email=identity.email,
            role=role,
            permissions=sorted(ROLE_PERMISSIONS[role], key=lambda p: p.value),
        ),
    )


@router.get("/me", response_model=UserProfile)
def me(user: CurrentUserDep) -> UserProfile:
    return UserProfile(
        object_sid=user.object_sid,
        sam_account_name=user.sam_account_name,
        display_name=user.display_name,
        email=None,
        role=user.role,
        permissions=sorted(ROLE_PERMISSIONS[user.role], key=lambda p: p.value),
    )
