"""FastAPI dependencies: current principal, role guards, permission guards."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Callable

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.connectors.base import ADConnector
from app.connectors.factory import get_connector
from app.core.config import Settings, get_settings
from app.core.rbac import Permission, Role, at_least, has_permission
from app.core.security import TokenError, decode_access_token

bearer_scheme = HTTPBearer(auto_error=False)

SettingsDep = Annotated[Settings, Depends(get_settings)]
ConnectorDep = Annotated[ADConnector, Depends(get_connector)]


@dataclass(frozen=True, slots=True)
class CurrentUser:
    object_sid: str
    sam_account_name: str
    display_name: str
    role: Role

    def can(self, permission: Permission) -> bool:
        return has_permission(self.role, permission)


def get_current_user(
    settings: SettingsDep,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> CurrentUser:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = decode_access_token(creds.credentials, settings)
        role = Role(claims["role"])
    except (TokenError, ValueError, KeyError):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    return CurrentUser(
        object_sid=claims["sub"],
        sam_account_name=claims.get("upn", ""),
        display_name=claims.get("name", ""),
        role=role,
    )


CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]


def require_permission(*permissions: Permission) -> Callable[[CurrentUser], CurrentUser]:
    def guard(user: CurrentUserDep) -> CurrentUser:
        missing = [p for p in permissions if not user.can(p)]
        if missing:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Requires permission: {', '.join(p.value for p in missing)}",
            )
        return user

    return guard


def require_role(minimum: Role) -> Callable[[CurrentUser], CurrentUser]:
    def guard(user: CurrentUserDep) -> CurrentUser:
        if not at_least(user.role, minimum):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
        return user

    return guard


# Ready-made guards used by routers.
RequireAssets = Annotated[CurrentUser, Depends(require_permission(Permission.VIEW_ASSETS))]
RequireFindings = Annotated[CurrentUser, Depends(require_permission(Permission.VIEW_FINDINGS))]
RequireAttackPaths = Annotated[
    CurrentUser, Depends(require_permission(Permission.VIEW_ATTACK_PATHS))
]
RequireSecurityAdmin = Annotated[CurrentUser, Depends(require_role(Role.SECURITY_ADMIN))]
