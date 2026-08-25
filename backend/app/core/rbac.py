"""Role model and authorization guards."""

from __future__ import annotations

from enum import Enum
from typing import Iterable, Sequence

from app.core.config import Settings


class Role(str, Enum):
    STANDARD_USER = "standard_user"
    IT_SUPPORT = "it_support"
    SECURITY_ADMIN = "security_admin"


# Higher wins. Used for "at least this role" checks.
_ORDER = {Role.STANDARD_USER: 0, Role.IT_SUPPORT: 1, Role.SECURITY_ADMIN: 2}


class Permission(str, Enum):
    VIEW_OWN_HYGIENE = "view:own_hygiene"
    VIEW_ASSETS = "view:assets"
    VIEW_FINDINGS = "view:findings"
    VIEW_ATTACK_PATHS = "view:attack_paths"
    RUN_SCAN = "run:scan"
    SUBMIT_MALWARE_SAMPLE = "submit:malware_sample"
    VIEW_MALWARE_ANALYSIS = "view:malware_analysis"
    EXPORT_REPORTS = "export:reports"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.STANDARD_USER: frozenset(
        {Permission.VIEW_OWN_HYGIENE, Permission.SUBMIT_MALWARE_SAMPLE}
    ),
    Role.IT_SUPPORT: frozenset(
        {
            Permission.VIEW_OWN_HYGIENE,
            Permission.VIEW_ASSETS,
            Permission.SUBMIT_MALWARE_SAMPLE,
            Permission.VIEW_MALWARE_ANALYSIS,
        }
    ),
    Role.SECURITY_ADMIN: frozenset(Permission),
}


def normalize(group: str) -> str:
    """Accept either a full DN or a bare group name; compare on the CN/name."""
    g = group.strip().lower()
    if g.startswith("cn="):
        g = g.split(",", 1)[0][3:]
    return g


def resolve_role(group_dns: Sequence[str], settings: Settings) -> Role:
    """Map the user's AD group membership to the highest matching role."""
    memberships = {normalize(g) for g in group_dns}

    soc = {normalize(g) for g in settings.role_security_admin_groups}
    if memberships & soc or "domain admins" in memberships or "enterprise admins" in memberships:
        return Role.SECURITY_ADMIN

    helpdesk = {normalize(g) for g in settings.role_it_support_groups}
    if memberships & helpdesk:
        return Role.IT_SUPPORT

    return Role.STANDARD_USER


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS[role]


def has_all(role: Role, permissions: Iterable[Permission]) -> bool:
    return all(has_permission(role, p) for p in permissions)


def at_least(role: Role, minimum: Role) -> bool:
    return _ORDER[role] >= _ORDER[minimum]
