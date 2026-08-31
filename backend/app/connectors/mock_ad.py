"""MockADConnector - deterministic fixture domain for UI/UX development.

Implements the exact same ADConnector contract as RealADConnector, so no
business logic or frontend code changes when switching via ADSHIELD_AD_CONNECTOR.
The fixture domain intentionally contains a realistic misconfiguration chain:

  j.doe -> (MemberOf) Helpdesk -> (ForceChangePassword) svc_backup
        -> (MemberOf) Backup Operators -> (AdminTo) DC01
  t.admin -> (GenericAll) Domain Admins
  svc_sql (unconstrained delegation + SPN, kerberoastable)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Iterable

from app.connectors.base import (
    ADAuthenticationError,
    ConnectorHealth,
    ADConnector,
    ADEdge,
    ADIdentity,
    ADPrincipal,
    EdgeType,
    PrincipalType,
)

DOMAIN = "corp.local"
BASE = "DC=corp,DC=local"
_NOW = datetime.now(timezone.utc)


def _sid(rid: int) -> str:
    return f"S-1-5-21-1004336348-1177238915-682003330-{rid}"



_USERS: list[ADPrincipal] = [
    ADPrincipal(_sid(1103), f"CN=Jane Doe,OU=Staff,{BASE}", "j.doe", "Jane Doe",
                PrincipalType.USER, password_last_set=_NOW - timedelta(days=412),
                last_logon=_NOW - timedelta(hours=3), description="Finance analyst"),
    ADPrincipal(_sid(1104), f"CN=Tom Admin,OU=IT,{BASE}", "t.admin", "Tom Admin",
                PrincipalType.USER, is_admin_count=True,
                password_last_set=_NOW - timedelta(days=61),
                last_logon=_NOW - timedelta(hours=1)),
    ADPrincipal(_sid(1105), f"CN=Helpdesk Op,OU=IT,{BASE}", "h.desk", "Helpdesk Op",
                PrincipalType.USER, password_last_set=_NOW - timedelta(days=120),
                last_logon=_NOW - timedelta(days=1)),
    ADPrincipal(_sid(1201), f"CN=svc_backup,OU=Service Accounts,{BASE}", "svc_backup",
                "svc_backup", PrincipalType.USER, password_never_expires=True,
                password_last_set=_NOW - timedelta(days=980),
                spns=("cifs/backup01.corp.local",)),
    ADPrincipal(_sid(1202), f"CN=svc_sql,OU=Service Accounts,{BASE}", "svc_sql", "svc_sql",
                PrincipalType.USER, password_never_expires=True,
                unconstrained_delegation=True, kerberos_preauth_disabled=True,
                password_last_set=_NOW - timedelta(days=1420),
                spns=("MSSQLSvc/sql01.corp.local:1433",)),
    ADPrincipal(_sid(1301), f"CN=Legacy Svc,OU=Disabled,{BASE}", "legacy.svc", "Legacy Svc",
                PrincipalType.USER, enabled=False,
                password_last_set=_NOW - timedelta(days=2100)),
]

_GROUPS: list[ADPrincipal] = [
    ADPrincipal(_sid(512), f"CN=Domain Admins,CN=Users,{BASE}", "Domain Admins",
                "Domain Admins", PrincipalType.GROUP, is_admin_count=True),
    ADPrincipal(_sid(519), f"CN=Enterprise Admins,CN=Users,{BASE}", "Enterprise Admins",
                "Enterprise Admins", PrincipalType.GROUP, is_admin_count=True),
    ADPrincipal(_sid(551), f"CN=Backup Operators,CN=Builtin,{BASE}", "Backup Operators",
                "Backup Operators", PrincipalType.GROUP, is_admin_count=True),
    ADPrincipal(_sid(1401), f"CN=ADShield-SOC,OU=Groups,{BASE}", "ADShield-SOC",
                "ADShield-SOC", PrincipalType.GROUP),
    ADPrincipal(_sid(1402), f"CN=ADShield-Helpdesk,OU=Groups,{BASE}", "ADShield-Helpdesk",
                "ADShield-Helpdesk", PrincipalType.GROUP),
    ADPrincipal(_sid(1403), f"CN=Finance,OU=Groups,{BASE}", "Finance", "Finance",
                PrincipalType.GROUP),
]

_COMPUTERS: list[ADPrincipal] = [
    ADPrincipal(_sid(1000), f"CN=DC01,OU=Domain Controllers,{BASE}", "DC01$", "DC01",
                PrincipalType.COMPUTER, is_domain_controller=True,
                operating_system="Windows Server 2022"),
    ADPrincipal(_sid(1501), f"CN=SQL01,OU=Servers,{BASE}", "SQL01$", "SQL01",
                PrincipalType.COMPUTER, operating_system="Windows Server 2019"),
    ADPrincipal(_sid(1502), f"CN=WKS-014,OU=Workstations,{BASE}", "WKS-014$", "WKS-014",
                PrincipalType.COMPUTER, operating_system="Windows 11 Enterprise"),
]

_GPOS: list[ADPrincipal] = [
    ADPrincipal(_sid(1601), f"CN={{31B2F340-016D-11D2-945F-00C04FB984F9}},CN=Policies,CN=System,{BASE}",
                "Default Domain Policy", "Default Domain Policy", PrincipalType.GPO),
]

_OUS: list[ADPrincipal] = [
    ADPrincipal(f"OU:{name}", f"OU={name},{BASE}", name, name, PrincipalType.OU)
    for name in ("Staff", "IT", "Service Accounts", "Servers", "Workstations",
                 "Domain Controllers", "Disabled")
]

_EDGES: list[ADEdge] = [
    ADEdge(_sid(1103), _sid(1403), EdgeType.MEMBER_OF),
    ADEdge(_sid(1105), _sid(1402), EdgeType.MEMBER_OF),
    ADEdge(_sid(1104), _sid(1402), EdgeType.MEMBER_OF),
    ADEdge(_sid(1201), _sid(551), EdgeType.MEMBER_OF),
    ADEdge(_sid(1403), _sid(1402), EdgeType.GENERIC_WRITE, note="Nested write on Helpdesk"),
    ADEdge(_sid(1402), _sid(1201), EdgeType.FORCE_CHANGE_PASSWORD,
           note="Helpdesk can reset svc_backup password"),
    ADEdge(_sid(551), _sid(1000), EdgeType.ADMIN_TO, note="Backup Operators local admin on DC01"),
    ADEdge(_sid(1104), _sid(512), EdgeType.GENERIC_ALL, note="Unexpected GenericAll on Domain Admins"),
    ADEdge(_sid(512), _sid(1000), EdgeType.ADMIN_TO),
    ADEdge(_sid(1202), _sid(1000), EdgeType.HAS_DCSYNC, note="DS-Replication-Get-Changes-All"),
    ADEdge(_sid(1103), _sid(1502), EdgeType.CAN_RDP),
    ADEdge(_sid(1202), _sid(1501), EdgeType.SESSION),
    ADEdge(_sid(1601), _sid(1502), EdgeType.GP_LINK),
]

# Demo credentials for the mock domain only. Never used by RealADConnector.
_MOCK_PASSWORDS = {
    "j.doe": "Password123!",
    "h.desk": "Password123!",
    "t.admin": "Password123!",
}
_MOCK_MEMBERSHIP = {
    "j.doe": [f"CN=Finance,OU=Groups,{BASE}"],
    "h.desk": [f"CN=ADShield-Helpdesk,OU=Groups,{BASE}"],
    "t.admin": [f"CN=ADShield-SOC,OU=Groups,{BASE}", f"CN=Domain Admins,CN=Users,{BASE}"],
}


class MockADConnector(ADConnector):
    def __init__(self, domain: str = DOMAIN) -> None:
        self.domain = domain
        self._connected = False

    def connect(self) -> None:
        self._connected = True

    def close(self) -> None:
        self._connected = False

    def authenticate(self, username: str, password: str) -> ADIdentity:
        sam = username.split("\\")[-1].split("@")[0].lower()
        if _MOCK_PASSWORDS.get(sam) != password:
            raise ADAuthenticationError("Invalid domain credentials.")
        principal = next(u for u in _USERS if u.sam_account_name == sam)
        return ADIdentity(
            object_sid=principal.object_sid,
            dn=principal.dn,
            sam_account_name=principal.sam_account_name,
            display_name=principal.display_name,
            email=f"{sam}@{self.domain}",
            group_dns=_MOCK_MEMBERSHIP.get(sam, []),
        )

    def get_users(self) -> Iterable[ADPrincipal]:
        return list(_USERS)

    def get_groups(self) -> Iterable[ADPrincipal]:
        return list(_GROUPS)

    def get_computers(self) -> Iterable[ADPrincipal]:
        return list(_COMPUTERS)

    def get_gpos(self) -> Iterable[ADPrincipal]:
        return list(_GPOS)

    def get_ous(self) -> Iterable[ADPrincipal]:
        return list(_OUS)

    def get_edges(self) -> Iterable[ADEdge]:
        return list(_EDGES)

    def health(self) -> ConnectorHealth:
        return ConnectorHealth(
            connected=self._connected,
            connector="mock",
            domain=self.domain,
            server=f"mock-dc01.{self.domain}",
            protocol="MOCK",
            port=0,
            base_dn=BASE,
            latency_ms=0.0,
        )
