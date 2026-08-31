"""Abstract Active Directory connector interface.

Every concrete connector (mock or real LDAP) implements this contract, so
business logic (attack-path engine, RBAC, dashboards) never needs to know
whether it is talking to a live Domain Controller or fixture data.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Iterable, Sequence


class PrincipalType(str, Enum):
    USER = "user"
    GROUP = "group"
    COMPUTER = "computer"
    GPO = "gpo"
    OU = "ou"


class EdgeType(str, Enum):
    """Relationship / abusable-permission taxonomy (BloodHound-compatible)."""

    MEMBER_OF = "MemberOf"
    ADMIN_TO = "AdminTo"
    GENERIC_ALL = "GenericAll"
    GENERIC_WRITE = "GenericWrite"
    WRITE_DACL = "WriteDacl"
    WRITE_OWNER = "WriteOwner"
    FORCE_CHANGE_PASSWORD = "ForceChangePassword"
    ADD_MEMBER = "AddMember"
    HAS_DCSYNC = "HasDCSync"
    ALLOWED_TO_DELEGATE = "AllowedToDelegate"
    GP_LINK = "GpLink"
    CAN_RDP = "CanRDP"
    SESSION = "HasSession"


@dataclass(frozen=True, slots=True)
class ADPrincipal:
    object_sid: str
    dn: str
    sam_account_name: str
    display_name: str
    principal_type: PrincipalType
    enabled: bool = True
    is_admin_count: bool = False
    is_domain_controller: bool = False
    spns: Sequence[str] = field(default_factory=tuple)
    password_last_set: datetime | None = None
    last_logon: datetime | None = None
    password_never_expires: bool = False
    kerberos_preauth_disabled: bool = False
    unconstrained_delegation: bool = False
    description: str | None = None
    operating_system: str | None = None


@dataclass(frozen=True, slots=True)
class ADEdge:
    """A directed, abusable relationship: source --edge_type--> target."""

    source_sid: str
    target_sid: str
    edge_type: EdgeType
    is_inherited: bool = False
    note: str | None = None


@dataclass(frozen=True, slots=True)
class ADIdentity:
    """Result of a successful credential validation (LDAP bind)."""

    object_sid: str
    dn: str
    sam_account_name: str
    display_name: str
    email: str | None
    group_dns: Sequence[str]


class ADConnectionError(RuntimeError):
    """Directory unreachable / TLS failure / service account rejected."""


class ADAuthenticationError(RuntimeError):
    """Credentials rejected by the Domain Controller."""


class ADConfigurationError(RuntimeError):
    """Connector is misconfigured (missing bind account, bad Base DN, ...)."""


class ADPermissionError(RuntimeError):
    """The bind account lacks the read rights required for collection."""


@dataclass(frozen=True, slots=True)
class ConnectorHealth:
    """Non-sensitive connection status surfaced by GET /api/ad/health."""

    connected: bool
    connector: str
    domain: str
    server: str
    protocol: str
    port: int
    base_dn: str
    latency_ms: float | None = None
    error: str | None = None


class ADConnector(ABC):
    """Contract implemented by MockADConnector and RealADConnector."""

    domain: str

    # --- lifecycle -----------------------------------------------------
    @abstractmethod
    def connect(self) -> None:
        """Bind the read-only service account. Raises ADConnectionError."""

    @abstractmethod
    def close(self) -> None: ...

    def __enter__(self) -> "ADConnector":
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- authentication ------------------------------------------------
    @abstractmethod
    def authenticate(self, username: str, password: str) -> ADIdentity:
        """Validate end-user credentials via a dedicated LDAP bind.

        Raises ADAuthenticationError on bad credentials.
        """

    # --- collection ----------------------------------------------------
    @abstractmethod
    def get_users(self) -> Iterable[ADPrincipal]: ...

    @abstractmethod
    def get_groups(self) -> Iterable[ADPrincipal]: ...

    @abstractmethod
    def get_computers(self) -> Iterable[ADPrincipal]: ...

    @abstractmethod
    def get_gpos(self) -> Iterable[ADPrincipal]: ...

    def get_ous(self) -> Iterable[ADPrincipal]:
        """Organizational Units. Optional: connectors may return nothing."""
        return []

    @abstractmethod
    def get_edges(self) -> Iterable[ADEdge]:
        """Membership + ACL/ACE-derived relationships for the graph engine."""

    # --- diagnostics -----------------------------------------------------
    def health(self) -> ConnectorHealth:
        """Cheap, credential-free connection report. Never returns secrets."""
        return ConnectorHealth(
            connected=True,
            connector=type(self).__name__,
            domain=self.domain,
            server=self.domain,
            protocol="MOCK",
            port=0,
            base_dn="",
        )

    # --- convenience ---------------------------------------------------
    def collect_all(self) -> tuple[list[ADPrincipal], list[ADEdge]]:
        principals = [
            *self.get_users(),
            *self.get_groups(),
            *self.get_computers(),
            *self.get_gpos(),
            *self.get_ous(),
        ]
        return principals, list(self.get_edges())
