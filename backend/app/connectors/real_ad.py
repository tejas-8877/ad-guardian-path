"""RealADConnector - live LDAPS collection via ldap3.

Security notes:
  * LDAPS only (TLS 1.2+), certificate validation REQUIRED outside dev.
  * The service account is read-only and needs no privileged rights beyond
    "Read" on the domain NC + "Read Security" on nTSecurityDescriptor.
  * End-user authentication uses a short-lived, separate bind connection;
    user credentials are never cached, logged, or reused.
"""

from __future__ import annotations

import ssl
import struct
from datetime import datetime, timedelta, timezone
from typing import Iterable, Iterator

from ldap3 import ALL, SASL, SIMPLE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPBindError, LDAPException

from app.connectors.base import (
    ADAuthenticationError,
    ADConnectionError,
    ADConnector,
    ADEdge,
    ADIdentity,
    ADPrincipal,
    EdgeType,
    PrincipalType,
)
from app.core.config import Settings

# --- userAccountControl flags ---
UAC_ACCOUNTDISABLE = 0x0002
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_DONT_REQ_PREAUTH = 0x400000
UAC_SERVER_TRUST_ACCOUNT = 0x2000  # domain controller

# --- extended rights GUIDs ---
GUID_DS_REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_DS_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
GUID_FORCE_CHANGE_PASSWORD = "00299570-246d-11d0-a768-00aa006e0529"
GUID_MEMBER_ATTR = "bf9679c0-0de6-11d0-a285-00aa003049e2"

# --- access mask bits ---
ADS_RIGHT_GENERIC_ALL = 0x10000000
ADS_RIGHT_GENERIC_WRITE = 0x40000000
ADS_RIGHT_WRITE_DAC = 0x00040000
ADS_RIGHT_WRITE_OWNER = 0x00080000
ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
ADS_RIGHT_DS_WRITE_PROP = 0x00000020

USER_ATTRS = [
    "objectSid", "distinguishedName", "sAMAccountName", "displayName", "mail",
    "userAccountControl", "adminCount", "servicePrincipalName", "pwdLastSet",
    "lastLogonTimestamp", "memberOf", "description", "nTSecurityDescriptor",
]
COMPUTER_ATTRS = USER_ATTRS + ["operatingSystem", "dNSHostName"]
GROUP_ATTRS = [
    "objectSid", "distinguishedName", "sAMAccountName", "displayName",
    "adminCount", "member", "memberOf", "description", "nTSecurityDescriptor",
]
GPO_ATTRS = ["objectGUID", "distinguishedName", "displayName", "nTSecurityDescriptor"]

_AD_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        ticks = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if ticks <= 0:
        return None
    return _AD_EPOCH + timedelta(microseconds=ticks // 10)


def _sid_to_string(raw: bytes | str) -> str:
    if isinstance(raw, str):
        return raw
    revision = raw[0]
    sub_count = raw[1]
    authority = int.from_bytes(raw[2:8], "big")
    parts = [
        str(struct.unpack("<I", raw[8 + 4 * i : 12 + 4 * i])[0]) for i in range(sub_count)
    ]
    return "-".join(["S", str(revision), str(authority), *parts])


class RealADConnector(ADConnector):
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self.domain = settings.ad_domain
        self._base_dn = settings.ad_base_dn
        self._conn: Connection | None = None
        self._dn_to_sid: dict[str, str] = {}

    # --- lifecycle -----------------------------------------------------
    def _server(self) -> Server:
        s = self._settings
        validate = ssl.CERT_REQUIRED if s.environment != "dev" else ssl.CERT_OPTIONAL
        tls = Tls(
            validate=validate,
            version=ssl.PROTOCOL_TLS_CLIENT,
            ca_certs_file=s.ad_ca_cert_path,
        )
        return Server(s.ad_server_uri, use_ssl=s.ad_use_ssl, tls=tls, get_info=ALL)

    def connect(self) -> None:
        s = self._settings
        try:
            self._conn = Connection(
                self._server(),
                user=s.ad_service_user,
                password=s.ad_service_password.get_secret_value(),
                authentication=SIMPLE,
                auto_bind=True,
                raise_exceptions=True,
                read_only=True,
            )
        except LDAPException as exc:
            raise ADConnectionError(f"LDAPS bind failed: {exc}") from exc

    def close(self) -> None:
        if self._conn is not None:
            self._conn.unbind()
            self._conn = None

    @property
    def conn(self) -> Connection:
        if self._conn is None:
            raise ADConnectionError("Connector is not connected; call connect() first.")
        return self._conn

    # --- authentication ------------------------------------------------
    def authenticate(self, username: str, password: str) -> ADIdentity:
        # Reject empty password: AD treats it as an anonymous/unauthenticated bind.
        if not username or not password:
            raise ADAuthenticationError("Username and password are required.")

        upn = username if "@" in username or "\\" in username else f"{username}@{self._settings.ad_domain_dns}"
        try:
            user_conn = Connection(
                self._server(),
                user=upn,
                password=password,
                authentication=SIMPLE,
                auto_bind=True,
                raise_exceptions=True,
                read_only=True,
            )
        except LDAPBindError as exc:
            raise ADAuthenticationError("Invalid domain credentials.") from exc
        except LDAPException as exc:
            raise ADConnectionError(f"Directory unreachable during bind: {exc}") from exc

        try:
            sam = username.split("\\")[-1].split("@")[0]
            user_conn.search(
                self._base_dn,
                f"(&(objectClass=user)(sAMAccountName={_escape(sam)}))",
                search_scope=SUBTREE,
                attributes=["objectSid", "distinguishedName", "sAMAccountName",
                            "displayName", "mail", "memberOf", "tokenGroups"],
            )
            if not user_conn.entries:
                raise ADAuthenticationError("Account not found in the directory.")
            e = user_conn.entries[0]
            return ADIdentity(
                object_sid=_sid_to_string(e.objectSid.raw_values[0]),
                dn=str(e.distinguishedName),
                sam_account_name=str(e.sAMAccountName),
                display_name=str(e.displayName) if e.displayName else str(e.sAMAccountName),
                email=str(e.mail) if e.mail else None,
                group_dns=self._expand_groups(user_conn, str(e.distinguishedName)),
            )
        finally:
            user_conn.unbind()

    def _expand_groups(self, conn: Connection, user_dn: str) -> list[str]:
        """Nested membership via LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941)."""
        conn.search(
            self._base_dn,
            f"(member:1.2.840.113556.1.4.1941:={_escape(user_dn)})",
            search_scope=SUBTREE,
            attributes=["distinguishedName", "sAMAccountName"],
        )
        return [str(e.distinguishedName) for e in conn.entries]

    # --- collection ----------------------------------------------------
    def _search(self, ldap_filter: str, attrs: list[str]) -> Iterator[object]:
        for entry in self.conn.extend.standard.paged_search(
            self._base_dn,
            ldap_filter,
            search_scope=SUBTREE,
            attributes=attrs,
            paged_size=500,
            generator=True,
        ):
            if entry.get("type") == "searchResEntry":
                yield entry

    def _principal(self, entry: dict, ptype: PrincipalType) -> ADPrincipal:
        a = entry["attributes"]
        raw_sid = entry["raw_attributes"].get("objectSid", [b""])[0]
        sid = _sid_to_string(raw_sid) if raw_sid else str(a.get("distinguishedName"))
        uac = int(a.get("userAccountControl") or 0)
        dn = str(a.get("distinguishedName"))
        self._dn_to_sid[dn.lower()] = sid
        return ADPrincipal(
            object_sid=sid,
            dn=dn,
            sam_account_name=str(a.get("sAMAccountName") or a.get("displayName") or dn),
            display_name=str(a.get("displayName") or a.get("sAMAccountName") or dn),
            principal_type=ptype,
            enabled=not bool(uac & UAC_ACCOUNTDISABLE),
            is_admin_count=bool(a.get("adminCount")),
            is_domain_controller=bool(uac & UAC_SERVER_TRUST_ACCOUNT),
            spns=tuple(a.get("servicePrincipalName") or ()),
            password_last_set=_filetime(a.get("pwdLastSet")),
            last_logon=_filetime(a.get("lastLogonTimestamp")),
            password_never_expires=bool(uac & UAC_DONT_EXPIRE_PASSWORD),
            kerberos_preauth_disabled=bool(uac & UAC_DONT_REQ_PREAUTH),
            unconstrained_delegation=bool(uac & UAC_TRUSTED_FOR_DELEGATION),
            description=str(a.get("description")) if a.get("description") else None,
            operating_system=str(a.get("operatingSystem")) if a.get("operatingSystem") else None,
        )

    def get_users(self) -> Iterable[ADPrincipal]:
        f = "(&(objectCategory=person)(objectClass=user))"
        return [self._principal(e, PrincipalType.USER) for e in self._search(f, USER_ATTRS)]

    def get_groups(self) -> Iterable[ADPrincipal]:
        return [
            self._principal(e, PrincipalType.GROUP)
            for e in self._search("(objectClass=group)", GROUP_ATTRS)
        ]

    def get_computers(self) -> Iterable[ADPrincipal]:
        return [
            self._principal(e, PrincipalType.COMPUTER)
            for e in self._search("(objectClass=computer)", COMPUTER_ATTRS)
        ]

    def get_gpos(self) -> Iterable[ADPrincipal]:
        return [
            self._principal(e, PrincipalType.GPO)
            for e in self._search("(objectClass=groupPolicyContainer)", GPO_ATTRS)
        ]

    def get_edges(self) -> Iterable[ADEdge]:
        edges: list[ADEdge] = []
        # MemberOf edges
        for entry in self._search("(objectClass=group)", GROUP_ATTRS):
            a = entry["attributes"]
            group_dn = str(a.get("distinguishedName"))
            group_sid = self._resolve(group_dn)
            for member_dn in a.get("member") or []:
                member_sid = self._resolve(str(member_dn))
                if member_sid and group_sid:
                    edges.append(ADEdge(member_sid, group_sid, EdgeType.MEMBER_OF))
        # ACL-derived edges
        for ldap_filter, attrs in (
            ("(&(objectCategory=person)(objectClass=user))", USER_ATTRS),
            ("(objectClass=group)", GROUP_ATTRS),
            ("(objectClass=computer)", COMPUTER_ATTRS),
            ("(objectClass=groupPolicyContainer)", GPO_ATTRS),
        ):
            for entry in self._search(ldap_filter, attrs):
                target_dn = str(entry["attributes"].get("distinguishedName"))
                target_sid = self._resolve(target_dn)
                raw_sd = entry["raw_attributes"].get("nTSecurityDescriptor")
                if not target_sid or not raw_sd:
                    continue
                edges.extend(self._edges_from_sd(raw_sd[0], target_sid))
        return edges

    def _resolve(self, dn: str) -> str | None:
        return self._dn_to_sid.get(dn.lower())

    @staticmethod
    def _edges_from_sd(raw_sd: bytes, target_sid: str) -> list[ADEdge]:
        """Parse nTSecurityDescriptor ACEs into abusable edges."""
        from ldap3.protocol.formatters.formatters import format_sid  # noqa: F401
        from ldap3.utils.conv import escape_filter_chars  # noqa: F401
        from impacket.ldap import ldaptypes  # parsed lazily; optional dependency

        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw_sd)
        out: list[ADEdge] = []
        dacl = getattr(sd, "__getitem__", None) and sd["Dacl"]
        if not dacl:
            return out
        repl_get, repl_all = set(), set()

        for ace in dacl.aces:
            if ace["AceType"] not in (0x00, 0x05):  # ALLOWED / ALLOWED_OBJECT
                continue
            body = ace["Ace"]
            src = body["Sid"].formatCanonical()
            mask = body["Mask"]["Mask"]
            inherited = bool(ace["AceFlags"] & 0x10)
            obj_guid = None
            if ace["AceType"] == 0x05 and body["ObjectTypeLen"] != 0:
                obj_guid = str(ldaptypes.bin_to_string(body["ObjectType"])).lower()

            def add(kind: EdgeType, note: str | None = None) -> None:
                out.append(ADEdge(src, target_sid, kind, inherited, note))

            if mask & ADS_RIGHT_GENERIC_ALL:
                add(EdgeType.GENERIC_ALL)
            if mask & ADS_RIGHT_WRITE_DAC:
                add(EdgeType.WRITE_DACL)
            if mask & ADS_RIGHT_WRITE_OWNER:
                add(EdgeType.WRITE_OWNER)
            if mask & ADS_RIGHT_GENERIC_WRITE:
                add(EdgeType.GENERIC_WRITE)
            if mask & ADS_RIGHT_DS_WRITE_PROP and obj_guid == GUID_MEMBER_ATTR:
                add(EdgeType.ADD_MEMBER, "WriteProperty on member")
            if mask & ADS_RIGHT_DS_CONTROL_ACCESS:
                if obj_guid == GUID_FORCE_CHANGE_PASSWORD:
                    add(EdgeType.FORCE_CHANGE_PASSWORD)
                elif obj_guid == GUID_DS_REPL_GET_CHANGES:
                    repl_get.add(src)
                elif obj_guid == GUID_DS_REPL_GET_CHANGES_ALL:
                    repl_all.add(src)

        for sid in repl_get & repl_all:
            out.append(ADEdge(sid, target_sid, EdgeType.HAS_DCSYNC, note="DS-Replication-Get-Changes(-All)"))
        return out


def _escape(value: str) -> str:
    """RFC 4515 filter escaping - prevents LDAP filter injection."""
    replacements = {"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\0": r"\00", "/": r"\2f"}
    return "".join(replacements.get(ch, ch) for ch in value)
