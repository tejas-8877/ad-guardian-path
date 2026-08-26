"""Hygiene / misconfiguration detection rules over collected AD data."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Sequence

from app.connectors.base import ADPrincipal, PrincipalType

STALE_PASSWORD_DAYS = 365
STALE_ACCOUNT_DAYS = 90

SEVERITY_WEIGHT = {"critical": 25, "high": 12, "medium": 5, "low": 2}


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    rule: str
    title: str
    severity: str
    principal_sid: str
    principal_name: str
    description: str
    remediation: str
    mitre_technique: str


def _f(rule: str, p: ADPrincipal, **kw: str) -> Finding:
    return Finding(
        id=f"{rule}:{p.object_sid}",
        rule=rule,
        principal_sid=p.object_sid,
        principal_name=p.sam_account_name,
        **kw,  # type: ignore[arg-type]
    )


def evaluate(principals: Iterable[ADPrincipal], now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []

    for p in principals:
        if p.kerberos_preauth_disabled:
            findings.append(
                _f(
                    "AS_REP_ROASTABLE",
                    p,
                    title="Kerberos pre-authentication disabled",
                    severity="critical",
                    description=(
                        "The account does not require Kerberos pre-authentication, so any "
                        "unauthenticated domain host can request an AS-REP and crack it offline."
                    ),
                    remediation="Clear DONT_REQ_PREAUTH on the account and rotate its password.",
                    mitre_technique="T1558.004",
                )
            )

        if p.spns and p.principal_type is PrincipalType.USER:
            findings.append(
                _f(
                    "KERBEROASTABLE",
                    p,
                    title="Service account exposes SPN (Kerberoastable)",
                    severity="high" if not p.is_admin_count else "critical",
                    description=(
                        f"SPNs registered: {', '.join(p.spns)}. Any authenticated user can "
                        "request a service ticket and crack the account password offline."
                    ),
                    remediation=(
                        "Migrate to a Group Managed Service Account (gMSA) or enforce a "
                        "25+ character random password and remove privileged group membership."
                    ),
                    mitre_technique="T1558.003",
                )
            )

        if p.unconstrained_delegation:
            findings.append(
                _f(
                    "UNCONSTRAINED_DELEGATION",
                    p,
                    title="Unconstrained Kerberos delegation enabled",
                    severity="critical",
                    description=(
                        "TGTs of any authenticating principal - including Domain Admins - are "
                        "cached on this host and can be extracted for full domain compromise."
                    ),
                    remediation=(
                        "Switch to constrained delegation with protocol transition disabled, or "
                        "add privileged accounts to the Protected Users group."
                    ),
                    mitre_technique="T1550.003",
                )
            )

        if p.password_never_expires and p.principal_type is PrincipalType.USER:
            findings.append(
                _f(
                    "PASSWORD_NEVER_EXPIRES",
                    p,
                    title="Password set to never expire",
                    severity="medium",
                    description="Credential lifetime is unbounded, extending the window of a leak.",
                    remediation="Remove DONT_EXPIRE_PASSWORD and enforce a rotation policy.",
                    mitre_technique="T1078.002",
                )
            )

        if p.password_last_set and now - p.password_last_set > timedelta(days=STALE_PASSWORD_DAYS):
            age = (now - p.password_last_set).days
            findings.append(
                _f(
                    "STALE_PASSWORD",
                    p,
                    title=f"Password unchanged for {age} days",
                    severity="high" if p.is_admin_count else "medium",
                    description="Long-lived credentials are prime targets for offline cracking.",
                    remediation="Force a password reset at next logon.",
                    mitre_technique="T1110",
                )
            )

        if (
            p.enabled
            and p.last_logon
            and now - p.last_logon > timedelta(days=STALE_ACCOUNT_DAYS)
            and p.principal_type is PrincipalType.USER
        ):
            findings.append(
                _f(
                    "DORMANT_ACCOUNT",
                    p,
                    title="Enabled but dormant account",
                    severity="medium",
                    description=(
                        f"No logon in {(now - p.last_logon).days} days while the account "
                        "remains enabled - an unmonitored foothold."
                    ),
                    remediation="Disable the account and move it to a quarantine OU.",
                    mitre_technique="T1078",
                )
            )

        if p.description and any(
            token in p.description.lower() for token in ("pass", "pwd", "creds")
        ):
            findings.append(
                _f(
                    "SECRET_IN_DESCRIPTION",
                    p,
                    title="Possible credential in object description",
                    severity="critical",
                    description=(
                        "The description attribute is world-readable to any authenticated user "
                        "and appears to contain credential material."
                    ),
                    remediation="Clear the attribute and rotate any exposed secret immediately.",
                    mitre_technique="T1552.001",
                )
            )

    findings.sort(key=lambda f: (-SEVERITY_WEIGHT[f.severity], f.principal_name))
    return findings


def risk_score(findings: Sequence[Finding], principal_count: int) -> int:
    """0-100 domain risk posture. Higher == worse."""
    if principal_count <= 0:
        return 0
    raw = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    normalized = raw / max(principal_count, 1) * 12
    return max(0, min(100, round(normalized)))
