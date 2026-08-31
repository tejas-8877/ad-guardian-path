"""Compromise Impact Analysis: endpoint -> identity -> attack path.

Given a (possibly compromised) endpoint, correlate it to an AD computer
object and to the identity most recently associated with it, then reuse the
existing attack-graph engine to quantify the blast radius.

Purely analytical: nothing is executed, nothing is written to AD.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Sequence

from app.connectors.base import ADEdge, ADPrincipal, EdgeType, PrincipalType
from app.services.graph import AttackGraph, AttackPath

log = logging.getLogger("adshield.correlation")

IDENTITY_UNAVAILABLE = "Identity correlation unavailable"

# Edge types that imply "this identity was/can be present on this host".
SESSION_EDGES = (EdgeType.SESSION, EdgeType.CAN_RDP, EdgeType.ADMIN_TO)


@dataclass(frozen=True, slots=True)
class BlastRadius:
    users: int
    groups: int
    computers: int
    privileged_targets: int
    total: int


@dataclass(frozen=True, slots=True)
class CompromiseImpact:
    endpoint: str
    endpoint_sid: str | None
    status: str
    identity: str | None
    identity_sid: str | None
    identity_source: str
    risk: str
    risk_score: int
    blast_radius: BlastRadius
    tier0_exposed: bool
    attack_path_count: int
    shortest_path: list[str]
    shortest_path_hops: int | None
    paths: list[AttackPath] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _normalize(hostname: str) -> str:
    return hostname.strip().lower().split(".")[0].rstrip("$")


def find_computer(principals: Sequence[ADPrincipal], hostname: str) -> ADPrincipal | None:
    needle = _normalize(hostname)
    for p in principals:
        if p.principal_type is not PrincipalType.COMPUTER:
            continue
        if _normalize(p.sam_account_name) == needle or _normalize(p.display_name) == needle:
            return p
    return None


def correlate_identity(
    graph: AttackGraph, computer_sid: str, hint: str | None = None
) -> tuple[ADPrincipal | None, str]:
    """Resolve the identity associated with an endpoint.

    Priority: explicit hint (e.g. logged-on user reported by the agent) ->
    inbound session/RDP/admin edges -> none.
    """
    if hint:
        needle = hint.strip().lower().split("\\")[-1].split("@")[0]
        for p in graph.principals.values():
            if p.sam_account_name.lower() == needle:
                return p, "reported_logon"

    for edge in graph.reverse.get(computer_sid, []):
        if edge.edge_type in SESSION_EDGES:
            principal = graph.principals.get(edge.source_sid)
            if principal and principal.principal_type is PrincipalType.USER:
                return principal, f"graph:{edge.edge_type.value}"

    for edge in graph.reverse.get(computer_sid, []):
        principal = graph.principals.get(edge.source_sid)
        if principal and principal.principal_type is PrincipalType.USER:
            return principal, f"graph:{edge.edge_type.value}"

    return None, "none"


def _blast_radius(graph: AttackGraph, sid: str) -> tuple[BlastRadius, set[str]]:
    reachable = graph.blast_radius(sid)
    tier0 = set(graph.tier0_sids())
    counts = {"user": 0, "group": 0, "computer": 0}
    for target in reachable:
        p = graph.principals.get(target)
        if p and p.principal_type.value in counts:
            counts[p.principal_type.value] += 1
    return (
        BlastRadius(
            users=counts["user"],
            groups=counts["group"],
            computers=counts["computer"],
            privileged_targets=len(reachable & tier0),
            total=len(reachable),
        ),
        reachable & tier0,
    )


def _risk_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def analyze_endpoint(
    graph: AttackGraph,
    principals: Sequence[ADPrincipal],
    hostname: str,
    status: str = "unknown",
    logged_on_user: str | None = None,
) -> CompromiseImpact:
    """Full endpoint -> identity -> attack-path correlation."""
    notes: list[str] = []
    computer = find_computer(principals, hostname)
    if computer is None:
        notes.append("No matching AD computer object; endpoint-level data only.")

    identity: ADPrincipal | None = None
    identity_source = "none"
    if computer is not None:
        identity, identity_source = correlate_identity(graph, computer.object_sid, logged_on_user)
    elif logged_on_user:
        needle = logged_on_user.strip().lower()
        identity = next(
            (p for p in principals if p.sam_account_name.lower() == needle), None
        )
        identity_source = "reported_logon" if identity else "none"

    pivot = identity or computer
    if pivot is None:
        return CompromiseImpact(
            endpoint=hostname,
            endpoint_sid=None,
            status=status,
            identity=None,
            identity_sid=None,
            identity_source="none",
            risk="LOW",
            risk_score=0,
            blast_radius=BlastRadius(0, 0, 0, 0, 0),
            tier0_exposed=False,
            attack_path_count=0,
            shortest_path=[],
            shortest_path_hops=None,
            notes=[*notes, IDENTITY_UNAVAILABLE],
        )

    if identity is None:
        notes.append(IDENTITY_UNAVAILABLE)

    radius, tier0_hits = _blast_radius(graph, pivot.object_sid)
    paths = graph.paths_to_tier0(pivot.object_sid, limit=25)
    shortest = min(paths, key=lambda p: (p.hops, p.total_cost), default=None)

    score = 0
    score += min(radius.total, 20) * 2                    # blast radius
    score += radius.privileged_targets * 12               # Tier-0 reachability
    score += min(len(paths), 8) * 4                       # number of viable paths
    if shortest is not None:
        score += max(0, 20 - (shortest.hops - 1) * 5)     # path length (shorter = worse)
    if pivot.is_admin_count:
        score += 10                                       # identity privilege
    if status in ("malicious", "compromised"):
        score += 20
    elif status == "suspicious":
        score += 10
    score = max(0, min(100, score))

    log.info(
        "correlation.endpoint host=%s identity=%s tier0=%s paths=%s risk=%s",
        hostname,
        identity.sam_account_name if identity else "-",
        bool(tier0_hits),
        len(paths),
        score,
    )

    return CompromiseImpact(
        endpoint=computer.display_name if computer else hostname,
        endpoint_sid=computer.object_sid if computer else None,
        status=status,
        identity=identity.sam_account_name if identity else None,
        identity_sid=identity.object_sid if identity else None,
        identity_source=identity_source,
        risk=_risk_level(score),
        risk_score=score,
        blast_radius=radius,
        tier0_exposed=bool(tier0_hits),
        attack_path_count=len(paths),
        shortest_path=(
            [shortest.source_name, *[s.target_name for s in shortest.steps]] if shortest else []
        ),
        shortest_path_hops=shortest.hops if shortest else None,
        paths=paths[:10],
        notes=notes,
    )


def list_endpoints(principals: Sequence[ADPrincipal], edges: Sequence[ADEdge]) -> list[dict]:
    """Endpoint inventory derived from AD computer objects + session edges."""
    graph = AttackGraph.build(principals, edges)
    out: list[dict] = []
    for p in principals:
        if p.principal_type is not PrincipalType.COMPUTER:
            continue
        identity, source = correlate_identity(graph, p.object_sid)
        out.append(
            {
                "endpoint_id": p.object_sid,
                "hostname": p.display_name,
                "operating_system": p.operating_system,
                "domain_controller": p.is_domain_controller,
                "identity": identity.sam_account_name if identity else None,
                "identity_source": source,
            }
        )
    return out
