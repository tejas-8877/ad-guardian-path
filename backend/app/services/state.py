"""Cached collection snapshot shared by all read endpoints."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone

from app.connectors.base import ADEdge, ADPrincipal
from app.connectors.factory import get_connector
from app.services.findings import Finding, evaluate, risk_score
from app.services.graph import AttackGraph


@dataclass(slots=True)
class Snapshot:
    collected_at: datetime
    domain: str
    principals: list[ADPrincipal]
    edges: list[ADEdge]
    graph: AttackGraph
    findings: list[Finding]
    risk_score: int


_lock = threading.Lock()
_snapshot: Snapshot | None = None


def collect() -> Snapshot:
    """Run a fresh collection and replace the cached snapshot."""
    global _snapshot
    connector = get_connector()
    principals, edges = connector.collect_all()
    findings = evaluate(principals)
    snapshot = Snapshot(
        collected_at=datetime.now(timezone.utc),
        domain=connector.domain,
        principals=principals,
        edges=edges,
        graph=AttackGraph.build(principals, edges),
        findings=findings,
        risk_score=risk_score(findings, len(principals)),
    )
    with _lock:
        _snapshot = snapshot
    return snapshot


def current() -> Snapshot:
    with _lock:
        snap = _snapshot
    return snap if snap is not None else collect()
