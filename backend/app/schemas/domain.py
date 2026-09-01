"""Response models for assets, findings, graph and malware endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class PrincipalOut(BaseModel):
    object_sid: str
    dn: str
    sam_account_name: str
    display_name: str
    principal_type: str
    enabled: bool
    is_admin_count: bool
    is_domain_controller: bool
    spns: list[str] = Field(default_factory=list)
    password_last_set: datetime | None = None
    last_logon: datetime | None = None
    operating_system: str | None = None
    description: str | None = None


class Page(BaseModel):
    total: int
    page: int
    page_size: int


class PrincipalPage(Page):
    items: list[PrincipalOut]


class FindingOut(BaseModel):
    id: str
    rule: str
    title: str
    severity: str
    principal_sid: str
    principal_name: str
    description: str
    remediation: str
    mitre_technique: str


class FindingPage(Page):
    items: list[FindingOut]


class PathStepOut(BaseModel):
    source_sid: str
    source_name: str
    target_sid: str
    target_name: str
    edge_type: str
    cost: float


class AttackPathOut(BaseModel):
    source_sid: str
    source_name: str
    target_sid: str
    target_name: str
    hops: int
    total_cost: float
    severity: str
    steps: list[PathStepOut]


class GraphNode(BaseModel):
    id: str
    label: str
    type: str
    tier0: bool = False
    enabled: bool = True


class GraphEdge(BaseModel):
    id: str | None = None
    source: str
    target: str
    type: str


class GraphOut(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class SeverityCount(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class DashboardOut(BaseModel):
    domain: str
    risk_score: int
    collected_at: datetime
    users: int
    groups: int
    computers: int
    gpos: int
    findings_by_severity: SeverityCount
    tier0_exposed_principals: int
    critical_paths: list[AttackPathOut]
    top_rules: list[dict[str, Any]]


class ScanResultOut(BaseModel):
    filename: str
    size_bytes: int
    md5: str
    sha1: str
    sha256: str
    entropy: float
    file_type: str
    packed: bool
    verdict: str
    score: int
    yara_matches: list[str]
    suspicious_imports: list[dict[str, str]]
    indicators: list[str]
    pe_info: dict[str, Any] | None
    sections: list[dict[str, Any]]


# --- AD connection / collection ---------------------------------------
class ADHealthOut(BaseModel):
    connected: bool
    connector: str
    domain: str
    server: str
    protocol: str
    port: int
    base_dn: str
    latency_ms: float | None = None
    error: str | None = None


class CollectionStatsOut(BaseModel):
    status: str
    connector: str
    domain: str
    users: int
    groups: int
    computers: int
    gpos: int
    ous: int
    relationships: int
    findings: int
    risk_score: int
    duration_ms: int
    collected_at: datetime


# --- remediation simulator ---------------------------------------------
class RemovableEdgeOut(BaseModel):
    edge_id: str
    source_sid: str
    source_name: str
    target_sid: str
    target_name: str
    edge_type: str
    note: str | None = None


class GraphMetricsOut(BaseModel):
    risk_score: int
    attack_paths: int
    tier0_exposure: int
    reachable_privileged: int
    average_path_cost: float
    shortest_path_hops: int | None = None


class SimulationRequest(BaseModel):
    edge_id: str | None = None
    edge_ids: list[str] = Field(default_factory=list)
    action: str = Field(default="remove", pattern="^remove$")
    reason: str = Field(default="Remove excessive privilege", max_length=200)

    def targets(self) -> list[str]:
        ids = [*self.edge_ids]
        if self.edge_id:
            ids.append(self.edge_id)
        return list(dict.fromkeys(ids))


class SimulationCompareRequest(BaseModel):
    candidates: list[list[str]] = Field(default_factory=list)


class SimulationOut(BaseModel):
    before: GraphMetricsOut
    after: GraphMetricsOut
    simulation: dict[str, Any]
    risk_reduction: int
    risk_reduction_pct: float
    paths_eliminated: int
    tier0_exposure_reduction: int
    eliminated_paths: list[AttackPathOut]
    remaining_paths: list[AttackPathOut]
    notice: str


# --- compromise impact --------------------------------------------------
class EndpointOut(BaseModel):
    endpoint_id: str
    hostname: str
    operating_system: str | None = None
    domain_controller: bool = False
    identity: str | None = None
    identity_source: str = "none"


class BlastRadiusOut(BaseModel):
    users: int
    groups: int
    computers: int
    privileged_targets: int
    total: int


class CompromiseImpactOut(BaseModel):
    endpoint: str
    endpoint_sid: str | None = None
    status: str
    identity: str | None = None
    identity_sid: str | None = None
    identity_source: str
    risk: str
    risk_score: int
    blast_radius: BlastRadiusOut
    tier0_exposed: bool
    attack_path_count: int
    shortest_path: list[str]
    shortest_path_hops: int | None = None
    paths: list[AttackPathOut]
    notes: list[str]
