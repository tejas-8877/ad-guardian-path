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
