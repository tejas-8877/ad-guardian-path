"""Endpoint -> identity -> attack-path correlation tests."""

from __future__ import annotations

import pytest

from app.connectors.mock_ad import MockADConnector
from app.services.correlation import (
    IDENTITY_UNAVAILABLE,
    analyze_endpoint,
    find_computer,
    list_endpoints,
)
from app.services.graph import AttackGraph


@pytest.fixture()
def snapshot():
    connector = MockADConnector()
    connector.connect()
    principals, edges = connector.collect_all()
    return principals, edges, AttackGraph.build(principals, edges)


def test_find_computer_is_case_and_suffix_insensitive(snapshot) -> None:
    principals, _, _ = snapshot
    assert find_computer(principals, "dc01").display_name == "DC01"
    assert find_computer(principals, "DC01$").display_name == "DC01"
    assert find_computer(principals, "dc01.corp.local").display_name == "DC01"
    assert find_computer(principals, "nope-01") is None


def test_correlates_session_identity_and_blast_radius(snapshot) -> None:
    principals, _, graph = snapshot
    impact = analyze_endpoint(graph, principals, "SQL01", status="malicious")

    assert impact.identity == "svc_sql"           # from the HasSession edge
    assert impact.identity_source.startswith("graph:")
    assert impact.blast_radius.total >= 1
    assert impact.risk in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def test_privileged_identity_is_tier0_exposed(snapshot) -> None:
    principals, _, graph = snapshot
    impact = analyze_endpoint(
        graph, principals, "SQL01", status="compromised", logged_on_user="t.admin"
    )
    assert impact.identity == "t.admin"
    assert impact.identity_source == "reported_logon"
    assert impact.tier0_exposed is True
    assert impact.attack_path_count > 0
    assert impact.shortest_path[0] == "t.admin"


def test_missing_identity_still_returns_endpoint_data(snapshot) -> None:
    principals, _, graph = snapshot
    impact = analyze_endpoint(graph, principals, "WKS-014", status="suspicious")
    if impact.identity is None:
        assert IDENTITY_UNAVAILABLE in impact.notes
    assert impact.endpoint == "WKS-014"


def test_unknown_endpoint_degrades_gracefully(snapshot) -> None:
    principals, _, graph = snapshot
    impact = analyze_endpoint(graph, principals, "UNKNOWN-HOST")
    assert impact.identity is None
    assert IDENTITY_UNAVAILABLE in impact.notes
    assert impact.risk == "LOW"


def test_status_increases_risk(snapshot) -> None:
    principals, _, graph = snapshot
    clean = analyze_endpoint(graph, principals, "SQL01", status="clean")
    bad = analyze_endpoint(graph, principals, "SQL01", status="malicious")
    assert bad.risk_score > clean.risk_score


def test_endpoint_inventory_lists_computers(snapshot) -> None:
    principals, edges, _ = snapshot
    inventory = list_endpoints(principals, edges)
    assert {e["hostname"] for e in inventory} >= {"DC01", "SQL01", "WKS-014"}
    assert all("identity" in e for e in inventory)
