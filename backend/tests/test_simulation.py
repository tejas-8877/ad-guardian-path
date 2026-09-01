"""Remediation-simulator tests: correctness + source-graph immutability."""

from __future__ import annotations

import copy

import pytest

from app.connectors.mock_ad import MockADConnector
from app.services.findings import evaluate
from app.services.graph import AttackGraph
from app.services.simulation import (
    compare_remediations,
    edge_id,
    measure,
    parse_edge_id,
    simulate_removal,
)


@pytest.fixture()
def domain():
    connector = MockADConnector()
    connector.connect()
    principals, edges = connector.collect_all()
    return principals, edges, evaluate(principals)


def _generic_all_edge(edges):
    return next(e for e in edges if e.edge_type.value == "GenericAll")


def test_edge_id_roundtrip(domain) -> None:
    _, edges, _ = domain
    e = edges[0]
    assert parse_edge_id(edge_id(e)) == (e.source_sid, e.edge_type.value, e.target_sid)


def test_parse_edge_id_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        parse_edge_id("not-an-edge")


def test_simulation_reduces_risk_and_paths(domain) -> None:
    principals, edges, findings = domain
    target = _generic_all_edge(edges)
    result = simulate_removal(principals, edges, findings, [edge_id(target)])

    assert result.after.attack_paths <= result.before.attack_paths
    assert result.after.risk_score <= result.before.risk_score
    assert result.risk_reduction == result.before.risk_score - result.after.risk_score
    assert result.notice.startswith("SIMULATION")
    assert result.removed_edges[0]["edge_type"] == "GenericAll"


def test_simulation_does_not_mutate_source_graph(domain) -> None:
    principals, edges, findings = domain
    before_snapshot = copy.deepcopy(edges)
    graph = AttackGraph.build(principals, edges)
    before = measure(graph, findings, len(principals))

    simulate_removal(principals, edges, findings, [edge_id(_generic_all_edge(edges))])

    assert edges == before_snapshot, "source edge list must never be mutated"
    after = measure(AttackGraph.build(principals, edges), findings, len(principals))
    assert after == before, "persistent graph metrics must be unchanged"


def test_simulation_unknown_edge_raises(domain) -> None:
    principals, edges, findings = domain
    with pytest.raises(LookupError):
        simulate_removal(principals, edges, findings, ["S-1-0-0|GenericAll|S-1-0-1"])


def test_simulation_requires_an_edge(domain) -> None:
    principals, edges, findings = domain
    with pytest.raises(ValueError):
        simulate_removal(principals, edges, findings, [])


def test_compare_remediations_orders_by_impact(domain) -> None:
    principals, edges, findings = domain
    candidates = [[edge_id(e)] for e in edges if e.edge_type.value in ("GenericAll", "GpLink")]
    results = compare_remediations(principals, edges, findings, candidates)
    assert len(results) == len(candidates)
    assert results == sorted(results, key=lambda r: (-r.risk_reduction, -r.paths_eliminated))
