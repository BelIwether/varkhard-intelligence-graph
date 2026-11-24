from dataclasses import replace
from pathlib import Path

import pytest

from varkhard.dashboard import read_graph
from varkhard.demo import seed_demo
from varkhard.detection import Finding
from varkhard.investigation import InvestigationBuilder
from varkhard.models import Agent, Interaction, Resource
from varkhard.store import GraphStore

_DEMO = Path(__file__).resolve().parents[1] / "examples" / "synthetic-demo.rl"


@pytest.fixture
def demo_graph():
    with GraphStore(_DEMO, read_only=True) as store:
        return read_graph(store, _DEMO.name)


def test_suspicious_trace_keeps_order_directions_and_recorded_outcomes(demo_graph):
    finding = demo_graph.findings[2]
    trace = finding.investigation
    assert trace.complete
    assert trace.origin == trace.steps[0]
    assert trace.trigger == trace.steps[-1]
    assert [step.record_node_id for step in trace.steps] == [
        f"interaction:{event_id}" for event_id in finding.evidence["interaction_ids"]
    ]
    assert [step.action for step in trace.steps] == ["read", "handoff", "export"]
    assert [step.outcome for step in trace.steps] == ["success", "success", "success"]
    assert [step.occurred_at for step in trace.steps] == [1767225600, 1767225660, 1767225780]
    assert set(trace.affected_node_ids) == {
        "agent:agent-research", "agent:agent-relay", "resource:resource-test-ledger",
        "resource:resource-demo-outbox", *[step.record_node_id for step in trace.steps],
    }

    edges = {edge.id: edge for edge in demo_graph.edges}
    assert [
        (edges[edge_id].source, edges[edge_id].target)
        for edge_id in trace.edge_ids if edges[edge_id].kind == "TRIGGERS"
    ] == [
        (trace.steps[0].record_node_id, trace.steps[1].record_node_id),
        (trace.steps[1].record_node_id, trace.steps[2].record_node_id),
    ]
    assert [
        (edges[edge_id].source, edges[edge_id].target)
        for edge_id in trace.edge_ids if edges[edge_id].kind == "HANDED_TO"
    ] == [(trace.steps[1].record_node_id, "agent:agent-relay")]
    assert len(trace.node_ids) == len(set(trace.node_ids))
    assert len(trace.edge_ids) == len(set(trace.edge_ids))
    assert set(trace.node_ids) <= {node.id for node in demo_graph.nodes}
    for step in trace.steps:
        assert step.record_node_id in step.node_ids
        assert set(step.node_ids) <= set(trace.node_ids)
        for edge_id in step.edge_ids:
            assert {edges[edge_id].source, edges[edge_id].target} <= set(step.node_ids)


def test_excessive_permission_trace_has_only_grant_and_baseline_records(demo_graph):
    trace = demo_graph.findings[1].investigation
    assert trace.complete
    assert trace.origin == trace.trigger == trace.steps[0]
    assert [step.record_node_id for step in trace.steps] == [
        "permission:grant-archive-delete", "permission:policy-archive-read", "permission:policy-archive-write",
    ]
    assert [step.action for step in trace.steps] == ["delete", "read", "write"]
    assert all(step.outcome is None and step.occurred_at is None for step in trace.steps)
    assert trace.affected_node_ids == [
        "permission:grant-archive-delete", "agent:agent-maintenance", "resource:resource-sample-archive",
    ]
    assert set(trace.edge_ids) == {
        edge.id for edge in demo_graph.edges
        if {edge.source, edge.target} <= set(trace.node_ids)
    }


@pytest.mark.parametrize("outcome", ["denied", "success"])
def test_unauthorized_trace_keeps_the_flagged_outcome_separate_from_the_origin(tmp_path, outcome):
    path = tmp_path / "trace.rl"
    parent = Interaction("origin", "agent", "resource", "read", "success", 100)
    child = Interaction("trigger", "agent", "resource", "write", outcome, 120, parent_id="origin")
    with GraphStore(path) as store:
        store.ingest(
            agents=[Agent("agent", "Test Agent")],
            resources=[Resource("resource", "Test Resource", "internal", "internal")],
            interactions=[parent, child],
        )
        graph = read_graph(store, path.name)

    trace = _event_finding(graph, "trigger").investigation
    assert trace.complete
    assert trace.origin.record_node_id == "interaction:origin"
    assert trace.trigger.record_node_id == "interaction:trigger"
    assert trace.trigger.outcome == outcome
    assert trace.trigger.action == "write"
    assert trace.trigger.occurred_at == 120
    assert [step.outcome for step in trace.steps] == ["success", outcome]
    assert [edge.source for edge in graph.edges if edge.kind == "TRIGGERS" and edge.id in trace.edge_ids] == [
        "interaction:origin",
    ]


@pytest.mark.parametrize("damage", [
    pytest.param(None, id="verified-recipient"),
    pytest.param(
        "MATCH (:Interaction {id: 'attempt'})-[link:HANDED_TO]->(:AIAgent) DELETE link",
        id="missing-recipient-link",
    ),
    pytest.param(
        "MATCH (event:Interaction {id: 'attempt'}), (agent:AIAgent {id: 'other'}) "
        "CREATE (event)-[:HANDED_TO]->(agent)",
        id="ambiguous-recipient-link",
    ),
])
def test_denied_handoff_trace_keeps_only_the_verified_recipient(tmp_path, damage):
    path = tmp_path / "handoff.rl"
    event = Interaction("attempt", "sender", "resource", "handoff", "denied", 120, recipient_id="recipient")
    with GraphStore(path) as store:
        store.ingest(
            agents=[Agent("sender", "Sender"), Agent("recipient", "Recipient"), Agent("other", "Other agent")],
            resources=[Resource("resource", "Test Resource", "internal", "internal")],
            interactions=[event],
        )
        if damage is not None:
            store.query(damage)
        graph = read_graph(store, path.name)

    assert graph.interactions == [event]
    trace = _event_finding(graph, event.id).investigation
    assert trace.origin == trace.trigger == trace.steps[0]
    assert trace.trigger.outcome == "denied"
    assert trace.complete == (damage is None)

    expected_nodes = {"agent:sender", "resource:resource", "interaction:attempt"}
    expected_kinds = {"PERFORMED", "TARGETS"}
    if damage is None:
        expected_nodes.add("agent:recipient")
        expected_kinds.add("HANDED_TO")
    assert set(trace.trigger.node_ids) == set(trace.affected_node_ids) == expected_nodes
    assert {edge.kind for edge in graph.edges if edge.id in trace.edge_ids} == expected_kinds


def test_missing_parent_edge_retains_only_the_verified_event(tmp_path):
    path = tmp_path / "missing-parent.rl"
    with GraphStore(path) as store:
        store.ingest(
            agents=[Agent("agent", "Test Agent")],
            resources=[Resource("resource", "Test Resource", "internal", "internal")],
            interactions=[
                Interaction("origin", "agent", "resource", "read", "success", 100),
                Interaction("trigger", "agent", "resource", "write", "denied", 120, parent_id="origin"),
            ],
        )
        store.query("MATCH (:Interaction {id: 'origin'})-[r:TRIGGERS]->(:Interaction {id: 'trigger'}) DELETE r")
        graph = read_graph(store, path.name)

    trace = _event_finding(graph, "trigger").investigation
    assert not trace.complete
    assert trace.origin == trace.trigger == trace.steps[0]
    assert trace.origin.record_node_id == "interaction:trigger"
    assert "interaction:origin" not in trace.node_ids
    assert all(edge.kind != "TRIGGERS" for edge in graph.edges if edge.id in trace.edge_ids)


def test_cycles_do_not_create_a_backwards_or_repeated_trace(tmp_path):
    path = tmp_path / "cycle.rl"
    with GraphStore(path) as store:
        store.ingest(
            agents=[Agent("agent", "Test Agent")],
            resources=[Resource("resource", "Test Resource", "internal", "internal")],
            interactions=[
                Interaction("first", "agent", "resource", "read", "success", 100, parent_id="second"),
                Interaction("second", "agent", "resource", "write", "denied", 120, parent_id="first"),
            ],
        )
        graph = read_graph(store, path.name)

    trace = _event_finding(graph, "second").investigation
    assert not trace.complete
    assert [step.record_node_id for step in trace.steps] == ["interaction:first", "interaction:second"]
    assert [
        (edge.source, edge.target) for edge in graph.edges
        if edge.kind == "TRIGGERS" and edge.id in trace.edge_ids
    ] == [("interaction:first", "interaction:second")]


def test_inconsistent_suspicious_chain_yields_only_supported_segments(demo_graph):
    finding = demo_graph.findings[2]
    read_id, handoff_id, export_id = finding.evidence["interaction_ids"]
    interactions = [
        replace(event, outcome="denied") if event.id == handoff_id else event
        for event in demo_graph.interactions
    ]
    builder = InvestigationBuilder(demo_graph.nodes, demo_graph.edges, demo_graph.permissions, interactions)
    trace = builder.build(Finding(finding.rule_id, finding.explanation, finding.evidence))

    assert not trace.complete
    assert trace.origin.record_node_id == f"interaction:{read_id}"
    assert trace.trigger.record_node_id == f"interaction:{export_id}"
    assert [step.action for step in trace.steps] == ["read", "export"]
    assert f"interaction:{handoff_id}" not in trace.node_ids
    assert all(edge.kind != "TRIGGERS" for edge in demo_graph.edges if edge.id in trace.edge_ids)


@pytest.mark.parametrize(("kind", "source_id", "target_id", "target_kind"), [
    ("TRIGGERS", "interaction-ledger-handoff", "interaction-outbox-export", "interaction"),
    ("HANDED_TO", "interaction-ledger-handoff", "agent-relay", "agent"),
])
def test_suspicious_trace_never_reconstructs_a_removed_relationship(tmp_path, kind, source_id, target_id, target_kind):
    path = tmp_path / "missing-relationship.rl"
    with GraphStore(path) as store:
        seed_demo(store)
        original = read_graph(store, path.name)
        store.query(
            f"MATCH (source:Interaction {{id: $source_id}})-[edge:{kind}]->(target {{id: $target_id}}) DELETE edge",
            {"source_id": source_id, "target_id": target_id},
        )
        graph = read_graph(store, path.name)

    finding = next(finding for finding in original.findings if finding.rule_id == "suspicious_chain")
    removed = next(
        edge for edge in original.edges
        if (edge.kind, edge.source, edge.target) == (kind, f"interaction:{source_id}", f"{target_kind}:{target_id}")
    )
    assert removed.id in finding.investigation.edge_ids
    assert removed.id not in {edge.id for edge in graph.edges}
    assert graph.interactions == original.interactions
    assert original.evidence_quality.status == "complete"
    assert original.evidence_quality.invalid_records == original.evidence_quality.invalid_relationships == 0
    assert graph.evidence_quality.status == "incomplete"
    assert graph.evidence_quality.invalid_relationships >= 1
    assert all(finding.rule_id != "suspicious_chain" for finding in graph.findings)

    builder = InvestigationBuilder(graph.nodes, graph.edges, graph.permissions, graph.interactions)
    partial = builder.build(Finding(finding.rule_id, finding.explanation, finding.evidence))
    assert not partial.complete
    assert [step.record_node_id for step in partial.steps] == [
        step.record_node_id for step in finding.investigation.steps
    ]
    assert partial.edge_ids == [edge_id for edge_id in finding.investigation.edge_ids if edge_id != removed.id]
    if kind == "HANDED_TO":
        handoff = next(step for step in partial.steps if step.record_node_id == removed.source)
        assert removed.target not in handoff.node_ids


@pytest.mark.parametrize("damage", [
    "MATCH (:AIAgent)-[edge:PERFORMED]->(:Interaction {id: 'interaction-ledger-handoff'}) DELETE edge",
    "MATCH (event:Interaction {id: 'interaction-ledger-handoff'}) SET event.occurred_at = 4611686018427387904",
])
def test_malformed_chain_records_dont_block_unrelated_findings(tmp_path, damage):
    path = tmp_path / "malformed.rl"
    with GraphStore(path) as store:
        seed_demo(store)
        store.query(damage)
        graph = read_graph(store, path.name)

    assert [finding.rule_id for finding in graph.findings] == ["unauthorized_access", "excessive_permission"]
    assert graph.evidence_quality.status == "incomplete"
    assert graph.evidence_quality.invalid_records >= 1
    node_ids = {node.id for node in graph.nodes}
    assert "interaction:interaction-ledger-handoff" not in node_ids
    assert all({edge.source, edge.target} <= node_ids for edge in graph.edges)


def test_unknown_event_and_unrelated_permission_cannot_create_a_trace(demo_graph):
    finding = demo_graph.findings[0]
    evidence = {
        **finding.evidence,
        "interaction_id": "unknown-event",
        "related_grant_ids": ["grant-archive-delete"],
    }
    builder = InvestigationBuilder(demo_graph.nodes, demo_graph.edges, demo_graph.permissions, demo_graph.interactions)
    trace = builder.build(Finding(finding.rule_id, finding.explanation, evidence))

    assert not trace.complete
    assert trace.origin is None
    assert trace.trigger is None
    assert trace.steps == trace.node_ids == trace.edge_ids == []


def _event_finding(graph, event_id):
    return next(finding for finding in graph.findings if finding.evidence.get("interaction_id") == event_id)
