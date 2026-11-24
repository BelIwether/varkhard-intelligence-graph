import pytest

from varkhard.dashboard import read_graph
from varkhard.demo import seed_demo
from varkhard.detection import detect_findings
from varkhard.store import GraphStore


_UNAUTHORIZED = "unauthorized_access"
_EXCESSIVE = "excessive_permission"
_CHAIN = "suspicious_chain"
_DENIED_EVENT = "interaction:interaction-catalog-write-denied"
_DEMO_RULES = [_UNAUTHORIZED, _EXCESSIVE, _CHAIN]
_EVIDENCE_RECORD_KINDS = {
    "agent_id": "agent",
    "sender_agent_id": "agent",
    "recipient_agent_id": "agent",
    "resource_id": "resource",
    "source_resource_id": "resource",
    "destination_resource_id": "resource",
    "permission_id": "permission",
    "related_grant_ids": "permission",
    "related_baseline_ids": "permission",
    "interaction_id": "interaction",
    "interaction_ids": "interaction",
}


def _read_views(path, query, params=None):
    with GraphStore(path) as store:
        seed_demo(store)
        store.query(query, params)
    with GraphStore(path, read_only=True) as store:
        graph = read_graph(store, path.name)
        core = detect_findings(store)

    assert [(finding.rule_id, finding.explanation, finding.evidence) for finding in graph.findings] == [
        (finding.rule_id, finding.explanation, finding.evidence) for finding in core
    ]
    return graph


def _assert_resolved_evidence(graph):
    nodes = {node.id for node in graph.nodes}
    edges = {edge.id: edge for edge in graph.edges}
    assert all({edge.source, edge.target} <= nodes for edge in edges.values())

    for finding in graph.findings:
        trace = finding.investigation
        for evidence in [finding.evidence, *finding.evidence.get("interactions", [])]:
            for field, kind in _EVIDENCE_RECORD_KINDS.items():
                if field not in evidence:
                    continue
                value = evidence[field]
                record_ids = value if isinstance(value, list) else [value]
                assert {f"{kind}:{record_id}" for record_id in record_ids} <= nodes
        assert set(finding.node_ids) <= nodes
        assert set(finding.edge_ids) <= edges.keys()
        assert set(trace.node_ids) <= nodes
        assert set(trace.edge_ids) <= edges.keys()
        assert set(trace.affected_node_ids) <= set(trace.node_ids)
        for step in [trace.origin, trace.trigger, *trace.steps]:
            if step is None:
                continue
            assert step.record_node_id in step.node_ids
            assert set(step.node_ids) <= set(trace.node_ids)
            assert set(step.edge_ids) <= set(trace.edge_ids)


@pytest.mark.parametrize("damage", [
    pytest.param(
        "MATCH (event:Interaction {id: 'interaction-catalog-write-denied'}) "
        "SET event.occurred_at = 4611686018427387904",
        id="out-of-range-timestamp",
    ),
    pytest.param(
        "MATCH (event:Interaction {id: 'interaction-catalog-write-denied'}) SET event.outcome = 'unknown'",
        id="invalid-outcome",
    ),
    pytest.param(
        "MATCH (:Interaction {id: 'interaction-catalog-write-denied'})-[link:TARGETS]->(:Resource) DELETE link",
        id="missing-target",
    ),
    pytest.param(
        "MATCH (agent:AIAgent {id: 'agent-catalog'}), "
        "(event:Interaction {id: 'interaction-catalog-write-denied'}) "
        "CREATE (agent)-[:PERFORMED]->(event)",
        id="ambiguous-performer",
    ),
    pytest.param(
        "MATCH (event:Interaction {id: 'interaction-catalog-write-denied'}), "
        "(resource:Resource {id: 'resource-sample-archive'}) "
        "CREATE (event)-[:TARGETS]->(resource)",
        id="ambiguous-target",
    ),
])
def test_discarded_trigger_cannot_support_an_unauthorized_finding(tmp_path, damage):
    graph = _read_views(tmp_path / "snapshot.rl", damage)

    assert graph.evidence_quality.status == "incomplete"
    assert graph.evidence_quality.invalid_records >= 1
    assert _DENIED_EVENT not in {node.id for node in graph.nodes}
    assert [finding.rule_id for finding in graph.findings] == [_EXCESSIVE, _CHAIN]
    _assert_resolved_evidence(graph)


def test_deleted_parent_cannot_leave_a_chain_or_dangling_references(tmp_path):
    graph = _read_views(
        tmp_path / "snapshot.rl",
        "MATCH (event:Interaction {id: 'interaction-ledger-handoff'}) DETACH DELETE event",
    )

    node_ids = {node.id for node in graph.nodes}
    assert graph.evidence_quality.status == "incomplete"
    assert graph.evidence_quality.invalid_relationships >= 1
    assert "interaction:interaction-ledger-handoff" not in node_ids
    assert "interaction:interaction-outbox-export" in node_ids
    assert [finding.rule_id for finding in graph.findings] == [_UNAUTHORIZED, _EXCESSIVE]
    _assert_resolved_evidence(graph)


def test_invalid_resource_enum_excludes_dependent_records_and_findings(tmp_path):
    graph = _read_views(
        tmp_path / "snapshot.rl",
        "MATCH (resource:Resource {id: 'resource-demo-outbox'}) SET resource.boundary = 'unknown'",
    )

    assert graph.evidence_quality.status == "incomplete"
    assert graph.evidence_quality.invalid_records >= 1
    assert {
        "resource:resource-demo-outbox",
        "interaction:interaction-outbox-export",
        "permission:grant-outbox-export",
        "permission:policy-outbox-export",
    }.isdisjoint(node.id for node in graph.nodes)
    assert [finding.rule_id for finding in graph.findings] == [_UNAUTHORIZED, _EXCESSIVE]
    _assert_resolved_evidence(graph)


@pytest.mark.parametrize(("agent_id", "resource_id", "action", "dependent_rule"), [
    ("agent-preview", "resource-sample-catalog", "write", _UNAUTHORIZED),
    ("agent-maintenance", "resource-sample-archive", "delete", _EXCESSIVE),
])
def test_invalid_permission_cannot_be_counted_as_an_absent_grant_or_baseline(
    tmp_path, agent_id, resource_id, action, dependent_rule,
):
    graph = _read_views(
        tmp_path / "snapshot.rl",
        "MATCH (agent:AIAgent {id: $agent_id}), (resource:Resource {id: $resource_id}) "
        "CREATE (agent)-[:HAS_PERMISSION]->"
        "(:Permission {id: 'unclassified-permission', action: $action, kind: 'unknown'})"
        "-[:ON_RESOURCE]->(resource)",
        {"agent_id": agent_id, "resource_id": resource_id, "action": action},
    )

    assert graph.evidence_quality.status == "incomplete"
    assert graph.evidence_quality.invalid_records >= 1
    assert "permission:unclassified-permission" not in {node.id for node in graph.nodes}
    assert [finding.rule_id for finding in graph.findings] == [rule for rule in _DEMO_RULES if rule != dependent_rule]
    _assert_resolved_evidence(graph)


def test_mislabeled_permission_cannot_be_counted_as_an_absent_grant(tmp_path):
    graph = _read_views(
        tmp_path / "snapshot.rl",
        "MATCH (agent:AIAgent {id: 'agent-preview'}), (resource:Resource {id: 'resource-sample-catalog'}) "
        "CREATE (agent)-[:HAS_PERMISSION]->"
        "(:UnclassifiedPolicy {id: 'unclassified-permission', action: 'write', kind: 'grant'})"
        "-[:ON_RESOURCE]->(resource)",
    )

    assert graph.evidence_quality.status == "incomplete"
    assert graph.evidence_quality.invalid_relationships == 2
    assert "permission:unclassified-permission" not in {node.id for node in graph.nodes}
    assert [finding.rule_id for finding in graph.findings] == [_EXCESSIVE, _CHAIN]
    _assert_resolved_evidence(graph)


@pytest.mark.parametrize("damage", [
    pytest.param(
        "MATCH (event:Interaction {id: 'interaction-ledger-handoff'}), "
        "(recipient:AIAgent {id: 'agent-catalog'}) CREATE (event)-[:HANDED_TO]->(recipient)",
        id="ambiguous-recipient",
    ),
    pytest.param(
        "MATCH (parent:Interaction {id: 'interaction-catalog-read'}), "
        "(child:Interaction {id: 'interaction-outbox-export'}) CREATE (parent)-[:TRIGGERS]->(child)",
        id="ambiguous-parent",
    ),
])
def test_ambiguous_optional_link_cannot_support_a_chain_finding(tmp_path, damage):
    graph = _read_views(tmp_path / "snapshot.rl", damage)

    assert graph.evidence_quality.status == "incomplete"
    assert graph.evidence_quality.invalid_relationships >= 1
    assert [finding.rule_id for finding in graph.findings] == [_UNAUTHORIZED, _EXCESSIVE]
    _assert_resolved_evidence(graph)


@pytest.mark.parametrize(("parent_id", "child_id"), [
    ("interaction-ledger-read", "interaction-ledger-handoff"),
    ("interaction-ledger-handoff", "interaction-outbox-export"),
])
def test_same_second_trigger_is_retained_without_supporting_a_chain(tmp_path, parent_id, child_id):
    graph = _read_views(
        tmp_path / "snapshot.rl",
        "MATCH (parent:Interaction {id: $parent_id})-[:TRIGGERS]->(child:Interaction {id: $child_id}) "
        "SET child.occurred_at = parent.occurred_at",
        {"parent_id": parent_id, "child_id": child_id},
    )

    assert graph.evidence_quality.status == "complete"
    assert graph.evidence_quality.invalid_relationships == 0
    assert any(
        (edge.kind, edge.source, edge.target) == ("TRIGGERS", f"interaction:{parent_id}", f"interaction:{child_id}")
        for edge in graph.edges
    )
    assert [finding.rule_id for finding in graph.findings] == [_UNAUTHORIZED, _EXCESSIVE]
    _assert_resolved_evidence(graph)


def test_same_second_trigger_does_not_establish_an_investigation_predecessor(tmp_path):
    parent_id = "interaction-catalog-preview"
    child_id = "interaction-catalog-write-denied"
    graph = _read_views(
        tmp_path / "snapshot.rl",
        "MATCH (parent:Interaction {id: $parent_id}), (child:Interaction {id: $child_id}) "
        "SET child.occurred_at = parent.occurred_at, child.parent_id = parent.id "
        "CREATE (parent)-[:TRIGGERS]->(child)",
        {"parent_id": parent_id, "child_id": child_id},
    )

    link = next(edge for edge in graph.edges if edge.kind == "TRIGGERS" and edge.target == _DENIED_EVENT)
    assert link.source == f"interaction:{parent_id}"
    assert graph.evidence_quality.status == "complete"
    finding = next(item for item in graph.findings if item.rule_id == _UNAUTHORIZED)
    trace = finding.investigation
    assert not trace.complete
    assert trace.trigger.outcome == "denied"
    assert [step.record_node_id for step in trace.steps if step.occurred_at is not None] == [_DENIED_EVENT]
    assert link.source not in trace.affected_node_ids
    assert link.id not in trace.edge_ids
    _assert_resolved_evidence(graph)
