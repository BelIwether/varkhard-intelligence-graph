"""JSON-ready projection of the Relate graph and its security findings."""

from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import quote

from .detection import Finding, detect_findings
from .models import Agent, Interaction, Permission, Resource
from .store import GraphStore

NodeKind = Literal["agent", "resource", "permission", "interaction"]
EdgeKind = Literal[
    "HAS_PERMISSION", "ON_RESOURCE", "PERFORMED", "TARGETS", "HANDED_TO", "TRIGGERS"
]


@dataclass(frozen=True)
class GraphNode:
    id: str
    record_id: str
    kind: NodeKind
    label: str


@dataclass(frozen=True)
class GraphEdge:
    id: str
    source: str
    target: str
    kind: EdgeKind


@dataclass(frozen=True)
class DashboardFinding:
    id: str
    rule_id: str
    category: str
    explanation: str
    evidence: dict[str, Any]
    node_ids: list[str]
    edge_ids: list[str]


@dataclass(frozen=True)
class GraphSource:
    filename: str
    read_only: Literal[True] = True


@dataclass(frozen=True)
class DashboardGraph:
    agents: list[Agent]
    resources: list[Resource]
    permissions: list[Permission]
    interactions: list[Interaction]
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    findings: list[DashboardFinding]
    source: GraphSource


_PERMISSIONS = """
MATCH (agent:AIAgent)-[:HAS_PERMISSION]->(permission:Permission)
      -[:ON_RESOURCE]->(resource:Resource)
RETURN permission.id AS id, agent.id AS agent_id, resource.id AS resource_id,
       permission.action AS action, permission.kind AS kind
ORDER BY id
"""

_INTERACTIONS = """
MATCH (agent:AIAgent)-[:PERFORMED]->(event:Interaction)-[:TARGETS]->(resource:Resource)
OPTIONAL MATCH (parent:Interaction)-[:TRIGGERS]->(event)
OPTIONAL MATCH (event)-[:HANDED_TO]->(recipient:AIAgent)
RETURN event.id AS id, agent.id AS agent_id, resource.id AS resource_id,
       event.action AS action, event.outcome AS outcome, event.occurred_at AS occurred_at,
       parent.id AS parent_id, recipient.id AS recipient_id
ORDER BY id
"""


def read_agents(store: GraphStore) -> list[Agent]:
    return [Agent(**row) for row in store.query("""
        MATCH (agent:AIAgent)
        RETURN agent.id AS id, agent.name AS name
        ORDER BY id
    """)]


def read_resources(store: GraphStore) -> list[Resource]:
    return [Resource(**row) for row in store.query("""
        MATCH (resource:Resource)
        RETURN resource.id AS id, resource.name AS name,
               resource.classification AS classification, resource.boundary AS boundary
        ORDER BY id
    """)]


def _node_id(kind: NodeKind, record_id: str) -> str:
    return f"{kind}:{record_id}"


def _node(kind: NodeKind, record_id: str, label: str) -> GraphNode:
    return GraphNode(_node_id(kind, record_id), record_id, kind, label)


def _stable_id(*parts: str) -> str:
    return ":".join(quote(part, safe="") for part in parts)


def _edge(kind: EdgeKind, source: str, target: str) -> GraphEdge:
    return GraphEdge(_stable_id(kind, source, target), source, target, kind)


def _graph_edges(permissions: list[Permission], interactions: list[Interaction]) -> list[GraphEdge]:
    edges = []
    for permission in permissions:
        node = _node_id("permission", permission.id)
        edges.extend((
            _edge("HAS_PERMISSION", _node_id("agent", permission.agent_id), node),
            _edge("ON_RESOURCE", node, _node_id("resource", permission.resource_id)),
        ))
    for event in interactions:
        node = _node_id("interaction", event.id)
        edges.extend((
            _edge("PERFORMED", _node_id("agent", event.agent_id), node),
            _edge("TARGETS", node, _node_id("resource", event.resource_id)),
        ))
        if event.parent_id is not None:
            edges.append(_edge("TRIGGERS", _node_id("interaction", event.parent_id), node))
        if event.recipient_id is not None:
            edges.append(_edge("HANDED_TO", node, _node_id("agent", event.recipient_id)))
    return edges


def _dashboard_finding(finding: Finding, edges: list[GraphEdge]) -> DashboardFinding:
    evidence = finding.evidence
    if finding.rule_id == "unauthorized_access":
        category = "Unauthorized Access"
        subject_ids = [evidence["interaction_id"]]
        node_ids = [
            _node_id("agent", evidence["agent_id"]),
            _node_id("resource", evidence["resource_id"]),
            _node_id("interaction", subject_ids[0]),
            *(_node_id("permission", item) for item in evidence["related_grant_ids"]),
        ]
    elif finding.rule_id == "excessive_permission":
        category = "Excessive Permission"
        subject_ids = [evidence["permission_id"]]
        node_ids = [
            _node_id("agent", evidence["agent_id"]),
            _node_id("resource", evidence["resource_id"]),
            _node_id("permission", subject_ids[0]),
            *(_node_id("permission", item) for item in evidence["related_baseline_ids"]),
        ]
    elif finding.rule_id == "suspicious_chain":
        category = "Suspicious Chain"
        subject_ids = evidence["interaction_ids"]
        node_ids = [
            _node_id("agent", evidence["sender_agent_id"]),
            _node_id("agent", evidence["recipient_agent_id"]),
            _node_id("resource", evidence["source_resource_id"]),
            _node_id("resource", evidence["destination_resource_id"]),
            *(_node_id("interaction", item) for item in subject_ids),
        ]
    else:
        raise ValueError(f"Unknown finding rule {finding.rule_id!r}")

    node_ids = list(dict.fromkeys(node_ids))
    involved = set(node_ids)
    return DashboardFinding(
        id=_stable_id(finding.rule_id, *subject_ids),
        rule_id=finding.rule_id,
        category=category,
        explanation=finding.explanation,
        evidence=evidence,
        node_ids=node_ids,
        edge_ids=[edge.id for edge in edges if edge.source in involved and edge.target in involved],
    )


def read_graph(store: GraphStore, filename: str) -> DashboardGraph:
    agents = read_agents(store)
    resources = read_resources(store)
    permissions = [Permission(**row) for row in store.query(_PERMISSIONS)]
    interactions = [Interaction(**row) for row in store.query(_INTERACTIONS)]
    nodes = [
        *(_node("agent", agent.id, agent.name) for agent in agents),
        *(_node("resource", resource.id, resource.name) for resource in resources),
        *(_node("permission", item.id, f"{item.action} {item.kind}") for item in permissions),
        *(_node("interaction", event.id, event.action) for event in interactions),
    ]
    edges = _graph_edges(permissions, interactions)
    return DashboardGraph(
        agents=agents,
        resources=resources,
        permissions=permissions,
        interactions=interactions,
        nodes=nodes,
        edges=edges,
        findings=[_dashboard_finding(finding, edges) for finding in detect_findings(store)],
        source=GraphSource(filename),
    )
