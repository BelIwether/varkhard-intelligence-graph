"""JSON-ready projection of the Relate graph and its security findings."""

from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import quote

from .detection import Finding, detect_findings
from .investigation import Investigation, InvestigationBuilder
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
    investigation: Investigation


@dataclass(frozen=True)
class GraphSource:
    filename: str
    read_only: Literal[True] = True
    synthetic_demo: bool = False


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
       event.parent_id AS declared_parent_id, event.recipient_id AS declared_recipient_id,
       parent.id AS linked_parent_id, recipient.id AS linked_recipient_id
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


def _read_interactions(store: GraphStore) -> tuple[list[Interaction], dict[str, list[GraphEdge]]]:
    interactions = []
    links: dict[str, list[GraphEdge]] = {}
    for row in store.query(_INTERACTIONS):
        linked_parent = row.pop("linked_parent_id")
        linked_recipient = row.pop("linked_recipient_id")
        declared_parent = row.pop("declared_parent_id")
        declared_recipient = row.pop("declared_recipient_id")
        parent = linked_parent if declared_parent is None else declared_parent or None
        recipient = declared_recipient or linked_recipient
        event_id = row["id"]
        try:
            event = Interaction(
                **row,
                parent_id=parent if parent != event_id else None,
                recipient_id=recipient if row["action"] == "handoff" else None,
            )
        except ValueError:
            # An incomplete record cannot support evidence. Retain the rest of the snapshot.
            continue
        interactions.append(event)
        event_node = _node_id("interaction", event_id)
        if linked_parent is not None:
            links.setdefault(event_id, []).append(_edge("TRIGGERS", _node_id("interaction", linked_parent), event_node))
        if linked_recipient is not None:
            links.setdefault(event_id, []).append(_edge("HANDED_TO", event_node, _node_id("agent", linked_recipient)))
    return list(dict.fromkeys(interactions)), links


def _graph_edges(
    permissions: list[Permission], interactions: list[Interaction], links: dict[str, list[GraphEdge]],
) -> list[GraphEdge]:
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
        edges.extend(links.get(event.id, ()))
    return edges


def _dashboard_finding(finding: Finding, investigations: InvestigationBuilder) -> DashboardFinding:
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

    node_ids = [node_id for node_id in dict.fromkeys(node_ids) if node_id in investigations.nodes]
    involved = set(node_ids)
    return DashboardFinding(
        id=_stable_id(finding.rule_id, *subject_ids),
        rule_id=finding.rule_id,
        category=category,
        explanation=finding.explanation,
        evidence=evidence,
        node_ids=node_ids,
        edge_ids=[
            edge.id for edge in investigations.edges.values()
            if edge.source in involved and edge.target in involved
        ],
        investigation=investigations.build(finding),
    )


def read_graph(store: GraphStore, filename: str, *, synthetic_demo: bool = False) -> DashboardGraph:
    agents = read_agents(store)
    resources = read_resources(store)
    permissions = [Permission(**row) for row in store.query(_PERMISSIONS)]
    interactions, links = _read_interactions(store)
    nodes = [
        *(_node("agent", agent.id, agent.name) for agent in agents),
        *(_node("resource", resource.id, resource.name) for resource in resources),
        *(_node("permission", item.id, f"{item.action} {item.kind}") for item in permissions),
        *(_node("interaction", event.id, event.action) for event in interactions),
    ]
    nodes = list({node.id: node for node in nodes}.values())
    node_ids = {node.id for node in nodes}
    edges = [
        edge for edge in dict.fromkeys(_graph_edges(permissions, interactions, links))
        if edge.source in node_ids and edge.target in node_ids
    ]
    investigations = InvestigationBuilder(nodes, edges, permissions, interactions)
    return DashboardGraph(
        agents=agents,
        resources=resources,
        permissions=permissions,
        interactions=interactions,
        nodes=nodes,
        edges=edges,
        findings=[_dashboard_finding(finding, investigations) for finding in detect_findings(store)],
        source=GraphSource(filename, synthetic_demo=synthetic_demo),
    )
