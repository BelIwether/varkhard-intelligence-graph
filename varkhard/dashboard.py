"""JSON-ready projection of the Relate graph and its security findings."""

from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import quote

from .detection import Finding, detect_snapshot
from .investigation import Investigation, InvestigationBuilder
from .models import Agent, Interaction, Permission, Resource
from .snapshot import EdgeKind, EvidenceQuality, NodeKind, read_snapshot
from .store import GraphStore


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
    evidence_quality: EvidenceQuality


def read_agents(store: GraphStore) -> list[Agent]:
    return read_snapshot(store).agents


def read_resources(store: GraphStore) -> list[Resource]:
    return read_snapshot(store).resources


def _node_id(kind: NodeKind, record_id: str) -> str:
    return f"{kind}:{record_id}"


def _node(kind: NodeKind, record_id: str, label: str) -> GraphNode:
    return GraphNode(_node_id(kind, record_id), record_id, kind, label)


def _stable_id(*parts: str) -> str:
    return ":".join(quote(part, safe="") for part in parts)


def _edge(kind: EdgeKind, source: str, target: str) -> GraphEdge:
    return GraphEdge(_stable_id(kind, source, target), source, target, kind)


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
    snapshot = read_snapshot(store)
    nodes = [
        *(_node("agent", agent.id, agent.name) for agent in snapshot.agents),
        *(_node("resource", resource.id, resource.name) for resource in snapshot.resources),
        *(_node("permission", item.id, f"{item.action} {item.kind}") for item in snapshot.permissions),
        *(_node("interaction", event.id, event.action) for event in snapshot.interactions),
    ]
    edges = [
        _edge(link.kind, _node_id(link.source_kind, link.source_id), _node_id(link.target_kind, link.target_id))
        for link in snapshot.relationships
    ]
    investigations = InvestigationBuilder(
        nodes, edges, snapshot.permissions, snapshot.interactions,
        incomplete_interaction_ids=snapshot.incomplete_interaction_ids,
    )
    return DashboardGraph(
        agents=snapshot.agents,
        resources=snapshot.resources,
        permissions=snapshot.permissions,
        interactions=snapshot.interactions,
        nodes=nodes,
        edges=edges,
        findings=[_dashboard_finding(finding, investigations) for finding in detect_snapshot(snapshot)],
        source=GraphSource(filename, synthetic_demo=synthetic_demo),
        evidence_quality=snapshot.evidence_quality,
    )
