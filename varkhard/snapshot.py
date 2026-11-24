"""Validate the records and explicit relationships in a Relate snapshot."""

from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, get_args

from .models import Action, Agent, Interaction, Permission, PermissionKind, Resource
from .store import GraphStore, UnsupportedSnapshotError

NodeKind = Literal["agent", "resource", "permission", "interaction"]
EdgeKind = Literal["HAS_PERMISSION", "ON_RESOURCE", "PERFORMED", "TARGETS", "HANDED_TO", "TRIGGERS"]

_LABELS: dict[str, NodeKind] = {
    "AIAgent": "agent", "Resource": "resource", "Permission": "permission", "Interaction": "interaction",
}
_ENDPOINTS: dict[EdgeKind, tuple[NodeKind, NodeKind]] = {
    "HAS_PERMISSION": ("agent", "permission"),
    "ON_RESOURCE": ("permission", "resource"),
    "PERFORMED": ("agent", "interaction"),
    "TARGETS": ("interaction", "resource"),
    "TRIGGERS": ("interaction", "interaction"),
    "HANDED_TO": ("interaction", "agent"),
}
_INCOMING = {"HAS_PERMISSION", "PERFORMED", "TRIGGERS"}
_EDGE_ORDER = {kind: index for index, kind in enumerate(_ENDPOINTS)}

_NODES = """
MATCH (node)
WHERE any(label IN labels(node) WHERE label IN $labels)
RETURN elementId(node) AS key, labels(node) AS labels, node.id AS id, node.name AS name,
       node.classification AS classification, node.boundary AS boundary,
       node.action AS action, node.kind AS kind, node.outcome AS outcome,
       node.occurred_at AS occurred_at, node.parent_id AS parent_id, node.recipient_id AS recipient_id
"""

_RELATIONSHIPS = """
MATCH (source)-[edge]->(target)
WHERE type(edge) IN $kinds
RETURN type(edge) AS kind, elementId(source) AS source, elementId(target) AS target
"""


@dataclass(frozen=True)
class EvidenceQuality:
    status: Literal["complete", "incomplete"]
    invalid_records: int
    invalid_relationships: int


@dataclass(frozen=True)
class SnapshotRelationship:
    kind: EdgeKind
    source_kind: NodeKind
    source_id: str
    target_kind: NodeKind
    target_id: str


@dataclass(frozen=True)
class _UncertainPermission:
    kind: PermissionKind | None
    action: Action | None
    agent_ids: frozenset[str]
    resource_ids: frozenset[str]

    def affects(self, kind: PermissionKind, agent_id: str, resource_id: str, action: Action) -> bool:
        return (
            self.kind in (None, kind)
            and self.action in (None, action)
            and (not self.agent_ids or agent_id in self.agent_ids)
            and (not self.resource_ids or resource_id in self.resource_ids)
        )


@dataclass(frozen=True)
class Snapshot:
    agents: list[Agent]
    resources: list[Resource]
    permissions: list[Permission]
    interactions: list[Interaction]
    relationships: list[SnapshotRelationship]
    evidence_quality: EvidenceQuality
    incomplete_interaction_ids: frozenset[str]
    uncertain_permissions: tuple[_UncertainPermission, ...]

    def policy_known(self, kind: PermissionKind, agent_id: str, resource_id: str, action: Action) -> bool:
        return not any(item.affects(kind, agent_id, resource_id, action) for item in self.uncertain_permissions)


def _require_schema(store: GraphStore) -> None:
    constraints = {
        row["labelsOrTypes"][0]
        for row in store.query("SHOW CONSTRAINTS")
        if row["entityType"] == "NODE"
        and row["type"] in {"NODE_PROPERTY_UNIQUENESS", "NODE_KEY"}
        and row["properties"] == ["id"]
        and len(row["labelsOrTypes"]) == 1
    }
    if not _LABELS.keys() <= constraints:
        raise UnsupportedSnapshotError("The Relate file does not have the VARKHARD snapshot schema.")


def _has_id(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _eligible_nodes(rows: list[dict]) -> dict[str, tuple[NodeKind, str]]:
    candidates = {}
    for row in rows:
        labels = _LABELS.keys() & set(row["labels"])
        if len(labels) == 1 and _has_id(row["id"]):
            candidates[row["key"]] = (_LABELS[labels.pop()], row["id"])
    counts = Counter(candidates.values())
    return {key: value for key, value in candidates.items() if counts[value] == 1}


class _Links:
    def __init__(self, rows: list[dict], nodes: dict[str, tuple[NodeKind, str]]) -> None:
        self.nodes = nodes
        self.observed: dict[tuple[str, EdgeKind], set[str]] = defaultdict(set)
        for row in rows:
            kind, source, target = row["kind"], row["source"], row["target"]
            subject, peer = (target, source) if kind in _INCOMING else (source, target)
            self.observed[subject, kind].add(peer)
        self.accepted: set[tuple[str, EdgeKind, str]] = set()
        self.missing = 0
        self.count = len(rows)

    def required(self, subject: str, kind: EdgeKind, records: Mapping[str, Agent | Resource]) -> str | None:
        peers = self.observed.get((subject, kind), set())
        if not peers:
            self.missing += 1
        if len(peers) == 1:
            key = next(iter(peers))
            source_kind, target_kind = _ENDPOINTS[kind]
            expected = source_kind if kind in _INCOMING else target_kind
            if key in records and self.nodes[key][0] == expected:
                return key
        return None

    def optional(
        self, subject: str, kind: EdgeKind, declared: object, peers_by_key: Mapping[str, str],
    ) -> tuple[str | None, str | None, bool]:
        peers = self.observed.get((subject, kind), set())
        # A missing property is accepted for older files that store only the link.
        # An empty property explicitly declares that there is no link.
        key = next(iter(peers)) if len(peers) == 1 else None
        linked_id = peers_by_key.get(key) if key is not None else None
        if declared is None:
            return linked_id, key if linked_id is not None else None, not peers or linked_id is not None
        if declared == "":
            return None, None, not peers
        if not peers:
            self.missing += 1
        if _has_id(declared):
            return declared, key if declared == linked_id else None, declared == linked_id
        return None, None, False

    def possible_peers(self, subject: str, kind: EdgeKind, records: Mapping[str, Agent | Resource]) -> frozenset[str]:
        peers = self.observed.get((subject, kind), set())
        source_kind, target_kind = _ENDPOINTS[kind]
        expected = source_kind if kind in _INCOMING else target_kind
        if any(key not in records or self.nodes[key][0] != expected for key in peers):
            return frozenset()
        return frozenset(records[key].id for key in peers)

    def keep(self, subject: str, kind: EdgeKind, peer: str) -> None:
        self.accepted.add((subject, kind, peer))

    def relationships(self) -> list[SnapshotRelationship]:
        edges = []
        for subject, kind, peer in sorted(
            self.accepted, key=lambda item: (
                self.nodes[item[0]][0] != "permission", self.nodes[item[0]][1], _EDGE_ORDER[item[1]], self.nodes[item[2]][1],
            ),
        ):
            source, target = (peer, subject) if kind in _INCOMING else (subject, peer)
            source_kind, source_id = self.nodes[source]
            target_kind, target_id = self.nodes[target]
            edges.append(SnapshotRelationship(kind, source_kind, source_id, target_kind, target_id))
        return edges


def _read_entities(rows: list[dict], eligible: dict[str, tuple[NodeKind, str]]) -> dict[str, Agent | Resource]:
    entities = {}
    for row in rows:
        key = row["key"]
        kind, node_id = eligible.get(key, (None, None))
        try:
            if kind == "agent":
                entities[key] = Agent(node_id, row["name"])
            elif kind == "resource":
                entities[key] = Resource(node_id, row["name"], row["classification"], row["boundary"])
        except ValueError:
            continue
    return entities


def _read_permissions(
    rows: list[dict], eligible: dict[str, tuple[NodeKind, str]], entities: dict[str, Agent | Resource], links: _Links,
) -> tuple[list[Permission], tuple[_UncertainPermission, ...]]:
    permissions = []
    uncertain = []
    rows_by_key = {row["key"]: row for row in rows}
    subjects = {row["key"] for row in rows if "Permission" in row["labels"]}
    # A stored policy relation can point at a record whose Permission label is missing.
    linked_subjects = {subject for subject, kind in links.observed if kind in {"HAS_PERMISSION", "ON_RESOURCE"}}
    for key in sorted(subjects | linked_subjects):
        row = rows_by_key.get(key, {})
        agent = links.required(key, "HAS_PERMISSION", entities) if key in subjects else None
        resource = links.required(key, "ON_RESOURCE", entities) if key in subjects else None
        permission = None
        if key in eligible and eligible[key][0] == "permission" and agent is not None and resource is not None:
            try:
                permission = Permission(row["id"], entities[agent].id, entities[resource].id, row["action"], row["kind"])
            except ValueError:
                pass
        if permission is None:
            uncertain.append(_UncertainPermission(
                row["kind"] if row.get("kind") in get_args(PermissionKind) else None,
                row["action"] if row.get("action") in get_args(Action) else None,
                links.possible_peers(key, "HAS_PERMISSION", entities),
                links.possible_peers(key, "ON_RESOURCE", entities),
            ))
            continue
        permissions.append(permission)
        links.keep(key, "HAS_PERMISSION", agent)
        links.keep(key, "ON_RESOURCE", resource)
    return sorted(permissions, key=lambda row: row.id), tuple(uncertain)


def _read_interactions(
    rows: list[dict], eligible: dict[str, tuple[NodeKind, str]], entities: dict[str, Agent | Resource], links: _Links,
) -> tuple[list[Interaction], frozenset[str]]:
    observed: dict[str, Interaction] = {}
    pending_parents: dict[str, str] = {}
    incomplete = set()
    recipients = {key: row.id for key, row in entities.items() if isinstance(row, Agent)}
    parents = {key: node_id for key, (kind, node_id) in eligible.items() if kind == "interaction"}
    for row in rows:
        key = row["key"]
        if key not in parents:
            continue
        event_id = parents[key]
        agent = links.required(key, "PERFORMED", entities)
        resource = links.required(key, "TARGETS", entities)
        if agent is None or resource is None:
            continue
        parent, parent_key, parent_complete = links.optional(key, "TRIGGERS", row["parent_id"], parents)
        recipient, recipient_key, recipient_complete = links.optional(key, "HANDED_TO", row["recipient_id"], recipients)
        if row["action"] == "handoff" and recipient is None and not links.observed.get((key, "HANDED_TO")):
            links.missing += int(row["recipient_id"] in (None, ""))
        try:
            event = Interaction(
                event_id, entities[agent].id, entities[resource].id, row["action"], row["outcome"],
                row["occurred_at"], parent if parent != event_id else None,
                recipient if row["action"] == "handoff" else None,
            )
        except ValueError:
            continue
        observed[key] = event
        links.keep(key, "PERFORMED", agent)
        links.keep(key, "TARGETS", resource)
        if parent_key is not None:
            pending_parents[key] = parent_key
        if recipient_key is not None and event.action == "handoff":
            links.keep(key, "HANDED_TO", recipient_key)
        if not parent_complete or not recipient_complete or (recipient is not None and event.action != "handoff"):
            incomplete.add(event_id)
    for child_key, parent_key in pending_parents.items():
        child, parent = observed[child_key], observed.get(parent_key)
        if parent is not None and parent.occurred_at < child.occurred_at:
            links.keep(child_key, "TRIGGERS", parent_key)
        else:
            incomplete.add(child.id)
    return sorted(observed.values(), key=lambda row: row.id), frozenset(incomplete)


def read_snapshot(store: GraphStore) -> Snapshot:
    """Load a supported snapshot and retain the evidence that can be validated."""
    _require_schema(store)
    rows = store.query(_NODES, {"labels": list(_LABELS)})
    eligible = _eligible_nodes(rows)
    entities = _read_entities(rows, eligible)
    links = _Links(store.query(_RELATIONSHIPS, {"kinds": list(_ENDPOINTS)}), eligible)
    permissions, uncertain = _read_permissions(rows, eligible, entities, links)
    interactions, incomplete = _read_interactions(rows, eligible, entities, links)
    invalid_records = len(rows) - len(entities) - len(permissions) - len(interactions)
    invalid_relationships = links.count - len(links.accepted) + links.missing
    quality = EvidenceQuality(
        "incomplete" if invalid_records or invalid_relationships else "complete", invalid_records, invalid_relationships,
    )
    return Snapshot(
        agents=sorted((row for row in entities.values() if isinstance(row, Agent)), key=lambda row: row.id),
        resources=sorted((row for row in entities.values() if isinstance(row, Resource)), key=lambda row: row.id),
        permissions=permissions,
        interactions=interactions,
        relationships=links.relationships(),
        evidence_quality=quality,
        incomplete_interaction_ids=incomplete,
        uncertain_permissions=uncertain,
    )
