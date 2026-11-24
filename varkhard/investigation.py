"""Build investigation views from recorded events and relationships."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, TypeVar

from .models import Action, Interaction, Outcome, Permission

if TYPE_CHECKING:
    from .dashboard import GraphEdge, GraphNode
    from .detection import Finding

_MAX_ANCESTOR_EVENTS = 64
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_Record = TypeVar("_Record", Interaction, Permission)


@dataclass(frozen=True)
class InvestigationStep:
    title: str
    description: str
    node_ids: list[str]
    edge_ids: list[str]
    record_node_id: str
    occurred_at: int | None = None
    action: Action | None = None
    outcome: Outcome | None = None


@dataclass(frozen=True)
class Investigation:
    origin: InvestigationStep | None
    trigger: InvestigationStep | None
    steps: list[InvestigationStep]
    affected_node_ids: list[str]
    node_ids: list[str]
    edge_ids: list[str]
    complete: bool


def _unambiguous_records(records: list[_Record]) -> dict[str, _Record]:
    by_id = {}
    conflicting = set()
    for record in records:
        previous = by_id.setdefault(record.id, record)
        if previous != record:
            conflicting.add(record.id)
    return {record_id: record for record_id, record in by_id.items() if record_id not in conflicting}


class InvestigationBuilder:
    """Index one dashboard snapshot and validate evidence against it."""

    def __init__(
        self,
        nodes: list[GraphNode],
        edges: list[GraphEdge],
        permissions: list[Permission],
        interactions: list[Interaction],
        *,
        incomplete_interaction_ids: frozenset[str] = frozenset(),
    ) -> None:
        self.nodes = {node.id: node for node in nodes}
        self.node_ids = {(node.kind, node.record_id): node.id for node in nodes}
        self.edges = {
            (edge.kind, edge.source, edge.target): edge
            for edge in edges
            if edge.source in self.nodes and edge.target in self.nodes
        }
        self.parents: dict[str, set[str]] = defaultdict(set)
        for edge in self.edges.values():
            if edge.kind == "TRIGGERS":
                self.parents[edge.target].add(edge.source)
        self.permissions = _unambiguous_records(permissions)
        self.interactions = _unambiguous_records(interactions)
        self.incomplete_interaction_ids = incomplete_interaction_ids

    def build(self, finding: Finding) -> Investigation:
        if finding.rule_id == "unauthorized_access":
            return self._unauthorized(finding.evidence)
        if finding.rule_id == "excessive_permission":
            return self._excessive(finding.evidence)
        return self._suspicious(finding.evidence)

    def _assemble(
        self,
        origin: InvestigationStep | None,
        trigger: InvestigationStep | None,
        steps: list[InvestigationStep],
        complete: bool,
    ) -> Investigation:
        node_ids = list(dict.fromkeys(node_id for step in steps for node_id in step.node_ids))
        return Investigation(
            origin=origin,
            trigger=trigger,
            steps=steps,
            affected_node_ids=[
                node_id for node_id in node_ids
                if self.nodes[node_id].kind != "permission"
                or (trigger is not None and node_id == trigger.record_node_id)
            ],
            node_ids=node_ids,
            edge_ids=list(dict.fromkeys(edge_id for step in steps for edge_id in step.edge_ids)),
            complete=complete,
        )

    def _relationship(self, kind: str, source: str | None, target: str | None) -> GraphEdge | None:
        if source is None or target is None:
            return None
        return self.edges.get((kind, source, target))

    def _step(
        self,
        title: str,
        description: str,
        record_node: str,
        related_nodes: list[str | None],
        relationships: list[GraphEdge | None],
        *,
        action: Action,
        occurred_at: int | None = None,
        outcome: Outcome | None = None,
    ) -> InvestigationStep:
        edges = [edge for edge in relationships if edge is not None]
        node_ids = dict.fromkeys([record_node, *(node for node in related_nodes if node is not None)])
        for edge in edges:
            node_ids[edge.source] = None
            node_ids[edge.target] = None
        return InvestigationStep(
            title, description, list(node_ids), [edge.id for edge in edges],
            record_node, occurred_at, action, outcome,
        )

    def _event_from_evidence(self, evidence: dict[str, Any]) -> Interaction | None:
        event_id = evidence.get("interaction_id")
        if not isinstance(event_id, str) or ("interaction", event_id) not in self.node_ids:
            return None
        event = self.interactions.get(event_id)
        if event is None:
            return None
        facts = {
            "agent_id": event.agent_id,
            "resource_id": event.resource_id,
            "action": event.action,
            "outcome": event.outcome,
            "occurred_at": (_UNIX_EPOCH + timedelta(seconds=event.occurred_at)).isoformat().replace("+00:00", "Z"),
        }
        return event if all(evidence.get(key, value) == value for key, value in facts.items()) else None

    def _parent_edge(self, parent: Interaction, child: Interaction) -> GraphEdge | None:
        source = self.node_ids.get(("interaction", parent.id))
        target = self.node_ids.get(("interaction", child.id))
        if (
            source is None or target is None or child.parent_id != parent.id
            or parent.occurred_at >= child.occurred_at or self.parents.get(target) != {source}
        ):
            return None
        return self._relationship("TRIGGERS", source, target)

    def _ancestors(self, event: Interaction) -> tuple[list[Interaction], bool]:
        events = [event]
        seen = {event.id}
        while len(events) < _MAX_ANCESTOR_EVENTS:
            child = events[-1]
            if child.parent_id is None:
                break
            parent = self.interactions.get(child.parent_id)
            if parent is None or parent.id in seen or self._parent_edge(parent, child) is None:
                break
            seen.add(parent.id)
            events.append(parent)
        earliest = events[-1]
        earliest_node = self.node_ids[("interaction", earliest.id)]
        return list(reversed(events)), earliest.parent_id is None and not self.parents.get(earliest_node)

    def _event_step(
        self, event: Interaction, title: str, description: str, parent_edge: GraphEdge | None,
    ) -> tuple[InvestigationStep, bool]:
        node = self.node_ids[("interaction", event.id)]
        agent = self.node_ids.get(("agent", event.agent_id))
        resource = self.node_ids.get(("resource", event.resource_id))
        relationships = [
            self._relationship("PERFORMED", agent, node),
            self._relationship("TARGETS", node, resource),
        ]
        related_nodes = [agent, resource]
        if event.recipient_id is not None:
            recipient = self.node_ids.get(("agent", event.recipient_id))
            related_nodes.append(recipient)
            relationships.append(self._relationship("HANDED_TO", node, recipient))
        step = self._step(
            title, description, node, related_nodes, [parent_edge, *relationships],
            action=event.action, occurred_at=event.occurred_at, outcome=event.outcome,
        )
        return step, event.id not in self.incomplete_interaction_ids and all(edge is not None for edge in relationships)

    def _permission_step(
        self,
        record_id: object,
        evidence: dict[str, Any],
        kind: str,
        title: str,
        description: str,
        *,
        match_action: bool = False,
    ) -> tuple[InvestigationStep | None, bool]:
        if not isinstance(record_id, str):
            return None, False
        permission = self.permissions.get(record_id)
        node = self.node_ids.get(("permission", record_id))
        if (
            permission is None or node is None or permission.kind != kind
            or permission.agent_id != evidence.get("agent_id")
            or permission.resource_id != evidence.get("resource_id")
            or (match_action and permission.action != evidence.get("action"))
        ):
            return None, False

        agent = self.node_ids.get(("agent", permission.agent_id))
        resource = self.node_ids.get(("resource", permission.resource_id))
        relationships = [
            self._relationship("HAS_PERMISSION", agent, node),
            self._relationship("ON_RESOURCE", node, resource),
        ]
        step = self._step(
            title, description.format(action=permission.action), node, [agent, resource], relationships,
            action=permission.action,
        )
        return step, all(edge is not None for edge in relationships)

    def _related_permissions(
        self, evidence: dict[str, Any], *, ids_key: str, actions_key: str, kind: str, title: str, description: str,
    ) -> tuple[list[InvestigationStep], bool]:
        ids, actions = evidence.get(ids_key), evidence.get(actions_key)
        if not isinstance(ids, list) or not isinstance(actions, list):
            return [], False
        steps = []
        complete = True
        for record_id in ids:
            step, linked = self._permission_step(record_id, evidence, kind, title, description)
            if step is not None:
                steps.append(step)
            complete = complete and linked
        return steps, complete and sorted({step.action for step in steps}) == actions

    def _unauthorized(self, evidence: dict[str, Any]) -> Investigation:
        event = self._event_from_evidence(evidence)
        event_steps = []
        complete = False
        if event is not None:
            path, complete = self._ancestors(event)
            previous = None
            for item in path:
                title = "Flagged access" if item == event else "Recorded predecessor"
                description = f"The graph records a {item.outcome} outcome for {item.action}."
                if item == event:
                    description += " The rule found no matching grant in the current policy."
                parent_edge = self._parent_edge(previous, item) if previous is not None else None
                step, linked = self._event_step(item, title, description, parent_edge)
                event_steps.append(step)
                complete = complete and linked
                previous = item

        grants, grants_match = self._related_permissions(
            evidence, ids_key="related_grant_ids", actions_key="granted_actions", kind="grant",
            title="Current grant", description="The current grant lists {action} for this agent and resource.",
        )
        return self._assemble(
            event_steps[0] if event_steps else None,
            event_steps[-1] if event_steps else None,
            [*event_steps, *grants],
            event is not None and complete and grants_match and all(step.action != event.action for step in grants),
        )

    def _excessive(self, evidence: dict[str, Any]) -> Investigation:
        grant, linked = self._permission_step(
            evidence.get("permission_id"), evidence, "grant", "Excess grant",
            "The current grant allows {action}. The rule found no matching baseline approval.",
            match_action=True,
        )
        baseline, baseline_match = self._related_permissions(
            evidence, ids_key="related_baseline_ids", actions_key="approved_actions", kind="baseline",
            title="Baseline approval", description="The least-privilege baseline lists {action} for this scope.",
        )
        steps = [grant, *baseline] if grant is not None else baseline
        return self._assemble(
            grant, grant, steps,
            grant is not None and linked and baseline_match and all(step.action != grant.action for step in baseline),
        )

    def _suspicious(self, evidence: dict[str, Any]) -> Investigation:
        event_ids = evidence.get("interaction_ids")
        details = evidence.get("interactions")
        if not isinstance(event_ids, list):
            return self._assemble(None, None, [], False)
        details = details if isinstance(details, list) else []
        event_steps = []
        trigger = None
        previous = None
        complete = len(event_ids) == len(details) == 3
        expected = (
            ("read", "Restricted resource read", evidence.get("sender_agent_id"), evidence.get("source_resource_id")),
            ("handoff", "Recorded handoff", evidence.get("sender_agent_id"), evidence.get("source_resource_id")),
            ("export", "External export", evidence.get("recipient_agent_id"), evidence.get("destination_resource_id")),
        )
        for index, (action, title, agent_id, resource_id) in enumerate(expected):
            detail = details[index] if index < len(details) else None
            record_id = event_ids[index] if index < len(event_ids) else None
            details_match = isinstance(detail, dict) and detail.get("interaction_id") == record_id
            facts = detail if details_match else {"interaction_id": record_id}
            item = self._event_from_evidence(facts)
            if (
                item is None or item.action != action or item.outcome != "success"
                or item.agent_id != agent_id or item.resource_id != resource_id
                or (action == "handoff" and item.recipient_id != evidence.get("recipient_agent_id"))
            ):
                complete = False
                previous = None
                continue
            parent_edge = self._parent_edge(previous, item) if previous is not None else None
            description = f"The graph records a successful {item.action} for this interaction."
            step, linked = self._event_step(item, title, description, parent_edge)
            event_steps.append(step)
            if action == "export":
                trigger = step
            complete = complete and details_match and linked and (index == 0 or parent_edge is not None)
            previous = item

        event_steps.sort(key=lambda step: (step.occurred_at, step.record_node_id))
        if complete:
            read_node = event_steps[0].record_node_id
            path_nodes = {step.record_node_id for step in event_steps}
            elapsed = event_steps[-1].occurred_at - event_steps[0].occurred_at
            window = evidence.get("window_seconds")
            complete = (
                not path_nodes.intersection(self.parents.get(read_node, ()))
                and type(window) is int
                and 0 < elapsed <= window
                and elapsed == evidence.get("elapsed_seconds")
            )
        return self._assemble(event_steps[0] if event_steps else None, trigger, event_steps, complete)
