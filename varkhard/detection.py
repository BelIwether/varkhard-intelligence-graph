"""Evaluate the access policy and interaction paths stored in Relate."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .store import GraphStore


_PERMISSIONS = """
MATCH (agent:AIAgent)-[:HAS_PERMISSION]->(permission:Permission)
      -[:ON_RESOURCE]->(resource:Resource)
RETURN permission.id AS permission_id, agent.id AS agent_id,
       resource.id AS resource_id, permission.action AS action,
       permission.kind AS kind
"""

_INTERACTIONS = """
MATCH (agent:AIAgent)-[:PERFORMED]->(event:Interaction)-[:TARGETS]->(resource:Resource)
RETURN event.id AS interaction_id, agent.id AS agent_id, resource.id AS resource_id,
       event.action AS action, event.outcome AS outcome, event.occurred_at AS occurred_at,
       resource.classification AS resource_classification, resource.boundary AS resource_boundary
"""

_HANDOFF_PATHS = """
MATCH (read_event:Interaction)-[:TRIGGERS]->(handoff:Interaction)
      -[:TRIGGERS]->(export_event:Interaction), (handoff)-[:HANDED_TO]->(recipient:AIAgent)
WHERE read_event.action = 'read' AND handoff.action = 'handoff' AND export_event.action = 'export'
  AND read_event.outcome = 'success' AND handoff.outcome = 'success'
  AND export_event.outcome = 'success'
RETURN DISTINCT read_event.id AS read_id, handoff.id AS handoff_id,
       export_event.id AS export_id, recipient.id AS recipient_id
"""

_CHAIN_WINDOW_SECONDS = 600
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    explanation: str
    evidence: dict[str, Any]


def detect_findings(store: GraphStore) -> list[Finding]:
    """Return findings for the current graph in a stable, rule-first order."""
    permissions = sorted(store.query(_PERMISSIONS), key=lambda row: row["permission_id"])
    interactions = sorted(store.query(_INTERACTIONS), key=lambda row: row["interaction_id"])

    policy: defaultdict[tuple[str, str, str], dict[str, list[str]]] = defaultdict(dict)
    for permission in permissions:
        scope = (permission["kind"], permission["agent_id"], permission["resource_id"])
        policy[scope].setdefault(permission["action"], []).append(permission["permission_id"])

    findings = []
    for event in interactions:
        scope = ("grant", event["agent_id"], event["resource_id"])
        grants = policy.get(scope, {})
        if event["action"] in grants:
            continue
        findings.append(Finding(
            rule_id="unauthorized_access",
            explanation=(
                f"The current policy has no {event['action']} grant for agent "
                f"{event['agent_id']} on {event['resource_id']}. "
                f"The recorded outcome was {event['outcome']}."
            ),
            evidence={
                **_event_evidence(event),
                "granted_actions": sorted(grants),
                "related_grant_ids": _permission_ids(grants),
            },
        ))

    for permission in permissions:
        if permission["kind"] != "grant":
            continue
        scope = ("baseline", permission["agent_id"], permission["resource_id"])
        baseline = policy.get(scope, {})
        if permission["action"] in baseline:
            continue
        findings.append(Finding(
            rule_id="excessive_permission",
            explanation=(
                f"Grant {permission['permission_id']} allows {permission['action']} for "
                f"agent {permission['agent_id']} on {permission['resource_id']} without "
                "a matching approval in the least-privilege baseline."
            ),
            evidence={
                **permission,
                "approved_actions": sorted(baseline),
                "related_baseline_ids": _permission_ids(baseline),
            },
        ))

    events_by_id = {event["interaction_id"]: event for event in interactions}
    findings.extend(_suspicious_chains(store, events_by_id))
    return findings


def _permission_ids(actions: dict[str, list[str]]) -> list[str]:
    return sorted(permission_id for ids in actions.values() for permission_id in ids)


def _event_evidence(event: dict[str, Any]) -> dict[str, Any]:
    occurred_at = _UNIX_EPOCH + timedelta(seconds=event["occurred_at"])
    return {**event, "occurred_at": occurred_at.isoformat().replace("+00:00", "Z")}


def _suspicious_chains(
    store: GraphStore, events: dict[str, dict[str, Any]]
) -> list[Finding]:
    paths = sorted(
        store.query(_HANDOFF_PATHS),
        key=lambda row: (row["read_id"], row["handoff_id"], row["export_id"], row["recipient_id"]),
    )
    findings = []
    for path in paths:
        read = events[path["read_id"]]
        handoff = events[path["handoff_id"]]
        export = events[path["export_id"]]
        sender_id = read["agent_id"]
        recipient_id = path["recipient_id"]
        if (
            read["resource_classification"] != "restricted"
            or handoff["resource_id"] != read["resource_id"]
            or handoff["agent_id"] != sender_id
            or recipient_id == sender_id
            or export["agent_id"] != recipient_id
            or export["resource_boundary"] != "external"
        ):
            continue

        elapsed = export["occurred_at"] - read["occurred_at"]
        if not (
            read["occurred_at"] < handoff["occurred_at"] < export["occurred_at"]
            and elapsed <= _CHAIN_WINDOW_SECONDS
        ):
            continue

        findings.append(Finding(
            rule_id="suspicious_chain",
            explanation=(
                f"Agent {sender_id} read restricted resource {read['resource_id']} and handed "
                f"it to {recipient_id}. The linked export to external resource "
                f"{export['resource_id']} succeeded within {elapsed} seconds of the read."
            ),
            evidence={
                "interaction_ids": [path["read_id"], path["handoff_id"], path["export_id"]],
                "interactions": [_event_evidence(event) for event in (read, handoff, export)],
                "sender_agent_id": sender_id,
                "recipient_agent_id": recipient_id,
                "source_resource_id": read["resource_id"],
                "destination_resource_id": export["resource_id"],
                "elapsed_seconds": elapsed,
                "window_seconds": _CHAIN_WINDOW_SECONDS,
            },
        ))
    return findings
