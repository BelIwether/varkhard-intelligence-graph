"""Evaluate the access policy and interaction paths in a validated snapshot."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .models import Action, Interaction, PermissionKind, Resource
from .snapshot import Snapshot, read_snapshot
from .store import GraphStore

_CHAIN_WINDOW_SECONDS = 600
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    explanation: str
    evidence: dict[str, Any]


def detect_findings(store: GraphStore) -> list[Finding]:
    """Return findings for the current graph in a stable, rule-first order."""
    return detect_snapshot(read_snapshot(store))


def detect_snapshot(snapshot: Snapshot) -> list[Finding]:
    """Report rules supported by the records and links in this snapshot."""
    policy: defaultdict[tuple[PermissionKind, str, str], dict[Action, list[str]]] = defaultdict(dict)
    for permission in snapshot.permissions:
        scope = (permission.kind, permission.agent_id, permission.resource_id)
        policy[scope].setdefault(permission.action, []).append(permission.id)

    resources = {resource.id: resource for resource in snapshot.resources}
    findings = []
    for event in snapshot.interactions:
        grants = policy.get(("grant", event.agent_id, event.resource_id), {})
        if event.action in grants or not snapshot.policy_known("grant", event.agent_id, event.resource_id, event.action):
            continue
        findings.append(Finding(
            rule_id="unauthorized_access",
            explanation=(
                f"The current policy has no {event.action} grant for agent "
                f"{event.agent_id} on {event.resource_id}. The recorded outcome was {event.outcome}."
            ),
            evidence={
                **_event_evidence(event, resources[event.resource_id]),
                "granted_actions": sorted(grants),
                "related_grant_ids": _permission_ids(grants),
            },
        ))

    for permission in snapshot.permissions:
        if permission.kind != "grant":
            continue
        baseline = policy.get(("baseline", permission.agent_id, permission.resource_id), {})
        if permission.action in baseline or not snapshot.policy_known(
            "baseline", permission.agent_id, permission.resource_id, permission.action,
        ):
            continue
        findings.append(Finding(
            rule_id="excessive_permission",
            explanation=(
                f"Grant {permission.id} allows {permission.action} for agent {permission.agent_id} "
                f"on {permission.resource_id} without a matching approval in the least-privilege baseline."
            ),
            evidence={
                "permission_id": permission.id,
                "agent_id": permission.agent_id,
                "resource_id": permission.resource_id,
                "action": permission.action,
                "kind": permission.kind,
                "approved_actions": sorted(baseline),
                "related_baseline_ids": _permission_ids(baseline),
            },
        ))

    findings.extend(_suspicious_chains(snapshot, resources))
    return findings


def _permission_ids(actions: dict[Action, list[str]]) -> list[str]:
    return sorted(permission_id for ids in actions.values() for permission_id in ids)


def _event_evidence(event: Interaction, resource: Resource) -> dict[str, Any]:
    occurred_at = _UNIX_EPOCH + timedelta(seconds=event.occurred_at)
    return {
        "interaction_id": event.id,
        "agent_id": event.agent_id,
        "resource_id": event.resource_id,
        "action": event.action,
        "outcome": event.outcome,
        "occurred_at": occurred_at.isoformat().replace("+00:00", "Z"),
        "resource_classification": resource.classification,
        "resource_boundary": resource.boundary,
    }


def _suspicious_chains(snapshot: Snapshot, resources: dict[str, Resource]) -> list[Finding]:
    events = {event.id: event for event in snapshot.interactions}
    children: defaultdict[str, list[Interaction]] = defaultdict(list)
    recipients = {}
    for edge in snapshot.relationships:
        if edge.kind == "TRIGGERS":
            children[edge.source_id].append(events[edge.target_id])
        elif edge.kind == "HANDED_TO":
            recipients[edge.source_id] = edge.target_id

    findings = []
    for read in snapshot.interactions:
        if read.action != "read" or read.outcome != "success" or resources[read.resource_id].classification != "restricted":
            continue
        for handoff in children.get(read.id, ()):
            recipient = recipients.get(handoff.id)
            if (
                handoff.action != "handoff" or handoff.outcome != "success" or recipient is None
                or handoff.resource_id != read.resource_id or handoff.agent_id != read.agent_id
                or recipient == read.agent_id
            ):
                continue
            for export in children.get(handoff.id, ()):
                elapsed = export.occurred_at - read.occurred_at
                if (
                    export.action != "export" or export.outcome != "success" or export.agent_id != recipient
                    or resources[export.resource_id].boundary != "external" or elapsed > _CHAIN_WINDOW_SECONDS
                ):
                    continue
                findings.append(Finding(
                    rule_id="suspicious_chain",
                    explanation=(
                        f"Agent {read.agent_id} read restricted resource {read.resource_id} and handed "
                        f"it to {recipient}. The linked export to external resource "
                        f"{export.resource_id} succeeded within {elapsed} seconds of the read."
                    ),
                    evidence={
                        "interaction_ids": [read.id, handoff.id, export.id],
                        "interactions": [_event_evidence(event, resources[event.resource_id]) for event in (read, handoff, export)],
                        "sender_agent_id": read.agent_id,
                        "recipient_agent_id": recipient,
                        "source_resource_id": read.resource_id,
                        "destination_resource_id": export.resource_id,
                        "elapsed_seconds": elapsed,
                        "window_seconds": _CHAIN_WINDOW_SECONDS,
                    },
                ))
    return findings
