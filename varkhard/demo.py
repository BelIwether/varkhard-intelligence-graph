"""Reproducible, entirely synthetic graph for the hackathon demo."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .models import Agent, Interaction, Permission, Resource

if TYPE_CHECKING:
    from .store import GraphStore


DEMO_AGENTS = (
    Agent("agent-research", "Research Agent"),
    Agent("agent-relay", "Relay Agent"),
    Agent("agent-catalog", "Catalog Agent"),
    Agent("agent-preview", "Preview Agent"),
    Agent("agent-maintenance", "Maintenance Agent"),
)

DEMO_RESOURCES = (
    Resource("resource-test-ledger", "Synthetic Ledger", "restricted", "internal"),
    Resource("resource-demo-outbox", "Simulated External Outbox", "public", "external"),
    Resource("resource-sample-catalog", "Sample Catalog", "public", "internal"),
    Resource("resource-sample-archive", "Sample Archive", "internal", "internal"),
)

# Each row has its own ID and scope so findings can cite individual policy records.
DEMO_PERMISSIONS = (
    Permission("grant-ledger-read", "agent-research", "resource-test-ledger", "read", "grant"),
    Permission("policy-ledger-read", "agent-research", "resource-test-ledger", "read", "baseline"),
    Permission(
        "grant-ledger-handoff", "agent-research", "resource-test-ledger", "handoff", "grant",
    ),
    Permission(
        "policy-ledger-handoff", "agent-research", "resource-test-ledger", "handoff", "baseline",
    ),
    Permission("grant-outbox-export", "agent-relay", "resource-demo-outbox", "export", "grant"),
    Permission(
        "policy-outbox-export", "agent-relay", "resource-demo-outbox", "export", "baseline",
    ),
    Permission("grant-catalog-read", "agent-catalog", "resource-sample-catalog", "read", "grant"),
    Permission(
        "policy-catalog-read", "agent-catalog", "resource-sample-catalog", "read", "baseline",
    ),
    Permission("grant-preview-read", "agent-preview", "resource-sample-catalog", "read", "grant"),
    Permission(
        "policy-preview-read", "agent-preview", "resource-sample-catalog", "read", "baseline",
    ),
    Permission(
        "grant-archive-read", "agent-maintenance", "resource-sample-archive", "read", "grant",
    ),
    Permission(
        "policy-archive-read", "agent-maintenance", "resource-sample-archive", "read", "baseline",
    ),
    Permission(
        "grant-archive-write", "agent-maintenance", "resource-sample-archive", "write", "grant",
    ),
    Permission(
        "policy-archive-write", "agent-maintenance", "resource-sample-archive", "write", "baseline",
    ),
    Permission(
        "grant-archive-delete", "agent-maintenance", "resource-sample-archive", "delete", "grant",
    ),
)

_DEMO_START = 1767225600  # 2026-01-01 00:00:00 UTC.

DEMO_INTERACTIONS = (
    Interaction(
        "interaction-ledger-read",
        "agent-research",
        "resource-test-ledger",
        "read",
        "success",
        _DEMO_START,
    ),
    Interaction(
        "interaction-ledger-handoff",
        "agent-research",
        "resource-test-ledger",
        "handoff",
        "success",
        _DEMO_START + 60,
        parent_id="interaction-ledger-read",
        recipient_id="agent-relay",
    ),
    Interaction(
        "interaction-outbox-export",
        "agent-relay",
        "resource-demo-outbox",
        "export",
        "success",
        _DEMO_START + 180,
        parent_id="interaction-ledger-handoff",
    ),
    Interaction(
        "interaction-catalog-read",
        "agent-catalog",
        "resource-sample-catalog",
        "read",
        "success",
        _DEMO_START + 20,
    ),
    Interaction(
        "interaction-catalog-preview",
        "agent-preview",
        "resource-sample-catalog",
        "read",
        "success",
        _DEMO_START + 30,
    ),
    Interaction(
        "interaction-catalog-write-denied",
        "agent-preview",
        "resource-sample-catalog",
        "write",
        "denied",
        _DEMO_START + 45,
    ),
    Interaction(
        "interaction-archive-read",
        "agent-maintenance",
        "resource-sample-archive",
        "read",
        "success",
        _DEMO_START + 90,
    ),
)


def seed_demo(store: GraphStore) -> None:
    """Add the demo records to a writable graph."""
    store.ingest(
        agents=DEMO_AGENTS,
        resources=DEMO_RESOURCES,
        permissions=DEMO_PERMISSIONS,
        interactions=DEMO_INTERACTIONS,
    )
