import json
from dataclasses import asdict, replace

import pytest

from varkhard.demo import seed_demo
from varkhard.detection import detect_findings
from varkhard.models import Agent, Interaction, Permission, Resource
from varkhard.store import GraphStore


def test_detection_survives_reopen_and_reseeding(tmp_path):
    path = tmp_path / "graph.rl"
    with GraphStore(path) as store:
        seed_demo(store)
        original = detect_findings(store)

    with GraphStore(path) as store:
        seed_demo(store)
        assert store.query("MATCH (a:AIAgent) RETURN count(a) AS total") == [{"total": 5}]

    with GraphStore(path, read_only=True) as store:
        restored = detect_findings(store)

    assert restored == original
    assert len(restored) == 3
    by_rule = {finding.rule_id: finding for finding in restored}
    assert (
        by_rule["unauthorized_access"].evidence["interaction_id"]
        == "interaction-catalog-write-denied"
    )
    assert by_rule["excessive_permission"].evidence["permission_id"] == "grant-archive-delete"
    assert by_rule["suspicious_chain"].evidence["interaction_ids"] == [
        "interaction-ledger-read",
        "interaction-ledger-handoff",
        "interaction-outbox-export",
    ]
    assert all(finding.explanation.strip() and finding.evidence for finding in restored)
    json.dumps([asdict(finding) for finding in restored])


def test_access_and_baseline_checks_compare_exact_agent_resource_and_action(tmp_path):
    agents = [Agent("primary", "Primary"), Agent("secondary", "Secondary")]
    resources = [
        Resource("ledger", "Synthetic ledger", "restricted", "internal"),
        Resource("archive", "Synthetic archive", "internal", "internal"),
    ]
    permissions = [
        Permission("ledger-read", "primary", "ledger", "read", "grant"),
        Permission("ledger-read-policy", "primary", "ledger", "read", "baseline"),
        Permission("ledger-unused-write", "primary", "ledger", "write", "grant"),
        Permission("ledger-write-policy", "primary", "ledger", "write", "baseline"),
        Permission("ledger-delete-policy", "primary", "ledger", "delete", "baseline"),
        Permission("other-agent-delete", "secondary", "ledger", "delete", "grant"),
        Permission("other-agent-delete-policy", "secondary", "ledger", "delete", "baseline"),
        Permission("archive-read-policy", "primary", "archive", "read", "baseline"),
        Permission("archive-excess-delete", "primary", "archive", "delete", "grant"),
    ]
    interactions = [
        Interaction("allowed", "primary", "ledger", "read", "success", 1000),
        Interaction("only-baselined", "primary", "ledger", "delete", "denied", 1010),
        Interaction("wrong-resource", "primary", "archive", "read", "success", 1020),
        Interaction("wrong-agent", "secondary", "ledger", "read", "success", 1030),
        Interaction("used-excess", "primary", "archive", "delete", "success", 1040),
    ]
    with GraphStore(tmp_path / "graph.rl") as store:
        store.ingest(
            agents=agents, resources=resources, permissions=permissions, interactions=interactions
        )
        findings = detect_findings(store)

    unauthorized = {
        finding.evidence["interaction_id"]: finding.evidence
        for finding in findings
        if finding.rule_id == "unauthorized_access"
    }
    assert set(unauthorized) == {"only-baselined", "wrong-resource", "wrong-agent"}
    denied = unauthorized["only-baselined"]
    assert denied["outcome"] == "denied"
    assert denied["agent_id"] == "primary"
    assert denied["resource_id"] == "ledger"
    assert denied["action"] == "delete"
    assert denied["occurred_at"] == "1970-01-01T00:16:50Z"
    assert set(denied["granted_actions"]) == {"read", "write"}
    assert set(denied["related_grant_ids"]) == {"ledger-read", "ledger-unused-write"}

    excessive = [
        finding.evidence for finding in findings if finding.rule_id == "excessive_permission"
    ]
    assert len(excessive) == 1
    assert excessive[0]["permission_id"] == "archive-excess-delete"
    assert excessive[0]["approved_actions"] == ["read"]
    assert excessive[0]["related_baseline_ids"] == ["archive-read-policy"]


READ = Interaction("read", "sender", "ledger", "read", "success", 1000)
HANDOFF = Interaction(
    "handoff", "sender", "ledger", "handoff", "success", 1001, parent_id="read", recipient_id="receiver"
)
EXPORT = Interaction("export", "receiver", "outbox", "export", "success", 1600, parent_id="handoff")


@pytest.mark.parametrize(
    ("handoff", "export", "matched"),
    [
        pytest.param(HANDOFF, EXPORT, True, id="window-inclusive"),
        pytest.param(HANDOFF, replace(EXPORT, occurred_at=1601), False, id="outside-window"),
        pytest.param(HANDOFF, replace(EXPORT, occurred_at=1001), False, id="same-timestamp"),
        pytest.param(HANDOFF, replace(EXPORT, occurred_at=1000), False, id="reversed-time"),
        pytest.param(HANDOFF, replace(EXPORT, parent_id=None), False, id="unlinked"),
        pytest.param(HANDOFF, replace(EXPORT, outcome="denied"), False, id="denied-export"),
        pytest.param(HANDOFF, replace(EXPORT, resource_id="ledger"), False, id="internal-export"),
        pytest.param(HANDOFF, replace(EXPORT, agent_id="bystander"), False, id="wrong-recipient"),
        pytest.param(replace(HANDOFF, resource_id="archive"), EXPORT, False, id="different-resource"),
        pytest.param(replace(HANDOFF, agent_id="bystander"), EXPORT, False, id="different-sender"),
    ],
)
def test_chain_requires_connected_successful_steps_and_respects_window(
    tmp_path, handoff, export, matched
):
    agents = [Agent(agent_id, agent_id.title()) for agent_id in ("sender", "receiver", "bystander")]
    resources = [
        Resource("ledger", "Synthetic ledger", "restricted", "internal"),
        Resource("archive", "Synthetic archive", "restricted", "internal"),
        Resource("outbox", "Synthetic outbox", "internal", "external"),
    ]
    with GraphStore(tmp_path / "graph.rl") as store:
        store.ingest(agents=agents, resources=resources, interactions=[READ, handoff, export])
        chains = [finding for finding in detect_findings(store) if finding.rule_id == "suspicious_chain"]

    if matched:
        assert len(chains) == 1
        evidence = chains[0].evidence
        assert evidence["interaction_ids"] == ["read", "handoff", "export"]
        assert evidence["elapsed_seconds"] == 600
        assert evidence["window_seconds"] == 600
        assert evidence["sender_agent_id"] == "sender"
        assert evidence["recipient_agent_id"] == "receiver"
        assert evidence["source_resource_id"] == "ledger"
        assert evidence["destination_resource_id"] == "outbox"
        assert [event["action"] for event in evidence["interactions"]] == [
            "read", "handoff", "export"
        ]
    else:
        assert chains == []
