import hashlib
import json
import os
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from threading import Barrier

import pytest

from varkhard.knowledge_store import KnowledgeError, KnowledgeStore


def _evidence(**changes):
    return {
        "snapshot_id": "synthetic-demo-v1",
        "snapshot_digest": "a" * 64,
        "finding_id": "synthetic-finding",
        "rule_id": "suspicious_chain",
        "rule_version": 1,
        "evidence_complete": True,
        "evidence_node_ids": ["interaction:synthetic-event"],
        "evidence_edge_ids": ["synthetic-edge"],
        "observed_behavior": [
            {"action": action, "outcome": "success"} for action in ("read", "handoff", "export")
        ],
        "root_cause_status": "not_established",
        **changes,
    }


def _draft(store):
    incident = store.register_incident("tenant-a", "analyst", _evidence())
    return store.create_advisory("tenant-a", "analyst", incident["id"])


def test_versions_preserve_the_envelope_and_record_exact_review_history(tmp_path):
    path = tmp_path / "knowledge.sqlite3"
    store = KnowledgeStore(path)
    private_field = "Free-form text that must never enter a knowledge artifact"
    incident = store.register_incident("tenant-a", "analyst", _evidence(raw_details=private_field))
    assert "raw_details" not in incident
    assert incident["audit"][0]["action"] == "register_incident"
    draft = store.create_advisory("tenant-a", "analyst", incident["id"])
    knowledge_id = draft["id"]
    envelope = draft["advisory"]
    digest = envelope["digest"]
    payload = {key: value for key, value in envelope.items() if key != "digest"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == digest
    assert {
        "knowledge_id", "version", "schema_version", "pattern_id", "pattern_version",
        "evidence_classification", "root_cause_status", "limitations", "validation_suite_id",
    } == payload.keys()
    assert envelope["knowledge_id"] == knowledge_id
    assert envelope["version"] == 1
    assert private_field not in canonical

    assert store.transition("tenant-a", "analyst", knowledge_id, 1, digest, "submit")["status"] == "in_review"
    approved = store.transition("tenant-a", "reviewer", knowledge_id, 1, digest, "approve")
    assert approved["status"] == "approved"
    assert [entry["action"] for entry in approved["audit"]] == ["create", "submit", "approve"]
    assert [entry["actor_id"] for entry in approved["audit"]] == ["analyst", "analyst", "reviewer"]
    assert all(entry["version"] == 1 and entry["digest"] == digest for entry in approved["audit"])

    subsequent = store.new_version("tenant-a", "another-analyst", knowledge_id, 1, digest)
    assert subsequent["status"] == "draft"
    assert subsequent["version"] == subsequent["advisory"]["version"] == 2
    assert subsequent["advisory"]["digest"] != digest
    assert [entry["action"] for entry in subsequent["audit"]] == ["new_version"]
    with pytest.raises(KnowledgeError) as stale:
        store.new_version("tenant-a", "analyst", knowledge_id, 1, digest)
    assert stale.value.status_code == 409

    reopened = KnowledgeStore(path)
    assert reopened.list_advisories("tenant-a") == [subsequent]
    assert reopened.get_advisory("tenant-a", knowledge_id, 1) == {**approved, "latest_version": 2}


def test_store_enforces_tenant_author_digest_and_state_boundaries(tmp_path):
    store = KnowledgeStore(tmp_path / "knowledge.sqlite3")
    draft = _draft(store)
    knowledge_id = draft["id"]
    digest = draft["advisory"]["digest"]
    assert store.list_incidents("tenant-b") == store.list_advisories("tenant-b") == []
    for expected, operation in (
        (404, lambda: store.get_advisory("tenant-b", knowledge_id, 1)),
        (404, lambda: store.create_advisory("tenant-b", "analyst", draft["incident_id"])),
        (404, lambda: store.transition("tenant-b", "analyst", knowledge_id, 1, digest, "submit")),
        (409, lambda: store.register_incident("tenant-a", "analyst", _evidence())),
        (409, lambda: store.create_advisory("tenant-a", "analyst", draft["incident_id"])),
        (409, lambda: store.new_version("tenant-a", "analyst", knowledge_id, 1, digest)),
        (409, lambda: store.transition("tenant-a", "analyst", knowledge_id, 1, "wrong", "submit")),
        (409, lambda: store.transition("tenant-a", "reviewer", knowledge_id, 1, digest, "approve")),
        (403, lambda: store.transition("tenant-a", "another-analyst", knowledge_id, 1, digest, "submit")),
        (403, lambda: store.transition("tenant-a", "analyst", knowledge_id, 1, digest, "approve")),
    ):
        with pytest.raises(KnowledgeError) as error:
            operation()
        assert error.value.status_code == expected

    distinct = store.register_incident("tenant-b", "analyst", _evidence())
    assert distinct["id"] != draft["incident_id"]
    assert store.get_advisory("tenant-a", knowledge_id, 1) == draft


def test_ineligible_evidence_is_not_registered(tmp_path):
    store = KnowledgeStore(tmp_path / "knowledge.sqlite3")
    for changes in (
        {"evidence_complete": False},
        {"evidence_classification": "production"},
        {"observed_behavior": [{"action": "read", "outcome": "denied"}]},
        {"rule_id": "unknown"},
    ):
        with pytest.raises(KnowledgeError) as error:
            store.register_incident("tenant-a", "analyst", _evidence(**changes))
        assert error.value.status_code == 422
    assert store.list_incidents("tenant-a") == []


def test_only_one_concurrent_review_can_win(tmp_path):
    store = KnowledgeStore(tmp_path / "knowledge.sqlite3")
    draft = _draft(store)
    knowledge_id = draft["id"]
    digest = draft["advisory"]["digest"]
    store.transition("tenant-a", "analyst", knowledge_id, 1, digest, "submit")
    ready = Barrier(2)

    def review(action):
        ready.wait(timeout=5)
        try:
            return store.transition("tenant-a", f"reviewer-{action}", knowledge_id, 1, digest, action)["status"]
        except KnowledgeError as error:
            return error.status_code

    with ThreadPoolExecutor(max_workers=2) as workers:
        outcomes = list(workers.map(review, ["approve", "reject"]))
    result = store.get_advisory("tenant-a", knowledge_id, 1)
    assert 409 in outcomes
    assert result["status"] in {"approved", "rejected"}
    assert result["status"] in outcomes
    assert len(result["audit"]) == 3


def test_sqlite_preserves_immutable_records_and_rejects_damaged_advisory(tmp_path):
    path = tmp_path / "knowledge.sqlite3"
    store = KnowledgeStore(path)
    draft = _draft(store)
    with closing(sqlite3.connect(path)) as connection, connection:
        for statement in (
            "UPDATE knowledge_versions SET advisory_json = '{}'",
            "UPDATE knowledge_versions SET status = 'approved'",
            "DELETE FROM knowledge_versions",
            "UPDATE knowledge_audit SET actor_id = 'another-actor'",
            "DELETE FROM knowledge_audit",
            "UPDATE knowledge_incidents SET registered_by = 'another-actor'",
            "DELETE FROM knowledge_incidents",
        ):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(statement)
        connection.execute("DROP TRIGGER knowledge_versions_keep_advisory_immutable")
        payload = {key: value for key, value in draft["advisory"].items() if key != "digest"}
        payload["private_note"] = "canary"
        changed = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        connection.execute(
            "UPDATE knowledge_versions SET advisory_json = ?, digest = ?",
            (changed, hashlib.sha256(changed.encode()).hexdigest()),
        )

    with pytest.raises(KnowledgeError) as invalid:
        store.get_advisory("tenant-a", draft["id"], 1)
    assert invalid.value.status_code == 503
    with pytest.raises(KnowledgeError) as invalid:
        store.transition("tenant-a", "analyst", draft["id"], 1, draft["advisory"]["digest"], "submit")
    assert invalid.value.status_code == 503


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_new_knowledge_database_is_private_and_existing_mode_is_preserved(tmp_path):
    path = tmp_path / "knowledge.sqlite3"
    KnowledgeStore(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    path.chmod(0o640)
    KnowledgeStore(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
