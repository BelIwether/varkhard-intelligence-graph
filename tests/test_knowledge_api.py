import asyncio
import hashlib
import json
import secrets
from datetime import datetime
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient, Response

from varkhard.api import create_app
from varkhard.knowledge_evidence import EvidenceCatalog
from varkhard.models import Agent, Interaction, Resource
from varkhard.store import GraphStore


_BASE = "/api/knowledge"
_BUNDLED = Path(__file__).resolve().parents[1] / "examples" / "synthetic-demo.rl"
_IDENTITIES = {
    "analyst": ("author", "alpha", "analyst"),
    "other_analyst": ("other-author", "alpha", "analyst"),
    "reviewer": ("reviewer", "alpha", "reviewer"),
    "other_reviewer": ("other-reviewer", "alpha", "reviewer"),
    "author_reviewer": ("author", "alpha", "reviewer"),
    "foreign_analyst": ("author", "beta", "analyst"),
    "foreign_reviewer": ("reviewer", "beta", "reviewer"),
}
_ADVISORY_KEYS = {
    "knowledge_id", "version", "pattern_id", "pattern_version", "schema_version",
    "evidence_classification", "root_cause_status", "limitations", "validation_suite_id", "digest",
}

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def credentials(tmp_path):
    tokens = {name: secrets.token_urlsafe(32) for name in _IDENTITIES}
    identities = [
        {
            "actor_id": actor,
            "tenant_id": tenant,
            "role": role,
            "token_sha256": hashlib.sha256(tokens[name].encode()).hexdigest(),
        }
        for name, (actor, tenant, role) in _IDENTITIES.items()
    ]
    path = tmp_path / "identities.json"
    path.write_text(json.dumps(identities), encoding="utf-8")
    return path, tokens


@pytest.fixture
async def knowledge(tmp_path, credentials):
    identities, tokens = credentials
    app = create_app(knowledge_db=tmp_path / "knowledge.sqlite3", knowledge_identities=identities)
    async with _client(app) as client:
        yield client, tokens


def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://knowledge.test")


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _json(response: Response, status: int):
    assert response.status_code == status, response.text
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def _candidate_reference(candidate):
    return {key: candidate[key] for key in ("snapshot_id", "finding_id")}


async def _register(client, token):
    headers = _bearer(token)
    candidates = _json(await client.get(f"{_BASE}/candidates", headers=headers), 200)
    candidate = next(item for item in candidates if item["rule_id"] == "suspicious_chain")
    return _json(await client.post(
        f"{_BASE}/incidents", headers=headers, json=_candidate_reference(candidate),
    ), 201)


async def _draft(client, token):
    incident = await _register(client, token)
    return _json(await client.post(
        f"{_BASE}/advisories", headers=_bearer(token), json={"incident_id": incident["id"]},
    ), 201)


def _version_url(advisory):
    return f"{_BASE}/advisories/{advisory['id']}/versions/{advisory['version']}"


async def _transition(client, token, advisory, action, *, digest=None):
    return await client.post(
        f"{_version_url(advisory)}/{action}", headers=_bearer(token),
        json={"digest": advisory["advisory"]["digest"] if digest is None else digest},
    )


def _assert_advisory(advisory):
    payload = advisory["advisory"]
    assert payload.keys() == _ADVISORY_KEYS
    assert payload["knowledge_id"] == advisory["id"]
    assert payload["version"] == advisory["version"]
    assert payload["evidence_classification"] == "synthetic"
    assert payload["root_cause_status"] == "not_established"
    canonical = json.dumps(
        {key: value for key, value in payload.items() if key != "digest"},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    assert payload["digest"] == hashlib.sha256(canonical).hexdigest()


def _assert_audit(advisory, expected):
    entries = advisory["audit"]
    assert [(entry["action"], entry["actor_id"], entry["to_status"]) for entry in entries] == expected
    assert [entry["from_status"] for entry in entries[1:]] == [entry["to_status"] for entry in entries[:-1]]
    assert all(entry["version"] == advisory["version"] for entry in entries)
    assert all(entry["digest"] == advisory["advisory"]["digest"] for entry in entries)
    times = [datetime.fromisoformat(entry["occurred_at"].replace("Z", "+00:00")) for entry in entries]
    assert all(time.utcoffset() is not None for time in times)


async def test_session_and_knowledge_reads_require_server_configured_bearer(knowledge, caplog):
    client, tokens = knowledge
    for endpoint in ("session", "candidates", "incidents", "advisories"):
        response = await client.get(f"{_BASE}/{endpoint}")
        _json(response, 401)
        assert response.headers["www-authenticate"].lower() == "bearer"

    unknown = secrets.token_urlsafe(32)
    for header in (f"Basic {tokens['analyst']}", f"Bearer {unknown}", "Bearer short"):
        response = await client.get(f"{_BASE}/session", headers={"Authorization": header})
        _json(response, 401)
        assert header.split()[1] not in response.text
    _json(await client.get(f"{_BASE}/session", headers=[
        ("Authorization", f"Bearer {tokens['analyst']}"), ("Authorization", f"Bearer {tokens['reviewer']}"),
    ]), 401)
    assert unknown not in caplog.text
    assert all(token not in caplog.text for token in tokens.values())

    for name in ("analyst", "reviewer", "foreign_analyst"):
        response = await client.get(f"{_BASE}/session", headers=_bearer(tokens[name]))
        actor, tenant, role = _IDENTITIES[name]
        session = _json(response, 200)
        assert (session["actor_id"], session["tenant_id"], session["role"]) == (actor, tenant, role)
        assert tokens[name] not in response.text


async def test_unconfigured_knowledge_refuses_access_without_changing_graph(monkeypatch):
    monkeypatch.delenv("VARKHARD_KNOWLEDGE_DB", raising=False)
    monkeypatch.delenv("VARKHARD_LOCAL_IDENTITIES", raising=False)
    async with _client(create_app(db_path=_BUNDLED)) as client:
        _json(await client.get(f"{_BASE}/session", headers=_bearer(secrets.token_urlsafe(32))), 401)
        graph = _json(await client.get("/api/graph"), 200)
        assert len(graph["findings"]) == 3


async def test_registration_uses_server_validated_finding_and_observed_outcome(knowledge, caplog):
    client, tokens = knowledge
    analyst = _bearer(tokens["analyst"])
    original = _BUNDLED.read_bytes()
    graph = _json(await client.get("/api/graph"), 200)
    findings = {finding["id"]: finding for finding in graph["findings"]}
    candidates = _json(await client.get(f"{_BASE}/candidates", headers=analyst), 200)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate["snapshot_id"] == "synthetic-demo-v1"
    assert candidate["rule_id"] == "suspicious_chain"
    assert candidate["finding_id"] in findings

    reference = _candidate_reference(candidate)
    for invalid in ({**reference, "snapshot_id": "unknown"}, {**reference, "finding_id": "unknown"}):
        _json(await client.post(f"{_BASE}/incidents", headers=analyst, json=invalid), 404)
    for non_promotable_id in findings.keys() - {candidate["finding_id"]}:
        _json(await client.post(
            f"{_BASE}/incidents", headers=analyst, json={**reference, "finding_id": non_promotable_id},
        ), 404)

    canary = "PRIVATE_FIXTURE_INPUT_62D90"
    invalid = await client.post(f"{_BASE}/incidents", headers=analyst, json={
        **reference, "actor_id": canary, "role": "reviewer", "tenant_id": canary,
        "evidence_node_ids": [canary], "root_cause_status": canary, canary: canary,
    })
    _json(invalid, 422)
    assert canary not in invalid.text
    assert canary not in caplog.text
    assert _json(await client.get(f"{_BASE}/incidents", headers=analyst), 200) == []

    incident = _json(await client.post(f"{_BASE}/incidents", headers=analyst, json=reference), 201)
    finding = findings[incident["finding_id"]]
    assert {key: incident[key] for key in reference} == reference
    assert incident["snapshot_digest"] == hashlib.sha256(original).hexdigest()
    assert incident["rule_id"] == finding["rule_id"]
    assert incident["rule_version"] == candidate["rule_version"]
    assert incident["evidence_complete"] is True
    assert incident["evidence_classification"] == "synthetic"
    assert incident["root_cause_status"] == "not_established"
    assert incident["observed_behavior"] == [
        {"action": action, "outcome": "success"} for action in ("read", "handoff", "export")
    ]
    assert incident["evidence_node_ids"] == finding["investigation"]["node_ids"]
    assert incident["evidence_edge_ids"] == finding["investigation"]["edge_ids"]
    assert incident["registered_by"] == "author"
    assert incident["audit"] == [{"action": "register_incident", "actor_id": "author", "occurred_at": incident["created_at"]}]

    _json(await client.post(f"{_BASE}/incidents", headers=analyst, json=reference), 409)
    incidents = _json(await client.get(f"{_BASE}/incidents", headers=analyst), 200)
    assert incidents == [incident]
    assert _BUNDLED.read_bytes() == original


async def test_envelope_contains_only_deterministic_advisory_fields(tmp_path, credentials, caplog):
    identities, tokens = credentials
    synthetic = tmp_path / "custom-synthetic.rl"
    canary = "PRIVATE_GRAPH_CANARY_794E"
    sender, recipient = f"{canary}-sender-id", f"{canary}-recipient-id"
    source, destination = f"{canary}-source-id", f"{canary}-destination-id"
    read_event, handoff_event = f"{canary}-read-id", f"{canary}-handoff-id"
    with GraphStore(synthetic) as store:
        store.ingest(
            agents=[Agent(sender, f"{canary} sender"), Agent(recipient, f"{canary} recipient")],
            resources=[
                Resource(source, f"{canary} source", "restricted", "internal"),
                Resource(destination, f"{canary} destination", "internal", "external"),
            ],
            interactions=[
                Interaction(read_event, sender, source, "read", "success", 100),
                Interaction(handoff_event, sender, source, "handoff", "success", 110, read_event, recipient),
                Interaction(f"{canary}-export-id", recipient, destination, "export", "success", 120, handoff_event),
            ],
        )
    original = synthetic.read_bytes()
    evidence = EvidenceCatalog(synthetic, hashlib.sha256(original).hexdigest())
    settings = {
        "knowledge_db": tmp_path / "knowledge.sqlite3", "knowledge_identities": identities, "knowledge_evidence": evidence,
    }

    async with _client(create_app(**settings)) as client:
        draft = await _draft(client, tokens["analyst"])
        _assert_advisory(draft)
        assert canary not in json.dumps(draft["advisory"])
    async with _client(create_app(**settings)) as reopened:
        persisted = _json(await reopened.get(_version_url(draft), headers=_bearer(tokens["reviewer"])), 200)
        assert persisted == draft
        assert canary not in json.dumps(persisted["advisory"])
    assert canary not in caplog.text
    assert synthetic.read_bytes() == original


async def test_persisted_review_is_available_during_candidate_outage(tmp_path, credentials):
    identities, tokens = credentials
    settings = {"knowledge_db": tmp_path / "knowledge.sqlite3", "knowledge_identities": identities}
    async with _client(create_app(**settings)) as client:
        draft = await _draft(client, tokens["analyst"])
        submitted = _json(await _transition(client, tokens["analyst"], draft, "submit"), 200)

    missing = EvidenceCatalog(tmp_path / "unavailable.rl", "0" * 64)
    reviewer = _bearer(tokens["reviewer"])
    async with _client(create_app(**settings, knowledge_evidence=missing)) as client:
        _json(await client.get(f"{_BASE}/candidates", headers=reviewer), 503)
        assert _json(await client.get(f"{_BASE}/advisories", headers=reviewer), 200) == [submitted]
        assert _json(await client.get(_version_url(draft), headers=reviewer), 200) == submitted
        approved = _json(await _transition(client, tokens["reviewer"], submitted, "approve"), 200)
        assert approved["advisory"] == draft["advisory"]


async def test_cross_tenant_lists_reads_and_mutations_are_isolated(knowledge):
    client, tokens = knowledge
    alpha = await _draft(client, tokens["analyst"])
    beta = await _draft(client, tokens["foreign_analyst"])
    assert alpha["id"] != beta["id"]
    assert alpha["incident_id"] != beta["incident_id"]

    for token, local in ((tokens["reviewer"], alpha), (tokens["foreign_reviewer"], beta)):
        incidents = _json(await client.get(f"{_BASE}/incidents", headers=_bearer(token)), 200)
        advisories = _json(await client.get(f"{_BASE}/advisories", headers=_bearer(token)), 200)
        assert [incident["id"] for incident in incidents] == [local["incident_id"]]
        assert [advisory["id"] for advisory in advisories] == [local["id"]]

    foreign = _bearer(tokens["foreign_analyst"])
    guesses = (
        await client.get(_version_url(alpha), headers=foreign),
        await client.post(f"{_BASE}/advisories", headers=foreign, json={"incident_id": alpha["incident_id"]}),
        await _transition(client, tokens["foreign_analyst"], alpha, "submit"),
        await _transition(client, tokens["foreign_reviewer"], alpha, "approve"),
    )
    for response in guesses:
        _json(response, 404)
        assert alpha["id"] not in response.text
        assert alpha["incident_id"] not in response.text

    persisted = _json(await client.get(_version_url(alpha), headers=_bearer(tokens["analyst"])), 200)
    assert persisted == alpha


async def test_reviewer_permissions_and_self_review_are_enforced_by_actor(knowledge):
    client, tokens = knowledge
    analyst, reviewer = _bearer(tokens["analyst"]), _bearer(tokens["reviewer"])
    candidate = _json(await client.get(f"{_BASE}/candidates", headers=reviewer), 200)[0]
    _json(await client.post(f"{_BASE}/incidents", headers=reviewer, json=_candidate_reference(candidate)), 403)

    draft = await _draft(client, tokens["analyst"])
    assert draft["author_id"] == "author"
    assert draft["status"] == "draft"
    _json(await client.post(f"{_BASE}/advisories", headers=reviewer, json={"incident_id": draft["incident_id"]}), 403)
    _json(await _transition(client, tokens["reviewer"], draft, "submit"), 403)
    _json(await _transition(client, tokens["other_analyst"], draft, "submit"), 403)
    submitted = _json(await _transition(client, tokens["analyst"], draft, "submit"), 200)
    assert submitted["status"] == "in_review"

    for token in (tokens["analyst"], tokens["author_reviewer"]):
        for action in ("approve", "reject"):
            _json(await _transition(client, token, submitted, action), 403)

    persisted = _json(await client.get(_version_url(draft), headers=analyst), 200)
    assert persisted == submitted
    approved = _json(await _transition(client, tokens["reviewer"], submitted, "approve"), 200)
    assert approved["status"] == "approved"
    assert approved["advisory"] == draft["advisory"]
    _assert_audit(approved, [
        ("create", "author", "draft"), ("submit", "author", "in_review"), ("approve", "reviewer", "approved"),
    ])


async def test_versions_are_immutable_and_wrong_digest_cannot_mutate_state(knowledge, caplog):
    client, tokens = knowledge
    headers = _bearer(tokens["analyst"])
    draft = await _draft(client, tokens["analyst"])
    revision_url = f"{_BASE}/advisories/{draft['id']}/versions"
    revision = {"version": draft["version"], "digest": draft["advisory"]["digest"]}
    _assert_advisory(draft)
    canary = "PRIVATE_DRAFT_DIGEST_INPUT_273A"
    invalid = await _transition(client, tokens["analyst"], draft, "submit", digest=canary)
    _json(invalid, 422)
    assert canary not in invalid.text and canary not in caplog.text
    _json(await _transition(client, tokens["analyst"], draft, "submit", digest="0" * 64), 409)
    _json(await client.post(revision_url, headers=headers, json=revision), 409)
    assert _json(await client.get(_version_url(draft), headers=headers), 200) == draft

    submitted = _json(await _transition(client, tokens["analyst"], draft, "submit"), 200)
    _json(await client.post(revision_url, headers=headers, json=revision), 409)
    rejected = _json(await _transition(client, tokens["reviewer"], submitted, "reject"), 200)
    assert rejected["status"] == "rejected"
    assert rejected["advisory"] == draft["advisory"]
    _assert_audit(rejected, [
        ("create", "author", "draft"), ("submit", "author", "in_review"), ("reject", "reviewer", "rejected"),
    ])

    _json(await client.post(revision_url, headers=headers, json={**revision, "digest": "0" * 64}), 409)
    next_draft = _json(await client.post(revision_url, headers=headers, json=revision), 201)
    _assert_advisory(next_draft)
    _assert_audit(next_draft, [("new_version", "author", "draft")])
    assert next_draft["id"] == draft["id"]
    assert next_draft["incident_id"] == draft["incident_id"]
    assert next_draft["version"] == draft["version"] + 1
    assert next_draft["advisory"]["digest"] != draft["advisory"]["digest"]
    assert next_draft["status"] == "draft"
    _json(await client.post(revision_url, headers=headers, json=revision), 409)
    _json(await _transition(client, tokens["analyst"], next_draft, "submit", digest=revision["digest"]), 409)
    historical = _json(await client.get(_version_url(draft), headers=headers), 200)
    assert historical == {**rejected, "latest_version": next_draft["version"]}
    assert _json(await client.get(_version_url(next_draft), headers=headers), 200) == next_draft
    assert _json(await client.get(f"{_BASE}/advisories", headers=headers), 200) == [next_draft]


async def test_concurrent_review_has_one_terminal_result_and_one_audit_entry(knowledge):
    client, tokens = knowledge
    draft = await _draft(client, tokens["analyst"])
    submitted = _json(await _transition(client, tokens["analyst"], draft, "submit"), 200)
    outcomes = await asyncio.gather(
        _transition(client, tokens["reviewer"], submitted, "approve"),
        _transition(client, tokens["other_reviewer"], submitted, "reject"),
    )
    assert sorted(response.status_code for response in outcomes) == [200, 409]
    approved = outcomes[0].status_code == 200
    winning, losing = outcomes if approved else outcomes[::-1]
    winner = _json(winning, 200)
    _json(losing, 409)
    terminal = "approved" if approved else "rejected"
    assert winner["status"] == terminal
    assert winner["advisory"] == draft["advisory"]
    _assert_audit(winner, [
        ("create", "author", "draft"), ("submit", "author", "in_review"),
        ("approve" if approved else "reject", "reviewer" if approved else "other-reviewer", terminal),
    ])
    assert _json(await client.get(_version_url(draft), headers=_bearer(tokens["analyst"])), 200) == winner
