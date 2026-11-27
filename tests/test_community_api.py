import hashlib
import json
import secrets
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import pytest
from fastapi.testclient import TestClient

from varkhard import community_store
from varkhard.api import create_app


KNOWLEDGE = "/api/knowledge"
COMMUNITY = f"{KNOWLEDGE}/community"
IDENTITIES = {
    "author": ("tenant-a", "analyst"),
    "reviewer": ("tenant-a", "reviewer"),
    "publisher": ("tenant-a", "publisher"),
    "validator": ("tenant-b", "validator"),
    "b-publisher": ("tenant-b", "publisher"),
    "outsider": ("tenant-c", "validator"),
    "other-publisher": ("tenant-a", "publisher"),
}


@pytest.fixture
def community(tmp_path):
    tokens = {name: secrets.token_urlsafe(32) for name in IDENTITIES}
    entries = [
        {
            "actor_id": name,
            "tenant_id": tenant,
            "role": role,
            "token_sha256": hashlib.sha256(tokens[name].encode()).hexdigest(),
            **({"community_recipients": ["tenant-b"]} if (tenant, role) == ("tenant-a", "publisher") else {}),
        }
        for name, (tenant, role) in IDENTITIES.items()
    ]
    registry = tmp_path / "identities.json"
    registry.write_text(json.dumps(entries), encoding="utf-8")
    database = tmp_path / "knowledge.sqlite3"
    with TestClient(create_app(knowledge_db=database, knowledge_identities=registry)) as client:
        def request(method, path, actor=None, **kwargs):
            headers = {"Authorization": f"Bearer {tokens[actor]}"} if actor else {}
            return client.request(method, path, headers=headers, **kwargs)

        yield request, database, registry


def body(response, status):
    assert response.status_code == status, response.text
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def draft(request):
    candidate = body(request("GET", f"{KNOWLEDGE}/candidates", "author"), 200)[0]
    incident = body(request("POST", f"{KNOWLEDGE}/incidents", "author", json={
        key: candidate[key] for key in ("snapshot_id", "finding_id")
    }), 201)
    return body(request("POST", f"{KNOWLEDGE}/advisories", "author", json={"incident_id": incident["id"]}), 201)


def version_url(advisory):
    return f"{KNOWLEDGE}/advisories/{advisory['id']}/versions/{advisory['version']}"


def approve(request, advisory):
    payload = {"digest": advisory["advisory"]["digest"]}
    body(request("POST", f"{version_url(advisory)}/submit", "author", json=payload), 200)
    return body(request("POST", f"{version_url(advisory)}/approve", "reviewer", json=payload), 200)


def delivery_payload(advisory, **changes):
    return {
        "knowledge_id": advisory["id"],
        "version": advisory["version"],
        "digest": advisory["advisory"]["digest"],
        "recipient_tenant": "tenant-b",
        "ttl_hours": 24,
        **changes,
    }


def send(request, advisory, actor="publisher"):
    return body(request("POST", f"{COMMUNITY}/outbox", actor, json=delivery_payload(advisory)), 201)


def create_fixture(request, scenario, actor="validator"):
    return body(request("POST", f"{COMMUNITY}/fixtures", actor, json={"scenario": scenario}), 201)


def test_explicit_two_tenant_exchange_and_minimized_feedback(community):
    request, _, _ = community
    approved = approve(request, draft(request))
    assert body(request("GET", f"{COMMUNITY}/inbox", "validator"), 200) == []
    assert body(request("GET", f"{COMMUNITY}/peers", "publisher"), 200) == ["tenant-b"]
    assert body(request("GET", f"{COMMUNITY}/approved", "publisher"), 200) == [{
        key: value for key, value in delivery_payload(approved).items() if key in {"knowledge_id", "version", "digest"}
    }]

    outgoing = send(request, approved)
    inbox_url = f"{COMMUNITY}/inbox/{outgoing['id']}"
    incoming = body(request("GET", f"{COMMUNITY}/inbox", "validator"), 200)[0]
    assert incoming["id"] == outgoing["id"]
    assert incoming["status"] == "unverified"
    assert incoming.get("advisory") is None
    assert incoming["validations"] == incoming["feedback"] == []

    positive = create_fixture(request, "positive")
    body(request("POST", f"{inbox_url}/validate", "validator", json={"fixture_id": positive["id"]}), 409)
    verified = body(request("POST", f"{inbox_url}/verify", "validator"), 200)
    assert verified["status"] == "verified"
    assert verified["advisory"] == approved["advisory"]
    assert verified["validations"] == []
    assert approved["incident_id"] not in json.dumps(verified)

    fixtures = [positive, create_fixture(request, "negative"), create_fixture(request, "inconclusive")]
    results = []
    for fixture, expected in zip(fixtures, ("pattern_observed", "pattern_not_observed", "inconclusive")):
        updated = body(request("POST", f"{inbox_url}/validate", "validator", json={"fixture_id": fixture["id"]}), 200)
        validation = updated["validations"][-1]
        assert validation["result"] == expected
        assert validation["fixture_id"] == fixture["id"]
        assert len(validation["fixture_digest"]) == 64
        assert validation["suite_id"] == approved["advisory"]["validation_suite_id"]
        assert validation["suite_version"] == 1
        assert validation["protection_effectiveness"] == "unmeasured"
        assert validation["limitations"]
        results.append(validation)

    sent = body(request("GET", f"{COMMUNITY}/outbox", "publisher"), 200)[0]
    assert sent["validations"] == sent["feedback"] == []
    feedback_payload = {"validation_id": results[2]["id"]}
    shared = body(request("POST", f"{inbox_url}/feedback", "validator", json=feedback_payload), 200)
    assert body(request("POST", f"{inbox_url}/feedback", "validator", json=feedback_payload), 200) == shared
    sent = body(request("GET", f"{COMMUNITY}/outbox", "publisher"), 200)[0]
    assert sent["validations"] == []
    feedback, = sent["feedback"]
    assert feedback["result"] == "inconclusive"
    assert feedback["protection_effectiveness"] == "unmeasured"
    assert feedback["suite_id"] == results[2]["suite_id"]
    assert feedback["suite_version"] == results[2]["suite_version"]
    assert all(fixture["id"] not in json.dumps(sent) for fixture in fixtures)
    assert all(result["fixture_digest"] not in json.dumps(sent) for result in results)
    received = body(request("GET", f"{COMMUNITY}/inbox", "validator"), 200)[0]
    assert received["validations"] == results
    assert received["feedback"] == sent["feedback"]
    assert [event["action"] for event in received["audit"]] == [
        "delivered", "verified", "validation_recorded", "validation_recorded", "validation_recorded", "feedback_shared",
    ]
    assert [event["action"] for event in sent["audit"]] == ["delivered", "feedback_shared"]


def test_publish_verify_and_validation_enforce_role_tenant_and_exact_approval(community):
    request, _, _ = community
    advisory = draft(request)
    post = f"{COMMUNITY}/outbox"
    payload = delivery_payload(advisory)
    body(request("GET", f"{COMMUNITY}/inbox"), 401)
    body(request("POST", post, "reviewer", json=payload), 403)
    body(request("POST", post, "publisher", json=payload), 409)
    approved = approve(request, advisory)
    body(request("POST", post, "publisher", json={**payload, "digest": "0" * 64}), 409)
    body(request("POST", post, "publisher", json={**payload, "version": 2}), 404)
    body(request("POST", post, "publisher", json={**payload, "recipient_tenant": "tenant-c"}), 403)
    body(request("POST", post, "publisher", json={**payload, "recipient_tenant": "tenant-a"}), 403)
    body(request("POST", post, "publisher", json={**payload, "advisory": {"note": "private-canary"}}), 422)

    # A subsequent draft does not replace the approved historical envelope.
    body(request("POST", f"{KNOWLEDGE}/advisories/{advisory['id']}/versions", "author", json={
        "version": payload["version"], "digest": payload["digest"],
    }), 201)
    delivery = send(request, approved)
    inbox_url = f"{COMMUNITY}/inbox/{delivery['id']}"
    assert body(request("GET", f"{COMMUNITY}/inbox", "outsider"), 200) == []
    assert body(request("GET", post, "b-publisher"), 200) == []
    body(request("POST", f"{post}/{delivery['id']}/withdraw", "b-publisher"), 404)
    body(request("GET", f"{KNOWLEDGE}/incidents", "publisher"), 403)
    body(request("GET", version_url(advisory), "validator"), 403)
    body(request("POST", f"{inbox_url}/verify", "outsider"), 404)
    body(request("POST", f"{inbox_url}/verify", "publisher"), 403)
    body(request("POST", f"{inbox_url}/verify", "validator"), 200)

    other_fixture = create_fixture(request, "positive", "outsider")
    fixture = create_fixture(request, "positive")
    assert all(item["id"] != other_fixture["id"] for item in body(request("GET", f"{COMMUNITY}/fixtures", "validator"), 200))
    body(request("POST", f"{inbox_url}/validate", "outsider", json={"fixture_id": fixture["id"]}), 404)
    body(request("POST", f"{inbox_url}/validate", "publisher", json={"fixture_id": fixture["id"]}), 403)
    body(request("POST", f"{inbox_url}/validate", "validator", json={"fixture_id": other_fixture["id"]}), 404)
    body(request("POST", f"{COMMUNITY}/fixtures", "validator", json={"scenario": "private-canary"}), 422)
    body(request("POST", f"{COMMUNITY}/fixtures", "validator", json={"scenario": "positive", "observations": []}), 422)


def test_concurrent_publication_and_verify_replays_keep_one_delivery_and_audit(community):
    request, database, _ = community
    approved = approve(request, draft(request))
    payload = delivery_payload(approved)
    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _: request("POST", f"{COMMUNITY}/outbox", "publisher", json=payload), range(2)))
    assert sorted(response.status_code for response in responses) == [200, 201]
    delivery_id = responses[0].json()["id"]
    assert responses[1].json()["id"] == delivery_id
    assert len(body(request("GET", f"{COMMUNITY}/inbox", "validator"), 200)) == 1

    verify = f"{COMMUNITY}/inbox/{delivery_id}/verify"
    first = body(request("POST", verify, "validator"), 200)
    assert body(request("POST", verify, "validator"), 200) == first
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT count(*) FROM community_deliveries").fetchone() == (1,)
        assert connection.execute("SELECT count(*) FROM community_validations").fetchone() == (0,)
        assert connection.execute("SELECT count(*) FROM community_audit").fetchone() == (2,)


@pytest.mark.parametrize("close_by", ["expiry", "withdrawal"])
def test_closed_delivery_hides_envelope_and_replay_cannot_reopen_it(community, monkeypatch, close_by):
    request, _, _ = community
    approved = approve(request, draft(request))
    monkeypatch.setattr(community_store, "_timestamp", lambda: "2030-01-01T00:00:00.000000Z")
    delivery = send(request, approved)
    delivery_id = delivery["id"]
    inbox_url = f"{COMMUNITY}/inbox/{delivery_id}"
    body(request("POST", f"{inbox_url}/verify", "validator"), 200)
    fixture = create_fixture(request, "positive")

    if close_by == "expiry":
        status = "expired"
        monkeypatch.setattr(community_store, "_timestamp", lambda: delivery["expires_at"])
    else:
        status = "withdrawn"
        closed = body(request("POST", f"{COMMUNITY}/outbox/{delivery_id}/withdraw", "publisher"), 200)
        assert closed["status"] == status
        assert body(request("POST", f"{COMMUNITY}/outbox/{delivery_id}/withdraw", "publisher"), 200) == closed

    body(request("POST", f"{inbox_url}/verify", "validator"), 410)
    body(request("POST", f"{inbox_url}/validate", "validator", json={"fixture_id": fixture["id"]}), 410)
    body(request("POST", f"{inbox_url}/feedback", "validator", json={"validation_id": fixture["id"]}), 410)
    incoming = body(request("GET", f"{COMMUNITY}/inbox", "validator"), 200)[0]
    assert incoming["status"] == status
    assert incoming.get("advisory") is None
    assert [entry["action"] for entry in incoming["audit"]] == ["delivered", "verified", status]

    replay = body(request("POST", f"{COMMUNITY}/outbox", "publisher", json=delivery_payload(approved, ttl_hours=48)), 200)
    assert (replay["id"], replay["status"], replay["expires_at"]) == (delivery_id, status, delivery["expires_at"])
    assert body(request("GET", f"{COMMUNITY}/inbox", "validator"), 200) == [incoming]


@pytest.mark.parametrize("column, value", [
    ("envelope_json", '{"private_note":"private-canary"}'),
    ("digest", "0" * 64),
    ("recipient_tenant", "tenant-c"),
    ("publisher_id", "forged-publisher"),
])
def test_tampered_delivery_fails_closed(community, column, value):
    request, database, _ = community
    approved = approve(request, draft(request))
    delivery = send(request, approved)
    with closing(sqlite3.connect(database)) as connection, connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(f"UPDATE community_deliveries SET {column} = ?", (value,))
        connection.execute("DROP TRIGGER community_deliveries_no_update")
        connection.execute(f"UPDATE community_deliveries SET {column} = ?", (value,))
    recipient = "outsider" if column == "recipient_tenant" else "validator"
    failure = request("POST", f"{COMMUNITY}/inbox/{delivery['id']}/verify", recipient)
    body(failure, 409)
    assert "private-canary" not in failure.text
    with closing(sqlite3.connect(database)) as connection:
        assert connection.execute("SELECT action FROM community_audit").fetchall() == [("delivered",)]


def test_approval_digest_mismatch_prevents_publish(community):
    request, database, _ = community
    approved = approve(request, draft(request))
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("DROP TRIGGER knowledge_audit_keep_entries")
        connection.execute("UPDATE knowledge_audit SET digest = ? WHERE action = 'approve'", ("0" * 64,))
    body(request("POST", f"{COMMUNITY}/outbox", "publisher", json=delivery_payload(approved)), 409)
    assert body(request("GET", f"{COMMUNITY}/inbox", "validator"), 200) == []


def test_invalid_fixture_bytes_cannot_create_validation_or_audit(community):
    request, database, _ = community
    delivery = send(request, approve(request, draft(request)))
    inbox_url = f"{COMMUNITY}/inbox/{delivery['id']}"
    body(request("POST", f"{inbox_url}/verify", "validator"), 200)
    fixture = create_fixture(request, "positive")
    payload = '{"private_note":"private-canary"}'
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("DROP TRIGGER community_fixtures_no_update")
        connection.execute("UPDATE community_fixtures SET fixture_json = ?, digest = ?", (
            payload, hashlib.sha256(payload.encode()).hexdigest(),
        ))
    failure = request("POST", f"{inbox_url}/validate", "validator", json={"fixture_id": fixture["id"]})
    body(failure, 422)
    assert "private-canary" not in failure.text
    incoming = body(request("GET", f"{COMMUNITY}/inbox", "validator"), 200)[0]
    assert incoming["validations"] == []
    assert [entry["action"] for entry in incoming["audit"]] == ["delivered", "verified"]


def test_result_keeps_original_fixture_provenance_when_fixture_is_damaged(community):
    request, database, _ = community
    delivery = send(request, approve(request, draft(request)))
    inbox_url = f"{COMMUNITY}/inbox/{delivery['id']}"
    body(request("POST", f"{inbox_url}/verify", "validator"), 200)
    fixture = create_fixture(request, "positive")
    payload = {"fixture_id": fixture["id"]}
    recorded = body(request("POST", f"{inbox_url}/validate", "validator", json=payload), 200)
    result, = recorded["validations"]
    assert result["fixture_digest"] == fixture["digest"]
    assert body(request("POST", f"{inbox_url}/validate", "validator", json=payload), 200) == recorded
    with closing(sqlite3.connect(database)) as connection, connection:
        connection.execute("DROP TRIGGER community_fixtures_no_update")
        connection.execute("UPDATE community_fixtures SET digest = ?", ("0" * 64,))
    body(request("POST", f"{inbox_url}/validate", "validator", json=payload), 422)
    assert body(request("GET", f"{COMMUNITY}/inbox", "validator"), 200) == [recorded]


def test_revoked_sender_audience_closes_verified_envelope_on_restart(community):
    request, database, registry = community
    initial = approve(request, draft(request))
    delivery = send(request, initial)
    verify_path = f"{COMMUNITY}/inbox/{delivery['id']}/verify"
    assert body(request("POST", verify_path, "validator"), 200)["advisory"]
    revision = body(request("POST", f"{KNOWLEDGE}/advisories/{initial['id']}/versions", "author", json={
        "version": initial["version"], "digest": initial["advisory"]["digest"],
    }), 201)
    authorized = send(request, approve(request, revision), "other-publisher")

    token = secrets.token_urlsafe(32)
    entries = json.loads(registry.read_text(encoding="utf-8"))
    for entry in entries:
        if entry["actor_id"] == "publisher":
            entry["community_recipients"] = []
        elif entry["actor_id"] == "validator":
            entry["token_sha256"] = hashlib.sha256(token.encode()).hexdigest()
    registry.write_text(json.dumps(entries), encoding="utf-8")
    headers = {"Authorization": f"Bearer {token}"}
    with TestClient(create_app(knowledge_db=database, knowledge_identities=registry), headers=headers) as client:
        rows = {item["id"]: item for item in body(client.get(f"{COMMUNITY}/inbox"), 200)}
        assert rows[delivery["id"]]["status"] == "unavailable"
        assert rows[delivery["id"]].get("advisory") is None
        assert rows[authorized["id"]]["status"] == "unverified"
        body(client.post(verify_path), 409)
        assert body(client.post(f"{COMMUNITY}/inbox/{authorized['id']}/verify"), 200)["status"] == "verified"


@pytest.mark.parametrize("audience", [["tenant-a"], ["unconfigured"], ["tenant-b", "tenant-b"]])
def test_invalid_publisher_audience_cannot_configure_a_server(community, audience):
    _, database, registry = community
    entries = json.loads(registry.read_text(encoding="utf-8"))
    next(entry for entry in entries if entry["actor_id"] == "publisher")["community_recipients"] = audience
    registry.write_text(json.dumps(entries), encoding="utf-8")
    with pytest.raises(RuntimeError, match="local Knowledge identity registry"):
        create_app(knowledge_db=database, knowledge_identities=registry)
