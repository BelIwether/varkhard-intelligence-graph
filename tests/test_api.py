import asyncio
from dataclasses import asdict
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from varkhard.api import app, create_app
from varkhard.demo import DEMO_AGENTS, DEMO_INTERACTIONS, DEMO_PERMISSIONS, DEMO_RESOURCES
from varkhard.detection import detect_findings
from varkhard.models import Agent, Resource
from varkhard.store import GraphStore

_DEMO = Path(__file__).resolve().parents[1] / "examples" / "synthetic-demo.rl"
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _client(application=app):
    return AsyncClient(transport=ASGITransport(app=application), base_url="http://dashboard.test")


async def test_dashboard_returns_relate_records_and_unmodified_core_evidence():
    before = _DEMO.read_bytes()
    with GraphStore(_DEMO, read_only=True) as store:
        core_findings = [asdict(finding) for finding in detect_findings(store)]

    async with _client() as client:
        response = await client.get("/api/graph")
        assert response.status_code == 200
        graph = response.json()
        for endpoint in ("agents", "resources", "findings"):
            assert (await client.get(f"/api/{endpoint}")).json() == graph[endpoint]

    assert _DEMO.read_bytes() == before
    assert graph["source"] == {"filename": "synthetic-demo.rl", "read_only": True}
    for key, records in {
        "agents": DEMO_AGENTS,
        "resources": DEMO_RESOURCES,
        "permissions": DEMO_PERMISSIONS,
        "interactions": DEMO_INTERACTIONS,
    }.items():
        assert graph[key] == sorted(map(asdict, records), key=lambda record: record["id"])
    assert [
        {key: finding[key] for key in ("rule_id", "explanation", "evidence")}
        for finding in graph["findings"]
    ] == core_findings


async def test_finding_highlights_resolve_to_graph_entities_and_relationships():
    async with _client() as client:
        graph = (await client.get("/api/graph")).json()

    nodes = {node["id"] for node in graph["nodes"]}
    edges = {edge["id"]: edge for edge in graph["edges"]}
    assert len(nodes) == 31
    assert len(edges) == 47
    assert {edge["kind"] for edge in edges.values()} == {
        "HAS_PERMISSION", "ON_RESOURCE", "PERFORMED", "TARGETS", "HANDED_TO", "TRIGGERS",
    }
    assert all({edge["source"], edge["target"]} <= nodes for edge in edges.values())

    unauthorized, excessive, chain = graph["findings"]
    assert [finding["category"] for finding in (unauthorized, excessive, chain)] == [
        "Unauthorized Access", "Excessive Permission", "Suspicious Chain",
    ]
    assert "interaction:interaction-catalog-write-denied" in unauthorized["node_ids"]
    assert "permission:grant-preview-read" in unauthorized["node_ids"]
    assert "permission:grant-archive-delete" in excessive["node_ids"]
    assert "permission:policy-archive-write" in excessive["node_ids"]
    assert {
        (edges[edge_id]["source"], edges[edge_id]["target"])
        for edge_id in chain["edge_ids"] if edges[edge_id]["kind"] == "TRIGGERS"
    } == {
        ("interaction:interaction-ledger-read", "interaction:interaction-ledger-handoff"),
        ("interaction:interaction-ledger-handoff", "interaction:interaction-outbox-export"),
    }
    assert {
        (edges[edge_id]["source"], edges[edge_id]["target"])
        for edge_id in chain["edge_ids"] if edges[edge_id]["kind"] == "HANDED_TO"
    } == {("interaction:interaction-ledger-handoff", "agent:agent-relay")}
    for finding in graph["findings"]:
        highlighted_nodes = set(finding["node_ids"])
        assert highlighted_nodes <= nodes
        assert finding["edge_ids"]
        for edge_id in finding["edge_ids"]:
            edge = edges[edge_id]
            assert {edge["source"], edge["target"]} <= highlighted_nodes


async def test_configured_file_is_read_on_each_request(tmp_path, monkeypatch):
    path = tmp_path / "custom.rl"
    monkeypatch.setenv("VARKHARD_DB_PATH", str(path))
    with GraphStore(path) as store:
        store.ingest(
            agents=[Agent("shared-id", "Custom agent")],
            resources=[Resource("shared-id", "Custom resource", "public", "internal")],
        )

    async with _client(create_app()) as client:
        first = (await client.get("/api/graph")).json()
        assert first["source"]["filename"] == "custom.rl"
        assert first["findings"] == []
        assert {node["id"] for node in first["nodes"]} == {"agent:shared-id", "resource:shared-id"}
        with GraphStore(path) as store:
            store.ingest(agents=[Agent("new-agent", "New agent")])

        assert (await client.get("/api/agents")).json() == [
            {"id": "new-agent", "name": "New agent"},
            {"id": "shared-id", "name": "Custom agent"},
        ]


async def test_locked_file_returns_retryable_error_and_recovers(tmp_path):
    path = tmp_path / "locked.rl"
    async with _client(create_app(path)) as client:
        with GraphStore(path):
            response = await client.get("/api/graph")
            assert response.status_code == 503
            assert response.json() == {
                "detail": "The Relate file is locked. Close the writer and try again.",
            }

        assert (await client.get("/api/graph")).status_code == 200


async def test_missing_file_returns_safe_error_without_creating_it(tmp_path):
    path = tmp_path / "missing.rl"
    async with _client(create_app(path)) as client:
        response = await client.get("/api/findings")

    assert response.status_code == 503
    assert response.json() == {
        "detail": "The Relate graph is unavailable. Check the configured Single File.",
    }
    assert not path.exists()


async def test_parallel_requests_use_independent_read_only_connections():
    async with _client() as client:
        responses = await asyncio.gather(*(client.get("/api/graph") for _ in range(8)))

    assert all(response.status_code == 200 for response in responses)
    assert all(response.json() == responses[0].json() for response in responses[1:])


async def test_serves_built_frontend_alongside_api(tmp_path):
    (tmp_path / "index.html").write_text("<main>Dashboard</main>", encoding="utf-8")
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "bundle.js").write_text("export {};", encoding="utf-8")

    async with _client(create_app(_DEMO, frontend_dir=tmp_path)) as client:
        assert (await client.get("/")).text == "<main>Dashboard</main>"
        assert (await client.get("/assets/bundle.js")).text == "export {};"
        assert (await client.get("/api/graph")).status_code == 200
        assert (await client.get("/api/unknown")).status_code == 404
