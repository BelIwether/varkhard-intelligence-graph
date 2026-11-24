import asyncio
from dataclasses import asdict
from pathlib import Path

import pytest
import relate
from httpx import ASGITransport, AsyncClient

from varkhard.api import app, create_app
from varkhard.demo import DEMO_AGENTS, DEMO_INTERACTIONS, DEMO_PERMISSIONS, DEMO_RESOURCES, seed_demo
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


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"Symbolic links are unavailable: {exc}")


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
    assert graph["source"] == {"filename": "synthetic-demo.rl", "read_only": True, "synthetic_demo": True}
    assert graph["evidence_quality"] == {"status": "complete", "invalid_records": 0, "invalid_relationships": 0}
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
        assert first["source"] == {"filename": "custom.rl", "read_only": True, "synthetic_demo": False}
        assert first["findings"] == []
        assert {node["id"] for node in first["nodes"]} == {"agent:shared-id", "resource:shared-id"}
        with GraphStore(path) as store:
            store.ingest(agents=[Agent("new-agent", "New agent")])

        assert (await client.get("/api/agents")).json() == [
            {"id": "new-agent", "name": "New agent"},
            {"id": "shared-id", "name": "Custom agent"},
        ]


async def test_snapshot_provenance_follows_the_opened_symlink_target(tmp_path):
    alias = tmp_path / "active.rl"
    custom = tmp_path / _DEMO.name
    _symlink(alias, _DEMO)
    with GraphStore(custom) as store:
        store.ingest(agents=[Agent("custom", "Custom agent")])

    async with _client(create_app(alias)) as client:
        for target, expected_demo in ((_DEMO, True), (custom, False), (_DEMO, True)):
            if alias.readlink() != target:
                alias.unlink()
                _symlink(alias, target)

            response = await client.get("/api/graph")
            assert response.status_code == 200
            assert response.headers["cache-control"] == "no-store"
            graph = response.json()
            assert graph["source"] == {
                "filename": target.name,
                "read_only": True,
                "synthetic_demo": expected_demo,
            }
            expected_agents = {agent.id for agent in DEMO_AGENTS} if expected_demo else {"custom"}
            assert {agent["id"] for agent in graph["agents"]} == expected_agents


async def test_circular_snapshot_symlink_returns_retryable_errors_and_recovers(tmp_path):
    alias = tmp_path / "active.rl"
    target = tmp_path / "target.rl"
    _symlink(alias, Path(target.name))
    _symlink(target, Path(alias.name))

    async with _client(create_app(alias)) as client:
        for endpoint in ("graph", "findings", "agents", "resources"):
            response = await client.get(f"/api/{endpoint}")
            assert response.status_code == 503
            assert response.headers["cache-control"] == "no-store"
            assert response.json() == {"detail": "The Relate graph is unavailable. Check the configured Single File."}

        assert alias.readlink() == Path(target.name)
        assert target.readlink() == Path(alias.name)
        alias.unlink()
        _symlink(alias, _DEMO)
        response = await client.get("/api/graph")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["source"]["synthetic_demo"] is True


async def test_locked_file_returns_retryable_error_and_recovers(tmp_path):
    path = tmp_path / "locked.rl"
    async with _client(create_app(path)) as client:
        with GraphStore(path):
            response = await client.get("/api/graph")
            assert response.status_code == 503
            assert response.headers["cache-control"] == "no-store"
            assert response.json() == {
                "detail": "The Relate file is locked. Close the writer and try again.",
            }

        assert (await client.get("/api/graph")).status_code == 200


async def test_missing_file_returns_safe_error_without_creating_it(tmp_path):
    path = tmp_path / "missing.rl"
    async with _client(create_app(path)) as client:
        response = await client.get("/api/findings")

    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "detail": "The Relate graph is unavailable. Check the configured Single File.",
    }
    assert not path.exists()


@pytest.mark.parametrize("file_kind", ["wrong_extension", "non_relate", "unrelated_schema", "uninitialized"])
async def test_unsupported_snapshot_returns_a_safe_non_cacheable_error(tmp_path, file_kind):
    path = tmp_path / ("sample.txt" if file_kind == "wrong_extension" else "sample.rl")
    if file_kind in ("wrong_extension", "non_relate"):
        path.write_text("A plain text fixture", encoding="utf-8")
    else:
        with relate.connect(str(path)) as connection:
            if file_kind == "unrelated_schema":
                connection.execute("CREATE (:Example {id: 'unrelated'})")

    original = path.read_bytes()
    async with _client(create_app(path)) as client:
        for endpoint in ("graph", "findings", "agents", "resources"):
            response = await client.get(f"/api/{endpoint}")
            assert response.status_code == 503
            assert response.headers["cache-control"] == "no-store"
            assert response.json() == {"detail": "The configured file is not a supported VARKHARD Relate snapshot."}
    assert path.read_bytes() == original


async def test_initialized_empty_snapshot_is_supported(tmp_path):
    path = tmp_path / "empty.rl"
    with GraphStore(path):
        pass

    async with _client(create_app(path)) as client:
        response = await client.get("/api/graph")

    assert response.status_code == 200
    assert response.json()["nodes"] == []
    assert response.json()["findings"] == []
    assert response.json()["evidence_quality"]["status"] == "complete"


async def test_data_endpoints_and_api_errors_forbid_caching():
    async with _client() as client:
        for endpoint in ("graph", "findings", "agents", "resources"):
            response = await client.get(f"/api/{endpoint}")
            assert response.status_code == 200
            assert response.headers["cache-control"] == "no-store"

        unknown = await client.get("/api/unknown")
        assert unknown.status_code == 404
        assert unknown.headers["cache-control"] == "no-store"


async def test_incomplete_snapshot_reports_quality_and_only_supported_findings(tmp_path):
    path = tmp_path / "partial.rl"
    with GraphStore(path) as store:
        seed_demo(store)
        store.query("""
            MATCH (:Interaction {id: 'interaction-ledger-handoff'})-[link:TRIGGERS]->
                  (:Interaction {id: 'interaction-outbox-export'})
            DELETE link
        """)

    async with _client(create_app(path)) as client:
        response = await client.get("/api/graph")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        graph = response.json()
        assert graph["evidence_quality"]["status"] == "incomplete"
        assert graph["evidence_quality"]["invalid_relationships"] >= 1
        assert {finding["rule_id"] for finding in graph["findings"]} == {"unauthorized_access", "excessive_permission"}
        assert (await client.get("/api/findings")).json() == graph["findings"]
        export = next(event for event in graph["interactions"] if event["id"] == "interaction-outbox-export")
        assert export["outcome"] == "success"


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
    shield = Path(__file__).resolve().parents[1] / "frontend" / "public" / "varkhard-shield.svg"
    shield_content = shield.read_bytes()
    (tmp_path / shield.name).write_bytes(shield_content)

    async with _client(create_app(_DEMO, frontend_dir=tmp_path)) as client:
        assert (await client.get("/")).text == "<main>Dashboard</main>"
        assert (await client.get("/assets/bundle.js")).text == "export {};"
        response = await client.get("/varkhard-shield.svg")
        assert response.status_code == 200
        assert response.headers["content-type"] == "image/svg+xml"
        assert response.content == shield_content
        assert (await client.get("/api/graph")).status_code == 200
        assert (await client.get("/api/unknown")).status_code == 404
