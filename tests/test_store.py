from concurrent.futures import ThreadPoolExecutor

import pytest

from varkhard.models import Agent, Interaction, Permission, Resource
from varkhard.store import GraphStore, GraphStoreError


AGENT = Agent("synthetic-reader", "Synthetic reader")
RESOURCE = Resource("synthetic-ledger", "Synthetic ledger", "restricted", "internal")
GRANT = Permission("grant-read", AGENT.id, RESOURCE.id, "read", "grant")
EVENT = Interaction("event-read", AGENT.id, RESOURCE.id, "read", "success", 1000)


def test_default_single_file_preserves_graph_after_reopen(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "data" / "varkhard-graph.rl"
    with GraphStore() as store:
        store.ingest(agents=[AGENT], resources=[RESOURCE])
        store.ingest(permissions=[GRANT], interactions=[EVENT])
        store.flush()
        assert path.is_file()

    assert list(path.parent.iterdir()) == [path]
    with GraphStore(path, read_only=True) as store:
        assert store.query(
            """
            MATCH (a:AIAgent)-[:HAS_PERMISSION]->(p:Permission)-[:ON_RESOURCE]->(r:Resource),
                  (a)-[:PERFORMED]->(i:Interaction)-[:TARGETS]->(r)
            WHERE i.id = $interaction_id
            RETURN a.id AS agent_id, r.id AS resource_id, p.id AS permission_id,
                   i.occurred_at AS occurred_at
            """,
            {"interaction_id": EVENT.id},
        ) == [
            {
                "agent_id": AGENT.id,
                "resource_id": RESOURCE.id,
                "permission_id": GRANT.id,
                "occurred_at": EVENT.occurred_at,
            }
        ]


@pytest.mark.parametrize("second_read_only", [False, True], ids=["writer", "reader"])
def test_writer_locks_file_until_closed(tmp_path, second_read_only):
    path = tmp_path / "graph.rl"
    with GraphStore(path):
        with pytest.raises(GraphStoreError, match="(?i)lock"):
            with GraphStore(path, read_only=second_read_only):
                pytest.fail("Unexpected second connection while writer owns file")

    with GraphStore(path, read_only=second_read_only) as store:
        assert store.query("RETURN 1 AS value") == [{"value": 1}]


def test_read_only_connections_can_share_file_and_block_writes(tmp_path):
    path = tmp_path / "graph.rl"
    with GraphStore(path) as store:
        store.ingest(agents=[AGENT])

    with GraphStore(path, read_only=True) as first, GraphStore(path, read_only=True) as second:
        first.flush()
        assert first.query("MATCH (a:AIAgent) RETURN a.id AS id") == [{"id": AGENT.id}]
        assert second.query("MATCH (a:AIAgent) RETURN a.id AS id") == [{"id": AGENT.id}]
        with pytest.raises(GraphStoreError):
            second.ingest(agents=[Agent("unexpected", "Unexpected agent")])
        with pytest.raises(GraphStoreError, match="(?i)lock"):
            with GraphStore(path):
                pytest.fail("Unexpected writer while readers own file")

    with GraphStore(path) as store:
        assert store.query("MATCH (a:AIAgent) RETURN a.id AS id") == [{"id": AGENT.id}]


def test_connection_rejects_use_and_close_from_another_thread(tmp_path):
    path = tmp_path / "graph.rl"
    with GraphStore(path) as store, ThreadPoolExecutor(max_workers=1) as executor:
        query = executor.submit(store.query, "RETURN 1 AS value")
        with pytest.raises(GraphStoreError, match="(?i)thread"):
            query.result(timeout=5)
        close = executor.submit(store.close)
        with pytest.raises(GraphStoreError, match="(?i)thread"):
            close.result(timeout=5)
        assert store.query("RETURN 1 AS value") == [{"value": 1}]

    with GraphStore(path, read_only=True) as store:
        assert store.query("RETURN 1 AS value") == [{"value": 1}]


def test_conflicting_id_leaves_no_partial_batch_and_can_be_retried(tmp_path):
    path = tmp_path / "graph.rl"
    with GraphStore(path) as store:
        store.ingest(agents=[AGENT], resources=[RESOURCE], interactions=[EVENT])
        new_agent = Agent("new-agent", "New agent")
        conflicting_event = Interaction(
            EVENT.id, new_agent.id, RESOURCE.id, "read", "success", 1000
        )
        with pytest.raises(GraphStoreError):
            store.ingest(agents=[new_agent], permissions=[GRANT], interactions=[conflicting_event])

        assert store.query("MATCH (a:AIAgent) RETURN a.id AS id") == [{"id": AGENT.id}]
        assert store.query("MATCH (p:Permission) RETURN p.id AS id") == []
        store.ingest(agents=[new_agent], permissions=[GRANT], interactions=[EVENT])

    with GraphStore(path, read_only=True) as store:
        assert store.query("MATCH (a:AIAgent) RETURN count(a) AS total") == [{"total": 2}]
        assert store.query("MATCH (p:Permission) RETURN count(p) AS total") == [{"total": 1}]
        assert store.query("MATCH (i:Interaction) RETURN count(i) AS total") == [{"total": 1}]


def test_missing_reference_leaves_no_partial_batch(tmp_path):
    with GraphStore(tmp_path / "graph.rl") as store:
        orphan = Interaction(
            "orphan", AGENT.id, RESOURCE.id, "read", "success", 1000, parent_id="missing"
        )
        with pytest.raises(GraphStoreError):
            store.ingest(agents=[AGENT], resources=[RESOURCE], interactions=[orphan])

        assert store.query("MATCH (a:AIAgent) RETURN a.id AS id") == []
        assert store.query("MATCH (r:Resource) RETURN r.id AS id") == []
        assert store.query("MATCH (i:Interaction) RETURN i.id AS id") == []
