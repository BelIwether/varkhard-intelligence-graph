"""Thread-confined storage for the embedded Relate graph."""

from collections.abc import Iterable
from dataclasses import asdict
from pathlib import Path
from threading import current_thread

import relate

from .models import Agent, Interaction, Permission, Resource

DEFAULT_DB_PATH = Path("data/varkhard-graph.rl")

# MERGE includes every immutable field and is backed by a uniqueness constraint
# on each ID. A different record with the same ID fails the entire transaction.
_MERGE_AGENTS = """
UNWIND $rows AS row
MERGE (:AIAgent {id: row.id, name: row.name})
RETURN row.id AS id
"""

_MERGE_RESOURCES = """
UNWIND $rows AS row
MERGE (:Resource {
    id: row.id, name: row.name, classification: row.classification, boundary: row.boundary
})
RETURN row.id AS id
"""

_MERGE_PERMISSIONS = """
UNWIND $rows AS row
MATCH (agent:AIAgent {id: row.agent_id}), (resource:Resource {id: row.resource_id})
MERGE (agent)-[:HAS_PERMISSION]->(:Permission {
    id: row.id, action: row.action, kind: row.kind
})-[:ON_RESOURCE]->(resource)
RETURN row.id AS id
"""

# Optional IDs are also kept on the event for immutable identity checks.
# Empty strings are reserved for absent references because MERGE disallows nulls.
_MERGE_INTERACTIONS = """
UNWIND $rows AS row
MATCH (agent:AIAgent {id: row.agent_id}), (resource:Resource {id: row.resource_id})
MERGE (agent)-[:PERFORMED]->(:Interaction {
    id: row.id, action: row.action, outcome: row.outcome, occurred_at: row.occurred_at,
    parent_id: coalesce(row.parent_id, ''), recipient_id: coalesce(row.recipient_id, '')
})-[:TARGETS]->(resource)
RETURN row.id AS id
"""

_LINK_PARENTS = """
UNWIND $rows AS row
MATCH (parent:Interaction {id: row.parent_id}), (child:Interaction {id: row.id})
MERGE (parent)-[:TRIGGERS]->(child)
RETURN row.id AS id
"""

_LINK_RECIPIENTS = """
UNWIND $rows AS row
MATCH (event:Interaction {id: row.id}), (recipient:AIAgent {id: row.recipient_id})
MERGE (event)-[:HANDED_TO]->(recipient)
RETURN row.id AS id
"""


class GraphStoreError(RuntimeError):
    """A graph operation failed or would violate the store's contract."""


class GraphStore:
    """One embedded Relate connection, owned by the thread that opens it."""

    def __init__(self, path: str | Path = DEFAULT_DB_PATH, *, read_only: bool = False) -> None:
        self._owner = current_thread()
        self._read_only = read_only
        self._path = Path(path).expanduser().resolve()
        if self._path.suffix != ".rl":
            raise GraphStoreError("A Relate Single File path must end in .rl.")
        if not read_only:
            self._path.parent.mkdir(parents=True, exist_ok=True)

        try:
            self._connection: relate.Connection | None = relate.connect(
                str(self._path), read_only=read_only
            )
        except relate.OperationalError as exc:
            if "storage locked" in str(exc).lower():
                raise GraphStoreError(
                    f"Relate file {self._path} is locked. Close the conflicting connection and retry."
                ) from exc
            raise

        if not read_only:
            try:
                for label in ("AIAgent", "Resource", "Permission", "Interaction"):
                    self.query(
                        f"CREATE CONSTRAINT varkhard_{label.lower()}_id IF NOT EXISTS "
                        f"FOR (node:{label}) REQUIRE node.id IS UNIQUE"
                    )
            except BaseException:
                self.close()
                raise

    def __enter__(self) -> "GraphStore":
        self._active_connection()
        return self

    def __exit__(self, *exc_details: object) -> None:
        self.close()

    def _check_owner(self) -> None:
        if current_thread() is not self._owner:
            raise GraphStoreError("Use and close the Relate graph on the thread that opened it.")

    def _active_connection(self) -> relate.Connection:
        self._check_owner()
        if self._connection is None:
            raise GraphStoreError("The Relate graph is closed.")
        return self._connection

    def close(self) -> None:
        self._check_owner()
        if self._connection is not None:
            try:
                self._connection.close()
            finally:
                self._connection = None

    def flush(self) -> None:
        """Checkpoint committed state. Relate treats this as a no-op for readers."""
        self._active_connection().flush()

    def query(self, cypher: str, parameters: dict | None = None) -> list[dict]:
        """Run trusted Cypher and materialize rows on the connection's owner thread."""
        cursor = self._active_connection().cursor()
        try:
            cursor.execute(cypher, parameters)
            return cursor.data()
        finally:
            cursor.close()

    def ingest(
        self,
        *,
        agents: Iterable[Agent] = (),
        resources: Iterable[Resource] = (),
        permissions: Iterable[Permission] = (),
        interactions: Iterable[Interaction] = (),
    ) -> None:
        """Write an immutable batch atomically, then checkpoint the committed data."""
        connection = self._active_connection()
        if self._read_only:
            raise GraphStoreError("Cannot ingest into a read-only Relate graph.")

        agent_rows = [asdict(agent) for agent in agents]
        resource_rows = [asdict(resource) for resource in resources]
        permission_rows = [asdict(permission) for permission in permissions]
        interaction_rows = [asdict(interaction) for interaction in interactions]
        parent_rows = [row for row in interaction_rows if row["parent_id"] is not None]
        recipient_rows = [row for row in interaction_rows if row["recipient_id"] is not None]

        connection.autocommit = False
        try:
            self._merge_rows(_MERGE_AGENTS, agent_rows, "agent")
            self._merge_rows(_MERGE_RESOURCES, resource_rows, "resource")
            self._merge_rows(_MERGE_PERMISSIONS, permission_rows, "permission")
            self._merge_rows(_MERGE_INTERACTIONS, interaction_rows, "interaction")
            self._merge_rows(_LINK_PARENTS, parent_rows, "interaction parent")
            self._merge_rows(_LINK_RECIPIENTS, recipient_rows, "handoff recipient")
            connection.commit()
        except BaseException:
            try:
                connection.rollback()
            except BaseException:
                self.close()
                raise
            raise
        finally:
            if not connection.closed:
                connection.autocommit = True
        self.flush()

    def _merge_rows(self, cypher: str, rows: list[dict], subject: str) -> None:
        if not rows:
            return
        try:
            matched = self.query(cypher, {"rows": rows})
        except relate.IntegrityError as exc:
            raise GraphStoreError(f"Conflicting {subject} ID in graph batch.") from exc
        if len(matched) != len(rows):
            raise GraphStoreError(f"Unknown graph reference in {subject} batch.")
