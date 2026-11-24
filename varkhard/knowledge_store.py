"""Persist synthetic incident records and versioned knowledge review state."""

import hashlib
import json
import os
import re
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from .knowledge_evidence import RULE_ID, RULE_VERSION, SNAPSHOT_ID

_VALIDATION_SUITE = "synthetic-suspicious-chain-v1"
_OBSERVED_ACTIONS = ("read", "handoff", "export")
_TRANSITIONS = {
    "submit": ("draft", "in_review"),
    "approve": ("in_review", "approved"),
    "reject": ("in_review", "rejected"),
}

_SCHEMA = """
BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS knowledge_incidents (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    registered_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, snapshot_digest, finding_id)
);
CREATE TABLE IF NOT EXISTS knowledge_advisories (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    latest_version INTEGER NOT NULL CHECK (latest_version >= 1),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, incident_id),
    FOREIGN KEY (tenant_id, incident_id) REFERENCES knowledge_incidents (tenant_id, id)
);
CREATE TABLE IF NOT EXISTS knowledge_versions (
    tenant_id TEXT NOT NULL,
    knowledge_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version >= 1),
    author_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('draft', 'in_review', 'approved', 'rejected')),
    advisory_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, knowledge_id, version),
    FOREIGN KEY (tenant_id, knowledge_id) REFERENCES knowledge_advisories (tenant_id, id)
);
CREATE TABLE IF NOT EXISTS knowledge_audit (
    sequence INTEGER PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    knowledge_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    action TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    from_status TEXT,
    to_status TEXT NOT NULL,
    digest TEXT NOT NULL,
    FOREIGN KEY (tenant_id, knowledge_id, version)
        REFERENCES knowledge_versions (tenant_id, knowledge_id, version)
);
CREATE INDEX IF NOT EXISTS knowledge_audit_version
    ON knowledge_audit (tenant_id, knowledge_id, version);
CREATE TRIGGER IF NOT EXISTS knowledge_versions_keep_advisory_immutable
BEFORE UPDATE OF tenant_id, knowledge_id, version, author_id, advisory_json, digest, created_at
ON knowledge_versions BEGIN
    SELECT RAISE(ABORT, 'Advisory versions are immutable');
END;
CREATE TRIGGER IF NOT EXISTS knowledge_versions_keep_history
BEFORE DELETE ON knowledge_versions BEGIN
    SELECT RAISE(ABORT, 'Advisory versions are immutable');
END;
CREATE TRIGGER IF NOT EXISTS knowledge_versions_validate_transition
BEFORE UPDATE OF status ON knowledge_versions
WHEN NOT (
    (OLD.status = 'draft' AND NEW.status = 'in_review') OR
    (OLD.status = 'in_review' AND NEW.status IN ('approved', 'rejected'))
) BEGIN
    SELECT RAISE(ABORT, 'Invalid advisory status transition');
END;
CREATE TRIGGER IF NOT EXISTS knowledge_audit_keep_entries
BEFORE UPDATE ON knowledge_audit BEGIN
    SELECT RAISE(ABORT, 'Audit entries are append-only');
END;
CREATE TRIGGER IF NOT EXISTS knowledge_audit_keep_history
BEFORE DELETE ON knowledge_audit BEGIN
    SELECT RAISE(ABORT, 'Audit entries are append-only');
END;
CREATE TRIGGER IF NOT EXISTS knowledge_incidents_keep_fields
BEFORE UPDATE ON knowledge_incidents BEGIN
    SELECT RAISE(ABORT, 'Incident records are immutable');
END;
CREATE TRIGGER IF NOT EXISTS knowledge_incidents_keep_history
BEFORE DELETE ON knowledge_incidents BEGIN
    SELECT RAISE(ABORT, 'Incident records are immutable');
END;
COMMIT;
"""

_ADVISORY_SELECT = """
SELECT v.*, a.incident_id, a.latest_version
FROM knowledge_versions AS v
JOIN knowledge_advisories AS a ON a.tenant_id = v.tenant_id AND a.id = v.knowledge_id
"""


class KnowledgeError(RuntimeError):
    """A service error suitable for a public response."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _canonical_json(data: dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _advisory_payload(knowledge_id: str, version: int) -> dict[str, Any]:
    return {
        "knowledge_id": knowledge_id,
        "version": version,
        "schema_version": 1,
        "pattern_id": RULE_ID,
        "pattern_version": RULE_VERSION,
        "evidence_classification": "synthetic",
        "root_cause_status": "not_established",
        "limitations": [
            "This pattern describes an observed sequence in synthetic evidence.",
            "Root cause remains undetermined.",
            "Protection remains unverified.",
        ],
        "validation_suite_id": _VALIDATION_SUITE,
    }


def _stored_advisory(row: sqlite3.Row) -> dict[str, Any]:
    # The MVP supports only the fixed schema-1 envelope. Check its contents as well as its digest.
    payload = _advisory_payload(row["knowledge_id"], row["version"])
    canonical = _canonical_json(payload)
    if row["advisory_json"] != canonical or row["digest"] != _digest(canonical):
        raise KnowledgeError(503, "The stored advisory could not be verified.")
    return {**payload, "digest": row["digest"]}


def _verified_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Project the verified source metadata without carrying over free-form fields."""
    observed = [{"action": action, "outcome": "success"} for action in _OBSERVED_ACTIONS]
    expected = {
        "snapshot_id": SNAPSHOT_ID,
        "rule_id": RULE_ID,
        "rule_version": RULE_VERSION,
        "evidence_complete": True,
        "observed_behavior": observed,
        "root_cause_status": "not_established",
    }
    if (
        any(evidence.get(field) != value for field, value in expected.items())
        or type(evidence.get("rule_version")) is not int
        or evidence.get("evidence_complete") is not True
        or evidence.get("evidence_classification", "synthetic") != "synthetic"
    ):
        raise KnowledgeError(422, "The finding does not have eligible synthetic evidence.")
    digest = evidence.get("snapshot_digest")
    finding_id = evidence.get("finding_id")
    if (
        not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or not isinstance(finding_id, str) or not finding_id
    ):
        raise KnowledgeError(422, "The finding does not have eligible synthetic evidence.")

    references = {}
    for field in ("evidence_node_ids", "evidence_edge_ids"):
        ids = evidence.get(field)
        if not isinstance(ids, list) or not ids or any(not isinstance(item, str) or not item for item in ids):
            raise KnowledgeError(422, "The finding does not have eligible synthetic evidence.")
        references[field] = list(dict.fromkeys(ids))

    return {
        **expected,
        **references,
        "snapshot_digest": digest,
        "finding_id": finding_id,
        "evidence_classification": "synthetic",
    }


class KnowledgeStore:
    """Use a separate SQLite file and tenant-scoped transactions for review."""

    def __init__(self, path: str | Path) -> None:
        try:
            self.path = Path(path).expanduser().absolute()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
        except (OSError, RuntimeError) as error:
            raise KnowledgeError(503, "Knowledge storage is unavailable.") from error
        with self._connection() as connection:
            connection.executescript(_SCHEMA)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        try:
            with closing(sqlite3.connect(self.path, timeout=5)) as connection:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys = ON")
                with connection:
                    yield connection
        except sqlite3.Error as error:
            raise KnowledgeError(503, "Knowledge storage is unavailable.") from error

    @contextmanager
    def _transaction(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection

    @staticmethod
    def _incident_view(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            **json.loads(row["evidence_json"]),
            "registered_by": row["registered_by"],
            "created_at": row["created_at"],
            "audit": [{
                "action": "register_incident",
                "actor_id": row["registered_by"],
                "occurred_at": row["created_at"],
            }],
        }

    def register_incident(self, tenant_id: str, actor_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
        verified = _verified_evidence(evidence)
        source = (tenant_id, verified["snapshot_digest"], verified["finding_id"])
        with self._transaction(write=True) as connection:
            existing = connection.execute(
                """
                SELECT id FROM knowledge_incidents
                WHERE tenant_id = ? AND snapshot_digest = ? AND finding_id = ?
                """,
                source,
            ).fetchone()
            if existing:
                raise KnowledgeError(409, "This finding is already registered for the snapshot.")
            incident_id = str(uuid4())
            connection.execute(
                """
                INSERT INTO knowledge_incidents
                    (id, tenant_id, snapshot_digest, finding_id, evidence_json, registered_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (incident_id, *source, _canonical_json(verified), actor_id, _timestamp()),
            )
            row = connection.execute(
                "SELECT * FROM knowledge_incidents WHERE tenant_id = ? AND id = ?", (tenant_id, incident_id),
            ).fetchone()
            return self._incident_view(row)

    def list_incidents(self, tenant_id: str) -> list[dict[str, Any]]:
        with self._transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM knowledge_incidents WHERE tenant_id = ? ORDER BY created_at, id", (tenant_id,),
            )
            return [self._incident_view(row) for row in rows]

    @staticmethod
    def _advisory_row(
        connection: sqlite3.Connection, tenant_id: str, knowledge_id: str, version: int,
    ) -> sqlite3.Row:
        row = connection.execute(
            _ADVISORY_SELECT + " WHERE v.tenant_id = ? AND v.knowledge_id = ? AND v.version = ?",
            (tenant_id, knowledge_id, version),
        ).fetchone()
        if row is None:
            raise KnowledgeError(404, "Advisory version not found.")
        return row

    @staticmethod
    def _advisory_view(connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        audit = connection.execute(
            """
            SELECT action, actor_id, occurred_at, from_status, to_status, version, digest
            FROM knowledge_audit
            WHERE tenant_id = ? AND knowledge_id = ? AND version = ?
            ORDER BY sequence
            """,
            (row["tenant_id"], row["knowledge_id"], row["version"]),
        )
        return {
            "id": row["knowledge_id"],
            "version": row["version"],
            "latest_version": row["latest_version"],
            "incident_id": row["incident_id"],
            "author_id": row["author_id"],
            "status": row["status"],
            "created_at": row["created_at"],
            "advisory": _stored_advisory(row),
            "audit": [dict(item) for item in audit],
        }

    @staticmethod
    def _audit(
        connection: sqlite3.Connection, tenant_id: str, actor_id: str, knowledge_id: str, version: int,
        digest: str, action: str, previous_status: str | None, next_status: str, occurred_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO knowledge_audit (
                tenant_id, knowledge_id, version, digest, action, actor_id, from_status, to_status, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (tenant_id, knowledge_id, version, digest, action, actor_id, previous_status, next_status, occurred_at),
        )

    def _create_draft(
        self, connection: sqlite3.Connection, tenant_id: str, actor_id: str, knowledge_id: str,
        version: int, audit_action: str,
    ) -> dict[str, Any]:
        payload = _canonical_json(_advisory_payload(knowledge_id, version))
        digest = _digest(payload)
        created = _timestamp()
        connection.execute(
            """
            INSERT INTO knowledge_versions (
                tenant_id, knowledge_id, version, author_id, status, advisory_json, digest, created_at
            ) VALUES (?, ?, ?, ?, 'draft', ?, ?, ?)
            """,
            (tenant_id, knowledge_id, version, actor_id, payload, digest, created),
        )
        self._audit(connection, tenant_id, actor_id, knowledge_id, version, digest, audit_action, None, "draft", created)
        return self._advisory_view(connection, self._advisory_row(connection, tenant_id, knowledge_id, version))

    def create_advisory(self, tenant_id: str, actor_id: str, incident_id: str) -> dict[str, Any]:
        with self._transaction(write=True) as connection:
            incident = connection.execute(
                "SELECT id FROM knowledge_incidents WHERE tenant_id = ? AND id = ?", (tenant_id, incident_id),
            ).fetchone()
            if incident is None:
                raise KnowledgeError(404, "Incident not found.")
            existing = connection.execute(
                "SELECT id FROM knowledge_advisories WHERE tenant_id = ? AND incident_id = ?",
                (tenant_id, incident_id),
            ).fetchone()
            if existing:
                raise KnowledgeError(409, "This incident already has an advisory.")
            knowledge_id = str(uuid4())
            connection.execute(
                """
                INSERT INTO knowledge_advisories (tenant_id, id, incident_id, latest_version) VALUES (?, ?, ?, 1)
                """,
                (tenant_id, knowledge_id, incident_id),
            )
            return self._create_draft(connection, tenant_id, actor_id, knowledge_id, 1, "create")

    def list_advisories(self, tenant_id: str) -> list[dict[str, Any]]:
        with self._transaction() as connection:
            rows = connection.execute(
                _ADVISORY_SELECT + """
                WHERE v.tenant_id = ? AND v.version = a.latest_version
                ORDER BY v.created_at, v.knowledge_id
                """,
                (tenant_id,),
            )
            return [self._advisory_view(connection, row) for row in rows]

    def get_advisory(self, tenant_id: str, knowledge_id: str, version: int) -> dict[str, Any]:
        with self._transaction() as connection:
            return self._advisory_view(connection, self._advisory_row(connection, tenant_id, knowledge_id, version))

    def _current_advisory(
        self, connection: sqlite3.Connection, tenant_id: str, knowledge_id: str, version: int, digest: str,
    ) -> sqlite3.Row:
        row = self._advisory_row(connection, tenant_id, knowledge_id, version)
        _stored_advisory(row)
        if row["version"] != row["latest_version"] or row["digest"] != digest:
            raise KnowledgeError(409, "The advisory version or digest is stale.")
        return row

    def new_version(
        self, tenant_id: str, actor_id: str, knowledge_id: str, version: int, digest: str,
    ) -> dict[str, Any]:
        with self._transaction(write=True) as connection:
            source = self._current_advisory(connection, tenant_id, knowledge_id, version, digest)
            if source["status"] not in ("approved", "rejected"):
                raise KnowledgeError(409, "Review must end before creating a new version.")
            next_version = version + 1
            connection.execute(
                "UPDATE knowledge_advisories SET latest_version = ? WHERE tenant_id = ? AND id = ?",
                (next_version, tenant_id, knowledge_id),
            )
            return self._create_draft(connection, tenant_id, actor_id, knowledge_id, next_version, "new_version")

    def transition(
        self, tenant_id: str, actor_id: str, knowledge_id: str, version: int, digest: str, action: str,
    ) -> dict[str, Any]:
        if action not in _TRANSITIONS:
            raise KnowledgeError(422, "Unknown advisory review action.")
        previous_status, next_status = _TRANSITIONS[action]
        with self._transaction(write=True) as connection:
            row = self._current_advisory(connection, tenant_id, knowledge_id, version, digest)
            is_author = row["author_id"] == actor_id
            if action == "submit" and not is_author:
                raise KnowledgeError(403, "Only the author can submit this advisory.")
            if action != "submit" and is_author:
                raise KnowledgeError(403, "The reviewer must be different from the author.")
            if row["status"] != previous_status:
                raise KnowledgeError(409, "The advisory is not in the required review state.")

            connection.execute(
                "UPDATE knowledge_versions SET status = ? WHERE tenant_id = ? AND knowledge_id = ? AND version = ?",
                (next_status, tenant_id, knowledge_id, version),
            )
            self._audit(
                connection, tenant_id, actor_id, knowledge_id, version, digest, action,
                previous_status, next_status, _timestamp(),
            )
            return self._advisory_view(connection, self._advisory_row(connection, tenant_id, knowledge_id, version))
