"""Local, transactional exchange of reviewed Community advisory versions."""

import sqlite3
from datetime import datetime, timedelta
from typing import Any, Literal
from uuid import uuid4

from .community_validation import (
    FixtureScenario,
    fixture_payload,
    result_summary,
    run_suite,
    suite_for,
    verify_fixture,
)
from .knowledge_store import KnowledgeError, KnowledgeStore, _canonical_json, _digest, _stored_advisory, _timestamp

_SCHEMA = """
CREATE TABLE IF NOT EXISTS community_deliveries (
    id TEXT PRIMARY KEY NOT NULL,
    sender_tenant TEXT NOT NULL,
    recipient_tenant TEXT NOT NULL CHECK (recipient_tenant <> sender_tenant),
    publisher_id TEXT NOT NULL,
    knowledge_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    digest TEXT NOT NULL,
    envelope_json TEXT NOT NULL,
    approval_sequence INTEGER NOT NULL REFERENCES knowledge_audit (sequence),
    delivered_at TEXT NOT NULL,
    expires_at TEXT NOT NULL CHECK (expires_at > delivered_at),
    UNIQUE (sender_tenant, recipient_tenant, knowledge_id, version),
    UNIQUE (id, recipient_tenant),
    FOREIGN KEY (sender_tenant, knowledge_id, version)
        REFERENCES knowledge_versions (tenant_id, knowledge_id, version)
);
CREATE INDEX IF NOT EXISTS community_deliveries_recipient
    ON community_deliveries (recipient_tenant, delivered_at, id);
CREATE TABLE IF NOT EXISTS community_fixtures (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    scenario TEXT NOT NULL CHECK (scenario IN ('positive', 'negative', 'inconclusive')),
    fixture_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, scenario)
);
CREATE TABLE IF NOT EXISTS community_validations (
    id TEXT PRIMARY KEY NOT NULL,
    delivery_id TEXT NOT NULL,
    recipient_tenant TEXT NOT NULL,
    fixture_id TEXT NOT NULL,
    fixture_digest TEXT NOT NULL,
    fixture_scenario TEXT NOT NULL CHECK (fixture_scenario IN ('positive', 'negative', 'inconclusive')),
    suite_id TEXT NOT NULL,
    suite_version INTEGER NOT NULL CHECK (suite_version >= 1),
    result TEXT NOT NULL CHECK (result IN ('pattern_observed', 'pattern_not_observed', 'inconclusive')),
    recorded_at TEXT NOT NULL,
    UNIQUE (delivery_id, fixture_id, suite_id, suite_version),
    UNIQUE (delivery_id, id),
    FOREIGN KEY (delivery_id, recipient_tenant) REFERENCES community_deliveries (id, recipient_tenant),
    FOREIGN KEY (recipient_tenant, fixture_id) REFERENCES community_fixtures (tenant_id, id)
);
CREATE TABLE IF NOT EXISTS community_audit (
    sequence INTEGER PRIMARY KEY,
    delivery_id TEXT NOT NULL REFERENCES community_deliveries (id),
    tenant_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (
        action IN ('delivered', 'verified', 'expired', 'withdrawn', 'validation_recorded', 'feedback_shared')
    ),
    occurred_at TEXT NOT NULL,
    binding TEXT CHECK ((binding IS NOT NULL) = (action = 'delivered')),
    validation_id TEXT CHECK ((validation_id IS NOT NULL) = (action IN ('validation_recorded', 'feedback_shared'))),
    FOREIGN KEY (delivery_id, validation_id) REFERENCES community_validations (delivery_id, id)
);
CREATE INDEX IF NOT EXISTS community_audit_history ON community_audit (delivery_id, sequence);
CREATE UNIQUE INDEX IF NOT EXISTS community_audit_lifecycle_once
    ON community_audit (delivery_id, action) WHERE validation_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS community_audit_validation_once
    ON community_audit (delivery_id, action, validation_id) WHERE validation_id IS NOT NULL;
CREATE TRIGGER IF NOT EXISTS community_audit_check_tenant BEFORE INSERT ON community_audit
WHEN NEW.tenant_id <> (
    SELECT CASE WHEN NEW.action IN ('delivered', 'expired', 'withdrawn') THEN sender_tenant ELSE recipient_tenant END
    FROM community_deliveries WHERE id = NEW.delivery_id
)
BEGIN SELECT RAISE(ABORT, 'Community audit tenant does not match the delivery'); END;
"""
_IMMUTABLE_TABLES = ("community_deliveries", "community_fixtures", "community_validations", "community_audit")
_BINDING_FIELDS = (
    "id", "sender_tenant", "recipient_tenant", "publisher_id", "knowledge_id", "version", "digest",
    "approval_sequence", "delivered_at", "expires_at",
)
_InboxAction = Literal["verify", "validate", "feedback"]


class CommunityStore:
    """Use the Knowledge database as the authoritative local transport."""

    def __init__(self, knowledge: KnowledgeStore, audiences: dict[tuple[str, str], frozenset[str]]) -> None:
        self.knowledge = knowledge
        self.audiences = audiences
        schema = [_SCHEMA]
        for table in _IMMUTABLE_TABLES:
            for operation in ("UPDATE", "DELETE"):
                schema.append(f"""
                    CREATE TRIGGER IF NOT EXISTS {table}_no_{operation.lower()} BEFORE {operation} ON {table}
                    BEGIN SELECT RAISE(ABORT, 'Community records are immutable'); END;
                """)
        with self.knowledge._connection() as connection:
            connection.executescript("BEGIN IMMEDIATE;\n" + "\n".join(schema) + "COMMIT;")

    def peers(self, tenant: str, publisher: str) -> list[str]:
        return sorted(self.audiences.get((tenant, publisher), ()))

    def _allows(self, sender: str, publisher: str, recipient: str) -> bool:
        return recipient in self.audiences.get((sender, publisher), ())

    @staticmethod
    def _approved(connection: sqlite3.Connection, version: sqlite3.Row) -> tuple[dict[str, Any], int]:
        if version["status"] != "approved":
            raise KnowledgeError(409, "The exact advisory version must be approved before delivery.")
        envelope = _stored_advisory(version)
        approvals = connection.execute(
            """
            SELECT sequence FROM knowledge_audit
            WHERE tenant_id = ? AND knowledge_id = ? AND version = ? AND digest = ?
                AND action = 'approve' AND from_status = 'in_review' AND to_status = 'approved' AND actor_id <> ?
            """,
            (version["tenant_id"], version["knowledge_id"], version["version"], version["digest"], version["author_id"]),
        ).fetchall()
        if len(approvals) != 1:
            raise KnowledgeError(409, "The advisory's distinct approval could not be verified.")
        return envelope, approvals[0]["sequence"]

    def approved(self, tenant: str) -> list[dict[str, Any]]:
        with self.knowledge._transaction() as connection:
            versions = connection.execute(
                """
                SELECT * FROM knowledge_versions
                WHERE tenant_id = ? AND status = 'approved' ORDER BY created_at, knowledge_id, version
                """,
                (tenant,),
            )
            items = []
            for version in versions:
                envelope, _ = self._approved(connection, version)
                items.append({key: envelope[key] for key in ("knowledge_id", "version", "digest")})
            return items

    @staticmethod
    def _binding(delivery: sqlite3.Row) -> str:
        return _digest(_canonical_json({key: delivery[key] for key in _BINDING_FIELDS}))

    @staticmethod
    def _audit(
        connection: sqlite3.Connection, delivery: sqlite3.Row, tenant: str, actor: str, action: str, at: str,
        *, binding: str | None = None, validation_id: str | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO community_audit (delivery_id, tenant_id, actor_id, action, occurred_at, binding, validation_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (delivery["id"], tenant, actor, action, at, binding, validation_id),
        )

    def _events(self, connection: sqlite3.Connection, delivery: sqlite3.Row) -> list[sqlite3.Row]:
        events = connection.execute(
            "SELECT * FROM community_audit WHERE delivery_id = ? ORDER BY sequence", (delivery["id"],),
        ).fetchall()
        if not events or (
            events[0]["action"] != "delivered"
            or events[0]["tenant_id"] != delivery["sender_tenant"]
            or events[0]["actor_id"] != delivery["publisher_id"]
            or events[0]["occurred_at"] != delivery["delivered_at"]
            or events[0]["binding"] != self._binding(delivery)
        ):
            raise KnowledgeError(409, "The delivery's provenance or audience could not be verified.")
        return events

    def _delivery(
        self, connection: sqlite3.Connection, delivery_id: str, tenant: str, *, inbox: bool,
    ) -> sqlite3.Row:
        scope = "recipient_tenant" if inbox else "sender_tenant"
        delivery = connection.execute(
            f"SELECT * FROM community_deliveries WHERE {scope} = ? AND id = ?",
            (tenant, delivery_id),
        ).fetchone()
        if delivery is None:
            raise KnowledgeError(404, "Community delivery not found.")
        return delivery

    @staticmethod
    def _observed_state(delivery: sqlite3.Row, events: list[sqlite3.Row], now: str) -> tuple[str, bool]:
        """Return the status and whether its expiry still needs an audit event."""
        actions = {event["action"] for event in events}
        if "withdrawn" in actions:
            return "withdrawn", False
        if "expired" in actions or now >= delivery["expires_at"]:
            return "expired", "expired" not in actions
        return ("verified" if "verified" in actions else "unverified"), False

    def _state(
        self, connection: sqlite3.Connection, delivery: sqlite3.Row, now: str,
    ) -> tuple[str, list[sqlite3.Row]]:
        events = self._events(connection, delivery)
        status, record_expiry = self._observed_state(delivery, events, now)
        if record_expiry:
            self._audit(connection, delivery, delivery["sender_tenant"], "system", "expired", now)
            events = self._events(connection, delivery)
        return status, events

    def _verified_envelope(
        self, connection: sqlite3.Connection, delivery: sqlite3.Row, *, inbox: bool,
    ) -> dict[str, Any]:
        sender, publisher = delivery["sender_tenant"], delivery["publisher_id"]
        if inbox and not self._allows(sender, publisher, delivery["recipient_tenant"]):
            raise KnowledgeError(409, "The sender or recipient is no longer authorized for this delivery.")
        version = self.knowledge._advisory_row(connection, sender, delivery["knowledge_id"], delivery["version"])
        envelope, approval_sequence = self._approved(connection, version)
        if (
            envelope["digest"] != delivery["digest"]
            or version["advisory_json"] != delivery["envelope_json"]
            or approval_sequence != delivery["approval_sequence"]
        ):
            raise KnowledgeError(409, "The delivery does not match its approved advisory envelope.")
        return envelope

    def publish(
        self, tenant: str, actor: str, recipient: str, knowledge_id: str, version: int, digest: str, ttl_hours: int,
    ) -> tuple[dict[str, Any], bool]:
        if not self._allows(tenant, actor, recipient):
            raise KnowledgeError(403, "This publisher is not authorized to send to that tenant.")
        with self.knowledge._transaction(write=True) as connection:
            now = _timestamp()
            approved = self.knowledge._advisory_row(connection, tenant, knowledge_id, version)
            if approved["digest"] != digest:
                raise KnowledgeError(409, "The advisory version or digest is stale.")
            _, approval_sequence = self._approved(connection, approved)
            existing = connection.execute(
                """
                SELECT id FROM community_deliveries
                WHERE sender_tenant = ? AND recipient_tenant = ? AND knowledge_id = ? AND version = ?
                """,
                (tenant, recipient, knowledge_id, version),
            ).fetchone()
            if existing:
                delivery = self._delivery(connection, existing["id"], tenant, inbox=False)
                return self._view(connection, delivery, now, inbox=False), False
            delivery_id = str(uuid4())
            deadline = datetime.fromisoformat(now.replace("Z", "+00:00")) + timedelta(hours=ttl_hours)
            expires_at = deadline.isoformat(timespec="microseconds").replace("+00:00", "Z")
            connection.execute(
                """
                INSERT INTO community_deliveries (
                    id, sender_tenant, recipient_tenant, publisher_id, knowledge_id, version, digest,
                    envelope_json, approval_sequence, delivered_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    delivery_id, tenant, recipient, actor, knowledge_id, version, digest, approved["advisory_json"],
                    approval_sequence, now, expires_at,
                ),
            )
            delivery = self._delivery(connection, delivery_id, tenant, inbox=False)
            self._audit(connection, delivery, tenant, actor, "delivered", now, binding=self._binding(delivery))
            return self._view(connection, delivery, now, inbox=False), True

    def deliveries(self, tenant: str, *, inbox: bool) -> list[dict[str, Any]]:
        scope = "recipient_tenant" if inbox else "sender_tenant"
        while True:
            with self.knowledge._transaction() as connection:
                deliveries = connection.execute(
                    f"SELECT * FROM community_deliveries WHERE {scope} = ? ORDER BY delivered_at, id", (tenant,),
                ).fetchall()
                now = _timestamp()
                states, due = [], []
                for delivery in deliveries:
                    try:
                        events = self._events(connection, delivery)
                    except KnowledgeError:
                        # An invalid binding cannot establish the row's tenant scope.
                        continue
                    status, record_expiry = self._observed_state(delivery, events, now)
                    if record_expiry:
                        due.append(delivery["id"])
                    states.append((delivery, (status, events)))
                if not due:
                    return [
                        self._view(connection, delivery, now, inbox=inbox, list_state=state)
                        for delivery, state in states
                    ]

            # Release the read snapshot before taking the writer lock. A competing
            # request may have already closed the delivery, so check again in the write
            # transaction and build the response from a fresh read snapshot afterward.
            with self.knowledge._transaction(write=True) as connection:
                now = _timestamp()
                for delivery_id in due:
                    try:
                        delivery = self._delivery(connection, delivery_id, tenant, inbox=inbox)
                        self._state(connection, delivery, now)
                    except KnowledgeError:
                        continue

    def withdraw(self, tenant: str, actor: str, delivery_id: str) -> dict[str, Any]:
        with self.knowledge._transaction(write=True) as connection:
            now = _timestamp()
            delivery = self._delivery(connection, delivery_id, tenant, inbox=False)
            status, _ = self._state(connection, delivery, now)
            if status in ("verified", "unverified"):
                self._audit(connection, delivery, tenant, actor, "withdrawn", now)
            return self._view(connection, delivery, now, inbox=False)

    @staticmethod
    def _fixture_view(row: sqlite3.Row) -> dict[str, Any]:
        return {key: row[key] for key in ("id", "scenario", "digest", "created_at")}

    def fixtures(self, tenant: str) -> list[dict[str, Any]]:
        with self.knowledge._transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM community_fixtures WHERE tenant_id = ? ORDER BY created_at, id", (tenant,),
            )
            return [self._fixture_view(row) for row in rows]

    def create_fixture(self, tenant: str, actor: str, scenario: FixtureScenario) -> tuple[dict[str, Any], bool]:
        with self.knowledge._transaction(write=True) as connection:
            existing = connection.execute(
                "SELECT * FROM community_fixtures WHERE tenant_id = ? AND scenario = ?", (tenant, scenario),
            ).fetchone()
            if existing is not None:
                return self._fixture_view(existing), False
            fixture_id = str(uuid4())
            payload = fixture_payload(scenario, fixture_id)
            record = {
                "id": fixture_id, "scenario": scenario, "digest": _digest(payload), "created_at": _timestamp(),
            }
            connection.execute(
                """
                INSERT INTO community_fixtures (tenant_id, id, scenario, fixture_json, digest, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (tenant, fixture_id, scenario, payload, record["digest"], actor, record["created_at"]),
            )
            return record, True

    def _validate(
        self, connection: sqlite3.Connection, delivery: sqlite3.Row, tenant: str, actor: str, fixture_id: str,
        envelope: dict[str, Any], now: str,
    ) -> None:
        fixture = connection.execute(
            "SELECT * FROM community_fixtures WHERE tenant_id = ? AND id = ?", (tenant, fixture_id),
        ).fetchone()
        if fixture is None:
            raise KnowledgeError(404, "Recipient fixture not found.")
        suite_id, suite_version = suite_for(envelope)
        observations = verify_fixture(fixture["scenario"], fixture_id, fixture["fixture_json"], fixture["digest"])
        existing = connection.execute(
            """
            SELECT fixture_digest FROM community_validations
            WHERE delivery_id = ? AND fixture_id = ? AND suite_id = ? AND suite_version = ?
            """,
            (delivery["id"], fixture_id, suite_id, suite_version),
        ).fetchone()
        if existing is not None:
            if existing["fixture_digest"] != fixture["digest"]:
                raise KnowledgeError(409, "The fixture differs from the recorded validation.")
            return
        result = run_suite(observations)
        validation_id = str(uuid4())
        connection.execute(
            """
            INSERT INTO community_validations (
                id, delivery_id, recipient_tenant, fixture_id, fixture_digest, fixture_scenario,
                suite_id, suite_version, result, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                validation_id, delivery["id"], tenant, fixture_id, fixture["digest"], fixture["scenario"],
                suite_id, suite_version, result, now,
            ),
        )
        self._audit(connection, delivery, tenant, actor, "validation_recorded", now, validation_id=validation_id)

    def _share(
        self, connection: sqlite3.Connection, delivery: sqlite3.Row, tenant: str, actor: str, validation_id: str,
        events: list[sqlite3.Row], now: str,
    ) -> None:
        if not any(
            event["action"] == "validation_recorded" and event["tenant_id"] == tenant
            and event["validation_id"] == validation_id for event in events
        ):
            raise KnowledgeError(404, "Recipient validation not found.")
        if not any(
            event["action"] == "feedback_shared" and event["validation_id"] == validation_id for event in events
        ):
            self._audit(connection, delivery, tenant, actor, "feedback_shared", now, validation_id=validation_id)

    def inbox_action(
        self, tenant: str, actor: str, delivery_id: str, action: _InboxAction, reference: str = "",
    ) -> dict[str, Any]:
        with self.knowledge._transaction(write=True) as connection:
            now = _timestamp()
            delivery = self._delivery(connection, delivery_id, tenant, inbox=True)
            status, events = self._state(connection, delivery, now)
            if status in ("verified", "unverified"):
                envelope = self._verified_envelope(connection, delivery, inbox=True)
                if action == "verify":
                    if status == "unverified":
                        self._audit(connection, delivery, tenant, actor, "verified", now)
                elif status != "verified":
                    raise KnowledgeError(409, "Verify the Community delivery first.")
                elif action == "validate":
                    self._validate(connection, delivery, tenant, actor, reference, envelope, now)
                else:
                    self._share(connection, delivery, tenant, actor, reference, events, now)
                return self._view(connection, delivery, now, inbox=True)
        # Let the transaction commit an observed expiry before returning a denial.
        raise KnowledgeError(410, f"This Community delivery is {status}.")

    def _view(
        self, connection: sqlite3.Connection, delivery: sqlite3.Row, now: str, *, inbox: bool,
        list_state: tuple[str, list[sqlite3.Row]] | None = None,
    ) -> dict[str, Any]:
        status, events = list_state if list_state is not None else self._state(connection, delivery, now)
        view = {key: delivery[key] for key in (
            "id", "sender_tenant", "recipient_tenant", "knowledge_id", "version", "digest", "delivered_at", "expires_at",
        )}
        audience_allowed = self._allows(
            delivery["sender_tenant"], delivery["publisher_id"], delivery["recipient_tenant"],
        )
        if status in ("unverified", "verified") and not audience_allowed:
            status = "unavailable"
        elif status == "verified" or (status == "unverified" and not inbox):
            try:
                view["advisory"] = self._verified_envelope(connection, delivery, inbox=inbox)
            except KnowledgeError:
                if list_state is None:
                    raise
                status = "unavailable"
        view["status"] = status

        validations, feedback_by_sequence = [], {}
        rows = connection.execute(
            """
            SELECT v.*, shared.sequence AS shared_sequence, shared.occurred_at AS shared_at
            FROM community_validations AS v
            JOIN community_audit AS record
                ON record.delivery_id = v.delivery_id AND record.validation_id = v.id
                AND record.action = 'validation_recorded' AND record.tenant_id = v.recipient_tenant
            LEFT JOIN community_audit AS shared
                ON shared.delivery_id = v.delivery_id AND shared.validation_id = v.id
                AND shared.action = 'feedback_shared' AND shared.tenant_id = v.recipient_tenant
            WHERE v.delivery_id = ? AND v.recipient_tenant = ? AND (? OR shared.sequence IS NOT NULL)
            ORDER BY record.sequence
            """,
            (delivery["id"], delivery["recipient_tenant"], inbox),
        )
        for row in rows:
            summary = result_summary(row["suite_id"], row["suite_version"], row["result"])
            if inbox:
                validations.append({
                    **summary, "id": row["id"], "fixture_id": row["fixture_id"], "fixture_digest": row["fixture_digest"],
                    "fixture_scenario": row["fixture_scenario"], "recorded_at": row["recorded_at"],
                })
            if row["shared_sequence"] is not None:
                feedback_by_sequence[row["shared_sequence"]] = {
                    **summary, "validation_id": row["id"], "shared_at": row["shared_at"],
                }
        feedback = [feedback_by_sequence[sequence] for sequence in sorted(feedback_by_sequence)]
        return {
            **view, "validations": validations, "feedback": feedback,
            "audit": [
                {key: event[key] for key in ("action", "occurred_at")}
                for event in events if inbox or event["action"] not in ("verified", "validation_recorded")
            ],
        }
