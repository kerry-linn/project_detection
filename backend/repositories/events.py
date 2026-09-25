from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from psycopg.types.json import Jsonb

from backend.db import Connection
from security_events import SecurityEvent, events_have_same_source_content

SELECT_EVENT_COLUMNS = """
    event_id, occurred_at, ingested_at, source, event_type, organization_id,
    actor_id, attempted_account, target_actor_id, previous_role, new_role,
    session_id, host(source_ip) AS source_ip, resource_type, resource_id,
    outcome, request_id, schema_version, metadata
"""

INSERT_EVENT = """
    INSERT INTO security_events (
        event_id, occurred_at, ingested_at, source, event_type, organization_id,
        actor_id, attempted_account, target_actor_id, previous_role, new_role,
        session_id, source_ip, resource_type, resource_id,
        outcome, request_id, schema_version, metadata
    )
    VALUES (
        %(event_id)s, %(occurred_at)s, %(ingested_at)s, %(source)s,
        %(event_type)s, %(organization_id)s, %(actor_id)s,
        %(attempted_account)s, %(target_actor_id)s, %(previous_role)s,
        %(new_role)s, %(session_id)s, %(source_ip)s, %(resource_type)s,
        %(resource_id)s, %(outcome)s, %(request_id)s, %(schema_version)s,
        %(metadata)s
    )
    ON CONFLICT (event_id) DO NOTHING
    RETURNING event_id
"""


class EventIdConflict(Exception):
    def __init__(self, event_id: str) -> None:
        super().__init__(
            f"event_id reused with different source content: {event_id}"
        )
        self.event_id = event_id


@dataclass(frozen=True)
class IngestResult:
    inserted: int
    replayed: int


def ingest_events(conn: Connection, events: list[SecurityEvent]) -> IngestResult:
    """Caller owns the transaction so a conflict rolls back the whole batch."""
    inserted = 0
    replayed = 0
    for event in events:
        if insert_event(conn, event):
            inserted += 1
            continue

        stored = get_event(conn, event.event_id)
        if stored is None or not events_have_same_source_content(stored, event):
            raise EventIdConflict(event.event_id)
        replayed += 1

    return IngestResult(inserted=inserted, replayed=replayed)


def insert_event(conn: Connection, event: SecurityEvent) -> bool:
    """Returns False when the event_id already exists."""
    params = asdict(event)
    params["metadata"] = Jsonb(event.metadata)
    row = conn.execute(INSERT_EVENT, params).fetchone()
    return row is not None


def get_event(conn: Connection, event_id: str) -> SecurityEvent | None:
    row = conn.execute(
        f"SELECT {SELECT_EVENT_COLUMNS} FROM security_events WHERE event_id = %s",
        (event_id,),
    ).fetchone()
    if row is None:
        return None
    return SecurityEvent(**row)


def load_events(conn: Connection) -> list[SecurityEvent]:
    rows = conn.execute(
        f"""
        SELECT {SELECT_EVENT_COLUMNS}
        FROM security_events
        ORDER BY occurred_at, event_id
        """
    ).fetchall()
    return [SecurityEvent(**row) for row in rows]


def search_events(
    conn: Connection,
    *,
    organization_id: str | None = None,
    attempted_account: str | None = None,
    actor_id: str | None = None,
    event_type: str | None = None,
    limit: int = 100,
) -> list[SecurityEvent]:
    """Newest first, so a limit keeps the most recent activity.

    Only fixed SQL fragments are joined into the query; every value is sent
    separately as a parameter.
    """
    conditions = []
    params: list[Any] = []
    if organization_id is not None:
        conditions.append("organization_id = %s")
        params.append(organization_id)
    if attempted_account is not None:
        conditions.append("attempted_account = %s")
        params.append(attempted_account.casefold())
    if actor_id is not None:
        conditions.append("actor_id = %s")
        params.append(actor_id)
    if event_type is not None:
        conditions.append("event_type = %s")
        params.append(event_type)

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)
    params.append(limit)

    rows = conn.execute(
        f"""
        SELECT {SELECT_EVENT_COLUMNS}
        FROM security_events
        {where_clause}
        ORDER BY occurred_at DESC, event_id DESC
        LIMIT %s
        """,
        params,
    ).fetchall()
    return [SecurityEvent(**row) for row in rows]
