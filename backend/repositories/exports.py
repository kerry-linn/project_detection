from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
from datetime import timedelta
from uuid import UUID, uuid4

from psycopg.types.json import Jsonb

from backend.db import Connection
from backend.repositories.events import SELECT_EVENT_COLUMNS
from security_events import SecurityEvent, format_utc

FILTERS = ("organization_id", "attempted_account", "actor_id", "event_type")


class ExportError(ValueError):
    def __init__(self, status: int, detail: str):
        self.status = status
        super().__init__(detail)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_credential(conn: Connection, name: str, days: int = 30) -> tuple[str, str]:
    if not name.strip() or len(name) > 128 or not 1 <= days <= 365:
        raise ValueError("name must contain 1–128 characters; lifetime must be 1–365 days")
    credential_id = str(uuid4())
    token = "export_" + secrets.token_urlsafe(32)
    conn.execute(
        "INSERT INTO export_credentials (credential_id, name, token_hash, expires_at) "
        "VALUES (%s, %s, %s, now() + %s)",
        (credential_id, name.strip(), token_hash(token), timedelta(days=days)),
    )
    return credential_id, token


def authenticate(conn: Connection, token: str) -> str:
    row = conn.execute(
        "SELECT credential_id FROM export_credentials WHERE token_hash = %s "
        "AND scope = 'event_export' AND revoked_at IS NULL AND expires_at > clock_timestamp() "
        "FOR SHARE",
        (token_hash(token),),
    ).fetchone()
    if row is None:
        raise ExportError(401, "invalid or expired export credential")
    return row["credential_id"]


def cleanup_expired(conn: Connection) -> int:
    # Keep snapshot headers so a retry of the initial request cannot recreate an expired export.
    return conn.execute(
        "WITH expired AS (SELECT snapshot_id FROM export_snapshots "
        "WHERE expires_at <= clock_timestamp() FOR UPDATE SKIP LOCKED) "
        "DELETE FROM export_snapshot_events USING expired "
        "WHERE export_snapshot_events.snapshot_id = expired.snapshot_id"
    ).rowcount


def _encode_cursor(snapshot: dict, after: int) -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps([snapshot["snapshot_id"], after], separators=(",", ":")).encode()
    ).decode().rstrip("=")
    signature = hmac.new(bytes.fromhex(snapshot["cursor_key"]), payload.encode(), "sha256").hexdigest()
    return payload + "." + signature


def _decode_cursor(cursor: str) -> tuple[str, int, str, str]:
    try:
        payload, signature = cursor.split(".")
        value = json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True))
        snapshot_id, after = value
        if not isinstance(snapshot_id, str) or str(UUID(snapshot_id)) != snapshot_id or type(after) is not int or after < 1:
            raise ValueError
        if len(signature) != 64 or any(c not in "0123456789abcdef" for c in signature) or len(cursor) > 512:
            raise ValueError
        return snapshot_id, after, payload, signature
    except (ValueError, TypeError, binascii.Error, UnicodeError) as error:
        raise ExportError(400, "invalid export cursor") from error


def _create_snapshot(conn: Connection, credential_id: str, export_id: str, filters: dict, limit: int) -> dict:
    row = conn.execute(
        "INSERT INTO export_snapshots "
        "(snapshot_id, credential_id, export_id, filters, page_size, cursor_key) "
        "VALUES (%s, %s, %s, %s, %s, %s) "
        "ON CONFLICT (credential_id, export_id) DO NOTHING RETURNING *",
        (str(uuid4()), credential_id, export_id, Jsonb(filters), limit, secrets.token_hex(32)),
    ).fetchone()
    if row is None:
        return conn.execute(
            "SELECT * FROM export_snapshots WHERE credential_id = %s AND export_id = %s FOR SHARE",
            (credential_id, export_id),
        ).fetchone()
    conditions = [f"{key} = %s" for key in FILTERS if key in filters]
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    # One INSERT SELECT freezes exactly the rows visible to this PostgreSQL statement.
    count = conn.execute(
        "INSERT INTO export_snapshot_events (snapshot_id, ordinal, event_id) "
        'SELECT %s, row_number() OVER (ORDER BY occurred_at, event_id COLLATE "C"), event_id '
        "FROM security_events" + where,
        [row["snapshot_id"], *(filters[key] for key in FILTERS if key in filters)],
    ).rowcount
    conn.execute("UPDATE export_snapshots SET total_count = %s WHERE snapshot_id = %s", (count, row["snapshot_id"]))
    row["total_count"] = count
    return row


def export_page(conn: Connection, token: str, *, filters: dict, limit: int,
                export_id: str | None = None, cursor: str | None = None) -> dict:
    credential_id = authenticate(conn, token)
    filters = {key: value for key, value in filters.items() if value is not None}
    if set(filters) - set(FILTERS):
        raise ExportError(400, "unknown export filter")
    if "attempted_account" in filters:
        filters["attempted_account"] = filters["attempted_account"].casefold()
    after = 0
    if cursor:
        snapshot_id, after, payload, signature = _decode_cursor(cursor)
        snapshot = conn.execute("SELECT * FROM export_snapshots WHERE snapshot_id = %s FOR SHARE", (snapshot_id,)).fetchone()
        if snapshot is None:
            raise ExportError(410, "snapshot unavailable; begin a new export")
        if snapshot["credential_id"] != credential_id:
            raise ExportError(403, "snapshot belongs to another credential")
        expected = hmac.new(bytes.fromhex(snapshot["cursor_key"]), payload.encode(), "sha256").hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise ExportError(400, "invalid export cursor")
    else:
        cleanup_expired(conn)
        snapshot = _create_snapshot(conn, credential_id, export_id or str(uuid4()), filters, limit)
    if (snapshot["filters"] != filters or snapshot["page_size"] != limit
            or (export_id is not None and snapshot["export_id"] != export_id)):
        raise ExportError(409, "export filters, ID, and page size must match the original request")
    now = conn.execute("SELECT clock_timestamp() AS now").fetchone()["now"]
    if snapshot["expires_at"] <= now:
        raise ExportError(410, "snapshot expired; begin a new export")
    if after > snapshot["total_count"] or after % limit:
        raise ExportError(400, "invalid export cursor")
    rows = conn.execute(
        f"SELECT {SELECT_EVENT_COLUMNS} FROM security_events JOIN export_snapshot_events USING (event_id) "
        "WHERE snapshot_id = %s AND ordinal > %s ORDER BY ordinal LIMIT %s",
        (snapshot["snapshot_id"], after, limit),
    ).fetchall()
    end = after + len(rows)
    return {
        "items": [SecurityEvent(**row).to_dict() for row in rows],
        "next_cursor": _encode_cursor(snapshot, end) if end < snapshot["total_count"] else None,
        "snapshot_id": snapshot["snapshot_id"], "export_id": snapshot["export_id"],
        "expires_at": format_utc(snapshot["expires_at"]), "total_count": snapshot["total_count"],
    }
