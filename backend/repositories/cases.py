from backend.db import Connection
from backend.schemas import CaseDecision, CaseNote


class CaseNotFound(Exception):
    pass


class CaseConflict(Exception):
    pass


def write_activity(
    conn: Connection, alert_key: str, author_id: str, change: CaseDecision | CaseNote
) -> int:
    row = conn.execute(
        "SELECT status, disposition, revision FROM alerts WHERE alert_key = %s FOR UPDATE",
        (alert_key,),
    ).fetchone()
    if row is None:
        raise CaseNotFound
    if row["revision"] != change.revision:
        raise CaseConflict
    revision = row["revision"] + 1
    if isinstance(change, CaseDecision):
        status, disposition, body = change.status, change.disposition, change.rationale
        conn.execute(
            "UPDATE alerts SET status = %s, disposition = %s, rationale = %s, "
            "needs_review = FALSE, revision = %s, updated_at = now() WHERE alert_key = %s",
            (status, disposition, body, revision, alert_key),
        )
        kind = "decision"
    else:
        status, disposition, body = row["status"], row["disposition"], change.body
        conn.execute(
            "UPDATE alerts SET revision = %s, updated_at = now() WHERE alert_key = %s",
            (revision, alert_key),
        )
        kind = "note"
    conn.execute(
        "INSERT INTO case_activity "
        "(alert_key, author_id, revision, kind, status, disposition, body) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (alert_key, author_id, revision, kind, status, disposition, body),
    )
    return revision


def list_activity(conn: Connection, alert_key: str, limit: int, offset: int) -> list[dict]:
    return conn.execute(
        "SELECT activity_id, author_id, created_at, revision, kind, status, disposition, body "
        "FROM case_activity WHERE alert_key = %s ORDER BY activity_id DESC LIMIT %s OFFSET %s",
        (alert_key, limit, offset),
    ).fetchall()
