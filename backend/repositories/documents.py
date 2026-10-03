from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from backend.db import Connection

SELECT_DOCUMENT_COLUMNS = """
    document_id, organization_id, owner_id, title, body, created_at, updated_at
"""


@dataclass(frozen=True)
class Document:
    document_id: str
    organization_id: str
    owner_id: str
    title: str
    body: str
    created_at: datetime
    updated_at: datetime


def get_document(conn: Connection, document_id: str) -> Document | None:
    row = conn.execute(
        f"SELECT {SELECT_DOCUMENT_COLUMNS} FROM documents WHERE document_id = %s",
        (document_id,),
    ).fetchone()
    if row is None:
        return None
    return Document(**row)


def list_documents(
    conn: Connection, *, organization_id: str, owner_id: str | None,
    limit: int = 50, offset: int = 0
) -> list[Document]:
    """`owner_id=None` lists the whole organization (administrator scope)."""
    conditions = ["organization_id = %s"]
    params: list[object] = [organization_id]
    if owner_id is not None:
        conditions.append("owner_id = %s")
        params.append(owner_id)
    rows = conn.execute(
        f"""
        SELECT {SELECT_DOCUMENT_COLUMNS}
        FROM documents
        WHERE {" AND ".join(conditions)}
        ORDER BY updated_at DESC, document_id LIMIT %s OFFSET %s
        """,
        [*params, limit, offset],
    ).fetchall()
    return [Document(**row) for row in rows]


def create_document(
    conn: Connection,
    *,
    document_id: str,
    organization_id: str,
    owner_id: str,
    title: str,
    body: str,
) -> Document:
    row = conn.execute(
        f"""
        INSERT INTO documents (document_id, organization_id, owner_id, title, body)
        VALUES (%s, %s, %s, %s, %s)
        RETURNING {SELECT_DOCUMENT_COLUMNS}
        """,
        (document_id, organization_id, owner_id, title, body),
    ).fetchone()
    return Document(**row)


def update_document(
    conn: Connection,
    document_id: str,
    *,
    title: str | None,
    body: str | None,
) -> Document:
    row = conn.execute(
        f"""
        UPDATE documents
        SET title = COALESCE(%s, title),
            body = COALESCE(%s, body),
            updated_at = now()
        WHERE document_id = %s
        RETURNING {SELECT_DOCUMENT_COLUMNS}
        """,
        (title, body, document_id),
    ).fetchone()
    return Document(**row)


def count_documents(conn: Connection, organization_id: str, owner_id: str | None) -> int:
    return conn.execute(
        "SELECT count(*) AS n FROM documents WHERE organization_id = %s "
        "AND (%s::text IS NULL OR owner_id = %s)",
        (organization_id, owner_id, owner_id),
    ).fetchone()["n"]
