from __future__ import annotations

from pathlib import Path

import psycopg
from psycopg.rows import DictRow, dict_row

Connection = psycopg.Connection[DictRow]

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


def connect(database_url: str) -> Connection:
    """Use as `with connect(url) as conn:` - commits on success, rolls back on error.

    The UTC session time zone makes TIMESTAMPTZ values load as UTC datetimes,
    matching the normalized event contract.
    """
    return psycopg.connect(
        database_url, row_factory=dict_row, options="-c TimeZone=UTC"
    )


def apply_migrations(conn: Connection) -> list[str]:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version    TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )
    rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
    applied = {row["version"] for row in rows}

    newly_applied = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        if path.stem in applied:
            continue
        conn.execute(path.read_text(encoding="utf-8"))
        conn.execute(
            "INSERT INTO schema_migrations (version) VALUES (%s)",
            (path.stem,),
        )
        newly_applied.append(path.stem)
    return newly_applied
