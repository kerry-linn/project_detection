from __future__ import annotations

import argparse
from typing import Sequence

from backend.config import require_env
from backend.db import Connection, connect

TELEMETRY_TABLES = (
    "alert_replacements",
    "alert_events",
    "alerts",
    "detection_runs",
    "detection_checkpoints",
    "security_events",
    "sessions",
)


def reset_telemetry(conn: Connection) -> None:
    """Organizations, users, and documents are kept."""
    conn.execute(f"TRUNCATE {', '.join(TELEMETRY_TABLES)} RESTART IDENTITY")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Delete stored security events, alerts, detection runs, and sessions "
            "so a scenario can be replayed from a known state. Seeded "
            "organizations, users, and documents are kept."
        )
    )
    parser.add_argument(
        "--database-url-env",
        default="DATABASE_URL",
        help="Environment variable holding the connection URL "
        "(default: DATABASE_URL)",
    )
    parser.add_argument(
        "--yes", action="store_true", help="Confirm deleting the telemetry"
    )
    args = parser.parse_args(argv)

    with connect(require_env(args.database_url_env)) as conn:
        target = f"database {conn.info.dbname} on {conn.info.host}:{conn.info.port}"
        if not args.yes:
            print(f"Would delete {', '.join(TELEMETRY_TABLES)} from {target}.")
            print("Rerun with --yes to confirm.")
            return 2
        reset_telemetry(conn)

    print(f"Deleted {', '.join(TELEMETRY_TABLES)} from {target}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
