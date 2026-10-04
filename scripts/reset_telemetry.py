from __future__ import annotations

import argparse
import os
from typing import Sequence

from backend.config import require_env
from backend.db import Connection, connect

TELEMETRY_TABLES = (
    "export_snapshot_events",
    "case_activity",
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
    conn.execute("LOCK TABLE export_snapshots IN ACCESS EXCLUSIVE MODE")
    if conn.execute("SELECT 1 FROM export_snapshots WHERE expires_at > clock_timestamp() LIMIT 1").fetchone():
        raise ValueError("active export snapshots prevent reset; wait until they expire")
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
    parser.add_argument("--confirm-target", help="Exact host:port/database shown by the dry run")
    args = parser.parse_args(argv)

    with connect(require_env(args.database_url_env)) as conn:
        target = f"database {conn.info.dbname} on {conn.info.host}:{conn.info.port}"
        identity = f"{conn.info.host}:{conn.info.port}/{conn.info.dbname}"
        if not args.yes or os.environ.get("LAB_ENV") != "local" or args.confirm_target != identity:
            print(f"Would delete {', '.join(TELEMETRY_TABLES)} from {target}.")
            print(f"Requires LAB_ENV=local, --yes, and --confirm-target {identity}.")
            return 2
        try:
            reset_telemetry(conn)
        except ValueError as error:
            print(str(error))
            return 2

    print(f"Deleted {', '.join(TELEMETRY_TABLES)} from {target}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
