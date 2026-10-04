from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from uuid import UUID

import psycopg

from backend.config import ConfigurationError, require_env
from backend.db import connect
from backend.repositories.exports import cleanup_expired, create_credential


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Manage credentials for event export only.")
    parser.add_argument("--database-url-env", default="DATABASE_URL")
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--name", required=True)
    create.add_argument("--days", type=int, default=30)
    create.add_argument("--output", type=Path, required=True, help="New private token file; never overwritten")
    commands.add_parser("list")
    revoke = commands.add_parser("revoke")
    revoke.add_argument("credential_id", type=UUID)
    commands.add_parser("cleanup", help="Release expired snapshot members; retain expiry tombstones")
    args = parser.parse_args(argv)
    created_file = False
    try:
        with connect(require_env(args.database_url_env)) as conn:
            if args.command == "create":
                credential_id, token = create_credential(conn, args.name, args.days)
                descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                created_file = True
                with os.fdopen(descriptor, "w") as file:
                    file.write(token + "\n")
                    file.flush()
                    os.fsync(file.fileno())
                result = {"credential_id": credential_id, "scope": "event_export", "expires_in_days": args.days}
            elif args.command == "revoke":
                changed = conn.execute(
                    "UPDATE export_credentials SET revoked_at = COALESCE(revoked_at, now()) "
                    "WHERE credential_id = %s", (str(args.credential_id),)
                ).rowcount
                if not changed:
                    raise ValueError("credential not found")
                result = {"revoked": str(args.credential_id)}
            elif args.command == "cleanup":
                result = {"expired_members_removed": cleanup_expired(conn)}
            else:
                result = conn.execute(
                    "SELECT credential_id, name, scope, created_at, expires_at, revoked_at "
                    "FROM export_credentials ORDER BY created_at, credential_id"
                ).fetchall()
        print(json.dumps(result, default=str))
        return 0
    except (OSError, ValueError, psycopg.Error, ConfigurationError):
        if created_file:
            args.output.unlink(missing_ok=True)
        print(json.dumps({"error": "credential operation failed; check database, arguments, and output permissions"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
