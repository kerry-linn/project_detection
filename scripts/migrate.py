from __future__ import annotations

import argparse
from typing import Sequence

from backend.config import require_env
from backend.db import apply_migrations, connect


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Apply pending SQL migrations to PostgreSQL."
    )
    parser.add_argument(
        "--database-url-env",
        default="DATABASE_URL",
        help="Environment variable holding the connection URL "
        "(default: DATABASE_URL)",
    )
    args = parser.parse_args(argv)

    with connect(require_env(args.database_url_env)) as conn:
        applied = apply_migrations(conn)

    if applied:
        print(f"Applied migrations: {', '.join(applied)}")
    else:
        print("Database schema is up to date")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
