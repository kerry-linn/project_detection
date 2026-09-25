from __future__ import annotations

import argparse
import getpass
import os
from dataclasses import dataclass
from typing import Sequence

from backend.auth import hash_password
from backend.config import ConfigurationError, require_env
from backend.db import Connection, connect
from backend.repositories.users import LAB_ANALYST, MEMBER, ORGANIZATION_ADMIN

MIN_PASSWORD_LENGTH = 12
PASSWORD_ENV = "SEED_USER_PASSWORD"


@dataclass(frozen=True)
class SeedUser:
    user_id: str
    login: str
    display_name: str
    organization_id: str | None
    role: str


@dataclass(frozen=True)
class SeedDocument:
    document_id: str
    organization_id: str
    owner_id: str
    title: str
    body: str


ORGANIZATIONS = (
    ("org-alpha", "Alpha Research (fictional)"),
    ("org-beta", "Beta Logistics (fictional)"),
)

USERS = (
    SeedUser("user-alice", "alice@alpha.example.test", "Alice", "org-alpha", MEMBER),
    SeedUser("user-bob", "bob@alpha.example.test", "Bob", "org-alpha", MEMBER),
    SeedUser(
        "admin-alpha",
        "admin@alpha.example.test",
        "Alpha Admin",
        "org-alpha",
        ORGANIZATION_ADMIN,
    ),
    SeedUser("user-dana", "dana@beta.example.test", "Dana", "org-beta", MEMBER),
    SeedUser(
        "admin-beta",
        "admin@beta.example.test",
        "Beta Admin",
        "org-beta",
        ORGANIZATION_ADMIN,
    ),
    SeedUser(
        "lab-analyst", "analyst@lab.example.test", "Lab Analyst", None, LAB_ANALYST
    ),
)

DOCUMENTS = (
    SeedDocument("doc-alpha-001", "org-alpha", "user-alice", "Q3 lab notes", "Fictional notes."),
    SeedDocument("doc-alpha-002", "org-alpha", "user-alice", "Vendor list", "Fictional vendors."),
    SeedDocument("doc-alpha-003", "org-alpha", "user-alice", "Draft proposal", "Fictional draft."),
    SeedDocument("doc-alpha-004", "org-alpha", "user-bob", "Bob's checklist", "Fictional tasks."),
    SeedDocument("doc-alpha-005", "org-alpha", "admin-alpha", "Org policy", "Fictional policy."),
    SeedDocument("doc-beta-001", "org-beta", "user-dana", "Route plan", "Fictional routes."),
    SeedDocument("doc-beta-002", "org-beta", "user-dana", "Carrier rates", "Fictional rates."),
    SeedDocument("doc-beta-003", "org-beta", "user-dana", "Warehouse map", "Fictional map."),
    SeedDocument("doc-beta-004", "org-beta", "admin-beta", "Beta onboarding", "Fictional guide."),
)


def seed_lab(conn: Connection, password_hash: str) -> None:
    """Idempotent: organizations and users are upserted; existing documents
    keep any edits made through the application."""
    with conn.cursor() as cursor:
        cursor.executemany(
            """
            INSERT INTO organizations (organization_id, name)
            VALUES (%s, %s)
            ON CONFLICT (organization_id) DO UPDATE SET name = EXCLUDED.name
            """,
            ORGANIZATIONS,
        )
        cursor.executemany(
            """
            INSERT INTO users (
                user_id, login, display_name, organization_id, role, password_hash
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (user_id) DO UPDATE
            SET login = EXCLUDED.login,
                display_name = EXCLUDED.display_name,
                role = EXCLUDED.role,
                password_hash = EXCLUDED.password_hash
            """,
            [
                (
                    user.user_id,
                    user.login,
                    user.display_name,
                    user.organization_id,
                    user.role,
                    password_hash,
                )
                for user in USERS
            ],
        )
        cursor.executemany(
            """
            INSERT INTO documents (document_id, organization_id, owner_id, title, body)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (document_id) DO NOTHING
            """,
            [
                (doc.document_id, doc.organization_id, doc.owner_id, doc.title, doc.body)
                for doc in DOCUMENTS
            ],
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Seed fictional organizations, users, and documents. Every seeded "
            f"user shares one lab password read from {PASSWORD_ENV} or a prompt."
        )
    )
    parser.add_argument(
        "--database-url-env",
        default="DATABASE_URL",
        help="Environment variable holding the connection URL "
        "(default: DATABASE_URL)",
    )
    args = parser.parse_args(argv)

    password = os.environ.get(PASSWORD_ENV) or getpass.getpass(
        "Password for all seeded lab users: "
    )
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ConfigurationError(
            f"seed password must be at least {MIN_PASSWORD_LENGTH} characters"
        )

    with connect(require_env(args.database_url_env)) as conn:
        seed_lab(conn, hash_password(password))

    print(
        f"Seeded {len(ORGANIZATIONS)} organizations, {len(USERS)} users, "
        f"and {len(DOCUMENTS)} documents"
    )
    for user in USERS:
        print(f"  {user.role:<18} {user.login}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
