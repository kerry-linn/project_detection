from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from backend.db import Connection

MEMBER = "member"
ORGANIZATION_ADMIN = "organization_admin"
LAB_ANALYST = "lab_analyst"


@dataclass(frozen=True)
class User:
    user_id: str
    login: str
    display_name: str
    organization_id: str | None
    role: str
    password_hash: str


@dataclass(frozen=True)
class SessionUser:
    session_id: str
    expires_at: datetime
    user_id: str
    login: str
    display_name: str
    organization_id: str | None
    role: str


def get_user_by_login(conn: Connection, login: str) -> User | None:
    row = conn.execute(
        """
        SELECT user_id, login, display_name, organization_id, role, password_hash
        FROM users
        WHERE login = %s
        """,
        (login,),
    ).fetchone()
    if row is None:
        return None
    return User(**row)


def create_session(
    conn: Connection,
    *,
    session_id: str,
    token_hash: str,
    user_id: str,
    created_at: datetime,
    expires_at: datetime,
) -> None:
    conn.execute(
        """
        INSERT INTO sessions (session_id, token_hash, user_id, created_at, expires_at)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (session_id, token_hash, user_id, created_at, expires_at),
    )


def get_active_session(
    conn: Connection, token_hash: str, now: datetime
) -> SessionUser | None:
    row = conn.execute(
        """
        SELECT s.session_id, s.expires_at, u.user_id, u.login, u.display_name,
               u.organization_id, u.role
        FROM sessions AS s
        JOIN users AS u USING (user_id)
        WHERE s.token_hash = %s
          AND s.revoked_at IS NULL
          AND s.expires_at > %s
        """,
        (token_hash, now),
    ).fetchone()
    if row is None:
        return None
    return SessionUser(**row)


def revoke_session(conn: Connection, session_id: str, now: datetime) -> None:
    conn.execute(
        """
        UPDATE sessions
        SET revoked_at = %s
        WHERE session_id = %s AND revoked_at IS NULL
        """,
        (now, session_id),
    )
