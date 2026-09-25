from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash

from backend.config import Settings
from backend.db import connect
from backend.repositories.users import (
    LAB_ANALYST,
    SessionUser,
    get_active_session,
)

bearer_scheme = HTTPBearer(auto_error=False)
password_hasher = PasswordHash.recommended()

# Verified when a login names an unknown account so that response time does
# not reveal whether the account exists.
_DUMMY_PASSWORD_HASH = password_hasher.hash(secrets.token_urlsafe(16))


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def canonical_login(login: str) -> str:
    return login.strip().casefold()


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    if password_hash is None:
        password_hasher.verify(password, _DUMMY_PASSWORD_HASH)
        return False
    return password_hasher.verify(password, password_hash)


def new_session_token() -> tuple[str, str]:
    """Returns (raw token for the client, hash stored in the database).

    The token carries 256 random bits, so a fast digest is sufficient; a slow
    password hash would only add latency to every request.
    """
    token = secrets.token_urlsafe(32)
    return token, hash_session_token(token)


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def require_collector(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> None:
    token = _bearer_token(credentials)
    if not secrets.compare_digest(
        token.encode("utf-8"), settings.collector_token.encode("utf-8")
    ):
        raise _unauthorized("invalid collector credential")


def require_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> SessionUser:
    token = _bearer_token(credentials)
    with connect(settings.database_url) as conn:
        user = get_active_session(
            conn, hash_session_token(token), datetime.now(timezone.utc)
        )
    if user is None:
        raise _unauthorized("invalid or expired session")
    return user


def require_analyst(user: SessionUser = Depends(require_user)) -> SessionUser:
    if user.role != LAB_ANALYST:
        raise HTTPException(
            status_code=403, detail="lab analyst role required"
        )
    return user


def require_organization_user(
    user: SessionUser = Depends(require_user),
) -> SessionUser:
    """The lab analyst investigates security records but holds no tenant
    membership, so it receives no implicit document access."""
    if user.organization_id is None:
        raise HTTPException(
            status_code=403, detail="organization membership required"
        )
    return user


def _bearer_token(credentials: HTTPAuthorizationCredentials | None) -> str:
    if credentials is None:
        raise _unauthorized("missing bearer token")
    return credentials.credentials


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=401,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )
