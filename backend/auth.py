from __future__ import annotations

import secrets

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.config import Settings

COLLECTOR = "collector"
ANALYST = "analyst"

bearer_scheme = HTTPBearer(auto_error=False)


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def require_collector(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> None:
    _require_role(COLLECTOR, credentials, settings)


def require_analyst(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> None:
    _require_role(ANALYST, credentials, settings)


def _require_role(
    required_role: str,
    credentials: HTTPAuthorizationCredentials | None,
    settings: Settings,
) -> None:
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    role = _identify_role(credentials.credentials, settings)
    if role is None:
        raise HTTPException(
            status_code=401,
            detail="invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if role != required_role:
        raise HTTPException(
            status_code=403,
            detail="credential is not authorized for this endpoint",
        )


def _identify_role(token: str, settings: Settings) -> str | None:
    presented = token.encode("utf-8")
    if secrets.compare_digest(presented, settings.collector_token.encode("utf-8")):
        return COLLECTOR
    if secrets.compare_digest(presented, settings.analyst_token.encode("utf-8")):
        return ANALYST
    return None
