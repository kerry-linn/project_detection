from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from backend.audit import record_event, request_context
from backend.auth import (
    canonical_login,
    get_settings,
    new_session_token,
    require_user,
    verify_password,
)
from backend.config import Settings
from backend.db import connect
from backend.repositories.users import (
    SessionUser,
    create_session,
    get_user_by_login,
    revoke_session,
)
from backend.schemas import LoginRequest, LoginResponse, UserProfile

router = APIRouter(prefix="/auth")

INVALID_LOGIN = "invalid login or password"


@router.post("/login", response_model=LoginResponse)
def login(
    body: LoginRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
) -> LoginResponse:
    account = canonical_login(body.login)
    context = request_context(request)

    with connect(settings.database_url) as conn:
        user = get_user_by_login(conn, account)
        password_hash = user.password_hash if user else None
        if not verify_password(body.password, password_hash):
            record_event(
                conn,
                context,
                event_type="login_failed",
                outcome="failure",
                organization_id=user.organization_id if user else None,
                attempted_account=account,
                metadata={
                    "reason": "invalid_password" if user else "unknown_account"
                },
            )
            user = None
        else:
            token, token_hash = new_session_token()
            session_id = f"sess-{uuid.uuid4()}"
            created_at = datetime.now(timezone.utc)
            expires_at = created_at + settings.session_lifetime
            create_session(
                conn,
                session_id=session_id,
                token_hash=token_hash,
                user_id=user.user_id,
                created_at=created_at,
                expires_at=expires_at,
            )
            record_event(
                conn,
                context,
                event_type="login_succeeded",
                outcome="success",
                organization_id=user.organization_id,
                actor_id=user.user_id,
                attempted_account=account,
                session_id=session_id,
            )

    if user is None:
        raise HTTPException(
            status_code=401,
            detail=INVALID_LOGIN,
            headers={"WWW-Authenticate": "Bearer"},
        )
    return LoginResponse(
        access_token=token,
        token_type="bearer",
        expires_at=expires_at,
        user=UserProfile(
            user_id=user.user_id,
            login=user.login,
            display_name=user.display_name,
            organization_id=user.organization_id,
            role=user.role,
        ),
    )


@router.post("/logout", status_code=204)
def logout(
    user: SessionUser = Depends(require_user),
    settings: Settings = Depends(get_settings),
) -> None:
    with connect(settings.database_url) as conn:
        revoke_session(conn, user.session_id, datetime.now(timezone.utc))


@router.get("/me", response_model=UserProfile)
def me(user: SessionUser = Depends(require_user)) -> UserProfile:
    return UserProfile(
        user_id=user.user_id,
        login=user.login,
        display_name=user.display_name,
        organization_id=user.organization_id,
        role=user.role,
    )
