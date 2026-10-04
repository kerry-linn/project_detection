from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials

from backend.auth import bearer_scheme, get_settings
from backend.config import Settings
from backend.db import connect
from backend.repositories.exports import ExportError, export_page

router = APIRouter(prefix="/security/events")
Filter = Annotated[str | None, Query(min_length=1, max_length=256)]


@router.get("/export")
def collect_events(
    request: Request,
    response: Response,
    organization_id: Filter = None,
    attempted_account: Filter = None,
    actor_id: Filter = None,
    event_type: Filter = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    export_id: UUID | None = None,
    cursor: Annotated[str | None, Query(min_length=1, max_length=512)] = None,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> dict:
    if credentials is None:
        raise HTTPException(401, "missing export credential", headers={"WWW-Authenticate": "Bearer"})
    response.headers["Cache-Control"] = "no-store"
    allowed = {"organization_id", "attempted_account", "actor_id", "event_type", "limit", "export_id", "cursor"}
    if set(request.query_params) - allowed or any(len(request.query_params.getlist(k)) > 1 for k in request.query_params):
        raise HTTPException(400, "unknown or repeated export parameter")
    try:
        with connect(settings.database_url) as conn:
            return export_page(
                conn, credentials.credentials, limit=limit, cursor=cursor,
                export_id=str(export_id) if export_id else None,
                filters={"organization_id": organization_id, "attempted_account": attempted_account,
                         "actor_id": actor_id, "event_type": event_type},
            )
    except ExportError as error:
        raise HTTPException(error.status, str(error), headers={"WWW-Authenticate": "Bearer"} if error.status == 401 else None) from error
