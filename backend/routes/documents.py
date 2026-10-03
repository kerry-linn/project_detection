from __future__ import annotations

import uuid
from dataclasses import asdict
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response

from backend.audit import RequestContext, record_event, request_context
from backend.auth import get_settings, require_organization_user
from backend.authorization import DocumentDecision, decide_document_access
from backend.config import Settings
from backend.db import Connection, connect
from backend.pagination import PageLimit, PageOffset, page_headers
from backend.repositories import documents as document_repository
from backend.repositories.users import ORGANIZATION_ADMIN, SessionUser
from backend.schemas import (
    DocumentCreate,
    DocumentDetail,
    DocumentSummary,
    DocumentUpdate,
)

router = APIRouter(prefix="/documents")

DocumentId = Annotated[str, Path(pattern=r"^[A-Za-z0-9_-]{1,64}$")]

# Cross-organization and nonexistent documents share one response so a caller
# cannot learn which document IDs exist in another tenant.
DENIAL_RESPONSES = {
    DocumentDecision.NOT_OWNER: (403, "not permitted to access this document"),
    DocumentDecision.CROSS_ORGANIZATION: (404, "document not found"),
    DocumentDecision.NOT_FOUND: (404, "document not found"),
}


@router.get("", response_model=list[DocumentSummary])
def list_documents(
    response: Response,
    limit: PageLimit = 50,
    offset: PageOffset = 0,
    user: SessionUser = Depends(require_organization_user),
    settings: Settings = Depends(get_settings),
) -> list[DocumentSummary]:
    owner_id = None if user.role == ORGANIZATION_ADMIN else user.user_id
    with connect(settings.database_url) as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        total = document_repository.count_documents(conn, user.organization_id, owner_id)
        documents = document_repository.list_documents(
            conn, organization_id=user.organization_id, owner_id=owner_id, limit=limit, offset=offset
        )
    page_headers(response, total, limit, offset)
    return [DocumentSummary(**asdict(document)) for document in documents]


@router.post("", response_model=DocumentDetail, status_code=201)
def create_document(
    body: DocumentCreate,
    request: Request,
    user: SessionUser = Depends(require_organization_user),
    settings: Settings = Depends(get_settings),
) -> DocumentDetail:
    context = request_context(request)
    with connect(settings.database_url) as conn:
        document = document_repository.create_document(
            conn,
            document_id=f"doc-{uuid.uuid4().hex}",
            organization_id=user.organization_id,
            owner_id=user.user_id,
            title=body.title,
            body=body.body,
        )
        _record_document_event(
            conn, context, user, "document_created", document.document_id
        )
    return DocumentDetail(**asdict(document))


@router.get("/{document_id}", response_model=DocumentDetail)
def read_document(
    document_id: DocumentId,
    request: Request,
    user: SessionUser = Depends(require_organization_user),
    settings: Settings = Depends(get_settings),
) -> DocumentDetail:
    context = request_context(request)
    with connect(settings.database_url) as conn:
        document = document_repository.get_document(conn, document_id)
        decision = decide_document_access(user, document)
        if decision is not DocumentDecision.ALLOWED:
            _record_denial(conn, context, user, document_id, decision, "read")
    _raise_if_denied(decision)
    return DocumentDetail(**asdict(document))


@router.patch("/{document_id}", response_model=DocumentDetail)
def update_document(
    document_id: DocumentId,
    body: DocumentUpdate,
    request: Request,
    user: SessionUser = Depends(require_organization_user),
    settings: Settings = Depends(get_settings),
) -> DocumentDetail:
    context = request_context(request)
    with connect(settings.database_url) as conn:
        document = document_repository.get_document(conn, document_id)
        decision = decide_document_access(user, document)
        if decision is DocumentDecision.ALLOWED:
            document = document_repository.update_document(
                conn, document_id, title=body.title, body=body.body
            )
            changed_fields = sorted(
                field for field in ("title", "body") if getattr(body, field) is not None
            )
            _record_document_event(
                conn,
                context,
                user,
                "document_updated",
                document_id,
                metadata={"changed_fields": changed_fields},
            )
        else:
            _record_denial(conn, context, user, document_id, decision, "update")
    _raise_if_denied(decision)
    return DocumentDetail(**asdict(document))


def _record_document_event(
    conn: Connection,
    context: RequestContext,
    user: SessionUser,
    event_type: str,
    document_id: str,
    metadata: dict[str, object] | None = None,
) -> None:
    record_event(
        conn,
        context,
        event_type=event_type,
        outcome="success",
        organization_id=user.organization_id,
        actor_id=user.user_id,
        session_id=user.session_id,
        resource_type="document",
        resource_id=document_id,
        metadata=metadata,
    )


def _record_denial(
    conn: Connection,
    context: RequestContext,
    user: SessionUser,
    document_id: str,
    decision: DocumentDecision,
    action: str,
) -> None:
    """Records only the requested ID and the caller's own tenant, never the
    document's content or another organization's identifiers."""
    record_event(
        conn,
        context,
        event_type="access_denied",
        outcome="denied",
        organization_id=user.organization_id,
        actor_id=user.user_id,
        session_id=user.session_id,
        resource_type="document",
        resource_id=document_id,
        metadata={"action": action, "reason": decision.value},
    )


def _raise_if_denied(decision: DocumentDecision) -> None:
    if decision is DocumentDecision.ALLOWED:
        return
    status_code, detail = DENIAL_RESPONSES[decision]
    raise HTTPException(status_code=status_code, detail=detail)
