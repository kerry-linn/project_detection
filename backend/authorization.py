from __future__ import annotations

from enum import Enum

from backend.repositories.documents import Document
from backend.repositories.users import ORGANIZATION_ADMIN, SessionUser


class DocumentDecision(str, Enum):
    ALLOWED = "allowed"
    NOT_OWNER = "not_owner"
    CROSS_ORGANIZATION = "cross_organization"
    NOT_FOUND = "not_found"


def decide_document_access(
    user: SessionUser, document: Document | None
) -> DocumentDecision:
    """Members may read and update only documents they own. Organization
    administrators may read and update any document in their organization.
    Nobody reaches another organization's documents.
    """
    if document is None:
        return DocumentDecision.NOT_FOUND
    if document.organization_id != user.organization_id:
        return DocumentDecision.CROSS_ORGANIZATION
    if user.role == ORGANIZATION_ADMIN or document.owner_id == user.user_id:
        return DocumentDecision.ALLOWED
    return DocumentDecision.NOT_OWNER
