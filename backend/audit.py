from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import Request

from backend.db import Connection
from backend.repositories.events import insert_event
from security_events import SecurityEvent, format_utc, parse_event

SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class RequestContext:
    request_id: str
    source_ip: str | None


def request_context(request: Request) -> RequestContext:
    """Source IP comes from the socket peer, never from client-supplied headers.

    Forwarding headers such as X-Forwarded-For are ignored because no trusted
    proxy is configured; behind Docker this may be a bridge gateway address.
    """
    return RequestContext(
        request_id=request.state.request_id,
        source_ip=_peer_ip(request),
    )


def record_event(
    conn: Connection,
    context: RequestContext,
    *,
    event_type: str,
    outcome: str,
    organization_id: str | None,
    actor_id: str | None = None,
    attempted_account: str | None = None,
    session_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityEvent:
    """Caller owns the transaction, so a business change and its audit event
    commit or roll back together."""
    now = format_utc(datetime.now(timezone.utc))
    event = parse_event(
        {
            "event_id": f"app-{uuid.uuid4()}",
            "occurred_at": now,
            "ingested_at": now,
            "source": "application",
            "event_type": event_type,
            "organization_id": organization_id,
            "actor_id": actor_id,
            "attempted_account": attempted_account,
            "session_id": session_id,
            "source_ip": context.source_ip,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "outcome": outcome,
            "request_id": context.request_id,
            "schema_version": SCHEMA_VERSION,
            "metadata": metadata or {},
        }
    )
    insert_event(conn, event)
    return event


def _peer_ip(request: Request) -> str | None:
    if request.client is None:
        return None
    try:
        return str(ipaddress.ip_address(request.client.host))
    except ValueError:
        return None
