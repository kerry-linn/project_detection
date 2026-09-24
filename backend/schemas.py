from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

MAX_BATCH_EVENTS = 500


class IncomingEvent(BaseModel):
    """What a trusted collector may assert about an event.

    `ingested_at` is deliberately absent: collection time belongs to the server.
    `application` is not an accepted source because application events are
    produced by server routes, never submitted from outside.
    Field values are validated by `security_events.parse_event`.
    """

    model_config = ConfigDict(extra="forbid")

    event_id: str
    occurred_at: str
    source: Literal["fixture", "cloudtrail"]
    event_type: str
    organization_id: str | None = None
    actor_id: str | None = None
    attempted_account: str | None = None
    target_actor_id: str | None = None
    previous_role: str | None = None
    new_role: str | None = None
    session_id: str | None = None
    source_ip: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    outcome: str
    request_id: str
    schema_version: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class EventBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[IncomingEvent] = Field(min_length=1, max_length=MAX_BATCH_EVENTS)


class BatchIngestResponse(BaseModel):
    received: int
    inserted: int
    replayed: int


class AlertSummary(BaseModel):
    alert_key: str
    rule_id: str
    rule_version: str
    severity: str
    status: str
    organization_id: str
    attempted_account: str
    window_start: datetime
    window_end: datetime
    threshold: int
    failure_count: int
    reason: str
    created_at: datetime
    updated_at: datetime


class AlertDetail(AlertSummary):
    actor_id: str | None
    session_id: str | None
    window_microseconds: int
    source_ips: list[str]
    evidence: list[dict[str, Any]]
