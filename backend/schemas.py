from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_BATCH_EVENTS = 500
MAX_LOGIN_LENGTH = 128
MAX_PASSWORD_LENGTH = 1024
MAX_TITLE_LENGTH = 200
MAX_BODY_LENGTH = 20_000
CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


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


class LoginRequest(BaseModel):
    """Only credentials: identity, organization, and outcome are server-derived."""

    model_config = ConfigDict(extra="forbid")

    login: str = Field(min_length=1, max_length=MAX_LOGIN_LENGTH)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)

    @field_validator("login")
    @classmethod
    def login_is_printable(cls, value: str) -> str:
        if not value.strip() or CONTROL_CHARACTERS.search(value):
            raise ValueError("login must be printable text")
        return value


class UserProfile(BaseModel):
    user_id: str
    login: str
    display_name: str
    organization_id: str | None
    role: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"]
    expires_at: datetime
    user: UserProfile


class DocumentCreate(BaseModel):
    """Owner and organization come from the session, never the request body."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=MAX_TITLE_LENGTH)
    body: str = Field(default="", max_length=MAX_BODY_LENGTH)


class DocumentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=1, max_length=MAX_TITLE_LENGTH)
    body: str | None = Field(default=None, max_length=MAX_BODY_LENGTH)

    @model_validator(mode="after")
    def has_a_change(self) -> DocumentUpdate:
        if self.title is None and self.body is None:
            raise ValueError("provide title or body")
        return self


class DocumentSummary(BaseModel):
    document_id: str
    organization_id: str
    owner_id: str
    title: str
    created_at: datetime
    updated_at: datetime


class DocumentDetail(DocumentSummary):
    body: str


class AlertSummary(BaseModel):
    alert_key: str
    rule_id: str
    rule_version: str
    severity: str
    status: str
    detection_state: str
    needs_review: bool
    organization_id: str | None
    attempted_account: str | None
    actor_id: str | None
    window_start: datetime
    window_end: datetime
    threshold: int
    match_count: int
    reason: str
    created_at: datetime
    updated_at: datetime


class AlertDetail(AlertSummary):
    session_id: str | None
    window_microseconds: int
    cooldown_microseconds: int | None
    suppression_until: datetime | None
    source_ips: list[str]
    resource_ids: list[str]
    evidence: list[dict[str, Any]]
    replaces: list[str]
    replaced_by: list[str]
