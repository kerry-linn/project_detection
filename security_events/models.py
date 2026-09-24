from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    occurred_at: datetime
    ingested_at: datetime
    source: str
    event_type: str
    organization_id: str | None
    actor_id: str | None
    attempted_account: str | None
    target_actor_id: str | None
    previous_role: str | None
    new_role: str | None
    session_id: str | None
    source_ip: str | None
    resource_type: str | None
    resource_id: str | None
    outcome: str
    request_id: str
    schema_version: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["occurred_at"] = format_utc(self.occurred_at)
        data["ingested_at"] = format_utc(self.ingested_at)
        return data


def events_have_same_source_content(
    first: SecurityEvent, second: SecurityEvent
) -> bool:
    """Collection time is ignored: a replay received later is the same event."""
    for field in fields(SecurityEvent):
        if field.name == "ingested_at":
            continue
        if getattr(first, field.name) != getattr(second, field.name):
            return False
    return True


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
