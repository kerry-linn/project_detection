from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVENT_TYPES = {
    "login_failed",
    "login_succeeded",
    "access_denied",
    "document_downloaded",
    "role_changed",
}
SOURCES = {"application", "fixture", "cloudtrail"}
OUTCOMES = {"success", "denied", "failure"}
ROLES = {"member", "organization_admin", "lab_analyst"}
RESOURCE_TYPES = {"document", "alert", "admin_route"}
SUPPORTED_SCHEMA_VERSIONS = {"1.0"}
ALLOWED_FIELDS = {
    "event_id",
    "occurred_at",
    "ingested_at",
    "source",
    "event_type",
    "organization_id",
    "actor_id",
    "attempted_account",
    "target_actor_id",
    "previous_role",
    "new_role",
    "session_id",
    "source_ip",
    "resource_type",
    "resource_id",
    "outcome",
    "request_id",
    "schema_version",
    "metadata",
}
FORBIDDEN_METADATA_KEYS = {
    "password",
    "password_hash",
    "access_token",
    "refresh_token",
    "session_cookie",
    "cookie",
    "document_content",
}
MAX_LINE_BYTES = 16_384
MAX_STRING_LENGTH = 256
MAX_METADATA_BYTES = 4_096
CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class EventValidationError(ValueError):
    pass


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
        return {
            "event_id": self.event_id,
            "occurred_at": _format_utc(self.occurred_at),
            "ingested_at": _format_utc(self.ingested_at),
            "source": self.source,
            "event_type": self.event_type,
            "organization_id": self.organization_id,
            "actor_id": self.actor_id,
            "attempted_account": self.attempted_account,
            "target_actor_id": self.target_actor_id,
            "previous_role": self.previous_role,
            "new_role": self.new_role,
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "outcome": self.outcome,
            "request_id": self.request_id,
            "schema_version": self.schema_version,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class RejectedRecord:
    line_number: int
    reason: str


@dataclass(frozen=True)
class DuplicateRecord:
    line_number: int
    event_id: str
    retained_line_number: int


@dataclass(frozen=True)
class ParseResult:
    events: tuple[SecurityEvent, ...]
    rejected: tuple[RejectedRecord, ...]
    duplicates: tuple[DuplicateRecord, ...]
    lines_read: int

    @property
    def event_type_counts(self) -> dict[str, int]:
        counts = Counter(event.event_type for event in self.events)
        return dict(sorted(counts.items()))


def parse_event(record: object) -> SecurityEvent:
    if not isinstance(record, dict):
        raise EventValidationError("record must be a JSON object")

    unknown_fields = sorted(set(record) - ALLOWED_FIELDS)
    if unknown_fields:
        raise EventValidationError(
            f"unknown field(s): {', '.join(unknown_fields)}"
        )

    event_type = _require_choice(record, "event_type", EVENT_TYPES)
    outcome = _require_choice(record, "outcome", OUTCOMES)
    organization_id = _optional_string(record, "organization_id")
    actor_id = _optional_string(record, "actor_id")
    attempted_account = _optional_string(record, "attempted_account")
    target_actor_id = _optional_string(record, "target_actor_id")
    previous_role = _optional_choice(record, "previous_role", ROLES)
    new_role = _optional_choice(record, "new_role", ROLES)
    session_id = _optional_string(record, "session_id")
    resource_type = _optional_choice(record, "resource_type", RESOURCE_TYPES)
    resource_id = _optional_string(record, "resource_id")

    _validate_event_shape(
        event_type=event_type,
        outcome=outcome,
        organization_id=organization_id,
        actor_id=actor_id,
        attempted_account=attempted_account,
        target_actor_id=target_actor_id,
        previous_role=previous_role,
        new_role=new_role,
        session_id=session_id,
        resource_type=resource_type,
        resource_id=resource_id,
    )

    if attempted_account is not None:
        attempted_account = attempted_account.casefold()

    return SecurityEvent(
        event_id=_require_string(record, "event_id"),
        occurred_at=_require_timestamp(record, "occurred_at"),
        ingested_at=_require_timestamp(record, "ingested_at"),
        source=_require_choice(record, "source", SOURCES),
        event_type=event_type,
        organization_id=organization_id,
        actor_id=actor_id,
        attempted_account=attempted_account,
        target_actor_id=target_actor_id,
        previous_role=previous_role,
        new_role=new_role,
        session_id=session_id,
        source_ip=_optional_ip(record, "source_ip"),
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        request_id=_require_string(record, "request_id"),
        schema_version=_require_choice(
            record, "schema_version", SUPPORTED_SCHEMA_VERSIONS
        ),
        metadata=_validate_metadata(record.get("metadata", {})),
    )


def parse_jsonl(path: str | Path) -> ParseResult:
    records_by_event_id: dict[str, list[tuple[int, SecurityEvent]]] = {}
    rejected: list[RejectedRecord] = []
    lines_read = 0

    with Path(path).open("rb") as source:
        for line_number, raw_line in enumerate(source, start=1):
            lines_read = line_number
            try:
                if len(raw_line) > MAX_LINE_BYTES:
                    raise EventValidationError(
                        f"line exceeds {MAX_LINE_BYTES} bytes"
                    )
                line = raw_line.decode("utf-8")
                if not line.strip():
                    raise EventValidationError("line is blank")
                record = json.loads(line)
                event = parse_event(record)
                records_by_event_id.setdefault(event.event_id, []).append(
                    (line_number, event)
                )
            except UnicodeDecodeError:
                rejected.append(
                    RejectedRecord(line_number, "line is not valid UTF-8")
                )
            except json.JSONDecodeError as error:
                rejected.append(
                    RejectedRecord(
                        line_number,
                        f"invalid JSON at column {error.colno}",
                    )
                )
            except EventValidationError as error:
                rejected.append(RejectedRecord(line_number, str(error)))

    events: list[SecurityEvent] = []
    duplicates: list[DuplicateRecord] = []
    for event_id, occurrences in records_by_event_id.items():
        reference = occurrences[0][1]
        if any(
            not events_have_same_source_content(reference, event)
            for _, event in occurrences[1:]
        ):
            rejected.extend(
                RejectedRecord(
                    line_number,
                    f"conflicting event_id: {event_id}",
                )
                for line_number, _ in occurrences
            )
            continue

        retained_line_number, retained_event = min(
            occurrences,
            key=lambda occurrence: (
                occurrence[1].ingested_at,
                occurrence[0],
            ),
        )
        events.append(retained_event)
        duplicates.extend(
            DuplicateRecord(
                line_number=line_number,
                event_id=event_id,
                retained_line_number=retained_line_number,
            )
            for line_number, _ in occurrences
            if line_number != retained_line_number
        )

    events.sort(key=lambda event: (event.occurred_at, event.event_id))
    rejected.sort(key=lambda record: record.line_number)
    duplicates.sort(key=lambda record: record.line_number)
    return ParseResult(
        tuple(events),
        tuple(rejected),
        tuple(duplicates),
        lines_read,
    )


def events_have_same_source_content(
    first: SecurityEvent, second: SecurityEvent
) -> bool:
    return all(
        getattr(first, field.name) == getattr(second, field.name)
        for field in fields(SecurityEvent)
        if field.name != "ingested_at"
    )


def _validate_event_shape(
    *,
    event_type: str,
    outcome: str,
    organization_id: str | None,
    actor_id: str | None,
    attempted_account: str | None,
    target_actor_id: str | None,
    previous_role: str | None,
    new_role: str | None,
    session_id: str | None,
    resource_type: str | None,
    resource_id: str | None,
) -> None:
    required_outcome = {
        "login_failed": "failure",
        "login_succeeded": "success",
        "access_denied": "denied",
        "document_downloaded": "success",
        "role_changed": "success",
    }[event_type]
    if outcome != required_outcome:
        raise EventValidationError(
            f"{event_type} outcome must be {required_outcome}"
        )
    if organization_id is None:
        raise EventValidationError(
            f"{event_type} requires organization_id"
        )
    if event_type in {"login_failed", "login_succeeded"}:
        _require_present(attempted_account, event_type, "attempted_account")
    if event_type != "login_failed":
        _require_present(actor_id, event_type, "actor_id")
        _require_present(session_id, event_type, "session_id")
    if event_type == "access_denied":
        _require_present(resource_type, event_type, "resource_type")
        if resource_type == "document":
            _require_present(resource_id, event_type, "resource_id")
    if event_type == "document_downloaded":
        if resource_type != "document":
            raise EventValidationError(
                "document_downloaded resource_type must be document"
            )
        _require_present(resource_id, event_type, "resource_id")
    if event_type == "role_changed":
        _require_present(target_actor_id, event_type, "target_actor_id")
        _require_present(previous_role, event_type, "previous_role")
        _require_present(new_role, event_type, "new_role")
        if previous_role == new_role:
            raise EventValidationError(
                "role_changed previous_role and new_role must differ"
            )


def _require_present(
    value: str | None, event_type: str, field: str
) -> None:
    if value is None:
        raise EventValidationError(f"{event_type} requires {field}")


def _require_string(record: dict[str, Any], field: str) -> str:
    if field not in record:
        raise EventValidationError(f"missing required field: {field}")
    value = record[field]
    if not isinstance(value, str) or not value.strip():
        raise EventValidationError(f"{field} must be a non-empty string")
    value = value.strip()
    if len(value) > MAX_STRING_LENGTH:
        raise EventValidationError(
            f"{field} exceeds {MAX_STRING_LENGTH} characters"
        )
    if CONTROL_CHARACTERS.search(value):
        raise EventValidationError(f"{field} contains control characters")
    return value


def _optional_string(record: dict[str, Any], field: str) -> str | None:
    if field not in record or record[field] is None:
        return None
    return _require_string(record, field)


def _require_choice(
    record: dict[str, Any], field: str, choices: set[str]
) -> str:
    value = _require_string(record, field)
    if value not in choices:
        raise EventValidationError(
            f"{field} must be one of: {', '.join(sorted(choices))}"
        )
    return value


def _optional_choice(
    record: dict[str, Any], field: str, choices: set[str]
) -> str | None:
    value = _optional_string(record, field)
    if value is not None and value not in choices:
        raise EventValidationError(
            f"{field} must be one of: {', '.join(sorted(choices))}"
        )
    return value


def _require_timestamp(record: dict[str, Any], field: str) -> datetime:
    value = _require_string(record, field)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        timestamp = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise EventValidationError(
            f"{field} must be a valid ISO 8601 timestamp"
        ) from error
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise EventValidationError(f"{field} must include a timezone")
    return timestamp.astimezone(timezone.utc)


def _optional_ip(record: dict[str, Any], field: str) -> str | None:
    value = _optional_string(record, field)
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as error:
        raise EventValidationError(
            f"{field} must be a valid IPv4 or IPv6 address"
        ) from error


def _validate_metadata(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EventValidationError("metadata must be a JSON object")
    serialized = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > MAX_METADATA_BYTES:
        raise EventValidationError(
            f"metadata exceeds {MAX_METADATA_BYTES} bytes"
        )
    _validate_metadata_values(value)
    return value


def _validate_metadata_values(value: object) -> None:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            if key.casefold() in FORBIDDEN_METADATA_KEYS:
                raise EventValidationError(
                    f"metadata contains forbidden key: {key}"
                )
            _validate_metadata_values(nested_value)
    elif isinstance(value, list):
        for item in value:
            _validate_metadata_values(item)
    elif isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise EventValidationError(
                f"metadata string exceeds {MAX_STRING_LENGTH} characters"
            )
        if CONTROL_CHARACTERS.search(value):
            raise EventValidationError(
                "metadata contains control characters"
            )


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
