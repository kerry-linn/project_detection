"""Validated security-event contract shared by the CLI, detections, and API."""

from security_events.jsonl import (
    DuplicateRecord,
    ParseResult,
    RejectedRecord,
    parse_jsonl,
)
from security_events.models import (
    SecurityEvent,
    events_have_same_source_content,
    format_utc,
)
from security_events.validation import EventValidationError, parse_event

__all__ = [
    "DuplicateRecord",
    "EventValidationError",
    "ParseResult",
    "RejectedRecord",
    "SecurityEvent",
    "events_have_same_source_content",
    "format_utc",
    "parse_event",
    "parse_jsonl",
]
