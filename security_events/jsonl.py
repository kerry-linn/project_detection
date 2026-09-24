from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from security_events.models import (
    SecurityEvent,
    events_have_same_source_content,
)
from security_events.validation import EventValidationError, parse_event

MAX_LINE_BYTES = 16_384


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


Occurrence = tuple[int, SecurityEvent]


def parse_jsonl(path: str | Path) -> ParseResult:
    occurrences_by_id: dict[str, list[Occurrence]] = {}
    rejected: list[RejectedRecord] = []
    lines_read = 0

    with Path(path).open("rb") as source:
        for line_number, raw_line in enumerate(source, start=1):
            lines_read = line_number
            try:
                event = _parse_line(raw_line)
            except EventValidationError as error:
                rejected.append(RejectedRecord(line_number, str(error)))
                continue
            occurrences_by_id.setdefault(event.event_id, []).append(
                (line_number, event)
            )

    events: list[SecurityEvent] = []
    duplicates: list[DuplicateRecord] = []
    for event_id, occurrences in occurrences_by_id.items():
        if _has_conflict(occurrences):
            for line_number, _ in occurrences:
                rejected.append(
                    RejectedRecord(
                        line_number, f"conflicting event_id: {event_id}"
                    )
                )
            continue

        retained_line_number, retained_event = _earliest_ingested(occurrences)
        events.append(retained_event)
        for line_number, _ in occurrences:
            if line_number != retained_line_number:
                duplicates.append(
                    DuplicateRecord(line_number, event_id, retained_line_number)
                )

    events.sort(key=lambda event: (event.occurred_at, event.event_id))
    rejected.sort(key=lambda record: record.line_number)
    duplicates.sort(key=lambda record: record.line_number)
    return ParseResult(
        events=tuple(events),
        rejected=tuple(rejected),
        duplicates=tuple(duplicates),
        lines_read=lines_read,
    )


def _parse_line(raw_line: bytes) -> SecurityEvent:
    if len(raw_line) > MAX_LINE_BYTES:
        raise EventValidationError(f"line exceeds {MAX_LINE_BYTES} bytes")
    try:
        line = raw_line.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EventValidationError("line is not valid UTF-8") from error
    if not line.strip():
        raise EventValidationError("line is blank")
    try:
        record = json.loads(line)
    except json.JSONDecodeError as error:
        raise EventValidationError(
            f"invalid JSON at column {error.colno}"
        ) from error
    return parse_event(record)


def _has_conflict(occurrences: list[Occurrence]) -> bool:
    reference = occurrences[0][1]
    for _, event in occurrences[1:]:
        if not events_have_same_source_content(reference, event):
            return True
    return False


def _earliest_ingested(occurrences: list[Occurrence]) -> Occurrence:
    return min(
        occurrences,
        key=lambda occurrence: (occurrence[1].ingested_at, occurrence[0]),
    )
