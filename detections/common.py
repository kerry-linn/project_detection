from __future__ import annotations

from datetime import timedelta
from typing import Iterable

from security_events import SecurityEvent, events_have_same_source_content


def duration_microseconds(duration: timedelta) -> int:
    return (
        duration.days * 86_400_000_000
        + duration.seconds * 1_000_000
        + duration.microseconds
    )


def deduplicate_and_sort(events: Iterable[SecurityEvent]) -> list[SecurityEvent]:
    """Collapse source-equivalent replays (keeping the earliest collection
    time) and order by event time, then event ID, for deterministic results."""
    unique_events: dict[str, SecurityEvent] = {}
    for event in events:
        existing = unique_events.get(event.event_id)
        if existing is None:
            unique_events[event.event_id] = event
        elif not events_have_same_source_content(existing, event):
            raise ValueError(
                f"conflicting records for event_id: {event.event_id}"
            )
        elif event.ingested_at < existing.ingested_at:
            unique_events[event.event_id] = event

    return sorted(
        unique_events.values(),
        key=lambda event: (event.occurred_at, event.event_id),
    )
