from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from backend.auth import get_settings, require_collector
from backend.config import Settings
from backend.db import connect
from backend.repositories.events import EventIdConflict, ingest_events
from backend.schemas import BatchIngestResponse, EventBatch
from security_events import (
    EventValidationError,
    SecurityEvent,
    format_utc,
    parse_event,
)

router = APIRouter(dependencies=[Depends(require_collector)])


@router.post("/internal/events/batch", response_model=BatchIngestResponse)
def ingest_event_batch(
    batch: EventBatch,
    settings: Settings = Depends(get_settings),
) -> BatchIngestResponse:
    events, invalid_events = _normalize_batch(batch)
    if invalid_events:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "batch rejected; no events were stored",
                "invalid_events": invalid_events,
            },
        )

    try:
        with connect(settings.database_url) as conn:
            result = ingest_events(conn, events)
    except EventIdConflict as error:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "event_id reused with different source content; "
                "no events were stored",
                "event_id": error.event_id,
            },
        ) from error

    return BatchIngestResponse(
        received=len(events),
        inserted=result.inserted,
        replayed=result.replayed,
    )


def _normalize_batch(
    batch: EventBatch,
) -> tuple[list[SecurityEvent], list[dict[str, object]]]:
    ingested_at = format_utc(datetime.now(timezone.utc))
    events = []
    invalid_events = []
    for index, item in enumerate(batch.events):
        record = item.model_dump()
        record["ingested_at"] = ingested_at
        try:
            events.append(parse_event(record))
        except EventValidationError as error:
            invalid_events.append({"index": index, "reason": str(error)})
    return events, invalid_events
