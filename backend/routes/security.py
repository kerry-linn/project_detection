from __future__ import annotations

from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.auth import get_settings, require_analyst
from backend.config import Settings
from backend.db import connect
from backend.repositories import alerts as alert_repository
from backend.repositories.events import search_events
from backend.schemas import AlertDetail, AlertSummary

router = APIRouter(prefix="/security", dependencies=[Depends(require_analyst)])

FilterValue = Annotated[str | None, Query(max_length=256)]


@router.get("/events")
def list_events(
    organization_id: FilterValue = None,
    attempted_account: FilterValue = None,
    actor_id: FilterValue = None,
    event_type: FilterValue = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    settings: Settings = Depends(get_settings),
) -> list[dict[str, Any]]:
    with connect(settings.database_url) as conn:
        events = search_events(
            conn,
            organization_id=organization_id,
            attempted_account=attempted_account,
            actor_id=actor_id,
            event_type=event_type,
            limit=limit,
        )
    return [event.to_dict() for event in events]


@router.get("/alerts", response_model=list[AlertSummary])
def list_alerts(
    include_superseded: bool = False,
    settings: Settings = Depends(get_settings),
) -> list[AlertSummary]:
    with connect(settings.database_url) as conn:
        alerts = alert_repository.list_alerts(conn, include_superseded=include_superseded)
    return [AlertSummary(**asdict(alert)) for alert in alerts]


@router.get("/alerts/{alert_key}", response_model=AlertDetail)
def get_alert(
    alert_key: str,
    settings: Settings = Depends(get_settings),
) -> AlertDetail:
    with connect(settings.database_url) as conn:
        alert = alert_repository.get_alert(conn, alert_key)
        if alert is None:
            raise HTTPException(status_code=404, detail="alert not found")
        evidence = alert_repository.list_alert_evidence(conn, alert_key)
        replaced_by, replaces = alert_repository.get_alert_replacements(conn, alert_key)

    source_ips = set()
    resource_ids = set()
    evidence_records = []
    for item in evidence:
        if item.event.source_ip is not None:
            source_ips.add(item.event.source_ip)
        if item.event.resource_id is not None:
            resource_ids.add(item.event.resource_id)
        evidence_records.append(
            {"evidence_role": item.evidence_role, **item.event.to_dict()}
        )

    return AlertDetail(
        **asdict(alert),
        source_ips=sorted(source_ips),
        resource_ids=sorted(resource_ids),
        evidence=evidence_records,
        replaces=replaces,
        replaced_by=replaced_by,
    )
