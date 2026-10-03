from __future__ import annotations

from dataclasses import asdict
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from backend.auth import get_settings, require_analyst
from backend.config import Settings
from backend.db import connect
from backend.repositories import alerts as alert_repository
from backend.repositories import cases
from backend.repositories.users import SessionUser
from backend.pagination import PageLimit, PageOffset, page_headers
from backend.repositories.events import search_events
from backend.schemas import AlertDetail, AlertSummary, CaseDecision, CaseNote

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
    response: Response,
    include_superseded: bool = False,
    rule: FilterValue = None,
    status: FilterValue = None,
    organization: FilterValue = None,
    entity: FilterValue = None,
    limit: PageLimit = 50,
    offset: PageOffset = 0,
    settings: Settings = Depends(get_settings),
) -> list[AlertSummary]:
    with connect(settings.database_url) as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        alerts, total = alert_repository.search_alerts(
            conn, include_superseded=include_superseded, rule=rule, status=status,
            organization=organization, entity=entity, limit=limit, offset=offset,
        )
    page_headers(response, total, limit, offset)
    return [AlertSummary(**asdict(alert)) for alert in alerts]


@router.get("/alerts/{alert_key}", response_model=AlertDetail)
def get_alert(
    alert_key: str,
    evidence_limit: PageLimit = 50,
    evidence_offset: PageOffset = 0,
    replacement_offset: PageOffset = 0,
    settings: Settings = Depends(get_settings),
) -> AlertDetail:
    with connect(settings.database_url) as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        alert = alert_repository.get_alert(conn, alert_key)
        if alert is None:
            raise HTTPException(status_code=404, detail="alert not found")
        evidence = alert_repository.list_alert_evidence(
            conn, alert_key, limit=evidence_limit, offset=evidence_offset
        )
        replaced_by, replaces = alert_repository.get_alert_replacements(
            conn, alert_key, limit=100, offset=replacement_offset
        )
        counts = alert_repository.detail_counts(conn, alert_key)

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
        evidence_limit=evidence_limit,
        evidence_offset=evidence_offset,
        **counts,
    )


@router.patch("/alerts/{alert_key}")
def update_case(
    alert_key: str,
    change: CaseDecision,
    user: SessionUser = Depends(require_analyst),
    settings: Settings = Depends(get_settings),
) -> dict[str, int]:
    return _write_case(settings, alert_key, user.user_id, change)


@router.post("/alerts/{alert_key}/notes", status_code=201)
def add_note(
    alert_key: str,
    note: CaseNote,
    user: SessionUser = Depends(require_analyst),
    settings: Settings = Depends(get_settings),
) -> dict[str, int]:
    return _write_case(settings, alert_key, user.user_id, note)


@router.get("/alerts/{alert_key}/activity")
def case_activity(
    alert_key: str,
    response: Response,
    limit: PageLimit = 50,
    offset: PageOffset = 0,
    settings: Settings = Depends(get_settings),
) -> list[dict]:
    with connect(settings.database_url) as conn:
        conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        if alert_repository.get_alert(conn, alert_key) is None:
            raise HTTPException(status_code=404, detail="alert not found")
        total = conn.execute(
            "SELECT count(*) AS n FROM case_activity WHERE alert_key = %s", (alert_key,)
        ).fetchone()["n"]
        activity = cases.list_activity(conn, alert_key, limit, offset)
    page_headers(response, total, limit, offset)
    return activity


def _write_case(
    settings: Settings, alert_key: str, author_id: str, change: CaseDecision | CaseNote
) -> dict[str, int]:
    try:
        with connect(settings.database_url) as conn:
            revision = cases.write_activity(conn, alert_key, author_id, change)
    except cases.CaseNotFound as error:
        raise HTTPException(status_code=404, detail="alert not found") from error
    except cases.CaseConflict as error:
        raise HTTPException(status_code=409, detail="case changed; reload before saving") from error
    return {"revision": revision}
