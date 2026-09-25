from __future__ import annotations

from datetime import datetime, timedelta, timezone

import psycopg

from backend.db import connect
from backend.detection_runner import run_denied_document_detection
from backend.repositories.alerts import get_alert, list_alerts
from backend.repositories.events import ingest_events
from detections.denied_document_access import RULE_ID
from security_events import SecurityEvent, parse_event

START = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
FIRST_KEY = (
    f"{RULE_ID}:1.0:threshold=5:window_us=300000000:cooldown_us=900000000:"
    "org-alpha:user-bob:denial-4"
)


def test_rerun_does_not_duplicate_the_episode(database_url: str) -> None:
    _ingest(database_url, _distinct_denials(5))

    first = _run(database_url)
    second = _run(database_url)

    assert (first.alerts_created, first.alerts_updated) == (1, 0)
    assert (second.alerts_created, second.alerts_unchanged) == (0, 1)
    with connect(database_url) as conn:
        alerts = list_alerts(conn)
        roles = _evidence(conn, FIRST_KEY)
    assert [alert.alert_key for alert in alerts] == [FIRST_KEY]
    assert alerts[0].match_count == 5
    assert alerts[0].attempted_account is None
    assert alerts[0].actor_id == "user-bob"
    assert roles == {
        (f"denial-{index}", "denied_document_access") for index in range(5)
    }


def test_new_denials_extend_the_open_episode_and_keep_analyst_status(
    database_url: str,
) -> None:
    initial = _distinct_denials(5)
    _ingest(database_url, initial)
    _run(database_url)
    with connect(database_url) as conn:
        conn.execute(
            "UPDATE alerts SET status = 'investigating' WHERE alert_key = %s",
            (FIRST_KEY,),
        )

    later = _denial("later", initial[-1].occurred_at + timedelta(minutes=10), "doc-9")
    _ingest(database_url, [later])
    summary = _run(database_url)

    with connect(database_url) as conn:
        alert = get_alert(conn, FIRST_KEY)
        evidence = _evidence(conn, FIRST_KEY)
    assert (summary.alerts_created, summary.alerts_updated) == (0, 1)
    assert alert.status == "investigating"
    assert alert.match_count == 6
    assert alert.window_end == later.occurred_at
    assert alert.suppression_until == later.occurred_at + timedelta(minutes=15)
    assert ("later", "denied_document_access") in evidence
    assert len(evidence) == 6


def test_activity_after_cooldown_creates_a_separate_alert(database_url: str) -> None:
    first = _distinct_denials(5)
    second = _distinct_denials(
        5, start=first[-1].occurred_at + timedelta(minutes=16), prefix="second"
    )
    _ingest(database_url, [*first, *second])

    summary = _run(database_url)

    with connect(database_url) as conn:
        keys = {alert.alert_key for alert in list_alerts(conn)}
    assert summary.alerts_created == 2
    assert FIRST_KEY in keys
    assert len(keys) == 2


def test_run_records_rule_and_cooldown(database_url: str) -> None:
    _ingest(database_url, _distinct_denials(5))
    _run(database_url)

    with connect(database_url) as conn:
        run = conn.execute("SELECT * FROM detection_runs").fetchone()

    assert run["rule_id"] == RULE_ID
    assert run["status"] == "succeeded"
    assert run["threshold"] == 5
    assert run["window_microseconds"] == 300_000_000
    assert run["cooldown_microseconds"] == 900_000_000


def _run(database_url: str):
    with connect(database_url) as conn:
        return run_denied_document_detection(conn)


def _ingest(database_url: str, events: list[SecurityEvent]) -> None:
    with connect(database_url) as conn:
        ingest_events(conn, events)


def _evidence(conn: psycopg.Connection, alert_key: str) -> set[tuple[str, str]]:
    rows = conn.execute(
        "SELECT event_id, evidence_role FROM alert_events WHERE alert_key = %s",
        (alert_key,),
    ).fetchall()
    return {(row["event_id"], row["evidence_role"]) for row in rows}


def _distinct_denials(
    count: int, *, start: datetime = START, prefix: str = "denial"
) -> list[SecurityEvent]:
    return [
        _denial(f"{prefix}-{index}", start + timedelta(seconds=30 * index), f"doc-{index}")
        for index in range(count)
    ]


def _denial(event_id: str, occurred_at: datetime, resource_id: str) -> SecurityEvent:
    return parse_event(
        {
            "event_id": event_id,
            "occurred_at": occurred_at.isoformat(),
            "ingested_at": (occurred_at + timedelta(seconds=1)).isoformat(),
            "source": "application",
            "event_type": "access_denied",
            "organization_id": "org-alpha",
            "actor_id": "user-bob",
            "session_id": "session-1",
            "source_ip": "198.51.100.10",
            "resource_type": "document",
            "resource_id": resource_id,
            "outcome": "denied",
            "request_id": f"request-{event_id}",
            "schema_version": "1.0",
            "metadata": {},
        }
    )
