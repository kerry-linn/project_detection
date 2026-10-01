from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest

import backend.detection_runner as detection_runner
from backend.db import connect
from backend.detection_runner import run_failed_login_detection
from backend.repositories.alerts import (
    get_alert,
    list_alert_evidence,
    save_alert,
)
from backend.repositories.events import (
    EventIdConflict,
    IngestResult,
    get_event,
    ingest_events,
    load_events,
)
from security_events import SecurityEvent, parse_event, parse_jsonl

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
EXPECTED = json.loads((FIXTURES / "expected" / "days_5_6.json").read_text())
ALERT_KEY = EXPECTED["alert"]["alert_key"]


def test_events_round_trip_without_changing_normalized_values(
    database_url: str,
) -> None:
    events = list(_fixture_events())

    with connect(database_url) as conn:
        result = ingest_events(conn, events)
    with connect(database_url) as conn:
        stored = load_events(conn)

    assert result == IngestResult(inserted=EXPECTED["stored_events"], replayed=0)
    assert stored == events


def test_replay_is_not_stored_twice_and_keeps_first_collection_time(
    database_url: str,
) -> None:
    events = list(_fixture_events())
    later_copies = [
        replace(event, ingested_at=event.ingested_at + timedelta(hours=1))
        for event in events
    ]

    with connect(database_url) as conn:
        ingest_events(conn, events)
    with connect(database_url) as conn:
        result = ingest_events(conn, later_copies)
    with connect(database_url) as conn:
        stored = load_events(conn)

    assert result == IngestResult(inserted=0, replayed=len(events))
    assert [event.ingested_at for event in stored] == [
        event.ingested_at for event in events
    ]


def test_duplicate_inside_one_batch_counts_as_replay(database_url: str) -> None:
    event = _login_failure("dup-1", minutes_before_success=3)

    with connect(database_url) as conn:
        result = ingest_events(conn, [event, event])

    assert result == IngestResult(inserted=1, replayed=1)


def test_conflicting_event_rolls_back_the_whole_batch(database_url: str) -> None:
    original = _login_failure("conflict-1", minutes_before_success=3)
    unrelated = _login_failure("new-in-same-batch", minutes_before_success=2)
    conflicting = replace(original, source_ip="203.0.113.99")

    with connect(database_url) as conn:
        ingest_events(conn, [original])

    with pytest.raises(EventIdConflict) as error:
        with connect(database_url) as conn:
            ingest_events(conn, [unrelated, conflicting])

    with connect(database_url) as conn:
        assert error.value.event_id == "conflict-1"
        assert get_event(conn, "new-in-same-batch") is None
        assert get_event(conn, "conflict-1") == original


def test_check_constraint_rejects_unknown_outcome(database_url: str) -> None:
    with pytest.raises(psycopg.errors.CheckViolation):
        with connect(database_url) as conn:
            conn.execute(
                """
                INSERT INTO security_events (
                    event_id, occurred_at, ingested_at, source, event_type,
                    organization_id, outcome, request_id, schema_version
                )
                VALUES ('bad', now(), now(), 'fixture', 'login_failed',
                        'org-alpha', 'maybe', 'request-bad', '1.0')
                """
            )


def test_foreign_key_rejects_evidence_for_unknown_event(
    database_url: str,
) -> None:
    with connect(database_url) as conn:
        ingest_events(conn, list(_fixture_events()))
    with connect(database_url) as conn:
        run_failed_login_detection(conn)

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with connect(database_url) as conn:
            conn.execute(
                "INSERT INTO alert_events (alert_key, event_id, evidence_role) "
                "VALUES (%s, 'missing-event', 'failed_login')",
                (ALERT_KEY,),
            )


def test_detector_rerun_does_not_duplicate_alerts(database_url: str) -> None:
    with connect(database_url) as conn:
        ingest_events(conn, list(_fixture_events()))

    with connect(database_url) as conn:
        first = run_failed_login_detection(conn)
    with connect(database_url) as conn:
        second = run_failed_login_detection(conn)

    assert (first.alerts_created, first.alerts_updated) == (1, 0)
    assert (second.alerts_created, second.alerts_unchanged) == (0, 1)
    with connect(database_url) as conn:
        assert _count(conn, "alerts") == 1
        assert _evidence(conn) == _expected_evidence()


def test_late_failure_updates_evidence_on_the_same_alert(
    database_url: str,
) -> None:
    with connect(database_url) as conn:
        ingest_events(conn, list(_fixture_events()))
    with connect(database_url) as conn:
        run_failed_login_detection(conn)
    with connect(database_url) as conn:
        conn.execute(
            "UPDATE alerts SET status = 'investigating' WHERE alert_key = %s",
            (ALERT_KEY,),
        )

    late_failure = _login_failure("late-failure", minutes_before_success=1)
    with connect(database_url) as conn:
        ingest_events(conn, [late_failure])
    with connect(database_url) as conn:
        summary = run_failed_login_detection(conn)

    with connect(database_url) as conn:
        alert = get_alert(conn, ALERT_KEY)
        evidence = _evidence(conn)

    assert summary.alerts_updated == 1
    assert alert.alert_key == ALERT_KEY
    assert alert.match_count == 6
    assert alert.status == "investigating"
    assert ("late-failure", "failed_login") in evidence
    assert len(evidence) == 7


def test_detection_runs_record_successful_runs(database_url: str) -> None:
    with connect(database_url) as conn:
        ingest_events(conn, list(_fixture_events()))
    with connect(database_url) as conn:
        first = run_failed_login_detection(conn)
    with connect(database_url) as conn:
        second = run_failed_login_detection(conn)

    with connect(database_url) as conn:
        runs = conn.execute(
            "SELECT * FROM detection_runs ORDER BY run_id"
        ).fetchall()

    assert [run["status"] for run in runs] == ["succeeded", "succeeded"]
    assert [run["alerts_created"] for run in runs] == [1, 0]
    assert [run["alerts_unchanged"] for run in runs] == [0, 1]
    assert runs[0]["events_scanned"] == EXPECTED["stored_events"]
    assert runs[0]["threshold"] == 5
    assert runs[0]["window_microseconds"] == 600_000_000
    assert runs[0]["first_event_at"] == datetime(
        2026, 9, 17, 12, 0, tzinfo=timezone.utc
    )
    assert runs[0]["finished_at"] >= runs[0]["started_at"]
    assert runs[0]["duration_ms"] == first.duration_ms
    assert runs[1]["duration_ms"] == second.duration_ms


def test_failed_run_is_recorded_without_partial_alert_writes(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def save_then_fail(conn, alert):
        save_alert(conn, alert)
        raise RuntimeError("simulated failure after writing an alert")

    monkeypatch.setattr(detection_runner, "save_alert", save_then_fail)
    with connect(database_url) as conn:
        ingest_events(conn, list(_fixture_events()))

    with pytest.raises(RuntimeError):
        with connect(database_url) as conn:
            run_failed_login_detection(conn)

    with connect(database_url) as conn:
        run = conn.execute("SELECT status, error FROM detection_runs").fetchone()
        assert _count(conn, "alerts") == 0
        assert _count(conn, "alert_events") == 0
    assert run["status"] == "failed"
    assert run["error"] == "detector_error"


def test_evidence_join_returns_raw_events_in_time_order(
    database_url: str,
) -> None:
    with connect(database_url) as conn:
        ingest_events(conn, list(_fixture_events()))
    with connect(database_url) as conn:
        run_failed_login_detection(conn)

    with connect(database_url) as conn:
        evidence = list_alert_evidence(conn, ALERT_KEY)

    assert [(item.event.event_id, item.evidence_role) for item in evidence] == [
        tuple(pair) for pair in EXPECTED["alert"]["evidence"]
    ]
    assert evidence[0].event.source_ip == "198.51.100.40"


def _fixture_events() -> tuple[SecurityEvent, ...]:
    return parse_jsonl(FIXTURES / "days_1_2.jsonl").events


def _login_failure(event_id: str, minutes_before_success: int) -> SecurityEvent:
    occurred_at = datetime(2026, 9, 17, 13, 0, tzinfo=timezone.utc) - timedelta(
        minutes=minutes_before_success
    )
    return parse_event(
        {
            "event_id": event_id,
            "occurred_at": occurred_at.isoformat(),
            "ingested_at": (occurred_at + timedelta(hours=2)).isoformat(),
            "source": "fixture",
            "event_type": "login_failed",
            "organization_id": "org-alpha",
            "attempted_account": "alice@example.test",
            "source_ip": "198.51.100.43",
            "outcome": "failure",
            "request_id": f"request-{event_id}",
            "schema_version": "1.0",
        }
    )


def _evidence(conn: psycopg.Connection) -> set[tuple[str, str]]:
    rows = conn.execute(
        "SELECT event_id, evidence_role FROM alert_events WHERE alert_key = %s",
        (ALERT_KEY,),
    ).fetchall()
    return {(row["event_id"], row["evidence_role"]) for row in rows}


def _expected_evidence() -> set[tuple[str, str]]:
    return {tuple(pair) for pair in EXPECTED["alert"]["evidence"]}


def _count(conn: psycopg.Connection, table: str) -> int:
    return conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
