from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest
from fastapi.testclient import TestClient

from backend.config import Settings
from backend.db import connect
from backend.detection_runner import DetectionRunError, run_denied_document_detection
from backend.repositories.alerts import get_alert, list_alerts
from backend.repositories.events import ingest_events, load_events
from detections.denied_document_access import (
    RULE_ID,
    DeniedDocumentAccessConfig,
    detect_repeated_denied_document_access,
)
from security_events import SecurityEvent, parse_event, parse_jsonl

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


def test_filtered_runner_preserves_an_episode_extending_for_hours(database_url: str) -> None:
    initial = _distinct_denials(5)
    _ingest(database_url, initial)
    _run(database_url)
    continuation = [
        _denial(f"long-{index}", initial[-1].occurred_at + timedelta(minutes=10 * index), "doc-9")
        for index in range(1, 25)
    ]
    _ingest(database_url, continuation)
    summary = _run(database_url)
    assert summary.events_scanned == 29
    assert (summary.alerts_created, summary.alerts_updated) == (0, 1)
    with connect(database_url) as conn:
        assert len(_evidence(conn, FIRST_KEY)) == 29
        _assert_active_matches_full_history(conn)


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


def test_late_denial_replaces_crossing_and_preserves_history(database_url: str) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "fixtures"
    fixture = fixtures / "r2_late_arrival.jsonl"
    expected = json.loads((fixtures / "expected" / "r2_late_arrival.json").read_text())
    expected_before = expected["before"]
    expected_after = expected["after"]
    events = list(parse_jsonl(fixture).events)
    initial = [event for event in events if event.event_id in expected["initial_event_ids"]]
    late = [event for event in events if event.event_id == expected["late_event_id"]]
    _ingest(database_url, initial)
    assert _run(database_url).alerts_created == 1
    old_key = FIRST_KEY
    with connect(database_url) as conn:
        initial_alerts = list_alerts(conn)
        trigger_ids = [alert.alert_key.rsplit(":", 1)[-1] for alert in initial_alerts]
        assert trigger_ids == expected_before["active_trigger_event_ids"]
        assert {event_id for event_id, _ in _evidence(conn, old_key)} == set(
            expected_before["denial-4_evidence"]
        )
        conn.execute("UPDATE alerts SET status = 'closed' WHERE alert_key = %s", (old_key,))

    _ingest(database_url, late)
    assert _run(database_url).alerts_created == 1
    with connect(database_url) as conn:
        current = list_alerts(conn)
        history = list_alerts(conn, include_superseded=True)
        links = conn.execute("SELECT * FROM alert_replacements").fetchall()
        old_evidence = _evidence(conn, old_key)

    trigger_ids = [alert.alert_key.rsplit(":", 1)[-1] for alert in current]
    assert trigger_ids == expected_after["active_trigger_event_ids"]
    assert len(history) == 2
    new_key = current[0].alert_key
    assert current[0].needs_review
    old_alert = next(alert for alert in history if alert.alert_key == old_key)
    assert old_alert.status == "closed"
    assert old_alert.detection_state == "superseded"
    assert [(link["old_alert_key"], link["new_alert_key"]) for link in links] == [
        (old_key, new_key)
    ]
    assert {event_id for event_id, _ in old_evidence} == set(
        expected_after["denial-4_evidence_retained"]
    )
    with connect(database_url) as conn:
        new_evidence = _evidence(conn, new_key)
    assert {event_id for event_id, _ in new_evidence} == set(
        expected_after["denial-3_evidence"]
    )
    assert _run(database_url).alerts_unchanged == 1
    with connect(database_url) as conn:
        assert conn.execute("SELECT count(*) AS n FROM alert_replacements").fetchone()["n"] == 1
        _assert_active_matches_full_history(conn)


def test_late_evidence_extends_same_episode(database_url: str) -> None:
    denials = _distinct_denials(5)
    _ingest(database_url, denials)
    _run(database_url)
    _ingest(database_url, [_denial("late", START + timedelta(seconds=105), "doc-2")])

    assert _run(database_url).alerts_updated == 1
    with connect(database_url) as conn:
        assert [alert.alert_key for alert in list_alerts(conn)] == [FIRST_KEY]
        assert len(_evidence(conn, FIRST_KEY)) == 6
        assert conn.execute("SELECT count(*) AS n FROM alert_replacements").fetchone()["n"] == 0


def test_late_denial_merges_two_episodes(database_url: str) -> None:
    first = _distinct_denials(5)
    second = _distinct_denials(5, start=START + timedelta(minutes=18), prefix="second")
    _ingest(database_url, [*first, *second])
    assert _run(database_url).alerts_created == 2
    second_key = FIRST_KEY.replace("denial-4", "second-4")
    bridge = _denial("bridge", START + timedelta(minutes=10), "doc-bridge")
    _ingest(database_url, [bridge])

    _run(database_url)
    with connect(database_url) as conn:
        current = list_alerts(conn)
        history = list_alerts(conn, include_superseded=True)
        links = conn.execute(
            "SELECT old_alert_key, new_alert_key FROM alert_replacements"
        ).fetchall()

    assert [alert.alert_key for alert in current] == [FIRST_KEY]
    assert current[0].match_count == 6
    with connect(database_url) as conn:
        assert len(_evidence(conn, FIRST_KEY)) == 11
    assert len(history) == 2
    assert [(row["old_alert_key"], row["new_alert_key"]) for row in links] == [
        (second_key, FIRST_KEY)
    ]


def test_multiple_superseded_episodes_link_to_one_result(database_url: str) -> None:
    events = []
    for index in range(3):
        episode_start = START + timedelta(minutes=18 * index)
        events.extend(_distinct_denials(5, start=episode_start, prefix=f"part-{index}"))
    _ingest(database_url, events)
    assert _run(database_url).alerts_created == 3
    bridges = [
        _denial(
            f"bridge-{index}",
            START + timedelta(minutes=10 + 18 * index),
            f"bridge-doc-{index}",
        )
        for index in range(2)
    ]
    _ingest(database_url, bridges)
    _run(database_url)

    first_key = FIRST_KEY.replace("denial-4", "part-0-4")
    with connect(database_url) as conn:
        assert [alert.alert_key for alert in list_alerts(conn)] == [first_key]
        assert len(list_alerts(conn, include_superseded=True)) == 3
        rows = conn.execute(
            "SELECT old_alert_key, new_alert_key FROM alert_replacements"
        ).fetchall()
        _assert_active_matches_full_history(conn)
    assert {(row["old_alert_key"], row["new_alert_key"]) for row in rows} == {
        (FIRST_KEY.replace("denial-4", f"part-{index}-4"), first_key)
        for index in (1, 2)
    }


def test_duplicate_replay_keeps_reconciliation_stable(database_url: str) -> None:
    denials = _distinct_denials(5)
    _ingest(database_url, denials)
    _run(database_url)
    _ingest(database_url, denials)

    assert _run(database_url).alerts_unchanged == 1
    with connect(database_url) as conn:
        assert [alert.alert_key for alert in list_alerts(conn)] == [FIRST_KEY]
        assert conn.execute("SELECT count(*) AS n FROM alert_replacements").fetchone()["n"] == 0


def test_historical_alerts_and_replacement_links_are_inspectable(
    client: TestClient, login_as, settings: Settings,
) -> None:
    def payload(event: SecurityEvent) -> dict:
        data = event.to_dict()
        del data["ingested_at"]
        data["source"] = "fixture"
        return data

    events = _distinct_denials(5)
    collector_headers = {"Authorization": f"Bearer {settings.collector_token}"}
    assert client.post(
        "/internal/events/batch",
        headers=collector_headers,
        json={"events": [payload(event) for event in events]},
    ).status_code == 200
    with connect(settings.database_url) as conn:
        run_denied_document_detection(conn)
    late = _denial("late", START - timedelta(seconds=15), "doc-late")
    assert client.post(
        "/internal/events/batch",
        headers=collector_headers,
        json={"events": [payload(late)]},
    ).status_code == 200
    with connect(settings.database_url) as conn:
        run_denied_document_detection(conn)

    analyst = login_as("analyst@lab.example.test")
    active = client.get("/security/alerts", headers=analyst).json()
    history = client.get("/security/alerts?include_superseded=true", headers=analyst).json()
    assert len(active) == 1
    assert len(history) == 2
    old = client.get(f"/security/alerts/{FIRST_KEY}", headers=analyst).json()
    new = client.get(f"/security/alerts/{active[0]['alert_key']}", headers=analyst).json()
    assert old["detection_state"] == "superseded"
    assert old["replaced_by"] == [new["alert_key"]]
    assert new["replaces"] == [FIRST_KEY]
    assert len(old["evidence"]) == 5
    assert len(new["evidence"]) == 6
    assert client.get("/security/alerts?include_superseded=true").status_code == 401
    assert client.get(
        "/security/alerts?include_superseded=true",
        headers=login_as("bob@alpha.example.test"),
    ).status_code == 403
    assert client.get(
        "/security/alerts?include_superseded=true",
        headers=collector_headers,
    ).status_code == 401


def test_reconciliation_does_not_touch_other_configuration(database_url: str) -> None:
    _ingest(database_url, _distinct_denials(5))
    _run(database_url)
    with connect(database_url) as conn:
        run_denied_document_detection(conn, DeniedDocumentAccessConfig(threshold=4))
    _ingest(database_url, [_denial("late", START - timedelta(seconds=15), "doc-late")])
    _run(database_url)

    with connect(database_url) as conn:
        current = list_alerts(conn)
    assert len(current) == 2
    assert {alert.threshold for alert in current} == {4, 5}


def test_late_event_does_not_supersede_another_actor(database_url: str) -> None:
    bob = _distinct_denials(5)
    alice = [
        replace(
            event,
            event_id=f"alice-{index}",
            actor_id="user-alice",
            request_id=f"request-alice-{index}",
        )
        for index, event in enumerate(bob)
    ]
    _ingest(database_url, [*bob, *alice])
    assert _run(database_url).alerts_created == 2
    _ingest(database_url, [_denial("late", START - timedelta(seconds=15), "doc-late")])
    _run(database_url)

    with connect(database_url) as conn:
        current = list_alerts(conn)
    assert len(current) == 2
    alice_alert = next(alert for alert in current if alert.actor_id == "user-alice")
    assert alice_alert.alert_key.endswith("alice-4")


def test_reconciliation_rollback_preserves_old_result(database_url: str) -> None:
    _ingest(database_url, _distinct_denials(5))
    _run(database_url)
    _ingest(database_url, [_denial("late", START - timedelta(seconds=15), "doc-late")])
    with connect(database_url) as conn:
        conn.execute("""
            CREATE OR REPLACE FUNCTION fail_replacement() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN RAISE EXCEPTION 'injected failure'; END $$
        """)
        conn.execute("""
            CREATE TRIGGER fail_replacement BEFORE INSERT ON alert_replacements
            FOR EACH ROW EXECUTE FUNCTION fail_replacement()
        """)
    try:
        with connect(database_url) as conn:
            with pytest.raises(DetectionRunError):
                run_denied_document_detection(conn)
    finally:
        with connect(database_url) as conn:
            conn.execute("DROP TRIGGER fail_replacement ON alert_replacements")
            conn.execute("DROP FUNCTION fail_replacement()")

    with connect(database_url) as conn:
        assert [alert.alert_key for alert in list_alerts(conn)] == [FIRST_KEY]
        assert len(list_alerts(conn, include_superseded=True)) == 1
        assert len(_evidence(conn, FIRST_KEY)) == 5
        assert conn.execute("SELECT count(*) AS n FROM alert_replacements").fetchone()["n"] == 0
    assert _run(database_url).alerts_created == 1


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


def _assert_active_matches_full_history(conn: psycopg.Connection) -> None:
    events = load_events(conn)
    expected = {
        alert.alert_key: set(alert.evidence_event_ids)
        for alert in detect_repeated_denied_document_access(events)
    }
    actual = {}
    for alert in list_alerts(conn):
        if alert.rule_id != RULE_ID or alert.threshold != 5:
            continue
        evidence_links = _evidence(conn, alert.alert_key)
        actual[alert.alert_key] = {event_id for event_id, _ in evidence_links}
    assert actual == expected


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
