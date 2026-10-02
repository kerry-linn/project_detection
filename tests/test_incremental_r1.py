from __future__ import annotations

import json
import os
import random
import subprocess
import sys
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone

import pytest

import backend.detection_runner as runner
import backend.r1_processing as processing
from backend.db import connect
from backend.r1_processing import R1ProcessingConfig
from backend.repositories.alerts import failed_login_alert_record, list_alerts
from backend.repositories.events import ingest_events, load_events
from detections.failed_login_success import FailedLoginSuccessConfig, detect_failed_logins_followed_by_success
from scripts.run_detection import main
from security_events import parse_event

START = datetime(2026, 1, 1, tzinfo=timezone.utc)
ONE_FAILURE = FailedLoginSuccessConfig(threshold=1)
INCREMENTAL = R1ProcessingConfig(mode="incremental", chunk_span=timedelta(minutes=10))


@pytest.fixture
def clock(monkeypatch):
    now = [START]
    original = processing.read_snapshot

    def read_snapshot(conn):
        _, snapshot = original(conn)
        return now[0], snapshot

    monkeypatch.setattr(processing, "read_snapshot", read_snapshot)
    return now


def login(event_id, minutes, *, success=False, account="user@example.test", organization="org"):
    at = START + timedelta(minutes=minutes)
    return parse_event({
        "event_id": event_id, "occurred_at": at.isoformat(), "ingested_at": at.isoformat(),
        "source": "fixture", "event_type": "login_succeeded" if success else "login_failed",
        "organization_id": organization, "attempted_account": account,
        "actor_id": "user" if success else None,
        "session_id": "session" if success else None,
        "outcome": "success" if success else "failure", "request_id": event_id,
        "schema_version": "1.0",
    })


def ingest(url, events):
    with connect(url) as conn:
        ingest_events(conn, events)


def run(url, *, mode="incremental", config=ONE_FAILURE, policy=None):
    with connect(url) as conn:
        return runner.run_failed_login_detection(
            conn, config, processing=policy or replace(INCREMENTAL, mode=mode)
        )


def checkpoint(url):
    with connect(url) as conn:
        return conn.execute("SELECT * FROM detection_checkpoints").fetchone()


def assert_full_parity(url, upper, config=ONE_FAILURE):
    with connect(url) as conn:
        eligible = [event for event in load_events(conn) if event.occurred_at <= upper]
        expected = {
            alert.alert_key: asdict(failed_login_alert_record(alert))
            for alert in detect_failed_logins_followed_by_success(eligible, config)
        }
        actual = {}
        for stored in list_alerts(conn):
            row = asdict(stored)
            for field in ("status", "detection_state", "needs_review", "created_at", "updated_at"):
                del row[field]
            links = conn.execute(
                "SELECT event_id, evidence_role FROM alert_events WHERE alert_key = %s",
                (stored.alert_key,),
            ).fetchall()
            row["evidence"] = frozenset((link["event_id"], link["evidence_role"]) for link in links)
            actual[stored.alert_key] = row
    assert actual == expected


def test_missing_checkpoint_requires_full_baseline(database_url, clock):
    ingest(database_url, [login("old-failure", -61), login("old-success", -60, success=True)])
    with pytest.raises(runner.DetectionRunError, match="checkpoint_required"):
        run(database_url)
    assert checkpoint(database_url) is None
    assert run(database_url, mode="full").alerts_created == 1
    assert run(database_url).events_scanned == 0
    assert_full_parity(database_url, clock[0])


@pytest.mark.parametrize("change", ["threshold", "window", "version", "lateness"])
def test_changed_configuration_requires_explicit_baseline(database_url, clock, monkeypatch, change):
    run(database_url, mode="full")
    config = ONE_FAILURE
    policy = INCREMENTAL
    if change == "threshold":
        config = replace(config, threshold=2)
    elif change == "window":
        config = replace(config, window=timedelta(minutes=11))
    elif change == "version":
        monkeypatch.setattr(runner.failed_login_success, "RULE_VERSION", "test-version")
    else:
        policy = replace(policy, allowed_lateness=timedelta(minutes=20))
    with pytest.raises(runner.DetectionRunError, match="checkpoint_required"):
        run(database_url, config=config, policy=policy)
    run(database_url, config=config, policy=replace(policy, mode="full"))
    assert run(database_url, config=config, policy=policy).backfill_required is False


def test_downtime_chunks_keep_context_and_do_not_repeat_boundary_successes(database_url, clock):
    run(database_url, mode="full")
    events = [login("failure", -16), login("at-overlap", -15, success=True)]
    for minute in (5, 15, 25, 65, 125):
        events.extend([
            login(f"failure-{minute}", minute - 10),
            login(f"success-{minute}", minute, success=True),
            login(f"success-tie-{minute}", minute, success=True),
        ])
    ingest(database_url, events)
    clock[0] += timedelta(minutes=130)
    summary = run(database_url)
    assert summary.chunks_processed == 15
    assert summary.alerts_detected == 11
    assert summary.checkpoint_at == clock[0]
    assert_full_parity(database_url, clock[0])


@pytest.mark.parametrize("offset_us,late", [(0, False), (-1, True), (1, False)])
def test_lateness_boundary_is_reported_and_full_backfill_clears_flag(database_url, clock, offset_us, late):
    ingest(database_url, [login("failure", -16)])
    run(database_url, mode="full")
    event = login("boundary-success", -15, success=True)
    event = replace(event, occurred_at=event.occurred_at + timedelta(microseconds=offset_us))
    ingest(database_url, [event])
    summary = run(database_url)
    assert summary.late_events_detected == int(late)
    assert summary.backfill_required == late
    assert summary.alerts_created == int(not late)
    rerun = run(database_url)
    assert rerun.late_events_detected == 0
    assert rerun.backfill_required == late
    assert run(database_url, mode="full").backfill_required is False
    assert_full_parity(database_url, clock[0])


def test_late_failure_updates_existing_alert_and_preserves_analyst_status(database_url, clock):
    ingest(database_url, [login("failure", -2), login("success", -1, success=True)])
    run(database_url, mode="full")
    with connect(database_url) as conn:
        conn.execute("UPDATE alerts SET status = 'closed'")
    ingest(database_url, [login("late-failure", -3)])
    assert run(database_url).alerts_updated == 1
    with connect(database_url) as conn:
        assert list_alerts(conn)[0].status == "closed"
    assert_full_parity(database_url, clock[0])


def test_commit_after_snapshot_is_seen_next_run_even_with_old_ingestion_time(database_url, clock, monkeypatch):
    ingest(database_url, [login("failure", -21)])
    run(database_url, mode="full")
    original = processing.read_snapshot
    with connect(database_url) as writer:
        # A savepoint still receives the top-level transaction identity.
        writer.execute("SELECT 1")
        with writer.transaction():
            ingest_events(writer, [
                login("delayed-old", -20, success=True),
                login("delayed-failure", -2),
                login("delayed-success", -1, success=True),
            ])

        def snapshot_then_commit(conn):
            snapshot = original(conn)
            writer.commit()
            return snapshot

        monkeypatch.setattr(processing, "read_snapshot", snapshot_then_commit)
        first = run(database_url)
    assert first.late_events_detected == 0
    assert first.events_scanned == 1  # Only the original failure context is visible.
    monkeypatch.setattr(processing, "read_snapshot", original)
    next_run = run(database_url)
    assert next_run.late_events_detected == 1
    assert next_run.alerts_created == 1
    assert next_run.backfill_required
    assert run(database_url).late_events_detected == 0
    run(database_url, mode="full")
    assert_full_parity(database_url, clock[0])


def test_future_events_are_deferred_without_advancing_checkpoint(database_url, clock):
    ingest(database_url, [login("future-failure", 1), login("future-success", 2, success=True)])
    first = run(database_url, mode="full")
    assert first.future_events_deferred == 2
    assert first.events_scanned == 0
    assert first.checkpoint_at == START
    clock[0] += timedelta(minutes=2)
    second = run(database_url)
    assert second.future_events_deferred == 0
    assert second.alerts_created == 1
    assert_full_parity(database_url, clock[0])


def test_clock_regression_does_not_move_checkpoint_backwards(database_url, clock):
    run(database_url, mode="full")
    before = checkpoint(database_url)
    clock[0] -= timedelta(seconds=1)
    with pytest.raises(runner.DetectionRunError, match="checkpoint_clock_regression"):
        run(database_url)
    assert checkpoint(database_url) == before


@pytest.mark.parametrize("failure_point", ["save_alert", "save_checkpoint", "finish_run"])
def test_failure_rolls_back_alert_evidence_and_checkpoint_then_restart_recovers(
    database_url, clock, monkeypatch, failure_point
):
    run(database_url, mode="full")
    before = checkpoint(database_url)
    ingest(database_url, [login("failure", 1), login("success", 2, success=True)])
    clock[0] += timedelta(hours=2)
    original = getattr(runner, failure_point)

    def write_then_fail(*args):
        original(*args)
        raise RuntimeError("injected failure")

    with monkeypatch.context() as patch:
        patch.setattr(runner, failure_point, write_then_fail)
        with pytest.raises(runner.DetectionRunError):
            run(database_url)
    assert checkpoint(database_url) == before
    with connect(database_url) as conn:
        assert list_alerts(conn) == []
        assert conn.execute("SELECT COUNT(*) AS n FROM alert_events").fetchone()["n"] == 0
    assert run(database_url).alerts_created == 1
    assert_full_parity(database_url, clock[0])


def test_kill_after_checkpoint_write_rolls_back_and_restart_recovers(database_url):
    run(database_url, mode="full")
    before = checkpoint(database_url)
    now = datetime.now(timezone.utc)
    failure = replace(login("failure", 0), occurred_at=now - timedelta(seconds=2))
    success = replace(login("success", 0, success=True), occurred_at=now - timedelta(seconds=1))
    ingest(database_url, [failure, success])
    code = """
import os
import backend.detection_runner as runner
from backend.db import connect
from backend.r1_processing import R1ProcessingConfig
from detections.failed_login_success import FailedLoginSuccessConfig
runner.finish_run = lambda *args: os._exit(17)
with connect(os.environ['TEST_DATABASE_URL']) as conn:
    runner.run_failed_login_detection(conn, FailedLoginSuccessConfig(threshold=1),
        processing=R1ProcessingConfig(mode='incremental'))
"""
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, timeout=15,
        env={**os.environ, "TEST_DATABASE_URL": database_url},
    )
    assert result.returncode == 17, result.stderr
    assert checkpoint(database_url) == before
    with connect(database_url) as conn:
        assert list_alerts(conn) == []
    assert run(database_url).alerts_created == 1
    with connect(database_url) as conn:
        statuses = [row["status"] for row in conn.execute("SELECT status FROM detection_runs ORDER BY run_id")]
    assert statuses == ["succeeded", "abandoned", "succeeded"]


def test_seeded_out_of_order_arrivals_match_full_history_each_run(database_url, clock):
    randomizer = random.Random(3101)
    pending = []
    for index in range(400):
        minute = randomizer.randrange(-20, 100)
        event = login(
            f"event-{index}", minute, success=randomizer.randrange(4) == 0,
            account=f"user-{index % 3}@example.test",
            organization=None if index % 2 else "org",
        )
        pending.append((minute + randomizer.randrange(0, 15), event))
    config = FailedLoginSuccessConfig(threshold=2)
    for minute in range(0, 116, 5):
        arrived = [event for visible_at, event in pending if visible_at <= minute]
        pending = [(visible_at, event) for visible_at, event in pending if visible_at > minute]
        ingest(database_url, arrived + arrived[:2])
        clock[0] = START + timedelta(minutes=minute)
        summary = run(database_url, mode="full" if minute == 0 else "incremental", config=config)
        assert not summary.backfill_required
        assert_full_parity(database_url, clock[0], config)
    assert pending == []


def test_cli_explains_missing_baseline_and_serializes_checkpoint(database_url, clock, monkeypatch, capsys):
    monkeypatch.setenv("DATABASE_URL", database_url)
    assert main(["--rule", "r1", "--r1-mode", "incremental"]) == 1
    assert json.loads(capsys.readouterr().out)[0]["category"] == "checkpoint_required"
    assert main(["--rule", "r1", "--r1-mode", "full"]) == 0
    report = json.loads(capsys.readouterr().out)[0]
    assert report["checkpoint_at"] == "2026-01-01T00:00:00Z"
    assert main(["--rule", "r1", "--r1-mode", "incremental"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["processing_mode"] == "incremental"
