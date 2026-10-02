from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import psycopg
import pytest

import backend.detection_runner as runner
import backend.repositories.alerts as alert_repository
import scripts.run_detection as detection_cli
from backend.db import connect
from backend.repositories.events import ingest_events
from security_events import parse_jsonl

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "days_1_2.jsonl"


def _ingest(database_url: str) -> None:
    with connect(database_url) as conn:
        ingest_events(conn, list(parse_jsonl(FIXTURE).events))


def _state(database_url: str) -> tuple[list[dict], list[dict]]:
    with connect(database_url) as conn:
        alerts = conn.execute("SELECT * FROM alerts ORDER BY alert_key").fetchall()
        evidence = conn.execute(
            "SELECT * FROM alert_events ORDER BY alert_key, event_id"
        ).fetchall()
    return alerts, evidence


def test_failure_during_evidence_replacement_restores_alert_and_analyst_state(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ingest(database_url)
    with connect(database_url) as conn:
        runner.run_failed_login_detection(conn)
        conn.execute("UPDATE alerts SET status = 'investigating'")

    with connect(database_url) as conn:
        conn.execute("UPDATE alerts SET reason = 'previous analyst context'")
    before = _state(database_url)
    original = alert_repository._insert_evidence

    def fail_after_replacement(conn, alert_key, links):
        original(conn, alert_key, links)
        raise RuntimeError("sensitive failure detail")

    monkeypatch.setattr(alert_repository, "_insert_evidence", fail_after_replacement)
    with pytest.raises(runner.DetectionRunError):
        with connect(database_url) as conn:
            runner.run_failed_login_detection(conn)

    assert _state(database_url) == before
    with connect(database_url) as conn:
        run = conn.execute(
            "SELECT status, error FROM detection_runs ORDER BY run_id DESC LIMIT 1"
        ).fetchone()
    assert run == {"status": "failed", "error": "detector_error"}


def test_failure_immediately_before_commit_rolls_back_all_results(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ingest(database_url)
    original = runner.finish_run

    def fail_after_finish(conn, summary):
        original(conn, summary)
        raise RuntimeError("commit boundary failure")

    monkeypatch.setattr(runner, "finish_run", fail_after_finish)
    with pytest.raises(runner.DetectionRunError):
        with connect(database_url) as conn:
            runner.run_failed_login_detection(conn)

    assert _state(database_url) == ([], [])
    with connect(database_url) as conn:
        run = conn.execute(
            "SELECT status, events_scanned, first_event_at, last_event_at, "
            "alerts_detected, alerts_created, "
            "alerts_updated, alerts_unchanged, duration_ms FROM detection_runs"
        ).fetchone()
    assert run["status"] == "failed"
    assert (run["events_scanned"], run["alerts_detected"]) == (13, 1)
    assert run["first_event_at"] <= run["last_event_at"]
    assert (run["alerts_created"], run["alerts_updated"], run["alerts_unchanged"]) == (0, 0, 0)
    assert run["duration_ms"] >= 0


def test_killed_worker_is_abandoned_only_after_restart_takes_lock(
    database_url: str,
) -> None:
    _ingest(database_url)
    code = """
import os
import backend.detection_runner as runner
from backend.db import connect
runner._detect_and_save = lambda *args: os._exit(17)
with connect(os.environ['TEST_DATABASE_URL']) as conn:
    runner.run_failed_login_detection(conn)
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        env={**os.environ, "TEST_DATABASE_URL": database_url},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 17
    with connect(database_url) as conn:
        assert conn.execute("SELECT status FROM detection_runs").fetchone()["status"] == "running"

    with connect(database_url) as conn:
        first = runner.run_failed_login_detection(conn)
    with connect(database_url) as conn:
        second = runner.run_failed_login_detection(conn)
        runs = conn.execute(
            "SELECT status, error FROM detection_runs ORDER BY run_id"
        ).fetchall()
    assert [run["status"] for run in runs] == ["abandoned", "succeeded", "succeeded"]
    assert runs[0]["error"] == "worker_exited_before_completion"
    assert (first.alerts_created, second.alerts_unchanged) == (1, 1)
    assert len(_state(database_url)[0]) == 1


def test_concurrent_runner_exits_busy_without_mislabeling_active_run(
    database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _ingest(database_url)
    entered = Event()
    release = Event()
    original = runner._detect_and_save

    def wait_before_detection(*args):
        entered.set()
        assert release.wait(10)
        return original(*args)

    monkeypatch.setattr(runner, "_detect_and_save", wait_before_detection)

    def run():
        with connect(database_url) as conn:
            return runner.run_failed_login_detection(conn)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run)
        assert entered.wait(10)
        with pytest.raises(runner.RunnerBusy):
            with connect(database_url) as conn:
                runner.run_denied_document_detection(conn)
        with connect(database_url) as conn:
            statuses = [row["status"] for row in conn.execute("SELECT status FROM detection_runs")]
        assert statuses == ["running"]
        release.set()
        assert first.result(timeout=10).alerts_created == 1

    with connect(database_url) as conn:
        rows = conn.execute("SELECT status, alerts_created FROM detection_runs").fetchall()
    assert rows == [{"status": "succeeded", "alerts_created": 1}]
    assert len(_state(database_url)[1]) == 6

    with connect(database_url) as conn:
        r2 = runner.run_denied_document_detection(conn)
    assert r2.alerts_detected == 0


def test_failure_record_database_outage_logs_safe_category_and_recovers(
    database_url: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _ingest(database_url)

    def fail_save(*args):
        raise RuntimeError("password=must-never-be-logged")

    def fail_record(*args):
        raise psycopg.OperationalError("token=must-never-be-logged")

    monkeypatch.setattr(runner, "save_alert", fail_save)
    monkeypatch.setattr(runner, "fail_run", fail_record)
    with pytest.raises(runner.DetectionRunError) as error:
        with connect(database_url) as conn:
            runner.run_failed_login_detection(conn)
    assert error.value.category == "detector_error"
    assert "detection_failure_record_unavailable" in caplog.text
    assert "must-never-be-logged" not in caplog.text
    assert _state(database_url) == ([], [])
    with connect(database_url) as conn:
        assert conn.execute("SELECT status FROM detection_runs").fetchone()["status"] == "running"

    monkeypatch.undo()
    with connect(database_url) as conn:
        runner.run_failed_login_detection(conn)
        rows = conn.execute("SELECT status FROM detection_runs ORDER BY run_id").fetchall()
    assert [row["status"] for row in rows] == ["abandoned", "succeeded"]


def test_lost_database_connection_leaves_recoverable_run(
    database_url: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _ingest(database_url)

    def drop_connection(conn, alert):
        conn.execute("SELECT pg_terminate_backend(pg_backend_pid())")

    monkeypatch.setattr(runner, "save_alert", drop_connection)
    with pytest.raises(runner.DetectionRunError) as error:
        with connect(database_url) as conn:
            runner.run_failed_login_detection(conn)
    assert error.value.category == "database_unavailable"
    assert "detection_failure_record_unavailable" in caplog.text
    assert _state(database_url) == ([], [])

    monkeypatch.undo()
    with connect(database_url) as conn:
        runner.run_failed_login_detection(conn)
        runs = conn.execute("SELECT status FROM detection_runs ORDER BY run_id").fetchall()
    assert [run["status"] for run in runs] == ["abandoned", "succeeded"]


def test_cli_reports_partial_pipeline_success(
    database_url: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_r2(*args):
        raise RuntimeError("password=must-never-be-reported")

    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(runner, "detect_repeated_denied_document_access", fail_r2)
    assert detection_cli.main([]) == 1

    output = capsys.readouterr()
    reports = json.loads(output.out)
    assert [report["status"] for report in reports] == ["succeeded", "failed"]
    assert reports[1]["category"] == "detector_error"
    assert "must-never-be-reported" not in output.out + output.err
    with connect(database_url) as conn:
        runs = conn.execute("SELECT status FROM detection_runs ORDER BY run_id").fetchall()
    assert [run["status"] for run in runs] == ["succeeded", "failed"]


def test_cli_exits_nonzero_when_failure_record_cannot_reach_postgres(
    database_url: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    _ingest(database_url)

    def drop_connection(conn, alert):
        conn.execute("SELECT pg_terminate_backend(pg_backend_pid())")

    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setattr(runner, "save_alert", drop_connection)
    assert detection_cli.main(["--rule", "r1"]) == 1

    reports = json.loads(capsys.readouterr().out)
    assert len(reports) == 1
    assert reports[0]["status"] == "failed"
    assert reports[0]["category"] == "database_unavailable"
    assert "detection_failure_record_unavailable" in caplog.text
    with connect(database_url) as conn:
        assert conn.execute("SELECT status FROM detection_runs").fetchone()["status"] == "running"
