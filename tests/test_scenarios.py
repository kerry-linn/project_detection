from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import scripts.generate_scenarios as generate_scenarios
from backend.db import connect
from backend.detection_runner import (
    run_denied_document_detection,
    run_failed_login_detection,
)
from conftest import TEST_PASSWORD
from scripts import reset_telemetry

API_URL = "http://lab.test"


@pytest.fixture
def through_app(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def send(method, url, token, body):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        response = client.request(
            method, url.removeprefix(API_URL), headers=headers, json=body
        )
        return response.status_code, response.text

    monkeypatch.setattr(generate_scenarios, "send", send)
    monkeypatch.setenv("SEED_USER_PASSWORD", TEST_PASSWORD)


def test_suspicious_scenario_produces_one_r1_and_one_r2(
    through_app: None, database_url: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert generate_scenarios.main(["suspicious", "--api-url", API_URL]) == 0
    output = capsys.readouterr().out

    first = _run_rules(database_url)
    rerun = _run_rules(database_url)

    assert [(r.alerts_created, r.alerts_unchanged) for r in first] == [(1, 0), (1, 0)]
    assert [(r.alerts_created, r.alerts_unchanged) for r in rerun] == [(0, 1), (0, 1)]
    assert TEST_PASSWORD not in output
    assert "access_token" not in output


def test_benign_scenario_produces_no_alerts(
    through_app: None, database_url: str
) -> None:
    assert generate_scenarios.main(["benign", "--api-url", API_URL]) == 0

    assert [r.alerts_detected for r in _run_rules(database_url)] == [0, 0]
    assert _count(database_url, "security_events") == 11


def test_scenario_stops_at_the_first_unexpected_status(
    through_app: None,
    database_url: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("SEED_USER_PASSWORD", "not-the-seeded-password")

    assert generate_scenarios.main(["suspicious", "--api-url", API_URL]) == 1
    output = capsys.readouterr().out
    assert "returned 401, expected 200" in output
    assert "not-the-seeded-password" not in output
    assert _count(database_url, "security_events") == 1


def test_reset_requires_confirmation_and_keeps_seeded_state(
    through_app: None, database_url: str
) -> None:
    generate_scenarios.main(["suspicious", "--api-url", API_URL])
    _run_rules(database_url)
    args = ["--database-url-env", "TEST_DATABASE_URL"]

    assert reset_telemetry.main(args) == 2
    assert _count(database_url, "alerts") == 2

    assert reset_telemetry.main([*args, "--yes"]) == 0
    for table in reset_telemetry.TELEMETRY_TABLES:
        assert _count(database_url, table) == 0
    assert _count(database_url, "organizations") == 2
    assert _count(database_url, "users") == 6
    assert _count(database_url, "documents") == 9


def _run_rules(database_url: str):
    with connect(database_url) as conn:
        r1 = run_failed_login_detection(conn)
    with connect(database_url) as conn:
        r2 = run_denied_document_detection(conn)
    return [r1, r2]


def _count(database_url: str, table: str) -> int:
    with connect(database_url) as conn:
        return conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
