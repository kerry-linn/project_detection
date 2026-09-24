from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.api import create_app
from backend.config import ConfigurationError, Settings
from backend.db import connect
from backend.detection_runner import run_failed_login_detection
from scripts.replay_events import read_records

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
EXPECTED = json.loads((FIXTURES / "expected" / "days_5_6.json").read_text())
ALERT_KEY = EXPECTED["alert"]["alert_key"]

COLLECTOR_TOKEN = "collector-token-for-tests"
ANALYST_TOKEN = "analyst-token-for-tests"
COLLECTOR = {"Authorization": f"Bearer {COLLECTOR_TOKEN}"}
ANALYST = {"Authorization": f"Bearer {ANALYST_TOKEN}"}
UNKNOWN = {"Authorization": "Bearer not-a-configured-token"}

VALID_EVENT = {
    "event_id": "api-event-1",
    "occurred_at": "2026-09-17T12:30:00Z",
    "source": "fixture",
    "event_type": "login_failed",
    "organization_id": "org-alpha",
    "attempted_account": "Jordan@Example.test",
    "source_ip": "192.0.2.50",
    "outcome": "failure",
    "request_id": "request-api-1",
    "schema_version": "1.0",
}


@pytest.fixture
def client(database_url: str) -> TestClient:
    settings = Settings(
        database_url=database_url,
        collector_token=COLLECTOR_TOKEN,
        analyst_token=ANALYST_TOKEN,
    )
    return TestClient(create_app(settings))


@pytest.mark.parametrize(
    ("headers", "expected_status"),
    [({}, 401), (UNKNOWN, 401), (ANALYST, 403)],
)
def test_ingestion_requires_the_collector_credential(
    client: TestClient, headers: dict[str, str], expected_status: int
) -> None:
    response = client.post(
        "/internal/events/batch", json={"events": [VALID_EVENT]}, headers=headers
    )

    assert response.status_code == expected_status
    assert _stored_event_count(client) == 0


def test_authentication_is_checked_before_body_validation(
    client: TestClient,
) -> None:
    response = client.post("/internal/events/batch", json={"events": []})

    assert response.status_code == 401


@pytest.mark.parametrize(
    "path",
    ["/security/events", "/security/alerts", f"/security/alerts/{ALERT_KEY}"],
)
@pytest.mark.parametrize(
    ("headers", "expected_status"),
    [({}, 401), (UNKNOWN, 401), (COLLECTOR, 403)],
)
def test_security_reads_require_the_analyst_credential(
    client: TestClient, path: str, headers: dict[str, str], expected_status: int
) -> None:
    response = client.get(path, headers=headers)

    assert response.status_code == expected_status


def test_ingest_detect_and_follow_alert_to_raw_evidence(
    client: TestClient, database_url: str
) -> None:
    records, skipped = read_records(FIXTURES / "days_1_2.jsonl")

    first = client.post(
        "/internal/events/batch", json={"events": records}, headers=COLLECTOR
    )
    second = client.post(
        "/internal/events/batch", json={"events": records}, headers=COLLECTOR
    )
    for _ in range(2):
        with connect(database_url) as conn:
            run_failed_login_detection(conn)

    alerts = client.get("/security/alerts", headers=ANALYST).json()
    detail = client.get(f"/security/alerts/{ALERT_KEY}", headers=ANALYST).json()

    expected_first = EXPECTED["first_replay"]
    assert skipped == expected_first["skipped_lines"]
    assert first.status_code == 200
    assert first.json() == {
        "received": expected_first["received"],
        "inserted": expected_first["inserted"],
        "replayed": expected_first["replayed"],
    }
    assert second.json() == EXPECTED["second_replay"]

    expected_alert = EXPECTED["alert"]
    assert [alert["alert_key"] for alert in alerts] == [ALERT_KEY]
    assert detail["status"] == "new"
    assert detail["organization_id"] == expected_alert["organization_id"]
    assert detail["attempted_account"] == expected_alert["attempted_account"]
    assert detail["window_start"] == expected_alert["window_start"]
    assert detail["window_end"] == expected_alert["window_end"]
    assert detail["failure_count"] == expected_alert["failure_count"]
    assert detail["source_ips"] == expected_alert["source_ips"]
    assert [
        [item["event_id"], item["evidence_role"]] for item in detail["evidence"]
    ] == expected_alert["evidence"]


def test_server_assigns_collection_time(client: TestClient) -> None:
    before = datetime.now(timezone.utc)
    client.post("/internal/events/batch", json={"events": [VALID_EVENT]}, headers=COLLECTOR)
    after = datetime.now(timezone.utc)

    event = client.get("/security/events", headers=ANALYST).json()[0]
    ingested_at = datetime.fromisoformat(event["ingested_at"].replace("Z", "+00:00"))

    assert before <= ingested_at <= after
    assert event["attempted_account"] == "jordan@example.test"


@pytest.mark.parametrize(
    "change",
    [
        {"ingested_at": "2020-01-01T00:00:00Z"},
        {"source": "application"},
        {"unexpected_field": "value"},
        {"schema_version": 1},
    ],
)
def test_untrusted_or_unknown_fields_are_rejected(
    client: TestClient, change: dict[str, object]
) -> None:
    response = client.post(
        "/internal/events/batch",
        json={"events": [{**VALID_EVENT, **change}]},
        headers=COLLECTOR,
    )

    assert response.status_code == 422
    assert _stored_event_count(client) == 0


def test_invalid_event_rejects_the_batch_with_reasons(client: TestClient) -> None:
    naive_timestamp = {
        **VALID_EVENT,
        "event_id": "api-event-2",
        "occurred_at": "2026-09-17T12:31:00",
    }

    response = client.post(
        "/internal/events/batch",
        json={"events": [VALID_EVENT, naive_timestamp]},
        headers=COLLECTOR,
    )

    assert response.status_code == 422
    assert response.json()["detail"]["invalid_events"] == [
        {"index": 1, "reason": "occurred_at must include a timezone"}
    ]
    assert _stored_event_count(client) == 0


def test_empty_and_oversized_batches_are_rejected(client: TestClient) -> None:
    oversized = [{**VALID_EVENT, "event_id": f"e-{index}"} for index in range(501)]

    empty = client.post("/internal/events/batch", json={"events": []}, headers=COLLECTOR)
    too_many = client.post(
        "/internal/events/batch", json={"events": oversized}, headers=COLLECTOR
    )

    assert empty.status_code == 422
    assert too_many.status_code == 422


def test_reused_event_id_with_different_content_returns_conflict(
    client: TestClient,
) -> None:
    client.post("/internal/events/batch", json={"events": [VALID_EVENT]}, headers=COLLECTOR)
    changed = {**VALID_EVENT, "source_ip": "203.0.113.99"}
    new_event = {**VALID_EVENT, "event_id": "api-event-3"}

    response = client.post(
        "/internal/events/batch",
        json={"events": [new_event, changed]},
        headers=COLLECTOR,
    )
    events = client.get("/security/events", headers=ANALYST).json()

    assert response.status_code == 409
    assert response.json()["detail"]["event_id"] == "api-event-1"
    assert [(event["event_id"], event["source_ip"]) for event in events] == [
        ("api-event-1", "192.0.2.50")
    ]


def test_event_search_filters_by_canonical_account_newest_first(
    client: TestClient,
) -> None:
    records, _ = read_records(FIXTURES / "days_1_2.jsonl")
    client.post("/internal/events/batch", json={"events": records}, headers=COLLECTOR)

    response = client.get(
        "/security/events",
        params={
            "organization_id": "org-alpha",
            "attempted_account": "ALICE@example.test",
            "limit": 3,
        },
        headers=ANALYST,
    )

    assert response.status_code == 200
    assert [event["event_id"] for event in response.json()] == [
        "evt-009",
        "evt-008",
        "evt-007",
    ]


def test_unknown_alert_returns_not_found(client: TestClient) -> None:
    response = client.get("/security/alerts/not-a-real-alert", headers=ANALYST)

    assert response.status_code == 404


def test_settings_require_distinct_sufficiently_long_tokens() -> None:
    with pytest.raises(ConfigurationError, match="must differ"):
        Settings("postgresql://unused", COLLECTOR_TOKEN, COLLECTOR_TOKEN)
    with pytest.raises(ConfigurationError, match="at least 16"):
        Settings("postgresql://unused", "short", ANALYST_TOKEN)


def _stored_event_count(client: TestClient) -> int:
    response = client.get("/security/events", headers=ANALYST)
    return len(response.json())
