import asyncio
import json
import logging
from dataclasses import asdict
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from psycopg import sql

from backend.api import create_app
from backend.db import MIGRATIONS_DIR, connect
from backend.http_safety import MAX_REQUEST_BYTES
from backend.repositories.events import ingest_events, load_events
from backend.repositories.alerts import INSERT_ALERT, failed_login_alert_record
from detections.failed_login_success import detect_failed_logins_followed_by_success
from scripts.benchmark_detection import synthetic_events
from test_api import COLLECTOR, VALID_EVENT


def test_chunked_body_cap_ignores_untrusted_content_length(settings):
    app = create_app(settings)
    messages = iter([
        {"type": "http.request", "body": b" " * (MAX_REQUEST_BYTES // 2), "more_body": True},
        {"type": "http.request", "body": b" " * (MAX_REQUEST_BYTES // 2), "more_body": True},
        {"type": "http.request", "body": b"x", "more_body": False},
    ])
    output = []

    async def receive():
        return next(messages)

    async def send(message):
        output.append(message)

    asyncio.run(app({"type": "http", "method": "POST", "path": "/internal/events/batch",
                     "headers": [(b"content-length", b"1")], "query_string": b""}, receive, send))
    assert output[0]["status"] == 413
    assert b"request body too large" in output[1]["body"]


def test_request_logs_and_validation_never_echo_secrets(client, login_as, caplog, monkeypatch):
    from backend.routes import auth
    caplog.set_level(logging.INFO, logger="uvicorn.error.requests")
    secret = "private-secret-sentinel"
    response = client.post("/auth/login", json={"login": "alice", "password": secret, "extra": secret},
                           headers={"Authorization": f"Bearer {secret}", "X-Request-ID": secret})
    assert response.status_code == 422
    assert secret not in response.text
    assert response.headers["X-Request-ID"].startswith("req-")

    def fail(*args):
        raise RuntimeError(secret)

    monkeypatch.setattr(auth, "verify_password", fail)
    response = client.post("/auth/login", json={"login": "alice", "password": secret})
    assert response.status_code == 500 and secret not in response.text
    records = [json.loads(record.message) for record in caplog.records if record.name == "uvicorn.error.requests"]
    assert [row["category"] for row in records] == ["request_rejected", "server_error"]
    assert all(set(row) == {"request_id", "status", "category"} for row in records)
    assert secret not in json.dumps(records)


@pytest.mark.parametrize("conflict", [False, True])
def test_simultaneous_ingestion_is_atomic(client, database_url, conflict):
    barrier = Barrier(2)

    def send(index):
        event = {**VALID_EVENT, "source_ip": f"192.0.2.{index + 1}"} if conflict else VALID_EVENT
        batch = [{**VALID_EVENT, "event_id": f"unique-{index}"}, event] if conflict else [event]
        barrier.wait(timeout=5)
        return client.post("/internal/events/batch", headers=COLLECTOR, json={"events": batch})

    with ThreadPoolExecutor(2) as pool:
        responses = list(pool.map(send, range(2)))
    assert sorted(response.status_code for response in responses) == ([200, 409] if conflict else [200, 200])
    with connect(database_url) as conn:
        events = load_events(conn)
    assert len(events) == (2 if conflict else 1)
    if conflict:
        winner = next(index for index, response in enumerate(responses) if response.status_code == 200)
        assert {event.event_id for event in events} == {VALID_EVENT["event_id"], f"unique-{winner}"}
    else:
        assert sum(response.json()["inserted"] for response in responses) == 1
        assert sum(response.json()["replayed"] for response in responses) == 1


@pytest.mark.parametrize("upgrade", [False, True])
def test_case_migration_empty_and_upgrade(migrated_database_url, upgrade):
    schema = "case_migration_" + uuid4().hex
    with connect(migrated_database_url) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        try:
            for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
                if path.name.startswith("007") and upgrade:
                    events = synthetic_events(10, "hot")
                    ingest_events(conn, events)
                    [detected] = detect_failed_logins_followed_by_success(events)
                    record = failed_login_alert_record(detected)
                    params = asdict(record)
                    del params["evidence"]
                    conn.execute(INSERT_ALERT, params)
                    for event_id, role in record.evidence:
                        conn.execute("INSERT INTO alert_events VALUES (%s, %s, %s)",
                                     (record.alert_key, event_id, role))
                    conn.execute("UPDATE alerts SET status = 'closed'")
                conn.execute(path.read_text())
            if upgrade:
                assert load_events(conn) == events
            assert conn.execute("SELECT count(*) AS n FROM case_activity").fetchone()["n"] == 0
            rows = conn.execute("SELECT status, disposition, rationale, revision FROM alerts").fetchall()
            assert rows == ([{"status": "closed", "disposition": None, "rationale": None, "revision": 0}] if upgrade else [])
            if upgrade:
                assert conn.execute("SELECT count(*) AS n FROM alert_events").fetchone()["n"] == 6
        finally:
            conn.rollback()


def test_request_ids_correlate_without_exposing_credentials_or_document_content(client, login_as, caplog):
    caplog.set_level(logging.INFO, logger="uvicorn.error.requests")
    member = login_as("alice@alpha.example.test")
    analyst = login_as("analyst@lab.example.test")
    text = "private-document-text-sentinel"
    created = client.post("/documents", headers=member, json={"title": "Private title", "body": text})
    assert created.status_code == 201
    events = client.get("/security/events?event_type=document_created", headers=analyst).json()
    assert events[0]["request_id"] == created.headers["X-Request-ID"]
    export = json.dumps(events)
    log = "\n".join(record.message for record in caplog.records if record.name == "uvicorn.error.requests")
    for secret in (text, "Private title", member["Authorization"].removeprefix("Bearer "),
                   analyst["Authorization"].removeprefix("Bearer "), "password_hash", "token_hash"):
        assert secret not in export and secret not in log
