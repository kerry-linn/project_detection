from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from threading import Barrier

import pytest

from backend.db import connect
from backend.detection_runner import run_failed_login_detection, run_denied_document_detection
from backend.repositories import cases
from backend.repositories.events import ingest_events
from backend.schemas import CaseDecision
from scripts.benchmark_detection import synthetic_events
from test_api import ACCOUNTS, COLLECTOR, UNKNOWN, VALID_EVENT


@pytest.fixture
def case(client, database_url, login_as):
    with connect(database_url) as conn:
        ingest_events(conn, synthetic_events(10, "hot"))
    with connect(database_url) as conn:
        run_failed_login_detection(conn)
        key = conn.execute("SELECT alert_key FROM alerts").fetchone()["alert_key"]
    return key, login_as(ACCOUNTS["analyst"])


def decision(revision=0, **changes):
    return {"revision": revision, "status": "closed", "disposition": "suspicious",
            "rationale": "Repeated failures followed by success; investigate account access.", **changes}


@pytest.mark.parametrize("credential,expected", [
    ("none", 401), ("invalid", 401), ("collector", 401),
    ("future-reader", 401), ("member", 403), ("admin", 403), ("analyst", 404),
])
@pytest.mark.parametrize("method,suffix,body", [
    ("PATCH", "", decision()), ("POST", "/notes", {"revision": 0, "body": "note"}),
    ("GET", "/activity", None),
])
def test_new_route_credential_matrix(client, login_as, credential, expected, method, suffix, body):
    headers = {"none": {}, "invalid": UNKNOWN, "collector": COLLECTOR,
               "future-reader": {"Authorization": "Bearer future-read-only-credential"}}.get(credential)
    if headers is None:
        headers = login_as(ACCOUNTS[credential])
    response = client.request(method, f"/security/alerts/missing{suffix}", headers=headers, json=body)
    assert response.status_code == expected


def test_decision_notes_reopen_and_unchanged_detector_preserve_history(client, case, database_url):
    key, headers = case
    path = f"/security/alerts/{key}"
    assert client.patch(path, headers=headers, json=decision()).json() == {"revision": 1}
    assert client.post(path + "/notes", headers=headers,
                       json={"revision": 1, "body": "Follow up with account owner."}).status_code == 201
    with connect(database_url) as conn:
        assert run_failed_login_detection(conn).alerts_unchanged == 1
    detail = client.get(path, headers=headers).json()
    assert (detail["status"], detail["disposition"], detail["revision"]) == ("closed", "suspicious", 2)
    assert not detail["needs_review"]
    stale = client.patch(path, headers=headers, json=decision())
    assert stale.status_code == 409
    assert client.patch(path, headers=headers,
                        json=decision(2, status="investigating", disposition=None, rationale="Reopened for follow-up")).status_code == 200
    history = client.get(path + "/activity?limit=2", headers=headers)
    assert history.headers["X-Total-Count"] == "3"
    assert history.headers["X-Next-Offset"] == "2"
    assert [item["revision"] for item in history.json()] == [3, 2]
    old = client.get(path + "/activity?offset=2", headers=headers).json()[0]
    assert old["disposition"] == "suspicious"
    assert old["author_id"] == "lab-analyst"


@pytest.mark.parametrize("change", [
    {"disposition": None}, {"rationale": " "}, {"rationale": "x" * 2001},
    {"status": "new"}, {"revision": -1}, {"author_id": "user-bob"},
])
def test_invalid_decisions_are_atomic(client, case, change):
    key, headers = case
    path = f"/security/alerts/{key}"
    assert client.patch(path, headers=headers, json=decision(**change)).status_code == 422
    assert client.get(path + "/activity", headers=headers).json() == []
    assert client.get(path, headers=headers).json()["revision"] == 0


def test_history_insert_failure_rolls_back_decision(client, case, database_url, monkeypatch):
    key, headers = case
    original = cases.write_activity

    def fail_after_write(*args):
        original(*args)
        raise RuntimeError("private payload must not escape")

    monkeypatch.setattr(cases, "write_activity", fail_after_write)
    response = client.patch(f"/security/alerts/{key}", headers=headers, json=decision())
    assert response.status_code == 500
    assert response.json() == {"detail": "internal server error"}
    with connect(database_url) as conn:
        assert conn.execute("SELECT revision FROM alerts").fetchone()["revision"] == 0
        assert conn.execute("SELECT count(*) AS n FROM case_activity").fetchone()["n"] == 0


def test_two_analysts_cannot_silently_overwrite(client, case, database_url):
    key, _ = case
    barrier = Barrier(2)

    def write(conclusion):
        barrier.wait(timeout=5)
        try:
            with connect(database_url) as conn:
                cases.write_activity(conn, key, "lab-analyst", CaseDecision(**decision(disposition=conclusion)))
            return "saved"
        except cases.CaseConflict:
            return "conflict"

    with ThreadPoolExecutor(2) as pool:
        outcomes = list(pool.map(write, ["benign", "suspicious"]))
    assert sorted(outcomes) == ["conflict", "saved"]
    with connect(database_url) as conn:
        assert conn.execute("SELECT count(*) AS n FROM case_activity").fetchone()["n"] == 1


def test_late_evidence_flags_closed_case_and_invalidates_stale_revision(client, case, database_url):
    key, headers = case
    path = f"/security/alerts/{key}"
    client.patch(path, headers=headers, json=decision())
    event = synthetic_events(10, "hot")[0]
    with connect(database_url) as conn:
        ingest_events(conn, [replace(event, event_id="extra-late-failure")])
    with connect(database_url) as conn:
        run_failed_login_detection(conn)
    detail = client.get(path, headers=headers).json()
    assert detail["needs_review"] and detail["disposition"] == "suspicious"
    assert detail["rationale"] == decision()["rationale"]
    assert client.patch(path, headers=headers, json=decision(1)).status_code == 409
    with connect(database_url) as conn:
        run_failed_login_detection(conn)
    assert client.get(path, headers=headers).json()["revision"] == detail["revision"]


def test_pagination_filters_before_limiting_and_reports_evidence_totals(client, case, database_url):
    key, headers = case
    with connect(database_url) as conn:
        ingest_events(conn, [replace(event, event_id=f"other-{event.event_id}", attempted_account="other@example.test")
                             for event in synthetic_events(10, "hot")])
    with connect(database_url) as conn:
        run_failed_login_detection(conn)
    matching = client.get("/security/alerts?limit=1&entity=OTHER@", headers=headers)
    assert matching.headers["X-Total-Count"] == "1"
    assert matching.json()[0]["attempted_account"] == "other@example.test"
    first = client.get("/security/alerts?limit=1", headers=headers)
    second = client.get("/security/alerts?limit=1&offset=1", headers=headers)
    assert first.headers["X-Total-Count"] == "2"
    assert first.json()[0]["alert_key"] != second.json()[0]["alert_key"]
    page = client.get("/security/alerts?limit=1&entity=missing", headers=headers)
    assert page.json() == [] and page.headers["X-Total-Count"] == "0"
    page = client.get("/security/alerts?limit=1&status=new", headers=headers)
    assert len(page.json()) == 1 and page.headers["X-Total-Count"] == "2"
    ids = []
    for offset in (0, 3):
        detail = client.get(f"/security/alerts/{key}?evidence_limit=3&evidence_offset={offset}", headers=headers).json()
        assert detail["evidence_total"] == 6
        assert len(detail["evidence"]) <= 3
        ids.extend(event["event_id"] for event in detail["evidence"])
    assert len(ids) == len(set(ids)) == 6
    for query in ("limit=101", "offset=-1", "offset=abc"):
        assert client.get(f"/security/alerts?{query}", headers=headers).status_code == 422


@pytest.mark.parametrize("change", ["logout", "expiry", "revocation", "role"])
def test_case_routes_recheck_sessions(client, case, database_url, change):
    key, headers = case
    if change == "logout":
        assert client.post("/auth/logout", headers=headers).status_code == 204
    else:
        with connect(database_url) as conn:
            if change == "expiry":
                conn.execute("UPDATE sessions SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour'")
            elif change == "revocation":
                conn.execute("UPDATE sessions SET revoked_at = now()")
            else:
                conn.execute("UPDATE users SET role = 'member', organization_id = 'org-alpha' WHERE user_id = 'lab-analyst'")
    expected = 403 if change == "role" else 401
    assert client.patch(f"/security/alerts/{key}", headers=headers, json=decision()).status_code == expected
    assert client.get(f"/security/alerts/{key}/activity", headers=headers).status_code == expected
    assert client.post(f"/security/alerts/{key}/notes", headers=headers,
                       json={"revision": 0, "body": "note"}).status_code == expected


def test_repeated_r2_replacements_keep_decision_history_and_review_flag(client, database_url, login_as):
    from test_r2_persistence import _distinct_denials, _denial, START, FIRST_KEY
    with connect(database_url) as conn:
        ingest_events(conn, _distinct_denials(5))
    with connect(database_url) as conn:
        run_denied_document_detection(conn)
    headers = login_as(ACCOUNTS["analyst"])
    path = f"/security/alerts/{FIRST_KEY}"
    assert client.patch(path, headers=headers, json=decision(disposition="benign")).status_code == 200
    assert client.post(path + "/notes", headers=headers,
                       json={"revision": 1, "body": "Approved bookmark exercise"}).status_code == 201
    for index in (1, 2):
        with connect(database_url) as conn:
            ingest_events(conn, [_denial(f"earlier-{index}", START - timedelta(seconds=15 * index), f"older-doc-{index}")])
        with connect(database_url) as conn:
            run_denied_document_detection(conn)
        [active] = client.get("/security/alerts", headers=headers).json()
        assert active["needs_review"]
    old = client.get(path, headers=headers).json()
    assert old["disposition"] == "benign" and old["status"] == "closed"
    assert old["evidence_total"] == 5
    history = client.get(path + "/activity", headers=headers).json()
    assert [item["kind"] for item in history] == ["note", "decision"]
    import psycopg
    with connect(database_url) as conn:
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            conn.execute("UPDATE case_activity SET body = 'overwrite'")
        conn.rollback()
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            conn.execute("DELETE FROM case_activity")
        conn.rollback()
