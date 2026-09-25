from __future__ import annotations

import hashlib
import json

import pytest
from fastapi.testclient import TestClient

import backend.routes.documents as document_routes
from backend.db import connect
from backend.detection_runner import (
    run_denied_document_detection,
    run_failed_login_detection,
)
from backend.repositories.events import load_events
from conftest import CLIENT_IP, TEST_PASSWORD, LoginAs
from detections.denied_document_access import RULE_ID as R2_RULE_ID
from security_events import SecurityEvent

ALICE = "alice@alpha.example.test"
BOB = "bob@alpha.example.test"
ALPHA_ADMIN = "admin@alpha.example.test"
DANA = "dana@beta.example.test"
ANALYST = "analyst@lab.example.test"


def test_login_issues_an_opaque_session_and_records_success(
    client: TestClient, database_url: str
) -> None:
    response = client.post(
        "/auth/login", json={"login": "  Alice@Alpha.Example.TEST ", "password": TEST_PASSWORD}
    )
    body = response.json()
    token = body["access_token"]
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert body["user"] == {
        "user_id": "user-alice",
        "login": ALICE,
        "display_name": "Alice",
        "organization_id": "org-alpha",
        "role": "member",
    }
    assert me.json()["user_id"] == "user-alice"

    with connect(database_url) as conn:
        session = conn.execute("SELECT session_id, token_hash FROM sessions").fetchone()
    [event] = _events(database_url, "login_succeeded")
    assert session["token_hash"] == hashlib.sha256(token.encode()).hexdigest()
    assert event.source == "application"
    assert event.actor_id == "user-alice"
    assert event.organization_id == "org-alpha"
    assert event.attempted_account == ALICE
    assert event.session_id == session["session_id"]
    assert event.source_ip == CLIENT_IP
    assert token not in json.dumps(event.to_dict())


def test_wrong_password_and_unknown_account_are_indistinguishable(
    client: TestClient, database_url: str
) -> None:
    wrong_password = client.post(
        "/auth/login", json={"login": ALICE, "password": "not-the-password"}
    )
    unknown_account = client.post(
        "/auth/login", json={"login": "nobody@alpha.example.test", "password": "x"}
    )

    assert wrong_password.status_code == unknown_account.status_code == 401
    assert wrong_password.json() == unknown_account.json()

    known, unknown = _events(database_url, "login_failed")
    assert (known.organization_id, known.actor_id) == ("org-alpha", None)
    assert known.metadata == {"reason": "invalid_password"}
    assert (unknown.organization_id, unknown.actor_id) == (None, None)
    assert unknown.attempted_account == "nobody@alpha.example.test"
    assert unknown.metadata == {"reason": "unknown_account"}
    assert "not-the-password" not in json.dumps(known.to_dict())
    with connect(database_url) as conn:
        assert conn.execute("SELECT COUNT(*) AS n FROM sessions").fetchone()["n"] == 0


def test_login_rejects_client_asserted_identity(
    client: TestClient, database_url: str
) -> None:
    response = client.post(
        "/auth/login",
        json={
            "login": BOB,
            "password": TEST_PASSWORD,
            "actor_id": "admin-alpha",
            "outcome": "success",
        },
    )

    assert response.status_code == 422
    assert _events(database_url) == []


def test_source_ip_ignores_forwarding_headers(
    client: TestClient, database_url: str
) -> None:
    client.post(
        "/auth/login",
        json={"login": ALICE, "password": TEST_PASSWORD},
        headers={"X-Forwarded-For": "198.51.100.99"},
    )

    [event] = _events(database_url, "login_succeeded")
    assert event.source_ip == CLIENT_IP


def test_logout_revokes_the_session(client: TestClient, login_as: LoginAs) -> None:
    headers = login_as(ALICE)

    logout = client.post("/auth/logout", headers=headers)
    after = client.get("/auth/me", headers=headers)

    assert logout.status_code == 204
    assert after.status_code == 401


def test_expired_session_is_rejected(
    client: TestClient, login_as: LoginAs, database_url: str
) -> None:
    headers = login_as(ALICE)
    with connect(database_url) as conn:
        conn.execute(
            "UPDATE sessions SET created_at = now() - interval '9 hours', "
            "expires_at = now() - interval '1 hour'"
        )

    assert client.get("/auth/me", headers=headers).status_code == 401


def test_documents_require_authentication(client: TestClient) -> None:
    assert client.get("/documents").status_code == 401
    assert client.get("/documents/doc-alpha-001").status_code == 401


def test_members_list_their_own_documents_and_admins_list_the_organization(
    client: TestClient, login_as: LoginAs
) -> None:
    alice_docs = client.get("/documents", headers=login_as(ALICE)).json()
    admin_docs = client.get("/documents", headers=login_as(ALPHA_ADMIN)).json()

    assert sorted(doc["document_id"] for doc in alice_docs) == [
        "doc-alpha-001",
        "doc-alpha-002",
        "doc-alpha-003",
    ]
    assert sorted(doc["document_id"] for doc in admin_docs) == [
        f"doc-alpha-00{index}" for index in range(1, 6)
    ]


def test_owner_reads_and_updates_with_a_content_free_audit_event(
    client: TestClient, login_as: LoginAs, database_url: str
) -> None:
    headers = login_as(ALICE)

    read = client.get("/documents/doc-alpha-001", headers=headers)
    update = client.patch(
        "/documents/doc-alpha-001",
        json={"body": "Updated fictional notes."},
        headers=headers,
    )

    assert read.status_code == 200
    assert update.status_code == 200
    assert update.json()["body"] == "Updated fictional notes."
    [event] = _events(database_url, "document_updated")
    assert (event.actor_id, event.resource_id) == ("user-alice", "doc-alpha-001")
    assert event.metadata == {"changed_fields": ["body"]}
    assert "Updated fictional notes." not in json.dumps(event.to_dict())


def test_create_uses_the_session_for_owner_and_organization(
    client: TestClient, login_as: LoginAs, database_url: str
) -> None:
    headers = login_as(BOB)

    created = client.post(
        "/documents", json={"title": "New note", "body": "Fictional."}, headers=headers
    )
    spoofed = client.post(
        "/documents",
        json={"title": "Spoof", "owner_id": "user-alice", "organization_id": "org-beta"},
        headers=headers,
    )

    assert created.status_code == 201
    assert created.json()["owner_id"] == "user-bob"
    assert created.json()["organization_id"] == "org-alpha"
    assert spoofed.status_code == 422
    [event] = _events(database_url, "document_created")
    assert event.resource_id == created.json()["document_id"]


def test_same_organization_non_owner_is_forbidden_and_audited(
    client: TestClient, login_as: LoginAs, database_url: str
) -> None:
    headers = login_as(BOB)

    read = client.get("/documents/doc-alpha-001", headers=headers)
    update = client.patch(
        "/documents/doc-alpha-001", json={"title": "Taken over"}, headers=headers
    )
    after = client.get("/documents/doc-alpha-001", headers=login_as(ALICE))

    assert read.status_code == update.status_code == 403
    assert after.json()["title"] == "Q3 lab notes"
    denials = _events(database_url, "access_denied")
    assert [(event.metadata["action"], event.metadata["reason"]) for event in denials] == [
        ("read", "not_owner"),
        ("update", "not_owner"),
    ]
    assert all(event.organization_id == "org-alpha" for event in denials)
    assert all(event.actor_id == "user-bob" for event in denials)


def test_cross_organization_access_looks_like_a_missing_document(
    client: TestClient, login_as: LoginAs, database_url: str
) -> None:
    headers = login_as(DANA)

    foreign = client.get("/documents/doc-alpha-001", headers=headers)
    missing = client.get("/documents/doc-does-not-exist", headers=headers)

    assert foreign.status_code == missing.status_code == 404
    assert foreign.json() == missing.json()
    foreign_event, missing_event = _events(database_url, "access_denied")
    assert foreign_event.organization_id == "org-beta"
    assert foreign_event.metadata["reason"] == "cross_organization"
    assert missing_event.metadata["reason"] == "not_found"
    assert "org-alpha" not in json.dumps(foreign_event.to_dict())
    assert "Q3 lab notes" not in json.dumps(foreign_event.to_dict())


def test_admin_scope_is_limited_to_their_organization(
    client: TestClient, login_as: LoginAs
) -> None:
    headers = login_as(ALPHA_ADMIN)

    own_org = client.patch(
        "/documents/doc-alpha-001", json={"title": "Reviewed"}, headers=headers
    )
    other_org = client.get("/documents/doc-beta-001", headers=headers)

    assert own_org.status_code == 200
    assert own_org.json()["owner_id"] == "user-alice"
    assert other_org.status_code == 404


def test_lab_analyst_has_no_implicit_document_access(
    client: TestClient, login_as: LoginAs
) -> None:
    headers = login_as(ANALYST)

    assert client.get("/documents", headers=headers).status_code == 403
    assert client.get("/documents/doc-alpha-001", headers=headers).status_code == 403


def test_malformed_document_id_is_rejected_before_lookup(
    client: TestClient, login_as: LoginAs, database_url: str
) -> None:
    response = client.get("/documents/bad%20id%3B", headers=login_as(BOB))

    assert response.status_code == 422
    assert _events(database_url, "access_denied") == []


def test_audit_failure_rolls_back_the_business_change(
    client: TestClient,
    login_as: LoginAs,
    database_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = login_as(ALICE)

    def fail(*args, **kwargs):
        raise RuntimeError("simulated audit write failure")

    monkeypatch.setattr(document_routes, "record_event", fail)
    failing_client = TestClient(client.app, raise_server_exceptions=False)
    update = failing_client.patch(
        "/documents/doc-alpha-001", json={"title": "Unaudited"}, headers=headers
    )
    create = failing_client.post(
        "/documents", json={"title": "Unaudited"}, headers=headers
    )

    assert update.status_code == create.status_code == 500
    with connect(database_url) as conn:
        title = conn.execute(
            "SELECT title FROM documents WHERE document_id = 'doc-alpha-001'"
        ).fetchone()["title"]
        count = conn.execute(
            "SELECT COUNT(*) AS n FROM documents WHERE owner_id = 'user-alice'"
        ).fetchone()["n"]
    assert title == "Q3 lab notes"
    assert count == 3


def test_failed_logins_through_the_login_route_produce_r1(
    client: TestClient, login_as: LoginAs, database_url: str
) -> None:
    for _ in range(5):
        client.post("/auth/login", json={"login": ALICE, "password": "guess"})
    login_as(ALICE)

    with connect(database_url) as conn:
        first = run_failed_login_detection(conn)
    with connect(database_url) as conn:
        rerun = run_failed_login_detection(conn)

    analyst = login_as(ANALYST)
    [alert] = client.get("/security/alerts", headers=analyst).json()
    detail = client.get(f"/security/alerts/{alert['alert_key']}", headers=analyst).json()

    assert (first.alerts_created, rerun.alerts_unchanged) == (1, 1)
    assert detail["attempted_account"] == ALICE
    assert detail["organization_id"] == "org-alpha"
    assert detail["match_count"] == 5
    assert detail["source_ips"] == [CLIENT_IP]
    assert [item["evidence_role"] for item in detail["evidence"]] == [
        *["failed_login"] * 5,
        "successful_login",
    ]
    assert all(item["source"] == "application" for item in detail["evidence"])


def test_repeated_denied_documents_through_routes_produce_one_r2_episode(
    client: TestClient, login_as: LoginAs, database_url: str
) -> None:
    bob = login_as(BOB)
    probes = [
        "doc-alpha-001",
        "doc-alpha-001",
        "doc-alpha-002",
        "doc-alpha-003",
        "doc-alpha-005",
    ]
    for document_id in probes:
        client.get(f"/documents/{document_id}", headers=bob)
    client.get("/documents/doc-alpha-004", headers=bob)

    with connect(database_url) as conn:
        below_threshold = run_denied_document_detection(conn)

    client.get("/documents/doc-beta-001", headers=bob)
    trigger = _events(database_url, "access_denied")[-1]
    with connect(database_url) as conn:
        opened = run_denied_document_detection(conn)

    client.get("/documents/doc-beta-002", headers=bob)
    with connect(database_url) as conn:
        extended = run_denied_document_detection(conn)
    with connect(database_url) as conn:
        rerun = run_denied_document_detection(conn)

    analyst = login_as(ANALYST)
    alerts = client.get("/security/alerts", headers=analyst).json()
    detail = client.get(f"/security/alerts/{alerts[0]['alert_key']}", headers=analyst).json()

    assert below_threshold.alerts_detected == 0
    assert opened.alerts_created == 1
    assert (extended.alerts_created, extended.alerts_updated) == (0, 1)
    assert (rerun.alerts_created, rerun.alerts_unchanged) == (0, 1)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == R2_RULE_ID
    assert alerts[0]["alert_key"].endswith(f":org-alpha:user-bob:{trigger.event_id}")
    assert detail["actor_id"] == "user-bob"
    assert detail["match_count"] == 6
    assert detail["resource_ids"] == [
        "doc-alpha-001",
        "doc-alpha-002",
        "doc-alpha-003",
        "doc-alpha-005",
        "doc-beta-001",
        "doc-beta-002",
    ]
    assert len(detail["evidence"]) == 7
    assert {item["evidence_role"] for item in detail["evidence"]} == {
        "denied_document_access"
    }
    assert "Fictional" not in json.dumps(detail)


def _events(database_url: str, event_type: str | None = None) -> list[SecurityEvent]:
    with connect(database_url) as conn:
        events = load_events(conn)
    return [event for event in events if event_type in (None, event.event_type)]
