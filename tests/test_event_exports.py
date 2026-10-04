import base64
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from threading import Barrier
from uuid import uuid4

import psycopg
import pytest

from backend.db import connect
from backend.repositories import exports
from backend.repositories.events import ingest_events, load_events
from scripts.benchmark_detection import synthetic_events, verify_persisted_parity
from scripts.reset_telemetry import reset_telemetry
from backend.detection_runner import run_failed_login_detection
from scripts import export_credentials
from test_api import ACCOUNTS, COLLECTOR, VALID_EVENT

PATH = "/security/events/export"


@pytest.fixture
def reader(client, database_url):
    with connect(database_url) as conn:
        credential_id, token = exports.create_credential(conn, "test export")
    return credential_id, token, {"Authorization": "Bearer " + token}


def get_page(client, reader, **params):
    return client.get(PATH, headers=reader[2], params=params)


@pytest.mark.parametrize("size", [0, 1, 11])
def test_frozen_export_matches_every_source_field(client, reader, database_url, size):
    events = synthetic_events(size, "hot")
    if events:
        events = [replace(e, occurred_at=events[0].occurred_at) for e in events]
    with connect(database_url) as conn:
        ingest_events(conn, events)
    params = {"limit": 3, "export_id": str(uuid4())}
    first = get_page(client, reader, **params)
    assert first.status_code == 200, first.text
    page = first.json()
    assert get_page(client, reader, **params).json() == page
    snapshot = page["snapshot_id"]
    seen = []
    while True:
        assert page["snapshot_id"] == snapshot
        assert page["total_count"] == size
        seen.extend(page["items"])
        if page["next_cursor"] is None:
            break
        params["cursor"] = page["next_cursor"]
        page = get_page(client, reader, **params).json()
    assert seen == [e.to_dict() for e in sorted(events, key=lambda e: e.event_id)]
    assert len({e["event_id"] for e in seen}) == size


def test_snapshot_excludes_late_and_uncommitted_events(client, reader, database_url):
    events = synthetic_events(10, "hot")
    with connect(database_url) as conn:
        ingest_events(conn, events)
    with connect(database_url) as pending:
        late = replace(events[0], event_id="late-commit", occurred_at=events[0].occurred_at - timedelta(days=1))
        ingest_events(pending, [late])
        first = get_page(client, reader, limit=4).json()
    params = {"limit": 4, "cursor": first["next_cursor"]}
    items = first["items"]
    while params["cursor"]:
        page = get_page(client, reader, **params).json()
        items += page["items"]
        params["cursor"] = page["next_cursor"]
    assert items == [e.to_dict() for e in events]
    next_export = get_page(client, reader, limit=100).json()
    assert next_export["items"][0] == late.to_dict()
    assert next_export["total_count"] == 11


def test_filters_and_cursor_are_bound_to_original_scope(client, reader, database_url):
    with connect(database_url) as conn:
        ingest_events(conn, synthetic_events(10, "hot"))
        _, second_token = exports.create_credential(conn, "second exporter")
    params = {"limit": 2, "event_type": "login_failed", "attempted_account": "USER-0@EXAMPLE.TEST",
              "organization_id": "bench-org", "export_id": str(uuid4())}
    first = get_page(client, reader, **params).json()
    assert first["total_count"] == 5
    params["cursor"] = first["next_cursor"]
    for changes in ({"limit": 3}, {"event_type": "login_succeeded"}, {"export_id": str(uuid4())}):
        assert get_page(client, reader, **(params | changes)).status_code == 409
    assert client.get(PATH, params=params, headers={"Authorization": "Bearer " + second_token}).status_code == 403
    cursor = params["cursor"]
    payload, signature = cursor.split(".")
    decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    decoded[1] += 2
    changed = base64.urlsafe_b64encode(json.dumps(decoded).encode()).decode().rstrip("=") + "." + signature
    assert get_page(client, reader, **(params | {"cursor": changed})).status_code == 400
    assert get_page(client, reader, **params).status_code == 200


@pytest.mark.parametrize("params", [{"cursor": "bad"}, {"cursor": "e30.abc"}, {"unknown": "yes"},
                                       {"limit": 0}, {"limit": 1001}, {"export_id": "bad"}])
def test_bad_parameters_do_not_create_snapshots(client, reader, database_url, params):
    assert get_page(client, reader, **params).status_code in (400, 422)
    with connect(database_url) as conn:
        assert conn.execute("SELECT count(*) AS n FROM export_snapshots").fetchone()["n"] == 0


@pytest.mark.parametrize("credential", ["none", "invalid", "collector", "member", "admin", "analyst"])
def test_export_accepts_only_separate_machine_credential(client, login_as, credential):
    headers = {"none": {}, "invalid": {"Authorization": "Bearer bad"}, "collector": COLLECTOR}.get(credential)
    if headers is None:
        headers = login_as(ACCOUNTS[credential])
    assert client.get(PATH, headers=headers).status_code == 401


@pytest.mark.parametrize("method,path,body", [
    ("GET", "/security/events", None), ("GET", "/security/alerts", None),
    ("GET", "/security/alerts/missing", None), ("GET", "/security/alerts/missing/activity", None),
    ("GET", "/documents", None), ("GET", "/documents/doc-alpha-001", None),
    ("GET", "/auth/me", None), ("POST", "/auth/logout", None),
    ("POST", "/internal/events/batch", {"events": [VALID_EVENT]}),
    ("POST", "/documents", {"title": "forbidden"}),
    ("PATCH", "/documents/doc-alpha-001", {"title": "forbidden"}),
    ("PATCH", "/security/alerts/missing", {"revision": 0, "status": "new", "rationale": "forbidden"}),
    ("POST", "/security/alerts/missing/notes", {"revision": 0, "body": "forbidden"}),
])
def test_reader_has_no_other_privileges(client, reader, method, path, body):
    assert client.request(method, path, headers=reader[2], json=body).status_code == 401


@pytest.mark.parametrize("change", ["revocation", "expiry"])
def test_credential_rechecked_on_every_page(client, reader, database_url, change):
    with connect(database_url) as conn:
        ingest_events(conn, synthetic_events(10, "hot"))
    first = get_page(client, reader, limit=2).json()
    with connect(database_url) as conn:
        if change == "revocation":
            conn.execute("UPDATE export_credentials SET revoked_at = now() WHERE credential_id=%s", (reader[0],))
        else:
            conn.execute("UPDATE export_credentials SET created_at=now()-interval '2 days', expires_at=now()-interval '1 day' WHERE credential_id=%s", (reader[0],))
    assert get_page(client, reader, limit=2, cursor=first["next_cursor"]).status_code == 401


def test_retention_expiry_and_first_request_retry(client, reader, database_url):
    with connect(database_url) as conn:
        ingest_events(conn, synthetic_events(10, "hot"))
    params = {"limit": 2, "export_id": str(uuid4())}
    first = get_page(client, reader, **params).json()
    with connect(database_url) as conn:
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            conn.execute("DELETE FROM security_events")
        conn.rollback()
        with pytest.raises(psycopg.errors.RaiseException, match="immutable"):
            conn.execute("UPDATE security_events SET source_ip='192.0.2.99'")
        conn.rollback()
        with pytest.raises(ValueError, match="active export"):
            reset_telemetry(conn)
        conn.rollback()
        conn.execute("UPDATE export_snapshots SET expires_at=now()-interval '1 second'")
    assert get_page(client, reader, **params, cursor=first["next_cursor"]).status_code == 410
    assert get_page(client, reader, **params).status_code == 410
    with connect(database_url) as conn:
        assert exports.cleanup_expired(conn) == 10
        assert len(load_events(conn)) == 10
    assert get_page(client, reader, **params).status_code == 410
    with connect(database_url) as conn:
        reset_telemetry(conn)
        assert load_events(conn) == []
    assert get_page(client, reader, **params).status_code == 410


def test_concurrent_initial_retries_share_one_snapshot(client, reader, database_url):
    with connect(database_url) as conn:
        ingest_events(conn, synthetic_events(10, "hot"))
    barrier = Barrier(2)
    params = {"limit": 2, "export_id": str(uuid4())}
    def fetch(_):
        barrier.wait(timeout=5)
        return get_page(client, reader, **params)
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(fetch, range(2)))
    assert [r.status_code for r in results] == [200, 200]
    assert results[0].json() == results[1].json()
    with connect(database_url) as conn:
        assert conn.execute("SELECT count(*) AS n FROM export_snapshots").fetchone()["n"] == 1


def test_failed_snapshot_creation_rolls_back(client, reader, database_url, monkeypatch):
    with connect(database_url) as conn:
        ingest_events(conn, synthetic_events(10, "hot"))
    original = exports._create_snapshot
    def fail(*args):
        original(*args)
        raise RuntimeError("must not escape")
    monkeypatch.setattr(exports, "_create_snapshot", fail)
    assert get_page(client, reader).status_code == 500
    with connect(database_url) as conn:
        assert conn.execute("SELECT count(*) AS n FROM export_snapshot_events").fetchone()["n"] == 0
        assert conn.execute("SELECT count(*) AS n FROM export_snapshots").fetchone()["n"] == 0


def test_credential_management_hides_secret_and_refuses_overwrite(database_url, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("EXPORT_TEST_DATABASE_URL", database_url)
    token_file = tmp_path / "token"
    args = ["--database-url-env", "EXPORT_TEST_DATABASE_URL"]
    create = [*args, "create", "--name", "acceptance", "--output", str(token_file)]
    assert export_credentials.main(create) == 0
    token = token_file.read_text().strip()
    assert token_file.stat().st_mode & 0o777 == 0o600
    output = capsys.readouterr().out
    credential_id = json.loads(output)["credential_id"]
    assert token not in output
    assert export_credentials.main(create) == 1
    assert token_file.read_text().strip() == token
    with connect(database_url) as conn:
        rows = conn.execute("SELECT token_hash FROM export_credentials").fetchall()
        assert rows == [{"token_hash": exports.token_hash(token)}]
    assert export_credentials.main([*args, "list"]) == 0
    assert exports.token_hash(token) not in capsys.readouterr().out
    assert export_credentials.main([*args, "revoke", credential_id]) == 0
    with connect(database_url) as conn:
        with pytest.raises(exports.ExportError):
            exports.authenticate(conn, token)


def test_benchmark_comparison_accepts_current_case_schema(database_url):
    with connect(database_url) as conn:
        ingest_events(conn, synthetic_events(10, "hot"))
    with connect(database_url) as conn:
        run_failed_login_detection(conn)
        assert verify_persisted_parity(conn) == 1


def test_expiry_cleanup_preserves_a_page_transaction(client, reader, database_url):
    with connect(database_url) as conn:
        ingest_events(conn, synthetic_events(10, "hot"))
    first = get_page(client, reader, limit=2).json()
    with connect(database_url) as conn:
        conn.execute("UPDATE export_snapshots SET expires_at=now()-interval '1 second'")
    with connect(database_url) as page:
        page.execute("SELECT snapshot_id FROM export_snapshots WHERE snapshot_id=%s FOR SHARE", (first["snapshot_id"],))
        with connect(database_url) as cleanup:
            assert exports.cleanup_expired(cleanup) == 0
        assert page.execute("SELECT count(*) AS n FROM export_snapshot_events").fetchone()["n"] == 10
    with connect(database_url) as cleanup:
        assert exports.cleanup_expired(cleanup) == 10


def test_timestamp_ties_use_locale_independent_event_id_order(client, reader, database_url):
    event = synthetic_events(1, "hot")[0]
    ids = ["z", "A", "a", "a-1", "a_1", "Z"]
    with connect(database_url) as conn:
        ingest_events(conn, [replace(event, event_id=value) for value in ids])
    actual = []
    params = {"limit": 2}
    while True:
        response = get_page(client, reader, **params)
        assert response.headers["Cache-Control"] == "no-store"
        page = response.json()
        actual.extend(item["event_id"] for item in page["items"])
        if not page["next_cursor"]:
            break
        params["cursor"] = page["next_cursor"]
    assert actual == sorted(ids)
