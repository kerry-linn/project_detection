import csv
import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
from uuid import uuid4

import httpx2 as httpx
import pytest

from scripts import collect_events as collector
from scripts.benchmark_detection import synthetic_events


@pytest.fixture
def config():
    return collector.Config("http://127.0.0.1:8000", "export-test-secret", page_size=3)


@pytest.fixture
def records():
    return [e.to_dict() for e in synthetic_events(10, "hot")]


def page(store, items, cursor=None, total=None, snapshot=None):
    return {"items": items, "next_cursor": cursor, "total_count": len(items) if total is None else total,
            "snapshot_id": snapshot or store.state["snapshot_id"] or str(uuid4()),
            "export_id": store.state["export_id"], "expires_at": "2099-01-01T00:00:00Z"}


def server(records, calls):
    snapshot = str(uuid4())
    def send(request):
        calls.append(dict(request.url.params))
        params = request.url.params
        offset = int(params.get("cursor", "0"))
        limit = int(params["limit"])
        items = records[offset:offset + limit]
        end = offset + len(items)
        return httpx.Response(200, json={"items": items, "next_cursor": str(end) if end < len(records) else None,
                                       "snapshot_id": snapshot, "export_id": params["export_id"],
                                       "expires_at": "2099-01-01T00:00:00Z", "total_count": len(records)})
    return httpx.Client(transport=httpx.MockTransport(send))


@pytest.mark.parametrize("size", [0, 1, 10])
def test_resume_and_export_exact_raw_content(config, records, tmp_path, size):
    records = records[:size]
    calls = []
    state = tmp_path / "state.db"
    output = tmp_path / "events.jsonl"
    with server(records, calls) as client:
        with collector.Store(state, config) as store:
            complete = collector.collect(store, client, config, max_pages=1)
            assert complete == (size <= 3)
            export_id = store.state["export_id"]
        with collector.Store(state, config) as store:
            assert collector.collect(store, client, config)
            manifest = collector.export_output(store, output, "jsonl")
            assert manifest["event_count"] == size and manifest["complete"]
            assert config.token not in output.read_text() + json.dumps(manifest)
    assert [json.loads(line) for line in output.read_text().splitlines()] == records
    assert {call["export_id"] for call in calls} == {export_id}
    assert len({call.get("cursor", "0") for call in calls}) == len(calls)
    assert state.stat().st_mode & 0o777 == 0o600


def test_csv_neutralizes_formulas_without_changing_jsonl(config, records, tmp_path):
    item = {**records[0], "request_id": " \t=HYPERLINK(\"bad\")", "actor_id": "+danger", "metadata": {"raw": "=keep"}}
    with collector.Store(tmp_path / "state", config) as store:
        store.commit_page(page(store, [item]))
        collector.export_output(store, tmp_path / "events.jsonl", "jsonl")
        collector.export_output(store, tmp_path / "events.csv", "csv")
    assert json.loads((tmp_path / "events.jsonl").read_text()) == item
    with (tmp_path / "events.csv").open() as file:
        [row] = list(csv.DictReader(file))
    assert row["request_id"].startswith("'") and row["actor_id"] == "'+danger"
    assert json.loads(row["metadata"]) == item["metadata"]


@pytest.mark.parametrize("failure", ["timeout", "network", 429, 500, 502, 503, 504])
def test_transient_errors_retry_then_succeed(config, records, tmp_path, failure):
    calls, sleeps = [], []
    with collector.Store(tmp_path / "state", config) as store:
        response = page(store, records[:1])
        def send(request):
            calls.append(request)
            if len(calls) == 1:
                if failure == "timeout":
                    raise httpx.ReadTimeout("private error", request=request)
                if failure == "network":
                    raise httpx.ConnectError("private error", request=request)
                return httpx.Response(failure, headers={"Retry-After": "0"})
            return httpx.Response(200, json=response)
        with httpx.Client(transport=httpx.MockTransport(send)) as client:
            assert collector.collect(store, client, config, sleep=sleeps.append)
        assert store.state["count"] == 1 and len(calls) == 2 and len(sleeps) == 1


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 410, 422, 302])
def test_permanent_errors_never_retry(config, tmp_path, status):
    calls = []
    def send(request):
        calls.append(request)
        return httpx.Response(status, text="private body")
    with collector.Store(tmp_path / "state", config) as store, httpx.Client(transport=httpx.MockTransport(send)) as client:
        with pytest.raises(collector.CollectionError):
            collector.collect(store, client, config)
        assert store.state["count"] == 0
    assert len(calls) == 1


def test_retry_budgets_and_retry_after(config, tmp_path):
    calls, sleeps = [], []
    def send(request):
        calls.append(request)
        return httpx.Response(429, headers={"Retry-After": "2"})
    with collector.Store(tmp_path / "state", config) as store, httpx.Client(transport=httpx.MockTransport(send)) as client:
        with pytest.raises(collector.CollectionError, match="retry budget"):
            collector.collect(store, client, config, sleep=sleeps.append)
        assert len(calls) == 5 and sleeps == [2] * 4
        with pytest.raises(collector.CollectionError, match="wait budget"):
            collector.collect(store, client, replace(config, wait_budget=1), sleep=sleeps.append)
    assert collector.retry_delay("0", 1, config) == 0
    assert 0 <= collector.retry_delay("nonsense", 1, config) <= 2
    with pytest.raises(collector.CollectionError, match="Retry-After"):
        collector.retry_delay("999", 1, config)


@pytest.mark.parametrize("problem", ["json", "schema", "event", "count", "identity", "oversized"])
def test_malformed_responses_do_not_advance_checkpoint(config, records, tmp_path, problem, monkeypatch):
    calls = []
    with collector.Store(tmp_path / "state", config) as store:
        payload = page(store, records[:1])
        if problem == "schema": del payload["next_cursor"]
        if problem == "event": del payload["items"][0]["request_id"]
        if problem == "count": payload["total_count"] = 2
        if problem == "identity": payload["export_id"] = str(uuid4())
        if problem == "oversized": monkeypatch.setattr(collector, "MAX_RESPONSE_BYTES", 10)
        def send(request):
            calls.append(request)
            return httpx.Response(200, content=b"not json") if problem == "json" else httpx.Response(200, json=payload)
        with httpx.Client(transport=httpx.MockTransport(send)) as client:
            with pytest.raises(collector.CollectionError):
                collector.collect(store, client, config)
        assert store.state["pages"] == 0 and store.state["count"] == 0
        assert store.conn.execute("SELECT count(*) FROM events").fetchone()[0] == 0
    assert len(calls) == 1


def test_repeated_cursor_and_changed_snapshot_stop_before_commit(config, records, tmp_path):
    with collector.Store(tmp_path / "state", config) as store:
        store.commit_page(page(store, records[:3], cursor="next", total=10))
        second = page(store, records[3:6], cursor="next", total=10)
        with pytest.raises(collector.CollectionError, match="repeated cursor"):
            store.commit_page(second)
        second.update(next_cursor="third", snapshot_id=str(uuid4()))
        with pytest.raises(collector.CollectionError, match="metadata changed"):
            store.commit_page(second)
        assert store.state["count"] == 3


def test_conflicting_event_id_rolls_back_whole_page(config, records, tmp_path):
    with collector.Store(tmp_path / "state", config) as store:
        store.commit_page(page(store, records[:3], cursor="next", total=6))
        conflicting = {**records[5], "event_id": records[0]["event_id"]}
        with pytest.raises(collector.CollectionError, match="duplicate or conflicting"):
            store.commit_page(page(store, records[3:5] + [conflicting], total=6))
        assert store.conn.execute("SELECT count(*) FROM events").fetchone()[0] == 3
        assert store.state["next_cursor"] == "next"


def test_disk_failure_keeps_previous_progress(config, records, tmp_path):
    class FullDisk(sqlite3.Connection):
        def execute(self, sql, *args):
            if sql.startswith("UPDATE progress"):
                raise sqlite3.OperationalError("database or disk is full")
            return super().execute(sql, *args)
    path = tmp_path / "state"
    with collector.Store(path, config) as store:
        store.conn.close()
        store.conn = sqlite3.connect(path, factory=FullDisk)
        with pytest.raises(sqlite3.OperationalError):
            store.commit_page(page(store, records[:3], cursor="next", total=10))
        assert store.conn.execute("SELECT count(*) FROM events").fetchone()[0] == 0
    with collector.Store(path, config) as store:
        assert store.state["count"] == 0 and store.state["pages"] == 0


def test_output_failure_keeps_state_and_never_claims_completion(config, records, tmp_path, monkeypatch):
    output = tmp_path / "events.jsonl"
    original = os.replace
    def fail(source, destination):
        if str(destination).endswith(".manifest.json"):
            raise OSError("disk full")
        original(source, destination)
    with collector.Store(tmp_path / "state", config) as store:
        store.commit_page(page(store, records[:1]))
        monkeypatch.setattr(collector.os, "replace", fail)
        with pytest.raises(OSError):
            collector.export_output(store, output, "jsonl")
        assert store.state["complete"]
        assert not Path(str(output) + ".manifest.json").exists()
        monkeypatch.setattr(collector.os, "replace", original)
        assert collector.export_output(store, output, "jsonl")["complete"]


@pytest.mark.parametrize("point", ["before_commit", "after_commit"])
def test_killed_process_resumes_without_skipped_page(config, records, tmp_path, point):
    state = tmp_path / "state"
    with collector.Store(state, config): pass
    code = '''
import json, os, sqlite3, sys
from pathlib import Path
from scripts.collect_events import Config, Store
path, point, records = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
config = Config("http://127.0.0.1:8000", "export-test-secret", page_size=3)
with Store(Path(path), config) as store:
    if point == "before_commit":
        class Interrupted(sqlite3.Connection):
            def execute(self, sql, *args):
                if sql.startswith("UPDATE progress"): os._exit(19)
                return super().execute(sql, *args)
        store.conn.close()
        store.conn = sqlite3.connect(path, factory=Interrupted)
    store.commit_page({"items":records[:3], "next_cursor":"3", "total_count":10,
                       "snapshot_id":"00000000-0000-4000-8000-000000000001",
                       "export_id":store.state["export_id"], "expires_at":"2099-01-01T00:00:00Z"})
    os._exit(19)
'''
    result = subprocess.run([sys.executable, "-c", code, str(state), point, json.dumps(records)], timeout=15)
    assert result.returncode == 19
    calls = []
    with collector.Store(state, config) as store:
        assert store.state["count"] == (0 if point == "before_commit" else 3)
        snapshot = store.state["snapshot_id"]
        with server(records, calls) as original_client:
            def send(request):
                response = original_client.send(request)
                payload = response.json()
                if snapshot:
                    payload["snapshot_id"] = snapshot
                return httpx.Response(200, json=payload)
            with httpx.Client(transport=httpx.MockTransport(send)) as client:
                assert collector.collect(store, client, config)
        actual = [json.loads(row[0]) for row in store.conn.execute("SELECT payload FROM events ORDER BY ordinal")]
        assert actual == records
    assert calls[0].get("cursor") == (None if point == "before_commit" else "3")


def test_resume_rejects_config_changes_and_concurrent_writers(config, tmp_path):
    path = tmp_path / "state"
    with collector.Store(path, config):
        with pytest.raises(collector.CollectionError, match="another collector"):
            collector.Store(path, config)
    for changed in (replace(config, token="rotated"), replace(config, page_size=2), replace(config, filters={"actor_id": "someone"})):
        with pytest.raises(collector.CollectionError, match="configuration"):
            collector.Store(path, changed)


def test_cli_errors_are_sanitized(config, tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("EVENT_EXPORT_TOKEN", raising=False)
    assert collector.main(["--state", str(tmp_path / "state"), "--output", str(tmp_path / "output")]) == 1
    assert json.loads(capsys.readouterr().out)["state"] == "failed"


def test_retry_after_http_date_is_honored(config):
    header = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=10), usegmt=True)
    assert 8 <= collector.retry_delay(header, 0, config) <= 10


def test_expired_response_never_advances_state(config, records, tmp_path):
    with collector.Store(tmp_path / "state", config) as store:
        expired = page(store, records[:1]) | {"expires_at": "2000-01-01T00:00:00Z"}
        with pytest.raises(collector.CollectionError, match="expired"):
            store.commit_page(expired)
        assert store.state["count"] == 0


@pytest.mark.parametrize("suffix", ["", ".lock", "-journal", "-wal", "-shm"])
def test_output_cannot_overwrite_sqlite_files(config, records, tmp_path, suffix):
    path = tmp_path / "state"
    with collector.Store(path, config) as store:
        store.commit_page(page(store, records[:1]))
        with pytest.raises(collector.CollectionError, match="overwrite collection state"):
            collector.export_output(store, Path(str(path) + suffix), "jsonl")
