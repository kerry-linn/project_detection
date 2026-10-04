from __future__ import annotations

import argparse
import csv
import fcntl
import hashlib
import json
import math
import os
import random
import sqlite3
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx2 as httpx

from backend.config import require_env
from backend.repositories.exports import FILTERS
from security_events import parse_event
from security_events.validation import ALLOWED_FIELDS

MAX_RESPONSE_BYTES = 32 * 1024 * 1024
RETRY_STATUSES = {429, 500, 502, 503, 504}


class CollectionError(ValueError):
    pass


def json_text(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True)
class Config:
    base_url: str
    token: str = field(repr=False)
    page_size: int = 100
    filters: dict = field(default_factory=dict)
    connect_timeout: float = 5
    read_timeout: float = 30
    attempts: int = 5
    max_delay: float = 30
    wait_budget: float = 120

    def __post_init__(self):
        url = urlsplit(self.base_url)
        if (url.scheme not in {"http", "https"} or not url.hostname or url.username
                or url.password or url.query or url.fragment):
            raise CollectionError("base URL must be an HTTP(S) origin without credentials, query, or fragment")
        if url.scheme == "http" and url.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise CollectionError("HTTP is supported only for the local lab; use HTTPS elsewhere")
        if not self.token or not 1 <= self.page_size <= 1000 or not 1 <= self.attempts <= 10:
            raise CollectionError("credential, page size, or attempt limit is invalid")
        for value in (self.connect_timeout, self.read_timeout, self.max_delay, self.wait_budget):
            if not math.isfinite(value) or not 0 < value <= 300:
                raise CollectionError("timeouts and retry budgets must be positive and at most 300 seconds")
        if set(self.filters) - set(FILTERS) or any(not isinstance(v, str) or not 1 <= len(v) <= 256 for v in self.filters.values()):
            raise CollectionError("invalid export filter")

    def identity(self) -> dict:
        filters = dict(self.filters)
        if "attempted_account" in filters:
            filters["attempted_account"] = filters["attempted_account"].casefold()
        return {"base_url": self.base_url.rstrip("/"), "page_size": self.page_size,
                "filters": filters, "credential_hash": hashlib.sha256(self.token.encode()).hexdigest()}


def utc_timestamp(value) -> datetime:
    if not isinstance(value, str):
        raise CollectionError("response timestamp is invalid")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.utcoffset() is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except ValueError as error:
        raise CollectionError("response timestamp is invalid") from error


class Store:
    def __init__(self, path: Path, config: Config):
        self.path = path
        self.lock = None
        self.conn = None
        try:
            self.lock = os.fdopen(os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600), "a")
            try:
                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise CollectionError("another collector owns this state file") from error
            fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
            os.close(fd)
            self.conn = sqlite3.connect(path)
            self.conn.execute("PRAGMA synchronous=FULL")
            self.conn.executescript(
                "CREATE TABLE IF NOT EXISTS progress (id INTEGER PRIMARY KEY CHECK (id=1), value TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS events (event_id TEXT PRIMARY KEY, ordinal INTEGER UNIQUE NOT NULL, payload TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS cursors (token TEXT PRIMARY KEY);"
            )
            row = self.conn.execute("SELECT value FROM progress WHERE id=1").fetchone()
            if row:
                self.state = json.loads(row[0])
                if self.state.get("config") != config.identity() or self.state.get("version") != 1:
                    raise CollectionError("resume configuration or credential changed; use the original settings or a new state file")
            else:
                self.state = {"version": 1, "config": config.identity(), "export_id": str(uuid4()),
                              "snapshot_id": None, "next_cursor": None, "expires_at": None,
                              "total_count": None, "count": 0, "pages": 0, "complete": False,
                              "last_time": None, "last_id": None}
                with self.conn:
                    self.conn.execute("INSERT INTO progress VALUES (1, ?)", (json_text(self.state),))
            if self.conn.execute("SELECT count(*) FROM events").fetchone()[0] != self.state["count"]:
                raise CollectionError("state file is inconsistent; restore it or begin a new export")
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.conn is not None:
            self.conn.close()
        if self.lock is not None:
            self.lock.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def commit_page(self, page: dict):
        current = self.state
        required = {"items", "next_cursor", "snapshot_id", "export_id", "expires_at", "total_count"}
        if not isinstance(page, dict) or set(page) != required:
            raise CollectionError("invalid page schema")
        try:
            if str(UUID(page["snapshot_id"])) != page["snapshot_id"]:
                raise ValueError
        except (ValueError, TypeError, AttributeError) as error:
            raise CollectionError("invalid snapshot identity") from error
        if page["export_id"] != current["export_id"]:
            raise CollectionError("export identity changed")
        if utc_timestamp(page["expires_at"]) <= datetime.now(timezone.utc):
            raise CollectionError("snapshot expired; use a new state file")
        for key in ("snapshot_id", "expires_at", "total_count"):
            if current[key] is not None and page[key] != current[key]:
                raise CollectionError("snapshot metadata changed")
        total, items, cursor = page["total_count"], page["items"], page["next_cursor"]
        limit = current["config"]["page_size"]
        if type(total) is not int or total < 0 or not isinstance(items, list) or len(items) > limit:
            raise CollectionError("invalid page count or items")
        if cursor is not None and (not isinstance(cursor, str) or not 1 <= len(cursor) <= 512):
            raise CollectionError("invalid next cursor")
        if cursor is not None and (cursor == current["next_cursor"] or self.conn.execute("SELECT 1 FROM cursors WHERE token=?", (cursor,)).fetchone()):
            raise CollectionError("repeated cursor; collection stopped")
        count = current["count"] + len(items)
        if count > total or (cursor is None and count != total) or (cursor is not None and (count >= total or len(items) != limit)):
            raise CollectionError("page progress does not match the snapshot count")
        previous = (utc_timestamp(current["last_time"]), current["last_id"]) if current["last_time"] else None
        rows = []
        for ordinal, item in enumerate(items, start=current["count"] + 1):
            if not isinstance(item, dict) or set(item) != ALLOWED_FIELDS:
                raise CollectionError("invalid event schema")
            try:
                event = parse_event(item)
                payload = json_text(item)
            except (ValueError, TypeError) as error:
                raise CollectionError("invalid event content") from error
            order = (event.occurred_at, event.event_id)
            if previous is not None and order <= previous:
                raise CollectionError("events are repeated or out of order")
            previous = order
            rows.append((event.event_id, ordinal, payload))
        updated = dict(current, snapshot_id=page["snapshot_id"], expires_at=page["expires_at"],
                       total_count=total, next_cursor=cursor, count=count,
                       pages=current["pages"] + 1, complete=cursor is None)
        if previous:
            updated.update(last_time=previous[0].isoformat(), last_id=previous[1])
        try:
            with self.conn:
                self.conn.executemany("INSERT INTO events VALUES (?, ?, ?)", rows)
                self.conn.execute("INSERT INTO cursors VALUES (?)", (current["next_cursor"] or "",))
                self.conn.execute("UPDATE progress SET value=? WHERE id=1", (json_text(updated),))
        except sqlite3.IntegrityError as error:
            raise CollectionError("duplicate or conflicting event ID; page rolled back") from error
        self.state = updated


def retry_delay(header: str | None, attempt: int, config: Config) -> float:
    if header:
        try:
            delay = float(header)
        except ValueError:
            try:
                delay = (parsedate_to_datetime(header) - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError, OverflowError):
                delay = -1
        if math.isfinite(delay) and delay >= 0:
            if delay > config.max_delay:
                raise CollectionError("Retry-After exceeds the allowed wait; resume later")
            return delay
    return random.uniform(0, min(config.max_delay, 2 ** attempt))


def fetch_page(client, config: Config, state: dict, *, sleep=time.sleep, notify=lambda value: None) -> dict:
    params = {**state["config"]["filters"], "limit": config.page_size, "export_id": state["export_id"]}
    if state["next_cursor"]:
        params["cursor"] = state["next_cursor"]
    waited = 0.0
    for attempt in range(config.attempts):
        retry_after = None
        try:
            with client.stream("GET", config.base_url.rstrip("/") + "/security/events/export",
                               params=params, headers={"Authorization": "Bearer " + config.token}) as response:
                status = response.status_code
                if status == 200:
                    payload = bytearray()
                    for chunk in response.iter_bytes():
                        payload.extend(chunk)
                        if len(payload) > MAX_RESPONSE_BYTES:
                            raise CollectionError("export response exceeds the byte limit")
                    try:
                        return json.loads(payload)
                    except (ValueError, UnicodeError) as error:
                        raise CollectionError("invalid JSON response; page not saved") from error
                if status not in RETRY_STATUSES:
                    messages = {401: "credential invalid, expired, or revoked", 403: "credential cannot access this snapshot",
                                409: "export settings changed; use the original settings",
                                410: "snapshot expired or unavailable; use a new state file"}
                    raise CollectionError(messages.get(status, f"permanent HTTP error {status}"))
                retry_after = response.headers.get("Retry-After")
        except (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError):
            pass
        if attempt + 1 == config.attempts:
            raise CollectionError("transient failure exhausted the retry budget; resume using the same state file")
        delay = retry_delay(retry_after, attempt, config)
        if waited + delay > config.wait_budget:
            raise CollectionError("retry wait budget exceeded; resume later")
        notify({"state": "retrying", "retry": attempt + 1, "wait_seconds": round(delay, 3)})
        sleep(delay)
        waited += delay
    raise AssertionError("unreachable")


def collect(store: Store, client, config: Config, *, max_pages: int | None = None, notify=lambda value: None, sleep=time.sleep) -> bool:
    pages = 0
    while not store.state["complete"]:
        page = fetch_page(client, config, store.state, sleep=sleep, notify=notify)
        store.commit_page(page)
        pages += 1
        notify({"state": "collecting", "pages": store.state["pages"], "records": store.state["count"]})
        if max_pages is not None and pages >= max_pages:
            break
    return store.state["complete"]


def csv_cell(value):
    if isinstance(value, (dict, list)):
        value = json_text(value)
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _atomic_write(path: Path, write):
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as file:
            write(file)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def export_output(store: Store, output: Path, format: str) -> dict:
    if not store.state["complete"]:
        raise CollectionError("collection is incomplete")
    manifest_path = Path(str(output) + ".manifest.json")
    reserved = {Path(str(store.path) + suffix).resolve() for suffix in ("", ".lock", "-journal", "-wal", "-shm")}
    if output.resolve() in reserved or manifest_path.resolve() in reserved:
        raise CollectionError("output and manifest must not overwrite collection state")
    manifest_path.unlink(missing_ok=True)
    content_hash = hashlib.sha256()

    def write(file):
        writer = csv.DictWriter(file, fieldnames=sorted(ALLOWED_FIELDS)) if format == "csv" else None
        if writer:
            writer.writeheader()
        for (payload,) in store.conn.execute("SELECT payload FROM events ORDER BY ordinal"):
            content_hash.update((payload + "\n").encode())
            if writer:
                writer.writerow({key: csv_cell(value) for key, value in json.loads(payload).items()})
            else:
                file.write(payload + "\n")

    _atomic_write(output, write)
    file_hash = hashlib.sha256()
    with output.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            file_hash.update(chunk)
    manifest = {"format_version": 1, "format": format, "snapshot_id": store.state["snapshot_id"],
                "export_id": store.state["export_id"], "snapshot_expires_at": store.state["expires_at"],
                "filters": store.state["config"]["filters"], "event_count": store.state["count"],
                "content_sha256": content_hash.hexdigest(), "file_sha256": file_hash.hexdigest(),
                "complete": True, "csv_formula_prefix": "apostrophe" if format == "csv" else None}
    _atomic_write(manifest_path, lambda file: file.write(json_text(manifest) + "\n"))
    return manifest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Resume a frozen event export using a private SQLite state file.")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--token-env", default="EVENT_EXPORT_TOKEN")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--format", choices=("jsonl", "csv"), default="jsonl")
    parser.add_argument("--page-size", type=int, default=100)
    parser.add_argument("--connect-timeout", type=float, default=5)
    parser.add_argument("--read-timeout", type=float, default=30)
    parser.add_argument("--attempts", type=int, default=5)
    parser.add_argument("--max-delay", type=float, default=30)
    parser.add_argument("--wait-budget", type=float, default=120)
    parser.add_argument("--max-pages", type=int, help="Pause after this many newly committed pages")
    for key in FILTERS:
        parser.add_argument("--" + key.replace("_", "-"))
    args = parser.parse_args(argv)
    started = time.monotonic()
    notify = lambda value: print(json_text({**value, "elapsed_seconds": round(time.monotonic() - started, 3)}), flush=True)
    try:
        if args.max_pages is not None and args.max_pages < 1:
            raise CollectionError("max-pages must be positive")
        config = Config(args.base_url, require_env(args.token_env), args.page_size,
                        {key: getattr(args, key) for key in FILTERS if getattr(args, key) is not None},
                        args.connect_timeout, args.read_timeout, args.attempts, args.max_delay, args.wait_budget)
        with Store(args.state, config) as store, httpx.Client(
            timeout=httpx.Timeout(config.read_timeout, connect=config.connect_timeout),
            follow_redirects=False, trust_env=False,
        ) as client:
            if not collect(store, client, config, max_pages=args.max_pages, notify=notify):
                notify({"state": "paused", "pages": store.state["pages"], "records": store.state["count"]})
                return 2
            export_output(store, args.output, args.format)
            notify({"state": "complete", "pages": store.state["pages"], "records": store.state["count"]})
        return 0
    except CollectionError as error:
        notify({"state": "failed", "error": str(error)})
        return 1
    except (OSError, sqlite3.Error, httpx.HTTPError, RuntimeError):
        notify({"state": "failed", "error": "storage, configuration, or transport failure; committed state is retained"})
        return 1
    except KeyboardInterrupt:
        notify({"state": "interrupted", "error": "resume using the same state file"})
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
