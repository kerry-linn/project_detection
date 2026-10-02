from __future__ import annotations

import argparse
import gc
import hashlib
import json
import platform
import random
import subprocess
import time
import tracemalloc
from dataclasses import asdict, fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4
from unittest.mock import patch

from psycopg import sql
from psycopg.types.json import Jsonb

from backend.config import require_env
from backend.db import apply_migrations, connect
from backend.detection_runner import run_failed_login_detection
from backend.r1_processing import R1ProcessingConfig, read_snapshot
from backend.repositories.alerts import failed_login_alert_record, list_alerts
from backend.repositories.events import SELECT_EVENT_COLUMNS, load_document_denials, load_events, load_login_events
from detections.denied_document_access import detect_repeated_denied_document_access
from detections.common import deduplicate_and_sort
from detections.failed_login_success import FailedLoginSuccessConfig, _build_alert, detect_failed_logins_followed_by_success
from security_events import SecurityEvent

SEED = 3101
END = datetime(2026, 1, 1, tzinfo=timezone.utc)


def synthetic_events(size: int, distribution: str) -> list[SecurityEvent]:
    randomizer = random.Random(SEED)
    start = END - timedelta(seconds=size * 6)
    events = []
    for index in range(size):
        position = index % 10
        group = 0 if distribution == "hot" else (index // 10) % 100
        account = f"user-{group}@example.test"
        occurred_at = start + timedelta(seconds=index * 6)
        event_type = "login_failed"
        outcome = "failure"
        resource_id = None
        if position == 5:
            event_type, outcome = "login_succeeded", "success"
        elif position >= 6:
            event_type = "access_denied" if position < 9 else "document_updated"
            outcome = "denied" if position < 9 else "success"
            resource_id = f"doc-{randomizer.randrange(20)}"
        events.append(SecurityEvent(
            event_id=f"bench-{index:07d}", occurred_at=occurred_at,
            ingested_at=occurred_at + timedelta(seconds=1), source="fixture",
            event_type=event_type, organization_id="bench-org",
            actor_id=f"user-{group}", attempted_account=account if position < 6 else None,
            target_actor_id=None, previous_role=None, new_role=None,
            session_id=f"session-{group}" if position >= 5 else None, source_ip="192.0.2.1",
            resource_type="document" if resource_id else None, resource_id=resource_id,
            outcome=outcome, request_id=f"bench-request-{index}",
            schema_version="1.0", metadata={},
        ))
    return events


def copy_events(conn, events: list[SecurityEvent]) -> None:
    columns = [field.name for field in fields(SecurityEvent)]
    statement = sql.SQL("COPY security_events ({}) FROM STDIN").format(
        sql.SQL(", ").join(map(sql.Identifier, columns))
    )
    with conn.cursor().copy(statement) as copy:
        for event in events:
            values = [getattr(event, column) for column in columns]
            values[-1] = Jsonb(event.metadata)
            copy.write_row(values)


def reference_r1(events):
    """Retain the pre-Section-3 full scan for reproducible baseline measurements.

    Alert construction is shared; window matching deliberately uses the old scan.
    """
    config = FailedLoginSuccessConfig()
    failures_by_entity = {}
    alerts = []
    for event in deduplicate_and_sort(events):
        if event.attempted_account is None:
            continue
        entity = (event.organization_id, event.attempted_account)
        if event.event_type == "login_failed":
            failures_by_entity.setdefault(entity, []).append(event)
        elif event.event_type == "login_succeeded":
            failures = []
            start = event.occurred_at - config.window
            for failure in failures_by_entity.get(entity, []):
                if start <= failure.occurred_at < event.occurred_at:
                    failures.append(failure)
            if len(failures) >= config.threshold:
                alerts.append(_build_alert(event, failures, config))
    return tuple(alerts)


def measure_evaluation(conn, rule: str, loader, *, baseline: bool = False) -> dict:
    detector = (
        detect_failed_logins_followed_by_success if rule == "r1"
        else detect_repeated_denied_document_access
    )
    if baseline and rule == "r1":
        detector = reference_r1
    gc.collect()
    tracemalloc.start()
    started = time.perf_counter()
    events = loader(conn)
    alerts = detector(events)
    seconds = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    digest = hashlib.sha256()
    for alert in alerts:
        digest.update(json.dumps(asdict(alert), sort_keys=True, default=str).encode())
    return {
        "rule": rule, "seconds": round(seconds, 6),
        "peak_python_mib": round(peak / 1024**2, 3),
        "events_read": len(events), "alerts": len(alerts),
        "result_sha256": digest.hexdigest(),
    }


def query_plans(conn) -> dict:
    login_filter = "event_type IN ('login_failed', 'login_succeeded') AND attempted_account IS NOT NULL"
    denial_filter = (
        "event_type = 'access_denied' AND resource_type = 'document' "
        "AND organization_id IS NOT NULL AND actor_id IS NOT NULL AND resource_id IS NOT NULL"
    )
    snapshot = conn.execute("SELECT pg_current_snapshot()::text AS snapshot").fetchone()["snapshot"]
    queries = {
        "r1_full": (f"SELECT {SELECT_EVENT_COLUMNS} FROM security_events WHERE {login_filter} ORDER BY occurred_at, event_id", ()),
        "r2_full": (f"SELECT {SELECT_EVENT_COLUMNS} FROM security_events WHERE {denial_filter} ORDER BY occurred_at, event_id", ()),
        "r1_bounded": (
            f"SELECT {SELECT_EVENT_COLUMNS} FROM security_events WHERE {login_filter} "
            "AND occurred_at <= %s AND occurred_at >= %s "
            "AND ((event_type = 'login_failed' AND occurred_at >= %s) "
            "OR (event_type = 'login_succeeded' AND occurred_at >= %s)) ORDER BY occurred_at, event_id",
            (END, END - timedelta(minutes=25), END - timedelta(minutes=25), END - timedelta(minutes=15)),
        ),
        "r1_newly_visible": (
            f"SELECT count(*) FROM security_events WHERE {login_filter} AND occurred_at < %s "
            "AND processing_xid >= pg_snapshot_xmin(%s::pg_snapshot) "
            "AND NOT pg_visible_in_snapshot(processing_xid, %s::pg_snapshot)",
            (END - timedelta(minutes=15), snapshot, snapshot),
        ),
    }
    plans = {}
    for name, (query, params) in queries.items():
        plans[name] = conn.execute("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + query, params).fetchone()["QUERY PLAN"]
    return plans


def measure_persisted_run(conn, at: datetime, mode: str) -> dict:
    def fixed_clock(connection):
        _, snapshot = read_snapshot(connection)
        return at, snapshot

    conn.commit()
    gc.collect()
    tracemalloc.start()
    started = time.perf_counter()
    with patch("backend.r1_processing.read_snapshot", fixed_clock):
        summary = run_failed_login_detection(conn, processing=R1ProcessingConfig(mode=mode))
    seconds = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "mode": mode, "seconds": round(seconds, 6), "peak_python_mib": round(peak / 1024**2, 3),
        "events_read": summary.events_scanned, "alerts_evaluated": summary.alerts_detected,
        "created": summary.alerts_created, "updated": summary.alerts_updated,
        "unchanged": summary.alerts_unchanged, "backfill_required": summary.backfill_required,
    }


def verify_persisted_parity(conn) -> int:
    expected = {
        alert.alert_key: asdict(failed_login_alert_record(alert))
        for alert in detect_failed_logins_followed_by_success(load_events(conn))
    }
    actual = {}
    evidence = {}
    for link in conn.execute("SELECT * FROM alert_events"):
        evidence.setdefault(link["alert_key"], set()).add((link["event_id"], link["evidence_role"]))
    for alert in list_alerts(conn):
        row = asdict(alert)
        for field in ("status", "detection_state", "needs_review", "created_at", "updated_at"):
            del row[field]
        row["evidence"] = frozenset(evidence[alert.alert_key])
        actual[alert.alert_key] = row
    if actual != expected:
        raise AssertionError("persisted incremental results differ from full history")
    return len(actual)


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark in a disposable test-DB schema.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sizes", type=int, nargs="+", default=[1000, 10000, 100000])
    parser.add_argument("--phase", choices=["baseline", "optimized"], default="baseline")
    parser.add_argument("--compare", type=Path, help="Require full-result digests to match a baseline JSON")
    args = parser.parse_args()
    schema = "detection_benchmark_" + uuid4().hex
    report = {
        "seed": SEED, "python": platform.python_version(), "platform": platform.platform(),
        "machine": platform.machine(),
        "dirty_worktree": bool(subprocess.check_output(["git", "status", "--porcelain"], text=True).strip()),
        "dataset": "6-second spacing; 50% failed login, 10% successful login, 30% document denial, 10% document update; 100 accounts or one hot account",
        "simulated_checkpoint_time": END.isoformat(),
        "revision": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "measurement": "load plus pure detection; tracemalloc Python allocations; excludes writes",
        "phase": args.phase,
        "datasets": [],
    }
    with connect(require_env("TEST_DATABASE_URL")) as conn:
        if not conn.info.dbname.endswith("_test"):
            raise ValueError("benchmark requires a database ending in _test")
        report["postgres"] = conn.execute("SHOW server_version").fetchone()["server_version"]
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.commit()
        try:
            apply_migrations(conn)
            conn.commit()
            for size in args.sizes:
                for distribution in ("many", "hot"):
                    conn.execute("TRUNCATE security_events, alerts, alert_events, alert_replacements, detection_runs, detection_checkpoints")
                    conn.execute("DROP INDEX IF EXISTS security_events_r1_visibility_idx")
                    copy_events(conn, synthetic_events(size, distribution))
                    conn.execute("ANALYZE security_events")
                    conn.commit()
                    dataset = {"size": size, "distribution": distribution, "evaluations": []}
                    for rule in ("r1", "r2"):
                        loader = load_events
                        if args.phase == "optimized":
                            loader = load_login_events if rule == "r1" else load_document_denials
                        result = measure_evaluation(conn, rule, loader, baseline=args.phase == "baseline")
                        dataset["evaluations"].append(result)
                        print(size, distribution, result, flush=True)
                    dataset["full_plan"] = conn.execute(
                        "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "
                        "SELECT * FROM security_events ORDER BY occurred_at, event_id"
                    ).fetchone()["QUERY PLAN"]
                    if args.phase == "optimized":
                        dataset["plans_before_index"] = query_plans(conn)
                        conn.execute(
                            "CREATE INDEX security_events_r1_visibility_idx ON security_events (processing_xid) "
                            "WHERE event_type IN ('login_failed', 'login_succeeded') AND attempted_account IS NOT NULL"
                        )
                        conn.execute("ANALYZE security_events")
                        dataset["plans_after_index"] = query_plans(conn)
                        dataset["persisted_runs"] = [measure_persisted_run(conn, END, "full")]
                        new_events = [
                            replace(event, event_id="new-" + event.event_id,
                                    occurred_at=event.occurred_at + timedelta(minutes=1),
                                    ingested_at=event.ingested_at + timedelta(minutes=1))
                            for event in synthetic_events(10, distribution)
                        ]
                        copy_events(conn, new_events)
                        conn.commit()
                        dataset["persisted_runs"].append(measure_persisted_run(conn, END + timedelta(minutes=1), "incremental"))
                        dataset["persisted_alert_count"] = verify_persisted_parity(conn)
                        dataset["persisted_parity"] = True
                    if args.compare:
                        baseline = json.loads(args.compare.read_text())
                        previous = next(item for item in baseline["datasets"] if item["size"] == size and item["distribution"] == distribution)
                        for old, new in zip(previous["evaluations"], dataset["evaluations"]):
                            if old["result_sha256"] != new["result_sha256"]:
                                raise AssertionError(f"full result mismatch: {size} {distribution} {new['rule']}")
                        dataset["baseline_parity"] = True
                    report["datasets"].append(dataset)
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(json.dumps(report, indent=2) + "\n")
        finally:
            conn.rollback()
            conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


if __name__ == "__main__":
    main()
