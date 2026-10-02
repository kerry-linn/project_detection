from uuid import uuid4

from psycopg import sql

from backend.db import MIGRATIONS_DIR, connect
from backend.detection_runner import run_failed_login_detection
from backend.repositories.events import ingest_events, load_events
from scripts.benchmark_detection import reference_r1, synthetic_events
from detections.failed_login_success import detect_failed_logins_followed_by_success
from security_events import parse_event


def test_processing_migrations_preserve_existing_events(migrated_database_url):
    schema = "migration_test_" + uuid4().hex
    with connect(migrated_database_url) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        conn.execute(sql.SQL("SET search_path TO {}").format(sql.Identifier(schema)))
        conn.commit()
        try:
            migrations = sorted(MIGRATIONS_DIR.glob("*.sql"))
            for path in migrations:
                if path.name < "005":
                    conn.execute(path.read_text())
            events = synthetic_events(10, "hot")
            ingest_events(conn, events)
            conn.commit()
            for path in migrations:
                if path.name >= "005":
                    conn.execute(path.read_text())
            assert load_events(conn) == events
            assert conn.execute("SELECT count(*) AS n FROM detection_checkpoints").fetchone()["n"] == 0
            conn.commit()
            assert run_failed_login_detection(conn).alerts_created == 1
            conn.execute("SELECT pg_current_snapshot()")
            row = conn.execute(
                "SELECT bool_and(pg_visible_in_snapshot(processing_xid, pg_current_snapshot())) AS visible FROM security_events"
            ).fetchone()
            assert row["visible"]
        finally:
            conn.rollback()
            conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def test_benchmark_uses_valid_events_and_retains_the_full_scan_reference():
    for distribution in ("many", "hot"):
        events = synthetic_events(1000, distribution)
        assert [parse_event(event.to_dict()) for event in events] == events
        assert reference_r1(events) == detect_failed_logins_followed_by_success(events)
