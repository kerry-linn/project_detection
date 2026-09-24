from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from backend.db import Connection
from detections.failed_login_success import (
    RULE_ID,
    RULE_VERSION,
    FailedLoginSuccessConfig,
)

MAX_ERROR_LENGTH = 1_000


@dataclass(frozen=True)
class DetectionRunSummary:
    run_id: int
    events_scanned: int
    first_event_at: datetime | None
    last_event_at: datetime | None
    alerts_detected: int
    alerts_created: int
    alerts_updated: int
    alerts_unchanged: int


def start_run(conn: Connection, config: FailedLoginSuccessConfig) -> int:
    row = conn.execute(
        """
        INSERT INTO detection_runs (
            rule_id, rule_version, threshold, window_microseconds
        )
        VALUES (%s, %s, %s, %s)
        RETURNING run_id
        """,
        (RULE_ID, RULE_VERSION, config.threshold, config.window_microseconds),
    ).fetchone()
    return row["run_id"]


def finish_run(conn: Connection, summary: DetectionRunSummary) -> None:
    conn.execute(
        """
        UPDATE detection_runs
        SET status = 'succeeded',
            finished_at = clock_timestamp(),
            events_scanned = %(events_scanned)s,
            first_event_at = %(first_event_at)s,
            last_event_at = %(last_event_at)s,
            alerts_detected = %(alerts_detected)s,
            alerts_created = %(alerts_created)s,
            alerts_updated = %(alerts_updated)s,
            alerts_unchanged = %(alerts_unchanged)s
        WHERE run_id = %(run_id)s
        """,
        {
            "run_id": summary.run_id,
            "events_scanned": summary.events_scanned,
            "first_event_at": summary.first_event_at,
            "last_event_at": summary.last_event_at,
            "alerts_detected": summary.alerts_detected,
            "alerts_created": summary.alerts_created,
            "alerts_updated": summary.alerts_updated,
            "alerts_unchanged": summary.alerts_unchanged,
        },
    )


def fail_run(conn: Connection, run_id: int, error: str) -> None:
    conn.execute(
        """
        UPDATE detection_runs
        SET status = 'failed',
            finished_at = clock_timestamp(),
            error = %s
        WHERE run_id = %s
        """,
        (error[:MAX_ERROR_LENGTH], run_id),
    )
