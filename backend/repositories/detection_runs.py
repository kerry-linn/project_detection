from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from backend.db import Connection

MAX_ERROR_LENGTH = 1_000


@dataclass(frozen=True)
class RuleRun:
    """Rule identity and configuration recorded on every run."""

    rule_id: str
    rule_version: str
    threshold: int
    window_microseconds: int
    cooldown_microseconds: int | None = None


@dataclass(frozen=True)
class DetectionRunSummary:
    run_id: int
    rule_id: str
    rule_version: str
    threshold: int
    window_microseconds: int
    cooldown_microseconds: int | None
    events_scanned: int
    first_event_at: datetime | None
    last_event_at: datetime | None
    alerts_detected: int
    alerts_created: int
    alerts_updated: int
    alerts_unchanged: int
    duration_ms: int = 0


@dataclass
class DetectionRunProgress:
    events_scanned: int | None = None
    first_event_at: datetime | None = None
    last_event_at: datetime | None = None
    alerts_detected: int | None = None


def start_run(conn: Connection, rule: RuleRun) -> int:
    row = conn.execute(
        """
        INSERT INTO detection_runs (
            rule_id, rule_version, threshold, window_microseconds,
            cooldown_microseconds
        )
        VALUES (%s, %s, %s, %s, %s)
        RETURNING run_id
        """,
        (
            rule.rule_id,
            rule.rule_version,
            rule.threshold,
            rule.window_microseconds,
            rule.cooldown_microseconds,
        ),
    ).fetchone()
    return row["run_id"]


def finish_run(conn: Connection, summary: DetectionRunSummary) -> int:
    row = conn.execute(
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
            alerts_unchanged = %(alerts_unchanged)s,
            duration_ms = GREATEST(
                0, FLOOR(EXTRACT(EPOCH FROM (clock_timestamp() - started_at)) * 1000)
            )
        WHERE run_id = %(run_id)s
        RETURNING duration_ms
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
    ).fetchone()
    return row["duration_ms"]


def fail_run(
    conn: Connection, run_id: int, error: str, progress: DetectionRunProgress
) -> None:
    conn.execute(
        """
        UPDATE detection_runs
        SET status = 'failed',
            finished_at = clock_timestamp(),
            error = %s,
            duration_ms = GREATEST(
                0, FLOOR(EXTRACT(EPOCH FROM (clock_timestamp() - started_at)) * 1000)
            ),
            events_scanned = %s,
            first_event_at = %s,
            last_event_at = %s,
            alerts_detected = %s,
            alerts_created = 0,
            alerts_updated = 0,
            alerts_unchanged = 0
        WHERE run_id = %s
        """,
        (
            error[:MAX_ERROR_LENGTH],
            progress.events_scanned,
            progress.first_event_at,
            progress.last_event_at,
            progress.alerts_detected,
            run_id,
        ),
    )


def abandon_running_runs(conn: Connection) -> list[int]:
    rows = conn.execute(
        """
        UPDATE detection_runs
        SET status = 'abandoned',
            finished_at = clock_timestamp(),
            error = 'worker_exited_before_completion'
        WHERE status = 'running'
        RETURNING run_id
        """
    ).fetchall()
    return [row["run_id"] for row in rows]
