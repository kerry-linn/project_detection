from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterator, Literal

from backend.db import Connection
from backend.repositories.checkpoints import Checkpoint, get_checkpoint
from backend.repositories.detection_runs import RuleRun
from backend.repositories.events import load_login_events
from detections.common import duration_microseconds
from security_events import SecurityEvent


class CheckpointRequired(RuntimeError):
    pass


class CheckpointClockRegression(RuntimeError):
    pass


@dataclass(frozen=True)
class R1ProcessingConfig:
    mode: Literal["full", "incremental"] = "full"
    allowed_lateness: timedelta = timedelta(minutes=15)
    chunk_span: timedelta = timedelta(hours=1)

    def __post_init__(self) -> None:
        if self.mode not in {"full", "incremental"}:
            raise ValueError("unknown processing mode")
        if self.allowed_lateness < timedelta(0):
            raise ValueError("allowed lateness must not be negative")
        if self.chunk_span <= timedelta(0):
            raise ValueError("chunk span must be positive")


@dataclass(frozen=True)
class R1Scan:
    checkpoint: Checkpoint
    candidate_start: datetime | None
    late_events_detected: int
    future_events_deferred: int


def read_snapshot(conn: Connection) -> tuple[datetime, str]:
    row = conn.execute(
        "SELECT statement_timestamp() AS upper_bound, pg_current_snapshot()::text AS snapshot"
    ).fetchone()
    return row["upper_bound"], row["snapshot"]


def prepare_scan(conn: Connection, rule: RuleRun, config: R1ProcessingConfig) -> R1Scan:
    upper, snapshot = read_snapshot(conn)
    lateness_us = duration_microseconds(config.allowed_lateness)
    candidate_start = None
    late_count = 0
    backfill_required = False
    if config.mode == "incremental":
        previous = get_checkpoint(conn, rule)
        if previous is None or previous.allowed_lateness_microseconds != lateness_us:
            raise CheckpointRequired("run full R1 to initialize this configuration")
        if upper < previous.upper_bound:
            raise CheckpointClockRegression("database clock precedes checkpoint")
        candidate_start = previous.upper_bound - config.allowed_lateness
        late_count = conn.execute(
            """
            SELECT COUNT(*) AS count FROM security_events
            WHERE event_type IN ('login_failed', 'login_succeeded')
              AND attempted_account IS NOT NULL AND occurred_at < %s
              AND processing_xid >= pg_snapshot_xmin(%s::pg_snapshot)
              AND NOT pg_visible_in_snapshot(processing_xid, %s::pg_snapshot)
            """,
            (candidate_start, previous.visibility_snapshot, previous.visibility_snapshot),
        ).fetchone()["count"]
        backfill_required = previous.backfill_required or late_count > 0
    future_count = conn.execute(
        """
        SELECT COUNT(*) AS count FROM security_events
        WHERE event_type IN ('login_failed', 'login_succeeded')
          AND attempted_account IS NOT NULL AND occurred_at > %s
        """,
        (upper,),
    ).fetchone()["count"]
    return R1Scan(
        checkpoint=Checkpoint(upper, snapshot, lateness_us, backfill_required),
        candidate_start=candidate_start,
        late_events_detected=late_count,
        future_events_deferred=future_count,
    )


def event_batches(
    conn: Connection, rule: RuleRun, config: R1ProcessingConfig, scan: R1Scan
) -> Iterator[list[SecurityEvent]]:
    upper = scan.checkpoint.upper_bound
    if scan.candidate_start is None:
        yield load_login_events(conn, upper=upper)
        return

    start = scan.candidate_start
    include_start = True
    while True:
        end = min(start + config.chunk_span, upper)
        yield load_login_events(
            conn, upper=end, success_start=start,
            failure_start=start - timedelta(microseconds=rule.window_microseconds),
            include_start=include_start,
        )
        if end == upper:
            return
        start = end
        # A success at a shared boundary belongs to the preceding chunk.
        include_start = False
