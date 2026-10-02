from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from backend.db import Connection
from backend.repositories.detection_runs import RuleRun


@dataclass(frozen=True)
class Checkpoint:
    upper_bound: datetime
    visibility_snapshot: str
    allowed_lateness_microseconds: int
    backfill_required: bool


def get_checkpoint(conn: Connection, rule: RuleRun) -> Checkpoint | None:
    row = conn.execute(
        """
        SELECT upper_bound, visibility_snapshot::text,
               allowed_lateness_microseconds, backfill_required
        FROM detection_checkpoints
        WHERE rule_id = %s AND rule_version = %s
          AND threshold = %s AND window_microseconds = %s
        """,
        (rule.rule_id, rule.rule_version, rule.threshold, rule.window_microseconds),
    ).fetchone()
    return Checkpoint(**row) if row is not None else None


def save_checkpoint(conn: Connection, rule: RuleRun, checkpoint: Checkpoint) -> None:
    """Caller holds the runner lock and commits this with alerts and run success."""
    conn.execute(
        """
        INSERT INTO detection_checkpoints (
            rule_id, rule_version, threshold, window_microseconds,
            upper_bound, visibility_snapshot, allowed_lateness_microseconds,
            backfill_required
        ) VALUES (%s, %s, %s, %s, %s, %s::pg_snapshot, %s, %s)
        ON CONFLICT (rule_id, rule_version, threshold, window_microseconds)
        DO UPDATE SET upper_bound = EXCLUDED.upper_bound,
            visibility_snapshot = EXCLUDED.visibility_snapshot,
            allowed_lateness_microseconds = EXCLUDED.allowed_lateness_microseconds,
            backfill_required = EXCLUDED.backfill_required
        """,
        (
            rule.rule_id, rule.rule_version, rule.threshold, rule.window_microseconds,
            checkpoint.upper_bound, checkpoint.visibility_snapshot,
            checkpoint.allowed_lateness_microseconds, checkpoint.backfill_required,
        ),
    )
