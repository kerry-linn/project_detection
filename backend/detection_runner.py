from __future__ import annotations

from backend.db import Connection
from backend.repositories.alerts import CREATED, UNCHANGED, UPDATED, save_alert
from backend.repositories.detection_runs import (
    DetectionRunSummary,
    fail_run,
    finish_run,
    start_run,
)
from backend.repositories.events import load_events
from detections.failed_login_success import (
    FailedLoginSuccessConfig,
    detect_failed_logins_followed_by_success,
)


def run_failed_login_detection(
    conn: Connection, config: FailedLoginSuccessConfig | None = None
) -> DetectionRunSummary:
    """Run R1 over all stored events and persist the results.

    `conn` must have no open transaction. The run record, the detection work,
    and a failure record each commit separately, so a failed run is still
    visible in detection_runs while none of its partial alert writes are.
    """
    rule_config = config or FailedLoginSuccessConfig()

    with conn.transaction():
        run_id = start_run(conn, rule_config)

    try:
        with conn.transaction():
            summary = _detect_and_save(conn, run_id, rule_config)
            finish_run(conn, summary)
    except Exception as error:
        with conn.transaction():
            fail_run(conn, run_id, f"{type(error).__name__}: {error}")
        raise

    return summary


def _detect_and_save(
    conn: Connection, run_id: int, config: FailedLoginSuccessConfig
) -> DetectionRunSummary:
    # Serializes concurrent detector runs; API reads of alerts are not blocked.
    conn.execute("LOCK TABLE alerts IN EXCLUSIVE MODE")

    events = load_events(conn)
    alerts = detect_failed_logins_followed_by_success(events, config)

    outcomes = {CREATED: 0, UPDATED: 0, UNCHANGED: 0}
    for alert in alerts:
        outcome = save_alert(conn, alert)
        outcomes[outcome] += 1

    first_event_at = None
    last_event_at = None
    if events:
        first_event_at = events[0].occurred_at
        last_event_at = events[-1].occurred_at

    return DetectionRunSummary(
        run_id=run_id,
        events_scanned=len(events),
        first_event_at=first_event_at,
        last_event_at=last_event_at,
        alerts_detected=len(alerts),
        alerts_created=outcomes[CREATED],
        alerts_updated=outcomes[UPDATED],
        alerts_unchanged=outcomes[UNCHANGED],
    )
