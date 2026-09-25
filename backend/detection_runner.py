from __future__ import annotations

from typing import Callable

from backend.db import Connection
from backend.repositories.alerts import (
    CREATED,
    UNCHANGED,
    UPDATED,
    AlertRecord,
    denied_document_alert_record,
    failed_login_alert_record,
    save_alert,
)
from backend.repositories.detection_runs import (
    DetectionRunSummary,
    RuleRun,
    fail_run,
    finish_run,
    start_run,
)
from backend.repositories.events import load_events
from detections import denied_document_access, failed_login_success
from detections.denied_document_access import (
    DeniedDocumentAccessConfig,
    detect_repeated_denied_document_access,
)
from detections.failed_login_success import (
    FailedLoginSuccessConfig,
    detect_failed_logins_followed_by_success,
)
from security_events import SecurityEvent

Detector = Callable[[list[SecurityEvent]], list[AlertRecord]]


def run_failed_login_detection(
    conn: Connection, config: FailedLoginSuccessConfig | None = None
) -> DetectionRunSummary:
    """Run R1 over all stored events and persist the results."""
    rule_config = config or FailedLoginSuccessConfig()
    rule = RuleRun(
        rule_id=failed_login_success.RULE_ID,
        rule_version=failed_login_success.RULE_VERSION,
        threshold=rule_config.threshold,
        window_microseconds=rule_config.window_microseconds,
    )

    def detect(events: list[SecurityEvent]) -> list[AlertRecord]:
        alerts = detect_failed_logins_followed_by_success(events, rule_config)
        return [failed_login_alert_record(alert) for alert in alerts]

    return _run_detection(conn, rule, detect)


def run_denied_document_detection(
    conn: Connection, config: DeniedDocumentAccessConfig | None = None
) -> DetectionRunSummary:
    """Run R2 over all stored events and persist the results."""
    rule_config = config or DeniedDocumentAccessConfig()
    rule = RuleRun(
        rule_id=denied_document_access.RULE_ID,
        rule_version=denied_document_access.RULE_VERSION,
        threshold=rule_config.threshold,
        window_microseconds=rule_config.window_microseconds,
        cooldown_microseconds=rule_config.cooldown_microseconds,
    )

    def detect(events: list[SecurityEvent]) -> list[AlertRecord]:
        alerts = detect_repeated_denied_document_access(events, rule_config)
        return [denied_document_alert_record(alert) for alert in alerts]

    return _run_detection(conn, rule, detect)


def _run_detection(
    conn: Connection, rule: RuleRun, detect: Detector
) -> DetectionRunSummary:
    """`conn` must have no open transaction. The run record, the detection work,
    and a failure record each commit separately, so a failed run is still
    visible in detection_runs while none of its partial alert writes are.
    """
    with conn.transaction():
        run_id = start_run(conn, rule)

    try:
        with conn.transaction():
            summary = _detect_and_save(conn, run_id, rule, detect)
            finish_run(conn, summary)
    except Exception as error:
        with conn.transaction():
            fail_run(conn, run_id, f"{type(error).__name__}: {error}")
        raise

    return summary


def _detect_and_save(
    conn: Connection, run_id: int, rule: RuleRun, detect: Detector
) -> DetectionRunSummary:
    # Serializes concurrent detector runs; API reads of alerts are not blocked.
    conn.execute("LOCK TABLE alerts IN EXCLUSIVE MODE")

    events = load_events(conn)
    alerts = detect(events)

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
        rule_id=rule.rule_id,
        events_scanned=len(events),
        first_event_at=first_event_at,
        last_event_at=last_event_at,
        alerts_detected=len(alerts),
        alerts_created=outcomes[CREATED],
        alerts_updated=outcomes[UPDATED],
        alerts_unchanged=outcomes[UNCHANGED],
    )
