from __future__ import annotations

import json
import logging
from dataclasses import replace
from typing import Callable

import psycopg

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
    DetectionRunProgress,
    DetectionRunSummary,
    RuleRun,
    abandon_running_runs,
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
RUNNER_LOCK_KEY = 704511862
logger = logging.getLogger(__name__)


class RunnerBusy(RuntimeError):
    pass


class DetectionRunError(RuntimeError):
    def __init__(self, run_id: int, rule_id: str, category: str) -> None:
        super().__init__(f"run {run_id} ({rule_id}) failed: {category}")
        self.run_id = run_id
        self.rule_id = rule_id
        self.category = category


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
        locked = conn.execute(
            "SELECT pg_try_advisory_lock(%s) AS locked", (RUNNER_LOCK_KEY,)
        ).fetchone()["locked"]
    if not locked:
        raise RunnerBusy("another detector is running")
    try:
        with conn.transaction():
            abandoned = abandon_running_runs(conn)
            run_id = start_run(conn, rule)
        for abandoned_id in abandoned:
            logger.warning(
                json.dumps({"event": "detection_run_abandoned", "run_id": abandoned_id})
            )

        progress = DetectionRunProgress()
        try:
            with conn.transaction():
                summary = _detect_and_save(conn, run_id, rule, detect, progress)
                summary = replace(summary, duration_ms=finish_run(conn, summary))
        except Exception as error:
            category = _failure_category(error)
            try:
                with conn.transaction():
                    fail_run(conn, run_id, category, progress)
            except psycopg.Error:
                logger.error(
                    json.dumps(
                        {
                            "event": "detection_failure_record_unavailable",
                            "run_id": run_id,
                            "rule_id": rule.rule_id,
                            "category": category,
                        }
                    )
                )
            raise DetectionRunError(run_id, rule.rule_id, category) from None
        return summary
    finally:
        try:
            if not conn.closed:
                with conn.transaction():
                    conn.execute("SELECT pg_advisory_unlock(%s)", (RUNNER_LOCK_KEY,))
        except psycopg.Error:
            logger.error(json.dumps({"event": "detection_lock_release_unavailable"}))


def _failure_category(error: Exception) -> str:
    if isinstance(error, psycopg.OperationalError):
        return "database_unavailable"
    if isinstance(error, psycopg.Error):
        return "database_error"
    return "detector_error"


def _detect_and_save(
    conn: Connection,
    run_id: int,
    rule: RuleRun,
    detect: Detector,
    progress: DetectionRunProgress,
) -> DetectionRunSummary:
    conn.execute("LOCK TABLE alerts IN EXCLUSIVE MODE")

    events = load_events(conn)
    progress.events_scanned = len(events)
    if events:
        progress.first_event_at = events[0].occurred_at
        progress.last_event_at = events[-1].occurred_at
    alerts = detect(events)
    progress.alerts_detected = len(alerts)

    outcomes = {CREATED: 0, UPDATED: 0, UNCHANGED: 0}
    for alert in alerts:
        outcome = save_alert(conn, alert)
        outcomes[outcome] += 1

    return DetectionRunSummary(
        run_id=run_id,
        rule_id=rule.rule_id,
        rule_version=rule.rule_version,
        threshold=rule.threshold,
        window_microseconds=rule.window_microseconds,
        cooldown_microseconds=rule.cooldown_microseconds,
        events_scanned=len(events),
        first_event_at=progress.first_event_at,
        last_event_at=progress.last_event_at,
        alerts_detected=len(alerts),
        alerts_created=outcomes[CREATED],
        alerts_updated=outcomes[UPDATED],
        alerts_unchanged=outcomes[UNCHANGED],
    )
