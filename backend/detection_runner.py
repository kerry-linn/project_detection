from __future__ import annotations

import json
import logging
from dataclasses import replace
from typing import Callable

import psycopg

from backend.db import Connection
from backend.r1_processing import (
    CheckpointClockRegression,
    CheckpointRequired,
    R1ProcessingConfig,
    event_batches,
    prepare_scan,
)
from backend.repositories.alerts import (
    CREATED,
    UNCHANGED,
    UPDATED,
    AlertRecord,
    denied_document_alert_record,
    failed_login_alert_record,
    reconcile_denied_document_alerts,
    save_alert,
)
from backend.repositories.checkpoints import save_checkpoint
from backend.repositories.detection_runs import (
    DetectionRunProgress,
    DetectionRunSummary,
    RuleRun,
    abandon_running_runs,
    fail_run,
    finish_run,
    start_run,
)
from backend.repositories.events import load_document_denials
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
    conn: Connection,
    config: FailedLoginSuccessConfig | None = None,
    *,
    processing: R1ProcessingConfig | None = None,
) -> DetectionRunSummary:
    """Full history by default; incremental runs require a full baseline first."""
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

    return _run_detection(conn, rule, detect, processing or R1ProcessingConfig())


def run_denied_document_detection(
    conn: Connection, config: DeniedDocumentAccessConfig | None = None
) -> DetectionRunSummary:
    """Run R2 over complete stored document-denial histories."""
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
    conn: Connection,
    rule: RuleRun,
    detect: Detector,
    processing: R1ProcessingConfig | None = None,
) -> DetectionRunSummary:
    """`conn` must have no open transaction.

    The session advisory lock spans the separately committed run record and
    detection work. A failed work transaction rolls back before its failure
    record is committed. The lock is released only after that recovery attempt.
    """
    with conn.transaction():
        lock_acquired = conn.execute(
            "SELECT pg_try_advisory_lock(%s) AS locked", (RUNNER_LOCK_KEY,)
        ).fetchone()["locked"]
    if not lock_acquired:
        raise RunnerBusy("another detector is running")
    try:
        with conn.transaction():
            abandoned_run_ids = abandon_running_runs(conn)
            mode = processing.mode if processing else "full"
            run_id = start_run(conn, rule, mode)
        for abandoned_id in abandoned_run_ids:
            logger.warning(
                json.dumps({"event": "detection_run_abandoned", "run_id": abandoned_id})
            )

        progress = DetectionRunProgress()
        try:
            with conn.transaction():
                conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                summary = _detect_and_save(conn, run_id, rule, detect, progress, processing)
                duration_ms = finish_run(conn, summary)
                summary = replace(summary, duration_ms=duration_ms)
        except Exception as error:
            category = _failure_category(error)
            _record_failed_run(conn, run_id, rule.rule_id, category, progress)
            raise DetectionRunError(run_id, rule.rule_id, category) from None
        return summary
    finally:
        _release_runner_lock(conn)


def _record_failed_run(
    conn: Connection,
    run_id: int,
    rule_id: str,
    category: str,
    progress: DetectionRunProgress,
) -> None:
    """Commit the failure after the detection transaction has rolled back."""
    try:
        with conn.transaction():
            fail_run(conn, run_id, category, progress)
    except psycopg.Error:
        logger.error(
            json.dumps(
                {
                    "event": "detection_failure_record_unavailable",
                    "run_id": run_id,
                    "rule_id": rule_id,
                    "category": category,
                }
            )
        )


def _release_runner_lock(conn: Connection) -> None:
    try:
        if conn.closed:
            return
        with conn.transaction():
            conn.execute("SELECT pg_advisory_unlock(%s)", (RUNNER_LOCK_KEY,))
    except psycopg.Error:
        logger.error(json.dumps({"event": "detection_lock_release_unavailable"}))


def _failure_category(error: Exception) -> str:
    if isinstance(error, CheckpointRequired):
        return "checkpoint_required"
    if isinstance(error, CheckpointClockRegression):
        return "checkpoint_clock_regression"
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
    processing: R1ProcessingConfig | None = None,
) -> DetectionRunSummary:
    conn.execute("LOCK TABLE alerts IN EXCLUSIVE MODE")
    scan = None
    if processing is not None:
        scan = prepare_scan(conn, rule, processing)
        batches = event_batches(conn, rule, processing, scan)
    else:
        batches = [load_document_denials(conn)]

    progress.events_scanned = 0
    progress.alerts_detected = 0
    outcomes = {CREATED: 0, UPDATED: 0, UNCHANGED: 0}
    chunks_processed = 0
    for events in batches:
        _record_loaded_events(progress, events)
        alerts = detect(events)
        progress.alerts_detected += len(alerts)
        if rule.rule_id == denied_document_access.RULE_ID:
            outcomes = reconcile_denied_document_alerts(conn, alerts, rule)
        else:
            for alert in alerts:
                outcome = save_alert(conn, alert)
                outcomes[outcome] += 1
        chunks_processed += 1

    if scan is not None:
        save_checkpoint(conn, rule, scan.checkpoint)

    return DetectionRunSummary(
        run_id=run_id,
        rule_id=rule.rule_id,
        rule_version=rule.rule_version,
        threshold=rule.threshold,
        window_microseconds=rule.window_microseconds,
        cooldown_microseconds=rule.cooldown_microseconds,
        events_scanned=progress.events_scanned,
        first_event_at=progress.first_event_at,
        last_event_at=progress.last_event_at,
        alerts_detected=progress.alerts_detected,
        alerts_created=outcomes[CREATED],
        alerts_updated=outcomes[UPDATED],
        alerts_unchanged=outcomes[UNCHANGED],
        processing_mode=processing.mode if processing else "full",
        candidate_start=scan.candidate_start if scan else None,
        checkpoint_at=scan.checkpoint.upper_bound if scan else None,
        chunks_processed=chunks_processed,
        late_events_detected=scan.late_events_detected if scan else 0,
        future_events_deferred=scan.future_events_deferred if scan else 0,
        backfill_required=scan.checkpoint.backfill_required if scan else False,
    )


def _record_loaded_events(progress: DetectionRunProgress, events: list[SecurityEvent]) -> None:
    progress.events_scanned += len(events)
    if not events:
        return
    first, last = events[0].occurred_at, events[-1].occurred_at
    if progress.first_event_at is None or first < progress.first_event_at:
        progress.first_event_at = first
    if progress.last_event_at is None or last > progress.last_event_at:
        progress.last_event_at = last
