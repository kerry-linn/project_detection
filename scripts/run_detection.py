from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from datetime import timedelta
from typing import Sequence

import psycopg

from backend.config import require_env
from backend.db import connect
from backend.detection_runner import (
    DetectionRunError,
    RunnerBusy,
    run_denied_document_detection,
    run_failed_login_detection,
)
from detections import denied_document_access, failed_login_success
from detections.denied_document_access import DeniedDocumentAccessConfig
from detections.failed_login_success import FailedLoginSuccessConfig
from scripts.detect_r1 import positive_int
from security_events import format_utc


def _minutes(duration: timedelta) -> int:
    return int(duration.total_seconds() // 60)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run detections over events stored in PostgreSQL and save alerts."
    )
    parser.add_argument(
        "--rule",
        choices=["r1", "r2", "all"],
        default="all",
        help="Which rule to run (default: all)",
    )
    parser.add_argument(
        "--threshold",
        type=positive_int,
        default=failed_login_success.DEFAULT_THRESHOLD,
        help="R1 required failure count "
        f"(default: {failed_login_success.DEFAULT_THRESHOLD})",
    )
    parser.add_argument(
        "--window-minutes",
        type=positive_int,
        default=_minutes(failed_login_success.DEFAULT_WINDOW),
        help="R1 lookback window in minutes "
        f"(default: {_minutes(failed_login_success.DEFAULT_WINDOW)})",
    )
    parser.add_argument(
        "--r2-threshold",
        type=positive_int,
        default=denied_document_access.DEFAULT_THRESHOLD,
        help="R2 required distinct denied documents "
        f"(default: {denied_document_access.DEFAULT_THRESHOLD})",
    )
    parser.add_argument(
        "--r2-window-minutes",
        type=positive_int,
        default=_minutes(denied_document_access.DEFAULT_WINDOW),
        help="R2 rolling window in minutes "
        f"(default: {_minutes(denied_document_access.DEFAULT_WINDOW)})",
    )
    parser.add_argument(
        "--r2-cooldown-minutes",
        type=positive_int,
        default=_minutes(denied_document_access.DEFAULT_COOLDOWN),
        help="R2 inactivity cooldown that closes an episode "
        f"(default: {_minutes(denied_document_access.DEFAULT_COOLDOWN)})",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    selected = []
    if args.rule in {"r1", "all"}:
        selected.append((
            failed_login_success.RULE_ID,
            run_failed_login_detection,
            FailedLoginSuccessConfig(
                threshold=args.threshold,
                window=timedelta(minutes=args.window_minutes),
            ),
        ))
    if args.rule in {"r2", "all"}:
        selected.append((
            denied_document_access.RULE_ID,
            run_denied_document_detection,
            DeniedDocumentAccessConfig(
                threshold=args.r2_threshold,
                window=timedelta(minutes=args.r2_window_minutes),
                cooldown=timedelta(minutes=args.r2_cooldown_minutes),
            ),
        ))

    reports = []
    for rule_id, run, config in selected:
        try:
            with connect(require_env("DATABASE_URL")) as conn:
                summary = run(conn, config)
            report = asdict(summary)
            report["status"] = "succeeded"
            for field in ("first_event_at", "last_event_at"):
                if report[field] is not None:
                    report[field] = format_utc(report[field])
        except DetectionRunError as error:
            report = {
                "run_id": error.run_id,
                "rule_id": rule_id,
                "status": "failed",
                "category": error.category,
            }
        except RunnerBusy:
            report = {"rule_id": rule_id, "status": "busy"}
        except psycopg.OperationalError:
            report = {
                "rule_id": rule_id,
                "status": "failed",
                "category": "database_unavailable",
            }
        reports.append(report)
    print(json.dumps(reports, indent=2))
    return 0 if all(report["status"] == "succeeded" for report in reports) else 1


if __name__ == "__main__":
    raise SystemExit(main())
