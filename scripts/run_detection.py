from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from datetime import timedelta
from typing import Sequence

from backend.config import require_env
from backend.db import connect
from backend.detection_runner import run_failed_login_detection
from detections.failed_login_success import (
    DEFAULT_THRESHOLD,
    DEFAULT_WINDOW,
    FailedLoginSuccessConfig,
)
from scripts.detect_r1 import positive_int
from security_events import format_utc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run R1 over events stored in PostgreSQL and save alerts."
    )
    parser.add_argument(
        "--threshold",
        type=positive_int,
        default=DEFAULT_THRESHOLD,
        help=f"Required failure count (default: {DEFAULT_THRESHOLD})",
    )
    parser.add_argument(
        "--window-minutes",
        type=positive_int,
        default=int(DEFAULT_WINDOW.total_seconds() // 60),
        help="Lookback window in minutes (default: 10)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = FailedLoginSuccessConfig(
        threshold=args.threshold,
        window=timedelta(minutes=args.window_minutes),
    )

    with connect(require_env("DATABASE_URL")) as conn:
        summary = run_failed_login_detection(conn, config)

    report = asdict(summary)
    for field in ["first_event_at", "last_event_at"]:
        if report[field] is not None:
            report[field] = format_utc(report[field])
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
