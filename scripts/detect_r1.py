from __future__ import annotations

import argparse
import json
from datetime import timedelta
from pathlib import Path
from typing import Sequence

from detections.failed_login_success import (
    DEFAULT_THRESHOLD,
    DEFAULT_WINDOW,
    FailedLoginSuccessConfig,
    detect_failed_logins_followed_by_success,
)
from security_events import parse_jsonl


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Detect failed logins followed by a successful login in JSONL "
            "security events."
        )
    )
    parser.add_argument("path", type=Path, help="Path to a JSONL event file")
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
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with status 2 when any records are rejected",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = parse_jsonl(args.path)
    except OSError as error:
        print(
            json.dumps({"error": f"Unable to read {args.path}: {error}"}),
        )
        return 1

    config = FailedLoginSuccessConfig(
        threshold=args.threshold,
        window=timedelta(minutes=args.window_minutes),
    )
    alerts = detect_failed_logins_followed_by_success(result.events, config)
    report = {
        "lines_read": result.lines_read,
        "valid_events": len(result.events),
        "rejected_records": [
            {
                "line_number": record.line_number,
                "reason": record.reason,
            }
            for record in result.rejected
        ],
        "duplicate_records": [
            {
                "line_number": record.line_number,
                "event_id": record.event_id,
                "retained_line_number": record.retained_line_number,
            }
            for record in result.duplicates
        ],
        "alert_count": len(alerts),
        "alerts": [alert.to_dict() for alert in alerts],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.strict and result.rejected:
        return 2
    return 0


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
