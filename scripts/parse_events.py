from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from scripts.event_parser import ParseResult, parse_jsonl


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and summarize structured security event JSONL."
    )
    parser.add_argument("path", type=Path, help="Path to a JSONL event file")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit with status 2 when any records are rejected",
    )
    return parser


def format_report(result: ParseResult) -> str:
    lines = [
        f"Lines read: {result.lines_read}",
        f"Valid events: {len(result.events)}",
        f"Rejected records: {len(result.rejected)}",
        f"Duplicate records: {len(result.duplicates)}",
        "Event types:",
    ]
    if result.event_type_counts:
        lines.extend(
            f"  {event_type}: {count}"
            for event_type, count in result.event_type_counts.items()
        )
    else:
        lines.append("  none")

    if result.rejected:
        lines.append("Rejections:")
        lines.extend(
            f"  line {record.line_number}: {record.reason}"
            for record in result.rejected
        )
    if result.duplicates:
        lines.append("Duplicates:")
        lines.extend(
            (
                f"  line {record.line_number}: duplicate event_id "
                f"{record.event_id}; retained line "
                f"{record.retained_line_number}"
            )
            for record in result.duplicates
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = parse_jsonl(args.path)
    except OSError as error:
        print(f"Unable to read {args.path}: {error}")
        return 1

    print(format_report(result))
    if args.strict and result.rejected:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
