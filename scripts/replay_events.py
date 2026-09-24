from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Sequence

from backend.config import require_env
from scripts.detect_r1 import positive_int

DEFAULT_API_URL = "http://127.0.0.1:8000"
MAX_BATCH_SIZE = 500
REQUEST_TIMEOUT_SECONDS = 30


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Replay JSONL fixture events through the trusted collector "
            "endpoint POST /internal/events/batch."
        )
    )
    parser.add_argument("path", type=Path, help="Path to a JSONL event file")
    parser.add_argument(
        "--api-url",
        default=os.environ.get("API_URL", DEFAULT_API_URL),
        help=f"API base URL (default: API_URL or {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--batch-size",
        type=positive_int,
        default=MAX_BATCH_SIZE,
        help=f"Events per request, at most {MAX_BATCH_SIZE}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    batch_size = min(args.batch_size, MAX_BATCH_SIZE)
    token = require_env("COLLECTOR_TOKEN")

    records, skipped = read_records(args.path)
    for message in skipped:
        print(f"Skipped {message}")

    url = args.api_url.rstrip("/") + "/internal/events/batch"
    for start in range(0, len(records), batch_size):
        batch = records[start : start + batch_size]
        try:
            status, body = post_batch(url, token, batch)
        except urllib.error.URLError as error:
            print(f"Could not reach {url}: {error.reason}")
            return 1
        print(f"HTTP {status}: {body}")
        if status != 200:
            return 1
    return 0


def read_records(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """The API assigns collection time, so any fixture ingested_at is dropped."""
    records = []
    skipped = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            skipped.append(f"line {line_number}: blank")
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            skipped.append(f"line {line_number}: invalid JSON")
            continue
        if not isinstance(record, dict):
            skipped.append(f"line {line_number}: not a JSON object")
            continue
        record.pop("ingested_at", None)
        records.append(record)
    return records, skipped


def post_batch(
    url: str, token: str, events: list[dict[str, Any]]
) -> tuple[int, str]:
    request = urllib.request.Request(
        url,
        data=json.dumps({"events": events}).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(
            request, timeout=REQUEST_TIMEOUT_SECONDS
        ) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
