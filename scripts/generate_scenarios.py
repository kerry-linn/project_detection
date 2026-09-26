from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from typing import Any, Sequence

from backend.config import require_env
from scripts.replay_events import DEFAULT_API_URL
from scripts.seed import PASSWORD_ENV

REQUEST_TIMEOUT_SECONDS = 10
ALICE = "alice@alpha.example.test"
BOB = "bob@alpha.example.test"
WRONG_PASSWORD = "not-the-lab-password"

# Four same-organization documents Bob does not own, plus one from another tenant.
SUSPICIOUS_PROBES = (
    ("doc-alpha-001", 403),
    ("doc-alpha-002", 403),
    ("doc-alpha-003", 403),
    ("doc-alpha-005", 403),
    ("doc-beta-001", 404),
)


class ScenarioError(RuntimeError):
    pass


def send(
    method: str, url: str, token: str | None, body: dict[str, Any] | None
) -> tuple[int, str]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8")


def call(
    api_url: str,
    who: str,
    method: str,
    path: str,
    expected: int,
    token: str | None = None,
    body: dict[str, Any] | None = None,
) -> str:
    status, text = send(method, api_url + path, token, body)
    print(f"{who:<26} {method:<4} {path:<28} -> {status}")
    if status != expected:
        raise ScenarioError(
            f"{method} {path} as {who} returned {status}, expected {expected}: {text}"
        )
    return text


def login(api_url: str, account: str, password: str) -> str:
    body = {"login": account, "password": password}
    text = call(api_url, account, "POST", "/auth/login", 200, body=body)
    return json.loads(text)["access_token"]


def fail_login(api_url: str, account: str) -> None:
    body = {"login": account, "password": WRONG_PASSWORD}
    call(api_url, account, "POST", "/auth/login", 401, body=body)


def read_document(api_url: str, token: str, document_id: str, expected: int) -> None:
    call(api_url, BOB, "GET", f"/documents/{document_id}", expected, token=token)


def suspicious(api_url: str, password: str) -> None:
    """R2: Bob is denied five distinct documents. R1: five failures, then success."""
    bob = login(api_url, BOB, password)
    read_document(api_url, bob, "doc-alpha-004", 200)
    for document_id, expected in SUSPICIOUS_PROBES:
        read_document(api_url, bob, document_id, expected)
    for _ in range(5):
        fail_login(api_url, ALICE)
    login(api_url, ALICE, password)


def benign(api_url: str, password: str) -> None:
    """Below both thresholds: four failures, and five denials of one document."""
    for _ in range(4):
        fail_login(api_url, ALICE)
    login(api_url, ALICE, password)
    bob = login(api_url, BOB, password)
    read_document(api_url, bob, "doc-alpha-004", 200)
    for _ in range(5):
        read_document(api_url, bob, "doc-alpha-001", 403)


SCENARIOS = {"suspicious": suspicious, "benign": benign}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate R1/R2 activity through the real application routes. "
            f"Seeded users must share the password in {PASSWORD_ENV}."
        )
    )
    parser.add_argument("scenario", choices=sorted(SCENARIOS))
    parser.add_argument(
        "--api-url",
        default=os.environ.get("API_URL", DEFAULT_API_URL),
        help=f"API base URL (default: API_URL or {DEFAULT_API_URL})",
    )
    args = parser.parse_args(argv)
    password = require_env(PASSWORD_ENV)
    api_url = args.api_url.rstrip("/")

    try:
        SCENARIOS[args.scenario](api_url, password)
    except urllib.error.URLError as error:
        print(f"Could not reach {api_url}: {error.reason}")
        return 1
    except ScenarioError as error:
        print(f"Scenario stopped: {error}")
        return 1

    print(f"The {args.scenario} scenario completed. Next: python -m scripts.run_detection")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
