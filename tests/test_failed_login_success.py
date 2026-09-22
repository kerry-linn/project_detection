from __future__ import annotations

import json
import random
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from detections.failed_login_success import (
    RULE_ID,
    RULE_VERSION,
    FailedLoginSuccessConfig,
    detect_failed_logins_followed_by_success,
)
from scripts.detect_r1 import main
from scripts.event_parser import SecurityEvent, parse_event, parse_jsonl

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
SUCCESS_TIME = datetime(2026, 9, 17, 13, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("failure_count", "expected_alerts"),
    [(4, 0), (5, 1), (6, 1)],
)
def test_threshold_below_at_and_above(
    failure_count: int, expected_alerts: int
) -> None:
    failures = [
        _login_event(
            f"failure-{index}",
            SUCCESS_TIME - timedelta(minutes=9, seconds=-index),
            "login_failed",
        )
        for index in range(failure_count)
    ]
    success = _login_event("success", SUCCESS_TIME, "login_succeeded")

    alerts = detect_failed_logins_followed_by_success([*failures, success])

    assert len(alerts) == expected_alerts
    if alerts:
        assert alerts[0].failure_count == failure_count


def test_window_start_is_inclusive_and_success_time_is_exclusive() -> None:
    failures = [
        _login_event(
            "at-window-start",
            SUCCESS_TIME - timedelta(minutes=10),
            "login_failed",
        ),
        *[
            _login_event(
                f"inside-{index}",
                SUCCESS_TIME - timedelta(minutes=9 - index),
                "login_failed",
            )
            for index in range(4)
        ],
        _login_event("at-success", SUCCESS_TIME, "login_failed"),
    ]

    alert = detect_failed_logins_followed_by_success(
        [*failures, _login_event("success", SUCCESS_TIME, "login_succeeded")]
    )[0]

    assert alert.failure_event_ids == (
        "at-window-start",
        "inside-0",
        "inside-1",
        "inside-2",
        "inside-3",
    )
    assert "at-success" not in alert.evidence_event_ids


def test_accounts_and_organizations_are_isolated() -> None:
    target_failures = [
        _login_event(
            f"target-{index}",
            SUCCESS_TIME - timedelta(minutes=index + 1),
            "login_failed",
        )
        for index in range(3)
    ]
    other_entities = [
        _login_event(
            "other-account",
            SUCCESS_TIME - timedelta(minutes=1),
            "login_failed",
            attempted_account="other@example.test",
        ),
        _login_event(
            "other-organization",
            SUCCESS_TIME - timedelta(minutes=1),
            "login_failed",
            organization_id="org-beta",
        ),
    ]

    alerts = detect_failed_logins_followed_by_success(
        [
            *target_failures,
            *other_entities,
            _login_event("success", SUCCESS_TIME, "login_succeeded"),
        ]
    )

    assert alerts == ()


def test_duplicate_replay_and_shuffled_input_are_deterministic() -> None:
    events = [
        _login_event(
            f"failure-{index}",
            SUCCESS_TIME - timedelta(minutes=5 - index),
            "login_failed",
            source_ip=None,
        )
        for index in range(5)
    ]
    events.append(
        _login_event(
            "success",
            SUCCESS_TIME,
            "login_succeeded",
            source_ip=None,
        )
    )
    baseline = detect_failed_logins_followed_by_success(events)
    shuffled_with_duplicate = [*events, events[2]]
    random.Random(42).shuffle(shuffled_with_duplicate)

    replayed = detect_failed_logins_followed_by_success(
        shuffled_with_duplicate
    )

    assert replayed == baseline
    assert replayed[0].source_ips == ()
    assert replayed[0].alert_key == (
        f"{RULE_ID}:{RULE_VERSION}:"
        "threshold=5:window_us=600000000:success"
    )


def test_direct_replay_ignores_ingested_at() -> None:
    events = [
        _login_event(
            f"failure-{index}",
            SUCCESS_TIME - timedelta(minutes=5 - index),
            "login_failed",
        )
        for index in range(5)
    ]
    events.append(
        _login_event("success", SUCCESS_TIME, "login_succeeded")
    )
    replay = replace(
        events[0],
        ingested_at=events[0].ingested_at + timedelta(minutes=5),
    )

    alerts = detect_failed_logins_followed_by_success([*events, replay])

    assert len(alerts) == 1
    assert alerts[0].failure_count == 5


def test_conflicting_duplicate_event_ids_are_rejected() -> None:
    first = _login_event(
        "duplicate",
        SUCCESS_TIME - timedelta(minutes=1),
        "login_failed",
    )
    conflicting = _login_event(
        "duplicate",
        SUCCESS_TIME - timedelta(minutes=2),
        "login_failed",
    )

    with pytest.raises(
        ValueError, match="conflicting records for event_id: duplicate"
    ):
        detect_failed_logins_followed_by_success([first, conflicting])


def test_configurable_threshold_and_window() -> None:
    events = [
        _login_event(
            "outside-short-window",
            SUCCESS_TIME - timedelta(minutes=3),
            "login_failed",
        ),
        _login_event(
            "inside-1",
            SUCCESS_TIME - timedelta(seconds=90),
            "login_failed",
        ),
        _login_event(
            "inside-2",
            SUCCESS_TIME - timedelta(seconds=30),
            "login_failed",
        ),
        _login_event("success", SUCCESS_TIME, "login_succeeded"),
    ]
    config = FailedLoginSuccessConfig(
        threshold=2, window=timedelta(minutes=2)
    )

    alert = detect_failed_logins_followed_by_success(events, config)[0]

    assert alert.failure_event_ids == ("inside-1", "inside-2")
    assert alert.window_start == SUCCESS_TIME - timedelta(minutes=2)
    assert alert.threshold == 2
    assert alert.window_microseconds == 120_000_000
    assert "threshold=2:window_us=120000000" in alert.alert_key


def test_configuration_is_part_of_alert_identity() -> None:
    events = [
        _login_event(
            f"failure-{index}",
            SUCCESS_TIME - timedelta(minutes=index + 1),
            "login_failed",
        )
        for index in range(5)
    ]
    events.append(
        _login_event("success", SUCCESS_TIME, "login_succeeded")
    )

    default_alert = detect_failed_logins_followed_by_success(events)[0]
    tuned_alert = detect_failed_logins_followed_by_success(
        events,
        FailedLoginSuccessConfig(
            threshold=4,
            window=timedelta(seconds=600),
        ),
    )[0]
    equivalent_alert = detect_failed_logins_followed_by_success(
        events,
        FailedLoginSuccessConfig(
            threshold=5,
            window=timedelta(minutes=10),
        ),
    )[0]
    precise_alert = detect_failed_logins_followed_by_success(
        events,
        FailedLoginSuccessConfig(
            threshold=5,
            window=timedelta(minutes=10, microseconds=1),
        ),
    )[0]

    assert tuned_alert.alert_key != default_alert.alert_key
    assert equivalent_alert.alert_key == default_alert.alert_key
    assert precise_alert.window_microseconds == 600_000_001
    assert precise_alert.alert_key != default_alert.alert_key


def test_each_qualifying_success_creates_a_distinct_alert() -> None:
    events = [
        _login_event(
            f"failure-{index}",
            SUCCESS_TIME - timedelta(minutes=5 - index),
            "login_failed",
        )
        for index in range(5)
    ]
    events.extend(
        [
            _login_event("success-1", SUCCESS_TIME, "login_succeeded"),
            _login_event(
                "success-2",
                SUCCESS_TIME + timedelta(minutes=1),
                "login_succeeded",
            ),
        ]
    )

    alerts = detect_failed_logins_followed_by_success(events)

    assert [alert.success_event_id for alert in alerts] == [
        "success-1",
        "success-2",
    ]
    assert alerts[0].alert_key != alerts[1].alert_key


@pytest.mark.parametrize("reverse", [False, True])
def test_parser_excludes_conflicts_before_detection(
    tmp_path: Path, reverse: bool
) -> None:
    failures = [
        _login_event(
            f"failure-{index}",
            SUCCESS_TIME - timedelta(minutes=5 - index),
            "login_failed",
        ).to_dict()
        for index in range(4)
    ]
    first = _login_event(
        "conflicted-failure",
        SUCCESS_TIME - timedelta(minutes=1),
        "login_failed",
        source_ip="198.51.100.20",
    ).to_dict()
    conflicting = {
        **first,
        "source_ip": "198.51.100.21",
    }
    conflict_records = [first, conflicting]
    if reverse:
        conflict_records.reverse()
    records = [
        *failures,
        *conflict_records,
        _login_event(
            "success", SUCCESS_TIME, "login_succeeded"
        ).to_dict(),
    ]
    path = tmp_path / "conflicting-events.jsonl"
    path.write_text(
        "".join(f"{json.dumps(record)}\n" for record in records),
        encoding="utf-8",
    )

    result = parse_jsonl(path)
    alerts = detect_failed_logins_followed_by_success(result.events)

    assert len(result.rejected) == 2
    assert all(
        record.reason == "conflicting event_id: conflicted-failure"
        for record in result.rejected
    )
    assert alerts == ()


@pytest.mark.parametrize(
    "config",
    [
        FailedLoginSuccessConfig,
    ],
)
def test_invalid_configuration_is_rejected(
    config: type[FailedLoginSuccessConfig],
) -> None:
    with pytest.raises(ValueError, match="threshold must be at least 1"):
        config(threshold=0)
    with pytest.raises(ValueError, match="window must be greater than zero"):
        config(window=timedelta(0))


def test_days_1_2_fixture_produces_hand_checked_alert() -> None:
    expected = json.loads(
        (FIXTURES / "expected" / "days_1_2.json").read_text()
    )["hand_checked_r1_scenario_for_days_3_4"]
    result = parse_jsonl(FIXTURES / "days_1_2.jsonl")

    alerts = detect_failed_logins_followed_by_success(result.events)

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.organization_id == expected["organization_id"]
    assert alert.attempted_account == expected["attempted_account"]
    assert alert.success_event_id == expected["success_event_id"]
    assert list(alert.failure_event_ids) == expected[
        "qualifying_failure_event_ids"
    ]
    assert alert.to_dict()["window_start"] == expected[
        "window_start_inclusive"
    ]
    assert alert.to_dict()["window_end"] == expected[
        "window_end_exclusive"
    ]
    assert expected["excluded_out_of_window_event_id"] not in (
        alert.evidence_event_ids
    )
    assert alert.evidence_event_ids == (
        "evt-004",
        "evt-005",
        "evt-006",
        "evt-007",
        "evt-008",
        "evt-009",
    )
    assert alert.source_ips == (
        "198.51.100.40",
        "198.51.100.41",
        "198.51.100.42",
    )


def test_cli_outputs_rejections_and_alert_evidence(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main([str(FIXTURES / "days_1_2.jsonl")])

    report = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert report["valid_events"] == 18
    assert len(report["rejected_records"]) == 1
    assert report["duplicate_records"] == [
        {
            "event_id": "evt-009",
            "line_number": 19,
            "retained_line_number": 9,
        }
    ]
    assert report["alert_count"] == 1
    assert report["alerts"][0]["success_event_id"] == "evt-009"
    assert report["alerts"][0]["failure_event_ids"] == [
        "evt-004",
        "evt-005",
        "evt-006",
        "evt-007",
        "evt-008",
    ]


def test_cli_strict_mode_and_invalid_configuration(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main([str(FIXTURES / "days_1_2.jsonl"), "--strict"]) == 2
    capsys.readouterr()

    with pytest.raises(SystemExit) as error:
        main([str(FIXTURES / "days_1_2.jsonl"), "--threshold", "0"])

    assert error.value.code == 2
    assert "must be at least 1" in capsys.readouterr().err


def _login_event(
    event_id: str,
    occurred_at: datetime,
    event_type: str,
    *,
    organization_id: str = "org-alpha",
    attempted_account: str = "user@example.test",
    source_ip: str | None = "198.51.100.10",
) -> SecurityEvent:
    succeeded = event_type == "login_succeeded"
    return parse_event(
        {
            "event_id": event_id,
            "occurred_at": occurred_at.isoformat(),
            "ingested_at": (
                occurred_at + timedelta(seconds=1)
            ).isoformat(),
            "source": "fixture",
            "event_type": event_type,
            "organization_id": organization_id,
            "actor_id": "user-1" if succeeded else None,
            "attempted_account": attempted_account,
            "session_id": "session-1" if succeeded else None,
            "source_ip": source_ip,
            "outcome": "success" if succeeded else "failure",
            "request_id": f"request-{event_id}",
            "schema_version": "1.0",
            "metadata": {},
        }
    )
