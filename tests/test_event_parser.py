from __future__ import annotations

import json
from datetime import timezone
from pathlib import Path

import pytest

from security_events import (
    EventValidationError,
    parse_event,
    parse_jsonl,
)
from scripts.parse_events import main

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"

BASE_EVENT = {
    "event_id": "test-event-001",
    "occurred_at": "2026-09-17T10:00:00Z",
    "ingested_at": "2026-09-17T10:00:01Z",
    "source": "fixture",
    "event_type": "login_failed",
    "organization_id": "org-alpha",
    "actor_id": None,
    "attempted_account": "User@Example.test",
    "source_ip": "2001:0db8:0000:0000:0000:0000:0000:0001",
    "outcome": "failure",
    "request_id": "test-request-001",
    "schema_version": "1.0",
    "metadata": {},
}


def test_days_1_2_fixture_matches_independent_expectations() -> None:
    expected = json.loads(
        (FIXTURES / "expected" / "days_1_2.json").read_text()
    )

    result = parse_jsonl(FIXTURES / "days_1_2.jsonl")

    assert result.lines_read == expected["lines_read"]
    assert len(result.events) == expected["valid_events"]
    assert len(result.rejected) == expected["rejected_records"]
    assert len(result.duplicates) == expected["duplicate_records"]
    assert result.event_type_counts == expected["event_type_counts"]
    assert [event.event_id for event in result.events] == expected[
        "ordered_event_ids"
    ]
    assert [record.line_number for record in result.rejected] == [18]
    assert "invalid JSON" in result.rejected[0].reason
    assert result.duplicates[0].line_number == 19
    assert result.duplicates[0].event_id == "evt-009"
    assert result.duplicates[0].retained_line_number == 9


def test_invalid_records_do_not_discard_valid_records() -> None:
    result = parse_jsonl(FIXTURES / "invalid_events.jsonl")

    assert result.lines_read == 9
    assert [event.event_id for event in result.events] == [
        "invalid-fixture-valid"
    ]
    assert len(result.rejected) == 8


def test_parse_event_normalizes_values() -> None:
    event = parse_event(BASE_EVENT)

    assert event.occurred_at.tzinfo is timezone.utc
    assert event.occurred_at.isoformat() == "2026-09-17T10:00:00+00:00"
    assert event.attempted_account == "user@example.test"
    assert event.source_ip == "2001:db8::1"
    assert event.to_dict()["occurred_at"] == "2026-09-17T10:00:00Z"


def test_offset_timestamp_is_normalized_to_utc() -> None:
    record = {
        **BASE_EVENT,
        "occurred_at": "2026-09-17T06:00:00-04:00",
    }

    event = parse_event(record)

    assert event.occurred_at.isoformat() == "2026-09-17T10:00:00+00:00"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"event_id": None}, "event_id must be a non-empty string"),
        ({"occurred_at": "2026-09-17T10:00:00"}, "must include a timezone"),
        ({"source": "browser"}, "source must be one of"),
        ({"source_ip": "999.1.1.1"}, "must be a valid IPv4 or IPv6"),
        ({"outcome": "success"}, "login_failed outcome must be failure"),
        ({"organization_id": None}, "requires organization_id"),
        ({"metadata": []}, "metadata must be a JSON object"),
        (
            {"metadata": {"access_token": "secret"}},
            "metadata contains forbidden key",
        ),
        ({"schema_version": "2.0"}, "schema_version must be one of"),
        ({"schema_version": 1.0}, "schema_version must be a non-empty string"),
        ({"browser_actor": "untrusted"}, "unknown field"),
    ],
)
def test_invalid_events_are_rejected(
    change: dict[str, object], message: str
) -> None:
    with pytest.raises(EventValidationError, match=message):
        parse_event({**BASE_EVENT, **change})


def test_non_object_record_is_rejected() -> None:
    with pytest.raises(
        EventValidationError, match="record must be a JSON object"
    ):
        parse_event([])


@pytest.mark.parametrize("reverse", [False, True])
def test_conflicting_event_id_excludes_all_versions_without_stopping_batch(
    tmp_path: Path, reverse: bool
) -> None:
    conflicting = {
        **BASE_EVENT,
        "occurred_at": "2026-09-17T10:01:00Z",
    }
    unique = {
        **BASE_EVENT,
        "event_id": "test-event-002",
        "occurred_at": "2026-09-17T10:02:00Z",
    }
    conflict_records = [BASE_EVENT, conflicting]
    if reverse:
        conflict_records.reverse()
    path = _write_jsonl(tmp_path, [*conflict_records, unique])

    result = parse_jsonl(path)

    assert [event.event_id for event in result.events] == ["test-event-002"]
    assert [record.line_number for record in result.rejected] == [1, 2]
    assert {
        record.reason for record in result.rejected
    } == {"conflicting event_id: test-event-001"}
    assert result.duplicates == ()


@pytest.mark.parametrize("reverse", [False, True])
def test_replay_ignores_ingested_at_and_retains_earliest(
    tmp_path: Path, reverse: bool
) -> None:
    earlier = {
        **BASE_EVENT,
        "ingested_at": "2026-09-17T10:00:01Z",
    }
    later = {
        **BASE_EVENT,
        "ingested_at": "2026-09-17T10:05:00Z",
    }
    records = [earlier, later]
    if reverse:
        records.reverse()

    result = parse_jsonl(_write_jsonl(tmp_path, records))

    assert result.rejected == ()
    assert len(result.events) == 1
    assert result.events[0].ingested_at.isoformat() == (
        "2026-09-17T10:00:01+00:00"
    )
    assert len(result.duplicates) == 1
    assert result.duplicates[0].event_id == "test-event-001"
    assert (
        result.duplicates[0].line_number
        != result.duplicates[0].retained_line_number
    )


def test_conflicted_id_remains_excluded_for_a_b_a_sequence(
    tmp_path: Path,
) -> None:
    conflicting = {
        **BASE_EVENT,
        "source_ip": "192.0.2.99",
    }

    result = parse_jsonl(
        _write_jsonl(tmp_path, [BASE_EVENT, conflicting, BASE_EVENT])
    )

    assert result.events == ()
    assert result.duplicates == ()
    assert [record.line_number for record in result.rejected] == [1, 2, 3]
    assert all(
        record.reason == "conflicting event_id: test-event-001"
        for record in result.rejected
    )


def test_events_are_sorted_by_timestamp_then_event_id(
    tmp_path: Path,
) -> None:
    events = [
        {
            **BASE_EVENT,
            "event_id": "event-b",
            "occurred_at": "2026-09-17T10:02:00Z",
        },
        {
            **BASE_EVENT,
            "event_id": "event-c",
            "occurred_at": "2026-09-17T10:01:00Z",
        },
        {
            **BASE_EVENT,
            "event_id": "event-a",
            "occurred_at": "2026-09-17T10:01:00Z",
        },
    ]

    result = parse_jsonl(_write_jsonl(tmp_path, events))

    assert [event.event_id for event in result.events] == [
        "event-a",
        "event-c",
        "event-b",
    ]


def test_blank_and_malformed_lines_are_reported(
    tmp_path: Path,
) -> None:
    path = tmp_path / "events.jsonl"
    valid = json.dumps(BASE_EVENT)
    path.write_text(f"\n{{not-json}}\n{valid}\n", encoding="utf-8")

    result = parse_jsonl(path)

    assert [record.line_number for record in result.rejected] == [1, 2]
    assert result.rejected[0].reason == "line is blank"
    assert "invalid JSON" in result.rejected[1].reason
    assert len(result.events) == 1


def test_cli_prints_summary_and_rejections(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main([str(FIXTURES / "days_1_2.jsonl")])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Lines read: 20" in output
    assert "Valid events: 18" in output
    assert "Rejected records: 1" in output
    assert "Duplicate records: 1" in output
    assert "line 18: invalid JSON" in output
    assert "line 19: duplicate event_id evt-009; retained line 9" in output


def test_cli_strict_mode_fails_when_records_are_rejected() -> None:
    exit_code = main(
        [str(FIXTURES / "days_1_2.jsonl"), "--strict"]
    )

    assert exit_code == 2


def test_cli_strict_mode_allows_source_equivalent_replay(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    replay = {
        **BASE_EVENT,
        "ingested_at": "2026-09-17T10:05:00Z",
    }
    path = _write_jsonl(tmp_path, [BASE_EVENT, replay])

    exit_code = main([str(path), "--strict"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Rejected records: 0" in output
    assert "Duplicate records: 1" in output


def _write_jsonl(
    tmp_path: Path, records: list[dict[str, object]]
) -> Path:
    path = tmp_path / "events.jsonl"
    path.write_text(
        "".join(f"{json.dumps(record)}\n" for record in records),
        encoding="utf-8",
    )
    return path
