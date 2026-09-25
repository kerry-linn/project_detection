from __future__ import annotations

import random
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from detections.denied_document_access import (
    RULE_ID,
    RULE_VERSION,
    DeniedDocumentAccessConfig,
    detect_repeated_denied_document_access,
)
from security_events import SecurityEvent, parse_event

START = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
ONE_MICROSECOND = timedelta(microseconds=1)


@pytest.mark.parametrize(
    ("distinct_documents", "expected_alerts"),
    [(4, 0), (5, 1), (6, 1)],
)
def test_threshold_below_at_and_above(
    distinct_documents: int, expected_alerts: int
) -> None:
    denials = _distinct_denials(distinct_documents)

    alerts = detect_repeated_denied_document_access(denials)

    assert len(alerts) == expected_alerts
    if alerts:
        assert alerts[0].trigger_event_id == "denial-4"
        assert alerts[0].distinct_document_count == distinct_documents


def test_repeated_requests_for_one_document_do_not_count() -> None:
    same_document = [
        _denial(f"same-{index}", START + timedelta(seconds=index), "doc-1")
        for index in range(10)
    ]
    four_documents_many_requests = [
        _denial(f"mixed-{index}", START + timedelta(seconds=index), f"doc-{index % 4}")
        for index in range(12)
    ]

    assert detect_repeated_denied_document_access(same_document) == ()
    assert detect_repeated_denied_document_access(four_documents_many_requests) == ()


def test_only_document_denials_are_considered() -> None:
    denials = _distinct_denials(4)
    alert_route_denial = _denial(
        "alert-route", START + timedelta(minutes=1), "alert-1", resource_type="alert"
    )
    download = parse_event(
        {
            **_denial(
                "download", START + timedelta(minutes=1), "doc-download"
            ).to_dict(),
            "event_type": "document_downloaded",
            "outcome": "success",
        }
    )

    alerts = detect_repeated_denied_document_access(
        [*denials, alert_route_denial, download]
    )

    assert alerts == ()


def test_actors_and_organizations_are_isolated() -> None:
    events = [
        *_distinct_denials(3),
        _denial("other-org-1", START + timedelta(seconds=10), "doc-x1", organization_id="org-beta"),
        _denial("other-org-2", START + timedelta(seconds=11), "doc-x2", organization_id="org-beta"),
        _denial("other-actor-1", START + timedelta(seconds=12), "doc-y1", actor_id="user-alice"),
        _denial("other-actor-2", START + timedelta(seconds=13), "doc-y2", actor_id="user-alice"),
    ]

    assert detect_repeated_denied_document_access(events) == ()


def test_window_start_is_inclusive_and_current_event_counts() -> None:
    fifth_time = START + timedelta(minutes=5)
    at_window_start = [
        _denial("first", START, "doc-0"),
        *[
            _denial(f"inside-{index}", START + timedelta(minutes=index + 1), f"doc-{index + 1}")
            for index in range(3)
        ],
        _denial("fifth", fifth_time, "doc-4"),
    ]
    just_outside = [
        replace(at_window_start[0], occurred_at=START - ONE_MICROSECOND),
        *at_window_start[1:],
    ]

    alert = detect_repeated_denied_document_access(at_window_start)[0]

    assert alert.trigger_event_id == "fifth"
    assert alert.threshold_reached_at == fifth_time
    assert alert.evidence_event_ids == (
        "first",
        "inside-0",
        "inside-1",
        "inside-2",
        "fifth",
    )
    assert alert.window_start == START
    assert detect_repeated_denied_document_access(just_outside) == ()


def test_alert_key_is_anchored_to_the_threshold_crossing_event() -> None:
    alert = detect_repeated_denied_document_access(_distinct_denials(5))[0]

    assert alert.alert_key == (
        f"{RULE_ID}:{RULE_VERSION}:threshold=5:window_us=300000000:"
        "cooldown_us=900000000:org-alpha:user-bob:denial-4"
    )
    assert alert.document_ids == ("doc-0", "doc-1", "doc-2", "doc-3", "doc-4")


def test_denials_within_cooldown_extend_the_same_episode() -> None:
    initial = _distinct_denials(5)
    last_initial = initial[-1].occurred_at
    later = [
        _denial("later-1", last_initial + timedelta(minutes=10), "doc-0"),
        _denial("later-2", last_initial + timedelta(minutes=20), "doc-5"),
        # Exactly one cooldown after the previous denial still extends it.
        _denial("later-3", last_initial + timedelta(minutes=35), "doc-6"),
    ]

    baseline = detect_repeated_denied_document_access(initial)[0]
    alerts = detect_repeated_denied_document_access([*initial, *later])

    assert len(alerts) == 1
    extended = alerts[0]
    assert extended.alert_key == baseline.alert_key
    assert extended.evidence_event_ids == (
        *baseline.evidence_event_ids,
        "later-1",
        "later-2",
        "later-3",
    )
    assert extended.distinct_document_count == 7
    assert extended.window_end == later[-1].occurred_at
    assert extended.suppression_until == later[-1].occurred_at + timedelta(minutes=15)
    assert extended.reason != baseline.reason


def test_cooldown_expiry_allows_a_new_episode() -> None:
    first = _distinct_denials(5)
    gap_start = first[-1].occurred_at + timedelta(minutes=15) + ONE_MICROSECOND
    second = _distinct_denials(5, start=gap_start, prefix="second")

    alerts = detect_repeated_denied_document_access([*first, *second])

    assert [alert.trigger_event_id for alert in alerts] == ["denial-4", "second-4"]
    assert alerts[0].alert_key != alerts[1].alert_key
    assert alerts[1].evidence_event_ids == tuple(event.event_id for event in second)


def test_activity_after_an_episode_closes_must_reach_the_threshold_again() -> None:
    first = _distinct_denials(5)
    after_gap = first[-1].occurred_at + timedelta(minutes=16)
    below_threshold = _distinct_denials(4, start=after_gap, prefix="after")

    alerts = detect_repeated_denied_document_access([*first, *below_threshold])

    assert [alert.trigger_event_id for alert in alerts] == ["denial-4"]
    assert "after-0" not in alerts[0].evidence_event_ids


def test_shuffled_input_and_replayed_events_are_deterministic() -> None:
    events = [*_distinct_denials(5), _denial("repeat", START + timedelta(minutes=2), "doc-1")]
    baseline = detect_repeated_denied_document_access(events)
    replay = replace(events[2], ingested_at=events[2].ingested_at + timedelta(hours=1))
    shuffled = [*events, replay]
    random.Random(7).shuffle(shuffled)

    assert detect_repeated_denied_document_access(shuffled) == baseline


def test_source_ips_are_retained_as_evidence() -> None:
    events = [
        replace(event, source_ip=f"198.51.100.{index % 2 + 1}")
        for index, event in enumerate(_distinct_denials(5))
    ]

    alert = detect_repeated_denied_document_access(events)[0]

    assert alert.source_ips == ("198.51.100.1", "198.51.100.2")


def test_configuration_changes_the_threshold_and_identity() -> None:
    config = DeniedDocumentAccessConfig(
        threshold=3, window=timedelta(minutes=1), cooldown=timedelta(minutes=2)
    )
    events = [
        _denial("a", START, "doc-a"),
        _denial("b", START + timedelta(seconds=30), "doc-b"),
        _denial("c", START + timedelta(seconds=60), "doc-c"),
    ]

    alert = detect_repeated_denied_document_access(events, config)[0]

    assert alert.trigger_event_id == "c"
    assert "threshold=3:window_us=60000000:cooldown_us=120000000" in alert.alert_key
    assert alert.suppression_until == START + timedelta(minutes=3)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"threshold": 0}, "threshold must be at least 1"),
        ({"window": timedelta(0)}, "window must be greater than zero"),
        ({"cooldown": timedelta(0)}, "cooldown must be greater than zero"),
    ],
)
def test_invalid_configuration_is_rejected(
    kwargs: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        DeniedDocumentAccessConfig(**kwargs)


def _distinct_denials(
    count: int, *, start: datetime = START, prefix: str = "denial"
) -> list[SecurityEvent]:
    return [
        _denial(f"{prefix}-{index}", start + timedelta(seconds=30 * index), f"doc-{index}")
        for index in range(count)
    ]


def _denial(
    event_id: str,
    occurred_at: datetime,
    resource_id: str,
    *,
    actor_id: str = "user-bob",
    organization_id: str = "org-alpha",
    resource_type: str = "document",
) -> SecurityEvent:
    return parse_event(
        {
            "event_id": event_id,
            "occurred_at": occurred_at.isoformat(),
            "ingested_at": (occurred_at + timedelta(seconds=1)).isoformat(),
            "source": "application",
            "event_type": "access_denied",
            "organization_id": organization_id,
            "actor_id": actor_id,
            "session_id": "session-1",
            "source_ip": "198.51.100.10",
            "resource_type": resource_type,
            "resource_id": resource_id,
            "outcome": "denied",
            "request_id": f"request-{event_id}",
            "schema_version": "1.0",
            "metadata": {},
        }
    )
