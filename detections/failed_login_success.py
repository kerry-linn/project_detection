from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from scripts.event_parser import (
    SecurityEvent,
    events_have_same_source_content,
)

RULE_ID = "R1_FAILED_LOGINS_FOLLOWED_BY_SUCCESS"
RULE_VERSION = "1.0"
DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW = timedelta(minutes=10)


@dataclass(frozen=True)
class FailedLoginSuccessConfig:
    threshold: int = DEFAULT_THRESHOLD
    window: timedelta = DEFAULT_WINDOW

    def __post_init__(self) -> None:
        if self.threshold < 1:
            raise ValueError("threshold must be at least 1")
        if self.window <= timedelta(0):
            raise ValueError("window must be greater than zero")


@dataclass(frozen=True)
class FailedLoginSuccessAlert:
    alert_key: str
    rule_id: str
    rule_version: str
    severity: str
    organization_id: str
    attempted_account: str
    actor_id: str | None
    window_start: datetime
    window_end: datetime
    threshold: int
    window_microseconds: int
    failure_count: int
    failure_event_ids: tuple[str, ...]
    success_event_id: str
    evidence_event_ids: tuple[str, ...]
    source_ips: tuple[str, ...]
    session_id: str | None
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "alert_key": self.alert_key,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "severity": self.severity,
            "organization_id": self.organization_id,
            "attempted_account": self.attempted_account,
            "actor_id": self.actor_id,
            "window_start": _format_utc(self.window_start),
            "window_end": _format_utc(self.window_end),
            "threshold": self.threshold,
            "window_microseconds": self.window_microseconds,
            "failure_count": self.failure_count,
            "failure_event_ids": list(self.failure_event_ids),
            "success_event_id": self.success_event_id,
            "evidence_event_ids": list(self.evidence_event_ids),
            "source_ips": list(self.source_ips),
            "session_id": self.session_id,
            "reason": self.reason,
        }


def detect_failed_logins_followed_by_success(
    events: Iterable[SecurityEvent],
    config: FailedLoginSuccessConfig | None = None,
) -> tuple[FailedLoginSuccessAlert, ...]:
    rule_config = config or FailedLoginSuccessConfig()
    ordered_events = _deduplicate_and_sort(events)
    window_microseconds = _timedelta_microseconds(rule_config.window)
    failures_by_entity: dict[
        tuple[str, str], list[SecurityEvent]
    ] = {}
    alerts: list[FailedLoginSuccessAlert] = []

    for event in ordered_events:
        if event.organization_id is None or event.attempted_account is None:
            continue

        entity = (event.organization_id, event.attempted_account)
        if event.event_type == "login_failed":
            failures_by_entity.setdefault(entity, []).append(event)
            continue
        if event.event_type != "login_succeeded":
            continue

        window_start = event.occurred_at - rule_config.window
        qualifying_failures = tuple(
            failure
            for failure in failures_by_entity.get(entity, ())
            if window_start
            <= failure.occurred_at
            < event.occurred_at
        )
        if len(qualifying_failures) < rule_config.threshold:
            continue

        failure_event_ids = tuple(
            failure.event_id for failure in qualifying_failures
        )
        evidence = (*qualifying_failures, event)
        source_ips = tuple(
            sorted(
                {
                    evidence_event.source_ip
                    for evidence_event in evidence
                    if evidence_event.source_ip is not None
                }
            )
        )
        alerts.append(
            FailedLoginSuccessAlert(
                alert_key=(
                    f"{RULE_ID}:{RULE_VERSION}:"
                    f"threshold={rule_config.threshold}:"
                    f"window_us={window_microseconds}:"
                    f"{event.event_id}"
                ),
                rule_id=RULE_ID,
                rule_version=RULE_VERSION,
                severity="medium",
                organization_id=event.organization_id,
                attempted_account=event.attempted_account,
                actor_id=event.actor_id,
                window_start=window_start,
                window_end=event.occurred_at,
                threshold=rule_config.threshold,
                window_microseconds=window_microseconds,
                failure_count=len(qualifying_failures),
                failure_event_ids=failure_event_ids,
                success_event_id=event.event_id,
                evidence_event_ids=(*failure_event_ids, event.event_id),
                source_ips=source_ips,
                session_id=event.session_id,
                reason=(
                    f"{len(qualifying_failures)} failed logins for "
                    f"{event.attempted_account} in {event.organization_id} "
                    f"were followed by a successful login"
                ),
            )
        )

    return tuple(alerts)


def _deduplicate_and_sort(
    events: Iterable[SecurityEvent],
) -> tuple[SecurityEvent, ...]:
    unique_events: dict[str, SecurityEvent] = {}
    for event in events:
        existing = unique_events.get(event.event_id)
        if existing is None:
            unique_events[event.event_id] = event
        elif not events_have_same_source_content(existing, event):
            raise ValueError(
                f"conflicting records for event_id: {event.event_id}"
            )
        elif event.ingested_at < existing.ingested_at:
            unique_events[event.event_id] = event
    return tuple(
        sorted(
            unique_events.values(),
            key=lambda event: (event.occurred_at, event.event_id),
        )
    )


def _timedelta_microseconds(value: timedelta) -> int:
    return (
        value.days * 86_400_000_000
        + value.seconds * 1_000_000
        + value.microseconds
    )


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
