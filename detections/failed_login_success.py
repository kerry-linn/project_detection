from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from detections.common import deduplicate_and_sort, duration_microseconds
from security_events import SecurityEvent, format_utc

RULE_ID = "R1_FAILED_LOGINS_FOLLOWED_BY_SUCCESS"
RULE_VERSION = "1.0"
SEVERITY = "medium"
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

    @property
    def window_microseconds(self) -> int:
        return duration_microseconds(self.window)


@dataclass(frozen=True)
class FailedLoginSuccessAlert:
    alert_key: str
    rule_id: str
    rule_version: str
    severity: str
    organization_id: str | None
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
            "window_start": format_utc(self.window_start),
            "window_end": format_utc(self.window_end),
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
    # A None organization is part of the key: the lab analyst belongs to no
    # tenant, and its account still needs protection.
    failures_by_entity: dict[tuple[str | None, str], list[SecurityEvent]] = {}
    alerts: list[FailedLoginSuccessAlert] = []

    for event in deduplicate_and_sort(events):
        if event.attempted_account is None:
            continue
        entity = (event.organization_id, event.attempted_account)

        if event.event_type == "login_failed":
            failures_by_entity.setdefault(entity, []).append(event)
        elif event.event_type == "login_succeeded":
            failures = _failures_before(
                failures_by_entity.get(entity, []), event, rule_config.window
            )
            if len(failures) >= rule_config.threshold:
                alerts.append(_build_alert(event, failures, rule_config))

    return tuple(alerts)


def _failures_before(
    failures: list[SecurityEvent],
    success: SecurityEvent,
    window: timedelta,
) -> list[SecurityEvent]:
    """Window is [success - window, success): a failure at the success time is excluded."""
    window_start = success.occurred_at - window
    qualifying = []
    for failure in failures:
        if window_start <= failure.occurred_at < success.occurred_at:
            qualifying.append(failure)
    return qualifying


def _build_alert(
    success: SecurityEvent,
    failures: list[SecurityEvent],
    config: FailedLoginSuccessConfig,
) -> FailedLoginSuccessAlert:
    failure_event_ids = tuple(failure.event_id for failure in failures)
    source_ips = set()
    for evidence_event in [*failures, success]:
        if evidence_event.source_ip is not None:
            source_ips.add(evidence_event.source_ip)

    return FailedLoginSuccessAlert(
        alert_key=_alert_key(config, success.event_id),
        rule_id=RULE_ID,
        rule_version=RULE_VERSION,
        severity=SEVERITY,
        organization_id=success.organization_id,
        attempted_account=success.attempted_account,
        actor_id=success.actor_id,
        window_start=success.occurred_at - config.window,
        window_end=success.occurred_at,
        threshold=config.threshold,
        window_microseconds=config.window_microseconds,
        failure_count=len(failures),
        failure_event_ids=failure_event_ids,
        success_event_id=success.event_id,
        evidence_event_ids=(*failure_event_ids, success.event_id),
        source_ips=tuple(sorted(source_ips)),
        session_id=success.session_id,
        reason=(
            f"{len(failures)} failed logins for {success.attempted_account} "
            f"in {success.organization_id or 'no organization'} were followed "
            "by a successful login"
        ),
    )


def _alert_key(config: FailedLoginSuccessConfig, success_event_id: str) -> str:
    """Configuration is part of the identity so differently tuned runs never collide."""
    return (
        f"{RULE_ID}:{RULE_VERSION}:"
        f"threshold={config.threshold}:"
        f"window_us={config.window_microseconds}:"
        f"{success_event_id}"
    )
