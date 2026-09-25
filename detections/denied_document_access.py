from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from detections.common import deduplicate_and_sort, duration_microseconds
from security_events import SecurityEvent

RULE_ID = "R2_REPEATED_DENIED_DOCUMENT_ACCESS"
RULE_VERSION = "1.0"
SEVERITY = "medium"
DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW = timedelta(minutes=5)
DEFAULT_COOLDOWN = timedelta(minutes=15)


@dataclass(frozen=True)
class DeniedDocumentAccessConfig:
    threshold: int = DEFAULT_THRESHOLD
    window: timedelta = DEFAULT_WINDOW
    cooldown: timedelta = DEFAULT_COOLDOWN

    def __post_init__(self) -> None:
        if self.threshold < 1:
            raise ValueError("threshold must be at least 1")
        if self.window <= timedelta(0):
            raise ValueError("window must be greater than zero")
        if self.cooldown <= timedelta(0):
            raise ValueError("cooldown must be greater than zero")

    @property
    def window_microseconds(self) -> int:
        return duration_microseconds(self.window)

    @property
    def cooldown_microseconds(self) -> int:
        return duration_microseconds(self.cooldown)


@dataclass(frozen=True)
class DeniedDocumentAccessAlert:
    alert_key: str
    rule_id: str
    rule_version: str
    severity: str
    organization_id: str
    actor_id: str
    window_start: datetime
    window_end: datetime
    threshold_reached_at: datetime
    threshold: int
    window_microseconds: int
    cooldown_microseconds: int
    trigger_event_id: str
    evidence_event_ids: tuple[str, ...]
    document_ids: tuple[str, ...]
    source_ips: tuple[str, ...]
    suppression_until: datetime
    reason: str

    @property
    def distinct_document_count(self) -> int:
        return len(self.document_ids)


def detect_repeated_denied_document_access(
    events: Iterable[SecurityEvent],
    config: DeniedDocumentAccessConfig | None = None,
) -> tuple[DeniedDocumentAccessAlert, ...]:
    """One alert per episode of denied document access by one actor.

    An episode opens at the first denial `t` where `[t - window, t]` (both ends
    inclusive, `t` itself counted) holds at least `threshold` distinct
    document IDs. Every later denial within `cooldown` of the previous
    evidence joins the same episode; a longer gap closes it.
    """
    rule_config = config or DeniedDocumentAccessConfig()
    denials_by_entity: dict[tuple[str, str], list[SecurityEvent]] = {}
    for event in deduplicate_and_sort(events):
        if _is_document_denial(event):
            entity = (event.organization_id, event.actor_id)
            denials_by_entity.setdefault(entity, []).append(event)

    alerts = []
    for denials in denials_by_entity.values():
        alerts.extend(_episodes(denials, rule_config))
    return tuple(
        sorted(
            alerts,
            key=lambda alert: (alert.threshold_reached_at, alert.trigger_event_id),
        )
    )


def _is_document_denial(event: SecurityEvent) -> bool:
    return (
        event.event_type == "access_denied"
        and event.resource_type == "document"
        and event.organization_id is not None
        and event.actor_id is not None
        and event.resource_id is not None
    )


def _episodes(
    denials: list[SecurityEvent], config: DeniedDocumentAccessConfig
) -> list[DeniedDocumentAccessAlert]:
    alerts = []
    recent: deque[SecurityEvent] = deque()
    trigger: SecurityEvent | None = None
    episode: list[SecurityEvent] = []

    for denial in denials:
        if trigger is not None:
            if denial.occurred_at - episode[-1].occurred_at <= config.cooldown:
                episode.append(denial)
                continue
            alerts.append(_build_alert(trigger, episode, config))
            trigger = None

        recent.append(denial)
        window_start = denial.occurred_at - config.window
        while recent[0].occurred_at < window_start:
            recent.popleft()

        if len({event.resource_id for event in recent}) >= config.threshold:
            trigger = denial
            episode = list(recent)
            recent.clear()

    if trigger is not None:
        alerts.append(_build_alert(trigger, episode, config))
    return alerts


def _build_alert(
    trigger: SecurityEvent,
    episode: list[SecurityEvent],
    config: DeniedDocumentAccessConfig,
) -> DeniedDocumentAccessAlert:
    document_ids = tuple(sorted({event.resource_id for event in episode}))
    source_ips = tuple(
        sorted({event.source_ip for event in episode if event.source_ip is not None})
    )
    last_denial = episode[-1].occurred_at

    return DeniedDocumentAccessAlert(
        alert_key=_alert_key(trigger, config),
        rule_id=RULE_ID,
        rule_version=RULE_VERSION,
        severity=SEVERITY,
        organization_id=trigger.organization_id,
        actor_id=trigger.actor_id,
        window_start=episode[0].occurred_at,
        window_end=last_denial,
        threshold_reached_at=trigger.occurred_at,
        threshold=config.threshold,
        window_microseconds=config.window_microseconds,
        cooldown_microseconds=config.cooldown_microseconds,
        trigger_event_id=trigger.event_id,
        evidence_event_ids=tuple(event.event_id for event in episode),
        document_ids=document_ids,
        source_ips=source_ips,
        suppression_until=last_denial + config.cooldown,
        reason=(
            f"{trigger.actor_id} in {trigger.organization_id} was denied access "
            f"to {len(document_ids)} distinct documents across {len(episode)} "
            f"requests; {config.threshold} distinct documents were first "
            f"reached within {_describe(config.window)}"
        ),
    )


def _alert_key(trigger: SecurityEvent, config: DeniedDocumentAccessConfig) -> str:
    """Anchored to the threshold-crossing event, so later evidence extends
    the same alert instead of producing a new key."""
    return (
        f"{RULE_ID}:{RULE_VERSION}:"
        f"threshold={config.threshold}:"
        f"window_us={config.window_microseconds}:"
        f"cooldown_us={config.cooldown_microseconds}:"
        f"{trigger.organization_id}:{trigger.actor_id}:{trigger.event_id}"
    )


def _describe(duration: timedelta) -> str:
    seconds = duration.total_seconds()
    if seconds % 60 == 0:
        return f"{int(seconds // 60)} minutes"
    return f"{seconds:g} seconds"
