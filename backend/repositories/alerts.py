from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime

from backend.db import Connection
from backend.repositories.detection_runs import RuleRun
from backend.repositories.events import SELECT_EVENT_COLUMNS
from detections.denied_document_access import DeniedDocumentAccessAlert
from detections.failed_login_success import FailedLoginSuccessAlert
from security_events import SecurityEvent

CREATED = "created"
UPDATED = "updated"
UNCHANGED = "unchanged"

FAILED_LOGIN = "failed_login"
SUCCESSFUL_LOGIN = "successful_login"
DENIED_DOCUMENT_ACCESS = "denied_document_access"

SELECT_ALERT_COLUMNS = """
    alert_key, rule_id, rule_version, severity, status, detection_state,
    needs_review, disposition, rationale, revision, organization_id, attempted_account, actor_id, session_id,
    window_start, window_end,
    threshold, window_microseconds, cooldown_microseconds, suppression_until,
    match_count, reason, created_at, updated_at
"""

INSERT_ALERT = """
    INSERT INTO alerts (
        alert_key, rule_id, rule_version, severity, organization_id,
        attempted_account, actor_id, session_id, window_start, window_end,
        threshold, window_microseconds, cooldown_microseconds,
        suppression_until, match_count, reason
    )
    VALUES (
        %(alert_key)s, %(rule_id)s, %(rule_version)s, %(severity)s,
        %(organization_id)s, %(attempted_account)s, %(actor_id)s,
        %(session_id)s, %(window_start)s, %(window_end)s, %(threshold)s,
        %(window_microseconds)s, %(cooldown_microseconds)s,
        %(suppression_until)s, %(match_count)s, %(reason)s
    )
"""

UPDATE_ALERT = """
    UPDATE alerts
    SET severity = %(severity)s,
        actor_id = %(actor_id)s,
        session_id = %(session_id)s,
        window_start = %(window_start)s,
        window_end = %(window_end)s,
        suppression_until = %(suppression_until)s,
        match_count = %(match_count)s,
        reason = %(reason)s,
        updated_at = now()
    WHERE alert_key = %(alert_key)s
"""

INSERT_EVIDENCE = """
    INSERT INTO alert_events (alert_key, event_id, evidence_role)
    VALUES (%s, %s, %s)
"""


@dataclass(frozen=True)
class AlertRecord:
    """Rule-neutral row shape, so every rule shares one upsert path."""

    alert_key: str
    rule_id: str
    rule_version: str
    severity: str
    organization_id: str | None
    attempted_account: str | None
    actor_id: str | None
    session_id: str | None
    window_start: datetime
    window_end: datetime
    threshold: int
    window_microseconds: int
    cooldown_microseconds: int | None
    suppression_until: datetime | None
    match_count: int
    reason: str
    evidence: frozenset[tuple[str, str]]


@dataclass(frozen=True)
class StoredAlert:
    alert_key: str
    rule_id: str
    rule_version: str
    severity: str
    status: str
    detection_state: str
    needs_review: bool
    disposition: str | None
    rationale: str | None
    revision: int
    organization_id: str | None
    attempted_account: str | None
    actor_id: str | None
    session_id: str | None
    window_start: datetime
    window_end: datetime
    threshold: int
    window_microseconds: int
    cooldown_microseconds: int | None
    suppression_until: datetime | None
    match_count: int
    reason: str
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class EvidenceEvent:
    evidence_role: str
    event: SecurityEvent


@dataclass
class _PriorEpisode:
    organization_id: str
    actor_id: str
    status: str
    needs_review: bool
    evidence_ids: set[str]


def failed_login_alert_record(alert: FailedLoginSuccessAlert) -> AlertRecord:
    evidence = {(event_id, FAILED_LOGIN) for event_id in alert.failure_event_ids}
    evidence.add((alert.success_event_id, SUCCESSFUL_LOGIN))
    return AlertRecord(
        alert_key=alert.alert_key,
        rule_id=alert.rule_id,
        rule_version=alert.rule_version,
        severity=alert.severity,
        organization_id=alert.organization_id,
        attempted_account=alert.attempted_account,
        actor_id=alert.actor_id,
        session_id=alert.session_id,
        window_start=alert.window_start,
        window_end=alert.window_end,
        threshold=alert.threshold,
        window_microseconds=alert.window_microseconds,
        cooldown_microseconds=None,
        suppression_until=None,
        match_count=alert.failure_count,
        reason=alert.reason,
        evidence=frozenset(evidence),
    )


def denied_document_alert_record(alert: DeniedDocumentAccessAlert) -> AlertRecord:
    return AlertRecord(
        alert_key=alert.alert_key,
        rule_id=alert.rule_id,
        rule_version=alert.rule_version,
        severity=alert.severity,
        organization_id=alert.organization_id,
        attempted_account=None,
        actor_id=alert.actor_id,
        session_id=None,
        window_start=alert.window_start,
        window_end=alert.window_end,
        threshold=alert.threshold,
        window_microseconds=alert.window_microseconds,
        cooldown_microseconds=alert.cooldown_microseconds,
        suppression_until=alert.suppression_until,
        match_count=alert.distinct_document_count,
        reason=alert.reason,
        evidence=frozenset(
            (event_id, DENIED_DOCUMENT_ACCESS)
            for event_id in alert.evidence_event_ids
        ),
    )


def save_alert(conn: Connection, alert: AlertRecord) -> str:
    """Upsert an alert and replace its evidence links with the latest evaluation.

    Caller owns the transaction so an alert is never visible without its
    evidence. Analyst-owned fields such as status are never overwritten.
    """
    stored = conn.execute(
        "SELECT severity, reason FROM alerts WHERE alert_key = %s FOR UPDATE",
        (alert.alert_key,),
    ).fetchone()

    if stored is None:
        conn.execute(INSERT_ALERT, _alert_params(alert))
        _insert_evidence(conn, alert.alert_key, alert.evidence)
        return CREATED

    previous_evidence = _load_evidence_links(conn, alert.alert_key)
    unchanged = (
        stored["severity"] == alert.severity
        and stored["reason"] == alert.reason
        and previous_evidence == alert.evidence
    )
    if unchanged:
        return UNCHANGED

    conn.execute(UPDATE_ALERT, _alert_params(alert))
    conn.execute(
        "UPDATE alerts SET revision = revision + 1, "
        "needs_review = needs_review OR (status = 'closed' AND %s) WHERE alert_key = %s",
        (bool(alert.evidence - previous_evidence), alert.alert_key),
    )
    conn.execute(
        "DELETE FROM alert_events WHERE alert_key = %s", (alert.alert_key,)
    )
    _insert_evidence(conn, alert.alert_key, alert.evidence)
    return UPDATED


def list_alerts(
    conn: Connection, *, include_superseded: bool = False
) -> list[StoredAlert]:
    where = "" if include_superseded else "WHERE detection_state = 'active'"
    rows = conn.execute(
        f"""
        SELECT {SELECT_ALERT_COLUMNS}
        FROM alerts
        {where}
        ORDER BY window_end DESC, alert_key
        """
    ).fetchall()
    return [StoredAlert(**row) for row in rows]


def get_alert(conn: Connection, alert_key: str) -> StoredAlert | None:
    row = conn.execute(
        f"SELECT {SELECT_ALERT_COLUMNS} FROM alerts WHERE alert_key = %s",
        (alert_key,),
    ).fetchone()
    if row is None:
        return None
    return StoredAlert(**row)


def get_alert_replacements(
    conn: Connection, alert_key: str, *, limit: int | None = None, offset: int = 0
) -> tuple[list[str], list[str]]:
    replacements = conn.execute(
        "SELECT new_alert_key FROM alert_replacements "
        "WHERE old_alert_key = %s ORDER BY new_alert_key LIMIT %s OFFSET %s",
        (alert_key, limit, offset),
    ).fetchall()
    predecessors = conn.execute(
        "SELECT old_alert_key FROM alert_replacements "
        "WHERE new_alert_key = %s ORDER BY old_alert_key LIMIT %s OFFSET %s",
        (alert_key, limit, offset),
    ).fetchall()
    return (
        [row["new_alert_key"] for row in replacements],
        [row["old_alert_key"] for row in predecessors],
    )


def reconcile_denied_document_alerts(
    conn: Connection, alerts: list[AlertRecord], rule: RuleRun
) -> dict[str, int]:
    """Reconcile a full evaluation under the caller's transaction and alert lock.

    Snapshot prior evidence before saving current results. Supersession and
    replacement links must commit with those results or roll back together.
    """
    prior_episodes = _load_active_episodes(conn, rule)
    current_alert_keys = {alert.alert_key for alert in alerts}
    alerts_by_evidence: dict[
        tuple[str | None, str | None, str], set[str]
    ] = defaultdict(set)
    outcomes = {CREATED: 0, UPDATED: 0, UNCHANGED: 0}

    for alert in alerts:
        for event_id, _ in alert.evidence:
            evidence_identity = (alert.organization_id, alert.actor_id, event_id)
            alerts_by_evidence[evidence_identity].add(alert.alert_key)

        outcome = save_alert(conn, alert)
        outcomes[outcome] += 1
        conn.execute(
            "UPDATE alerts SET detection_state = 'active', revision = revision + 1, updated_at = now() "
            "WHERE alert_key = %s AND detection_state = 'superseded'",
            (alert.alert_key,),
        )

    for prior_key, prior_episode in prior_episodes.items():
        if prior_key in current_alert_keys:
            continue
        replacement_keys = _find_replacement_keys(prior_episode, alerts_by_evidence)
        if not replacement_keys:
            raise ValueError(f"no replacement for R2 alert {prior_key}")
        _supersede_alert(
            conn, prior_key, replacement_keys, needs_review=prior_episode.status == "closed" or prior_episode.needs_review
        )
    return outcomes


def _load_active_episodes(conn: Connection, rule: RuleRun) -> dict[str, _PriorEpisode]:
    rows = conn.execute(
        """
        SELECT a.alert_key, a.organization_id, a.actor_id, a.status, a.needs_review, e.event_id
        FROM alerts AS a
        LEFT JOIN alert_events AS e ON e.alert_key = a.alert_key
        WHERE a.rule_id = %s AND a.rule_version = %s
          AND a.threshold = %s AND a.window_microseconds = %s
          AND a.cooldown_microseconds = %s AND a.detection_state = 'active'
        """,
        (
            rule.rule_id,
            rule.rule_version,
            rule.threshold,
            rule.window_microseconds,
            rule.cooldown_microseconds,
        ),
    ).fetchall()
    episodes: dict[str, _PriorEpisode] = {}
    for row in rows:
        alert_key = row["alert_key"]
        if alert_key not in episodes:
            episodes[alert_key] = _PriorEpisode(
                organization_id=row["organization_id"],
                actor_id=row["actor_id"],
                status=row["status"],
                needs_review=row["needs_review"],
                evidence_ids=set(),
            )
        if row["event_id"] is not None:
            episodes[alert_key].evidence_ids.add(row["event_id"])
    return episodes


def _find_replacement_keys(
    episode: _PriorEpisode,
    alerts_by_evidence: dict[tuple[str | None, str | None, str], set[str]],
) -> set[str]:
    replacement_keys: set[str] = set()
    for event_id in episode.evidence_ids:
        evidence_identity = (episode.organization_id, episode.actor_id, event_id)
        matching_keys = alerts_by_evidence.get(evidence_identity)
        if matching_keys is not None:
            replacement_keys.update(matching_keys)
    return replacement_keys


def _supersede_alert(
    conn: Connection,
    prior_key: str,
    replacement_keys: set[str],
    *,
    needs_review: bool,
) -> None:
    conn.execute(
        "UPDATE alerts SET detection_state = 'superseded', revision = revision + 1, updated_at = now() "
        "WHERE alert_key = %s",
        (prior_key,),
    )
    for replacement_key in sorted(replacement_keys):
        conn.execute(
            "INSERT INTO alert_replacements (old_alert_key, new_alert_key) "
            "VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (prior_key, replacement_key),
        )
        if needs_review:
            conn.execute(
                "UPDATE alerts SET needs_review = TRUE, revision = revision + 1 WHERE alert_key = %s AND NOT needs_review",
                (replacement_key,),
            )


def list_alert_evidence(
    conn: Connection, alert_key: str, *, limit: int | None = None, offset: int = 0
) -> list[EvidenceEvent]:
    rows = conn.execute(
        f"""
        SELECT evidence_role, {SELECT_EVENT_COLUMNS}
        FROM alert_events
        JOIN security_events USING (event_id)
        WHERE alert_key = %s
        ORDER BY occurred_at, event_id LIMIT %s OFFSET %s
        """,
        (alert_key, limit, offset),
    ).fetchall()

    evidence = []
    for row in rows:
        role = row.pop("evidence_role")
        evidence.append(EvidenceEvent(evidence_role=role, event=SecurityEvent(**row)))
    return evidence


def _alert_params(alert: AlertRecord) -> dict[str, object]:
    params = asdict(alert)
    del params["evidence"]
    return params


def _load_evidence_links(conn: Connection, alert_key: str) -> set[tuple[str, str]]:
    rows = conn.execute(
        "SELECT event_id, evidence_role FROM alert_events WHERE alert_key = %s",
        (alert_key,),
    ).fetchall()
    return {(row["event_id"], row["evidence_role"]) for row in rows}


def _insert_evidence(
    conn: Connection, alert_key: str, links: frozenset[tuple[str, str]]
) -> None:
    rows = [(alert_key, event_id, role) for event_id, role in sorted(links)]
    with conn.cursor() as cursor:
        cursor.executemany(INSERT_EVIDENCE, rows)


def search_alerts(
    conn: Connection, *, include_superseded: bool, rule: str | None,
    status: str | None, organization: str | None, entity: str | None,
    limit: int, offset: int,
) -> tuple[list[StoredAlert], int]:
    conditions = [] if include_superseded else ["detection_state = 'active'"]
    params: list[object] = []
    for column, value in (("rule_id", rule), ("status", status), ("organization_id", organization)):
        if value:
            conditions.append(f"{column} = %s")
            params.append(value)
    if entity:
        conditions.append(
            "(strpos(lower(COALESCE(actor_id, '')), lower(%s)) > 0 OR "
            "strpos(lower(COALESCE(attempted_account, '')), lower(%s)) > 0)"
        )
        params.extend((entity.strip(), entity.strip()))
    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    total = conn.execute(f"SELECT count(*) AS n FROM alerts {where}", params).fetchone()["n"]
    rows = conn.execute(
        f"SELECT {SELECT_ALERT_COLUMNS} FROM alerts {where} "
        "ORDER BY window_end DESC, alert_key LIMIT %s OFFSET %s",
        [*params, limit, offset],
    ).fetchall()
    return [StoredAlert(**row) for row in rows], total


def detail_counts(conn: Connection, alert_key: str) -> dict[str, int]:
    return conn.execute(
        "SELECT (SELECT count(*) FROM alert_events WHERE alert_key = %s) AS evidence_total, "
        "(SELECT count(*) FROM alert_replacements WHERE new_alert_key = %s) AS replaces_total, "
        "(SELECT count(*) FROM alert_replacements WHERE old_alert_key = %s) AS replaced_by_total",
        (alert_key, alert_key, alert_key),
    ).fetchone()
