from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime

from backend.db import Connection
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
    alert_key, rule_id, rule_version, severity, status, organization_id,
    attempted_account, actor_id, session_id, window_start, window_end,
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
        "SELECT severity, reason FROM alerts WHERE alert_key = %s",
        (alert.alert_key,),
    ).fetchone()

    if stored is None:
        conn.execute(INSERT_ALERT, _alert_params(alert))
        _insert_evidence(conn, alert.alert_key, alert.evidence)
        return CREATED

    unchanged = (
        stored["severity"] == alert.severity
        and stored["reason"] == alert.reason
        and _load_evidence_links(conn, alert.alert_key) == alert.evidence
    )
    if unchanged:
        return UNCHANGED

    conn.execute(UPDATE_ALERT, _alert_params(alert))
    conn.execute(
        "DELETE FROM alert_events WHERE alert_key = %s", (alert.alert_key,)
    )
    _insert_evidence(conn, alert.alert_key, alert.evidence)
    return UPDATED


def list_alerts(conn: Connection) -> list[StoredAlert]:
    rows = conn.execute(
        f"""
        SELECT {SELECT_ALERT_COLUMNS}
        FROM alerts
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


def list_alert_evidence(conn: Connection, alert_key: str) -> list[EvidenceEvent]:
    rows = conn.execute(
        f"""
        SELECT evidence_role, {SELECT_EVENT_COLUMNS}
        FROM alert_events
        JOIN security_events USING (event_id)
        WHERE alert_key = %s
        ORDER BY occurred_at, event_id
        """,
        (alert_key,),
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
