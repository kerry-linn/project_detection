CREATE TABLE security_events (
    event_id          TEXT PRIMARY KEY,
    occurred_at       TIMESTAMPTZ NOT NULL,
    ingested_at       TIMESTAMPTZ NOT NULL,
    source            TEXT NOT NULL
        CHECK (source IN ('application', 'fixture', 'cloudtrail')),
    event_type        TEXT NOT NULL
        CHECK (event_type IN (
            'login_failed',
            'login_succeeded',
            'access_denied',
            'document_downloaded',
            'role_changed'
        )),
    organization_id   TEXT NOT NULL,
    actor_id          TEXT,
    attempted_account TEXT,
    target_actor_id   TEXT,
    previous_role     TEXT
        CHECK (previous_role IN ('member', 'organization_admin', 'lab_analyst')),
    new_role          TEXT
        CHECK (new_role IN ('member', 'organization_admin', 'lab_analyst')),
    session_id        TEXT,
    source_ip         INET,
    resource_type     TEXT
        CHECK (resource_type IN ('document', 'alert', 'admin_route')),
    resource_id       TEXT,
    outcome           TEXT NOT NULL
        CHECK (outcome IN ('success', 'denied', 'failure')),
    request_id        TEXT NOT NULL,
    schema_version    TEXT NOT NULL CHECK (schema_version = '1.0'),
    metadata          JSONB NOT NULL DEFAULT '{}'
        CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX security_events_time_idx
    ON security_events (occurred_at, event_id);

CREATE INDEX security_events_account_time_idx
    ON security_events (organization_id, attempted_account, occurred_at);


CREATE TABLE alerts (
    alert_key           TEXT PRIMARY KEY,
    rule_id             TEXT NOT NULL,
    rule_version        TEXT NOT NULL,
    severity            TEXT NOT NULL
        CHECK (severity IN ('low', 'medium', 'high')),
    status              TEXT NOT NULL DEFAULT 'new'
        CHECK (status IN ('new', 'investigating', 'closed')),
    organization_id     TEXT NOT NULL,
    attempted_account   TEXT NOT NULL,
    actor_id            TEXT,
    session_id          TEXT,
    window_start        TIMESTAMPTZ NOT NULL,
    window_end          TIMESTAMPTZ NOT NULL,
    threshold           INTEGER NOT NULL CHECK (threshold >= 1),
    window_microseconds BIGINT NOT NULL CHECK (window_microseconds > 0),
    failure_count       INTEGER NOT NULL,
    reason              TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (window_start < window_end),
    CHECK (failure_count >= threshold)
);


CREATE TABLE alert_events (
    alert_key     TEXT NOT NULL REFERENCES alerts (alert_key) ON DELETE CASCADE,
    event_id      TEXT NOT NULL REFERENCES security_events (event_id),
    evidence_role TEXT NOT NULL
        CHECK (evidence_role IN ('failed_login', 'successful_login')),
    PRIMARY KEY (alert_key, event_id)
);


CREATE TABLE detection_runs (
    run_id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_id             TEXT NOT NULL,
    rule_version        TEXT NOT NULL,
    threshold           INTEGER NOT NULL,
    window_microseconds BIGINT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'succeeded', 'failed')),
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at         TIMESTAMPTZ,
    events_scanned      INTEGER,
    first_event_at      TIMESTAMPTZ,
    last_event_at       TIMESTAMPTZ,
    alerts_detected     INTEGER,
    alerts_created      INTEGER,
    alerts_updated      INTEGER,
    alerts_unchanged    INTEGER,
    error               TEXT
);
