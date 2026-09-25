CREATE TABLE organizations (
    organization_id TEXT PRIMARY KEY,
    name            TEXT NOT NULL
);


CREATE TABLE users (
    user_id         TEXT PRIMARY KEY,
    login           TEXT NOT NULL UNIQUE
        CHECK (login <> '' AND login = btrim(login)),
    display_name    TEXT NOT NULL,
    organization_id TEXT REFERENCES organizations (organization_id),
    role            TEXT NOT NULL
        CHECK (role IN ('member', 'organization_admin', 'lab_analyst')),
    password_hash   TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((role = 'lab_analyst') = (organization_id IS NULL)),
    UNIQUE (user_id, organization_id)
);


CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id    TEXT NOT NULL REFERENCES users (user_id),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CHECK (created_at < expires_at)
);

CREATE INDEX sessions_user_idx ON sessions (user_id);


CREATE TABLE documents (
    document_id     TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations (organization_id),
    owner_id        TEXT NOT NULL,
    title           TEXT NOT NULL CHECK (char_length(title) BETWEEN 1 AND 200),
    body            TEXT NOT NULL CHECK (char_length(body) <= 20000),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A document's owner must belong to the document's organization.
    FOREIGN KEY (owner_id, organization_id)
        REFERENCES users (user_id, organization_id)
);

CREATE INDEX documents_organization_owner_idx
    ON documents (organization_id, owner_id);


ALTER TABLE security_events
    DROP CONSTRAINT security_events_event_type_check,
    ADD CONSTRAINT security_events_event_type_check
        CHECK (event_type IN (
            'login_failed',
            'login_succeeded',
            'access_denied',
            'document_created',
            'document_updated',
            'document_downloaded',
            'role_changed'
        )),
    ALTER COLUMN organization_id DROP NOT NULL,
    ADD CONSTRAINT security_events_organization_scope_check
        CHECK (
            organization_id IS NOT NULL
            OR event_type IN ('login_failed', 'login_succeeded')
        );

CREATE INDEX security_events_actor_time_idx
    ON security_events (actor_id, occurred_at);


ALTER TABLE alerts RENAME COLUMN failure_count TO match_count;

ALTER TABLE alerts
    DROP CONSTRAINT alerts_check,
    ADD CONSTRAINT alerts_window_check CHECK (window_start <= window_end),
    ALTER COLUMN organization_id DROP NOT NULL,
    ALTER COLUMN attempted_account DROP NOT NULL,
    ADD CONSTRAINT alerts_entity_check
        CHECK (attempted_account IS NOT NULL OR actor_id IS NOT NULL),
    ADD COLUMN cooldown_microseconds BIGINT
        CHECK (cooldown_microseconds > 0),
    ADD COLUMN suppression_until TIMESTAMPTZ,
    ADD CONSTRAINT alerts_suppression_check
        CHECK ((cooldown_microseconds IS NULL) = (suppression_until IS NULL));

ALTER TABLE alert_events
    DROP CONSTRAINT alert_events_evidence_role_check,
    ADD CONSTRAINT alert_events_evidence_role_check
        CHECK (evidence_role IN (
            'failed_login',
            'successful_login',
            'denied_document_access'
        ));

ALTER TABLE detection_runs
    ADD COLUMN cooldown_microseconds BIGINT;
