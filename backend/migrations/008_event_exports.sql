CREATE TABLE export_credentials (
    credential_id TEXT PRIMARY KEY,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    token_hash TEXT NOT NULL UNIQUE,
    scope TEXT NOT NULL DEFAULT 'event_export' CHECK (scope = 'event_export'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CHECK (expires_at > created_at)
);

CREATE TABLE export_snapshots (
    snapshot_id TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL REFERENCES export_credentials (credential_id),
    export_id TEXT NOT NULL,
    filters JSONB NOT NULL,
    page_size INTEGER NOT NULL CHECK (page_size BETWEEN 1 AND 1000),
    cursor_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '24 hours',
    total_count BIGINT NOT NULL DEFAULT 0 CHECK (total_count >= 0),
    UNIQUE (credential_id, export_id)
);

CREATE TABLE export_snapshot_events (
    snapshot_id TEXT NOT NULL REFERENCES export_snapshots (snapshot_id) ON DELETE CASCADE,
    ordinal BIGINT NOT NULL CHECK (ordinal > 0),
    event_id TEXT NOT NULL REFERENCES security_events (event_id),
    PRIMARY KEY (snapshot_id, ordinal),
    UNIQUE (snapshot_id, event_id)
);
CREATE INDEX export_snapshot_events_event_idx ON export_snapshot_events (event_id);
CREATE INDEX export_snapshots_expiry_idx ON export_snapshots (expires_at);

CREATE FUNCTION reject_security_event_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'security events are immutable';
END;
$$;
CREATE TRIGGER security_events_immutable BEFORE UPDATE ON security_events
    FOR EACH ROW EXECUTE FUNCTION reject_security_event_update();
