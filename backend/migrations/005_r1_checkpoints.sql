-- Top-level insertion transactions let the runner detect delayed commits.
ALTER TABLE security_events
    ADD COLUMN processing_xid xid8 NOT NULL DEFAULT pg_current_xact_id();

CREATE TABLE detection_checkpoints (
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    threshold INTEGER NOT NULL CHECK (threshold >= 1),
    window_microseconds BIGINT NOT NULL CHECK (window_microseconds > 0),
    allowed_lateness_microseconds BIGINT NOT NULL CHECK (allowed_lateness_microseconds >= 0),
    upper_bound TIMESTAMPTZ NOT NULL,
    visibility_snapshot pg_snapshot NOT NULL,
    backfill_required BOOLEAN NOT NULL,
    PRIMARY KEY (rule_id, rule_version, threshold, window_microseconds)
);

ALTER TABLE detection_runs
    ADD COLUMN processing_mode TEXT NOT NULL DEFAULT 'full'
        CHECK (processing_mode IN ('full', 'incremental')),
    ADD COLUMN candidate_start TIMESTAMPTZ,
    ADD COLUMN checkpoint_at TIMESTAMPTZ,
    ADD COLUMN chunks_processed INTEGER CHECK (chunks_processed >= 0),
    ADD COLUMN late_events_detected INTEGER CHECK (late_events_detected >= 0),
    ADD COLUMN future_events_deferred INTEGER CHECK (future_events_deferred >= 0),
    ADD COLUMN backfill_required BOOLEAN;
