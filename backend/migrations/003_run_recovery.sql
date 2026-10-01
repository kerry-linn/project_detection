ALTER TABLE detection_runs
    DROP CONSTRAINT detection_runs_status_check,
    ADD CONSTRAINT detection_runs_status_check
        CHECK (status IN ('running', 'succeeded', 'failed', 'abandoned')),
    ADD COLUMN duration_ms BIGINT CHECK (duration_ms >= 0);
