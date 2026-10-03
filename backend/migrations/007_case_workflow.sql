ALTER TABLE alerts
    ADD COLUMN disposition TEXT CHECK (disposition IN ('benign', 'suspicious', 'inconclusive')),
    ADD COLUMN rationale TEXT CHECK (char_length(rationale) BETWEEN 1 AND 2000),
    ADD COLUMN revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0);

CREATE TABLE case_activity (
    activity_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    alert_key TEXT NOT NULL REFERENCES alerts (alert_key),
    author_id TEXT NOT NULL REFERENCES users (user_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revision INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('decision', 'note')),
    status TEXT NOT NULL CHECK (status IN ('new', 'investigating', 'closed')),
    disposition TEXT CHECK (disposition IN ('benign', 'suspicious', 'inconclusive')),
    body TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 2000),
    UNIQUE (alert_key, revision)
);

CREATE FUNCTION reject_case_activity_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'case activity is append-only';
END;
$$;
CREATE TRIGGER case_activity_immutable BEFORE UPDATE OR DELETE ON case_activity
    FOR EACH ROW EXECUTE FUNCTION reject_case_activity_mutation();
