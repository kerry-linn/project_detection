ALTER TABLE alerts
    ADD COLUMN detection_state TEXT NOT NULL DEFAULT 'active'
        CHECK (detection_state IN ('active', 'superseded')),
    ADD COLUMN needs_review BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE alert_replacements (
    old_alert_key TEXT NOT NULL REFERENCES alerts (alert_key),
    new_alert_key TEXT NOT NULL REFERENCES alerts (alert_key),
    PRIMARY KEY (old_alert_key, new_alert_key),
    CHECK (old_alert_key <> new_alert_key)
);

CREATE INDEX alert_replacements_new_idx ON alert_replacements (new_alert_key);
