-- Measured with EXPLAIN before/after; see docs/hardening_section3.md.
CREATE INDEX security_events_r1_visibility_idx
    ON security_events (processing_xid)
    WHERE event_type IN ('login_failed', 'login_succeeded')
      AND attempted_account IS NOT NULL;
