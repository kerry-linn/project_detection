# Hardening section 2: R2 late-event reconciliation

Recorded October 1, 2026. The pre-fix fixture is
[`r2_late_arrival.jsonl`](../fixtures/r2_late_arrival.jsonl); its independently
specified before/after result is
[`expected/r2_late_arrival.json`](../fixtures/expected/r2_late_arrival.json).

## Reproduced defect and result

The first five denials opened an R2 episode at `denial-4`. A later-ingested
`denial-late`, timestamped before those five, moved the first crossing to
`denial-3`. Before reconciliation, a rerun left both keys visible as current.
Now only `denial-3` is active. The previous `denial-4` result remains available
with its original five evidence links and analyst status, and a replacement link
points to the new six-event result. A closed prior alert marks its replacement
`needs_review`; its closed status is not copied to the new alert.

R2 still recomputes from every stored event. Reconciliation is limited to the
same rule version and exact threshold, window, and cooldown configuration.
Replacement links require a shared evidence event for the same organization and
actor. If an obsolete result has no evidence-based successor, the run fails and
rolls back rather than silently discarding history. A runner lock and alert-table
lock serialize the full evaluation and write transaction.

`GET /security/alerts` shows active alerts by default. An analyst can use
`?include_superseded=true` or the UI checkbox to inspect prior results. Alert
details expose `replaces` and `replaced_by` keys, retained evidence, analyst
status, and the review flag. Existing role checks apply to both views.

## Verification

- The PostgreSQL regression suite covers same-key extension, earlier crossing,
  two and three episode merges, equivalent replay, configuration isolation,
  closed-case preservation, API history access, and failure during link creation.
- The injected link failure leaves the old result active, its evidence unchanged,
  and no new alert or replacement link. A retry succeeds.
- The full backend suite passed with 151 tests and no skips against the dedicated
  PostgreSQL test database. Eight frontend tests, TypeScript check, and production
  build passed locally.

Current case notes, dispositions, and analyst change history are not yet in the
schema; section 4 adds that workflow. R2's full-history scan remains a scaling
limit until a safe affected-entity change feed or episode state is added.
