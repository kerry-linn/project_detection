# Hardening section 1: baseline and recovery

Recorded October 1, 2026. Baseline revision: `a878fa3669423bd763482967eb0aa3cc4bfc8d98`.
The changes described below are local until committed and pushed.

## Environment and checks

macOS; Python 3.14.7, pytest 8.4.2, psycopg 3.3.6, PostgreSQL 17.11,
Node.js 26.4.0, npm 11.17.0. The project uses the dedicated `security_lab_test`
database for backend tests.

- `.venv/bin/python -m pytest -ra`: **143 passed, 0 skipped** after section 1 changes.
  Before Docker started, the same suite reported 64 passed and 70 skipped; that result
  did not verify persistence or API behavior.
- `npm test -- --reporter=dot`: **7 passed**. `npm run typecheck` and `npm run build` passed.
- [GitHub Actions run 36875258384](https://github.com/kerry-linn/project_detection/actions/runs/36875258384)
  succeeded for baseline revision `a878fa3`; both backend and frontend jobs passed, and
  the backend job ran migrations and the skip guard. The local changes require a new
  hosted run after they are pushed.
- Existing direct API tests cover missing credentials, role denial, same-organization
  `403`, and uniform foreign/nonexistent-document `404`; frontend tests retain their
  `401`/`403`/`404` behavior.

For a fresh setup, a separate Compose project used port `55433` and a new volume.
The application and test databases each applied `001_initial`, `002_application`, and
`003_run_recovery` from empty schemas. Seeding created two fictional organizations,
six users, and nine documents. A local API on port `8001` ran against this fresh
application database. The normal database and its telemetry were untouched.

The README suspicious sequence produced 12 events. The first detector pass created
one R1 and one R2 alert; the second pass reported `created=0, updated=0, unchanged=1`
for each. The observed alert keys were:

```text
R1_FAILED_LOGINS_FOLLOWED_BY_SUCCESS:1.0:threshold=5:window_us=600000000:app-38c8dcb0-335b-49e7-a1e3-207b844f51a0
R2_REPEATED_DENIED_DOCUMENT_ACCESS:1.0:threshold=5:window_us=300000000:cooldown_us=900000000:org-alpha:user-bob:app-38d3b269-0808-4267-ad86-b1a0139633a0
```

R1 evidence: failed-login IDs `app-3d26b464-d6a5-40ae-bc1f-3a29af00ecc2`,
`app-6c787344-ff2c-4069-ac06-8fe837567db8`,
`app-c7d335b2-e2bd-4f0d-8e00-2b090273a166`,
`app-c93a2e6c-1182-49ab-9ddc-f300360b2db3`, and
`app-d29d3e9c-026e-4e10-a87f-4d6d2538c7c5`; success ID
`app-38c8dcb0-335b-49e7-a1e3-207b844f51a0`.

R2 evidence: denial IDs `app-329d641e-1868-482a-98a0-67aee25fbe2c`,
`app-38d3b269-0808-4267-ad86-b1a0139633a0`,
`app-8fcaec27-9d50-4bb6-a032-609eaa52f05a`,
`app-993e4f12-edbc-4330-bff2-5e3fa4fc8ba9`, and
`app-d9efe8e3-2bb6-4131-af6c-541ad5802087`.

These application IDs are generated per replay. After a telemetry reset, the benign
sequence produced 11 events and zero alerts from both rules.

## Failure and recovery results

The existing first-alert-save failure test and new tests in
[`test_detection_recovery.py`](../tests/test_detection_recovery.py) verify:

- Failure after evidence replacement restores the entire previous alert row, its
  evidence, and `investigating` status. Failure after `finish_run`, immediately before
  commit, leaves no alert or evidence and records a failed run. The failed row retains
  the loaded event count, evaluated range, detected count, duration, and zero committed
  alert writes.
- A subprocess killed after its `running` row commits leaves that row `running`.
  The next worker first acquires the session advisory lock, marks the old row
  `abandoned`, and then succeeds. A further rerun creates no duplicate alert.
- When R1 owns the lock, a concurrent R2 attempt exits `busy` without changing the
  active row. R2 succeeds when retried; evidence counts remain consistent.
- A terminated PostgreSQL connection prevents recording the failure. The process
  emits a structured, sanitized `database_unavailable` category and exits with an
  error. A direct CLI test confirms exit status 1. Its row remains `running` until a
  later worker marks it `abandoned`.
- The CLI reports R1 success and R2 failure separately, returns a nonzero status,
  and does not print injected secret-like exception text. Successful runs report
  run ID, rule/configuration, evaluated event-time range, scanned count, alert
  outcomes, and duration. No checkpoint exists in this section to advance on failure.
- Existing R1/R2 rerun tests confirm stable keys and evidence, including updates
  that preserve analyst status.

## Gap classification

- **Fix in section 2:** [`r2_late_arrival.jsonl`](../fixtures/r2_late_arrival.jsonl)
  adds a sixth denial with an earlier event time after the first run. The canonical
  crossing moves from `denial-4` to `denial-3`, but the current database holds both
  keys. This is reproduced by `test_late_denial_changes_crossing_key_and_exposes_current_gap`.
- **New capability in section 3:** bounded incremental R1 and a checkpoint. R2 still
  reads full history.
- **Fix/verify in section 4:** request byte limits, paginated reads, concurrent
  ingestion, reset safeguards, and full authorization review.
- **New capability in section 4:** case notes, dispositions, and revision-safe case
  changes.
- **Verify after push:** a hosted CI run for the section 1 commit. Run 36875258384
  proves only the baseline revision.

Recovery policy: one detector runs at a time; a concurrent attempt reports `busy` and
can be retried. The advisory lock proves an older worker using this runner has stopped
before its `running` row is marked `abandoned`; elapsed age alone never triggers that
transition. The existing alert-table lock still protects writes during evaluation.
If the database is unavailable, a row may remain `running` until the next successful
runner obtains the lock. No partial alert/evidence writes survive a failed transaction.
