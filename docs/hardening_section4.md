# Section 4: security and investigation workflow

October 2, 2026. Starting revision: `3db1665`.
Scope: timeline Section 4, detailed roadmap H4–H5. Splunk, read-only machine
credentials, snapshot exports, public hosting, and stateful R2 remain later work.

## API and case policy

All requests are capped at 1 MiB of received body bytes before JSON parsing,
including chunked bodies and bodies with a misleading Content-Length. Existing
500-event, event-field, 200-character document-title, and 20,000-character document-body
limits remain. Notes and decision rationales are trimmed, nonempty, and at most
2,000 characters. Unknown identity/author fields are rejected.

Alert and document lists retain their JSON array shape. `limit` defaults to 50 and
is limited to 1–100; `offset` accepts 0–1,000,000. `X-Total-Count` describes all
matching rows, and `X-Next-Offset` is empty on the last page. Alert filters `rule`,
`status`, `organization`, and `entity` are applied in SQL before counting/paging.
Entity search is a literal, case-insensitive substring of actor/account; SQL wildcard
characters have no special meaning. Active alerts are the default; use
`include_superseded=true` for history. Ordering is event-window end descending,
then alert key. Documents remain owner/tenant-scoped before counting and paging.

Alert detail accepts `evidence_limit` and `evidence_offset`, returning
`evidence_total` separately from the page. Evidence is ordered by event time and
ID. Source IPs and requested resources describe only that evidence page and are
labelled accordingly. Replacement links are bounded to 100 per direction, with
separate totals and `replacement_offset`. Case activity is similarly paginated,
newest first. Counts and rows within each response use one repeatable-read snapshot.
These are live browsing pages: concurrent changes can shift offsets between requests.
They are not a frozen export; Section 6 owns that contract. `/security/events`
retains its existing maximum of 1,000 rows and is not a complete export endpoint.

Only current lab-analyst sessions may call:

- `PATCH /security/alerts/{key}` with `revision`, `status`, `disposition`, and `rationale`.
- `POST /security/alerts/{key}/notes` with `revision` and `body`.
- `GET /security/alerts/{key}/activity` with `limit` and `offset`.

Closing requires `benign`, `suspicious`, or `inconclusive` and a rationale. Reopening
to `new` or `investigating` clears the current disposition and requires a rationale;
old decisions remain in history. Existing pre-migration closed alerts remain untouched,
with no invented disposition. New case writes lock the row, compare its revision,
and save the change and activity in one transaction. Stale revisions return 409.
Author and time come from the server. Database triggers reject history UPDATE/DELETE.

Detector writes preserve status, disposition, rationale, and history. Changed results
advance the revision; added evidence on a closed case sets `needs_review`.
R2 replacement links retain the old decision and carry unresolved review flags
through subsequent replacements. Saving a decision acknowledges the displayed revision
and clears its review flag; adding a note does not. A concurrent detector change
therefore invalidates a pending decision instead of being silently acknowledged.

## Verification

- Baseline: 174 backend tests, no skips.
- Fresh installation: 218 backend tests, no skips; 12 frontend tests; typecheck/build passed.
- Final working tree: 219 backend tests, no skips; 12 frontend tests; typecheck/build passed.
  The additional check verifies request-ID correlation and secret-free event reads/logs.
- Dedicated empty databases: `section4_acceptance_test` and `section4_suite_test`.
  Migrations 001–007 applied; a second migration pass was a no-op. Seed: two
  organizations, six users, nine documents. A separate source copy and new Python
  virtual environment installed `.[dev]`; frontend dependencies came from `npm ci`.
- Live API on localhost:8004 and frontend on localhost:5174: suspicious scenario
  created one R1/one R2; rerun unchanged; guarded reset; benign scenario produced
  zero alerts; guarded reset; `triage` created one R1 and one benign-triggering R2.
- New tests cover every new route for absent/invalid/member/admin/analyst/collector
  credentials. A hypothetical future reader token is rejected; no read-only
  machine credential is implemented yet. Logout, expiry, revocation, and role
  change invalidate case access through direct requests.
- Existing direct 403/404 tests still verify tenant/ownership isolation and no
  foreign organization or document text in denial evidence. Concurrency tests
  prove identical ingestion replays once, conflicting ingestion rolls back its
  entire losing batch, and stale case changes cannot overwrite a winning decision.
- Failure injection after the history insert rolls back both history and case state.
  Closed-case evidence extension, unchanged reruns, repeated R2 replacement, immutable
  history, filtered pagination, invalid offsets/limits, and chunked body limits pass.
- UI tests cover 401/403/404, filter restoration, evidence paging, closing requirements,
  stale-write errors without losing the draft, and session expiry during note writes.

Environment: macOS, Python 3.14.7, PostgreSQL 17.11, psycopg 3.3.6,
pytest 8.4.2, Node 26.4.0, npm 11.17.0. The clean install resolved FastAPI 0.142.2.

Commands: `.venv/bin/python -m pytest --tb=short`; `npm ci`; `npm test`;
`npm run typecheck`; `npm run build`; the README migrate/seed/scenario commands
against the isolated targets.

Hosted release gate passed for published revision `f3fe14a6e3e061f1727f23853d8400ae57962a0e`: both backend and frontend jobs succeeded in
[GitHub Actions run 37150851207](https://github.com/kerry-linn/project_detection/actions/runs/37150851207).

October 3 revalidation: Docker was recovered without deleting volumes. The current
backend suite passed **231 tests with no skips**. A separate source copy and fresh
Python environment installed `.[dev]`; migrations 001–007 and a no-op second pass
ran against the new `section45_acceptance_retry_test` database. A live API on port
8006 reproduced suspicious (one R1/one R2), benign (zero alerts), and triage
(one R1/one R2) scenarios. Notes and closed suspicious/benign decisions survived
detector reruns with revision 2 and both history entries intact. A clean `npm ci`,
12 frontend tests, typecheck, and build also passed.

## Backup, reset, retention, and logging

A custom-format backup was taken before the case migration and restored into the
new isolated `section4_restore_test` database. Every table matched the original
row-for-row: 33 events, 3 alerts, 18 evidence links, 11 detector runs, 9 documents,
2 organizations, 6 users, 3 sessions, and 2 applied migrations. That existing lab
was on schema 002; it was not silently upgraded or reset. Tests separately cover
an empty database and upgrade through the prior schema.

Example commands (keep backups private; they contain credentials and application data):

```bash
docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > /tmp/security-lab.dump
docker compose exec -T postgres sh -c 'createdb -U "$POSTGRES_USER" security_lab_restore_test'
docker compose exec -T postgres sh -c 'pg_restore -U "$POSTGRES_USER" -d security_lab_restore_test --exit-on-error' < /tmp/security-lab.dump
```

Reset first prints the connected `host:port/database` identity. Destructive reset
requires all three: `LAB_ENV=local`, `--yes`, and exact `--confirm-target`. It clears
case activity as well as telemetry/checkpoints/sessions and retains seeded documents,
users, and organizations. Test fixtures still require a database ending in `_test`.

Retention: retain all evidence, active and superseded alerts, notes, and decisions
indefinitely in this lab. There is no automatic deletion. Back up before an intentional
full telemetry reset; reset explicitly destroys historical cases too. Database owners
can bypass controls: this is not tamper-proof storage or a regulatory archive.

Run the API with `--no-access-log`; application logging emits only a generated request
ID, status code, and safe category. `X-Request-ID` correlates with audit events.
Passwords, headers/tokens, hashes, paths/query strings, document text, request bodies,
and exception text are excluded. Validation errors do not echo submitted values.
Runner reports retain their existing run IDs and safe failure categories. Event views
contain validated telemetry, not document bodies or session-token digests; analyst notes
are case data, not event-export fields. Do not put secrets in notes or fixture fields.

## Concrete bug and limits

Previously a closed alert receiving new evidence retained its conclusion without
flagging a need for review. The detector now preserves that conclusion, sets the flag,
and increments the revision. Regression:
`test_late_evidence_flags_closed_case_and_invalidates_stale_revision`.
Repeated R2 replacements also retain unresolved review flags; the original decision,
notes, and evidence remain inspectable through replacement history.

This remains a local lab: no HTTPS/login throttling/MFA, shared seed password,
sessionStorage exposed to XSS, no background scheduler, no immutable security archive.
R2 scans full history, and incremental R1 bounds time spans rather than row counts.
Body caps and result pages do not impose a total database-size or concurrency quota.


## Investigation and demo artifacts

The real UI was visually checked and a captioned, silent **2:13** local demo recorded.
It shows raw R1 evidence, analyst notes, closing R1 as suspicious, explaining and closing
R2 as benign, case history, and a member receiving 403 on the analyst route.
Both saved decisions survived a further detector rerun unchanged.

- [Suspicious R1 investigation](investigations/section4_R1_suspicious.md)
- [Benign triggering R2 investigation](investigations/section4_R2_benign.md)
- [Captured API evidence and activity](investigations/section4_evidence.json)
- [Recording instructions](DEMO.md#section-4-recorded-take)

Video: `section4-demo.webm`, delivered as a local artifact outside the repository.
No credentials are visible; the login password is masked. The benign explanation is
explicitly external synthetic exercise context, not an inference from 404 responses.
