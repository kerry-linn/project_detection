# Section 6: snapshot event export and resumable collector

October 3, 2026 (live artifacts use October 4 UTC). Implementation and local/live
acceptance passed. Final hosted CI remains pending publication of this revision.
Sections 1–5 are complete: 231 earlier backend tests without skips, fresh setup and
investigation scenarios, live Splunk parity, and both hosted jobs passed for `f3fe14a6`
in [run 37150851207](https://github.com/kerry-linn/project_detection/actions/runs/37150851207).

## Credential lifecycle

Apply migration 008 and run the API with `--no-access-log` as in the README.
Credential management uses a database connection, separate from all HTTP roles:

```bash
python -m scripts.migrate
mkdir -p .exports
python -m scripts.export_credentials create --name local-export --days 30 --output .exports/token
export EVENT_EXPORT_TOKEN="$(cat .exports/token)"
python -m scripts.export_credentials list
```

Creation writes the secret once to a new mode-0600 file and prints only its ID, scope,
and lifetime. Existing files are never overwritten. PostgreSQL stores only a SHA-256
hash of the 256-bit random secret. Default lifetime: 30 days; `--days` accepts 1–365.
Names contain 1–128 characters. Git ignores `.exports/`. `--database-url-env` selects
an alternate database environment variable.

The sole scope, `event_export`, permits global event reads across the fictional
organizations, including null-organization login events. It grants no document,
ingestion, alert, case, or session access. Analyst sessions and the write-ingestion
token cannot call the export route. Every page checks expiry/revocation in its
transaction. An already-authorized page may finish while revocation waits; subsequent
requests fail. Rotate by creating a token, completing or abandoning old exports, and
revoking the old credential ID shown by `list`:

```bash
python -m scripts.export_credentials revoke CREDENTIAL_UUID
unset EVENT_EXPORT_TOKEN
```

A new token requires new export state. Snapshot ownership never transfers.

## HTTP contract

`GET /security/events/export` accepts a bearer machine token. The existing analyst
`GET /security/events` array response is unchanged. Optional query fields:

- `organization_id`, `attempted_account`, `actor_id`, `event_type`: exact filters
  combined with AND; 1–256 characters. Account matching uses casefold. Omit for all
  values; there is no special textual-null filter.
- `limit`: page size 1–1,000, default 100; fixed for the snapshot.
- `export_id`: client-generated UUID for idempotent initial requests. The collector
  saves it before HTTP. If omitted initially, the server creates a new export;
  direct clients should provide it when retrying.
- `cursor`: opaque signed continuation, at most 512 characters. Continue with the
  same filters/page size and credential. Unknown/repeated parameters fail.

Successful responses contain `items`, `next_cursor` (string or null), `snapshot_id`,
`export_id`, `expires_at` (UTC), and `total_count`. Items contain only the existing
public event fields, including nullable fields and metadata. Empty snapshots have
zero items/count and null cursor. Success sends `Cache-Control: no-store`.

Creation materializes matching event IDs and ordinals in one `INSERT SELECT` under
one PostgreSQL statement snapshot. Header, membership, count, and initial response
commit in one transaction. Ordering is `(occurred_at, event_id COLLATE "C")`, giving
locale-independent timestamp ties. Continuations seek by snapshot ID and ordinal.
Events committed afterward, including older timestamps and already-open transactions,
belong only to a new export.

The header binds credential, filters, page size, and export ID; HMAC-SHA256 cursors
bind snapshot and position. Retrying an initial request with the same export ID
returns the same snapshot, including after a lost response or concurrent first request.
Replaying a valid page cursor on the server is allowed; the client rejects repeated
*next* cursors and nonadvancing records. Event updates are rejected and foreign keys
retain referenced events. Snapshot expiry defaults to 24 hours from creation.

Errors: 400 malformed/tampered cursor or unknown/repeated parameter; 401 missing,
invalid, expired, or revoked credential; 403 another snapshot owner; 409 changed
filters/export ID/page size; 410 expired/unavailable snapshot; 422 invalid typed
parameters or bounds. A 410 requires an explicit new export.

Expired headers remain tombstones so an initial retry cannot silently choose new data.
New initial requests opportunistically release expired membership; manual cleanup:

```bash
python -m scripts.export_credentials cleanup
```

Cleanup exclusively locks expired headers and skips active page readers, preventing
removal between expiry checking and event reading. Event data itself remains under
the existing lab retention policy. Telemetry reset refuses every unexpired snapshot,
even completed ones; its snapshot-table lock prevents a concurrent creation. After
expiry, reset clears headers and telemetry but preserves credentials/users/documents.
Deleted snapshot continuations still return 410. Explicit destructive lab reset also
removes initial-request tombstones; do not resume old initial requests after reset.

## Collector operation

With the API running, from the repository root:

```bash
python -m scripts.collect_events --base-url http://127.0.0.1:8000 \
  --token-env EVENT_EXPORT_TOKEN --state .exports/run.sqlite \
  --output .exports/events.jsonl --page-size 17 --max-pages 2
# Exit 2 pauses after two committed pages. Resume without max-pages:
python -m scripts.collect_events --base-url http://127.0.0.1:8000 \
  --token-env EVENT_EXPORT_TOKEN --state .exports/run.sqlite \
  --output .exports/events.jsonl --page-size 17
# Reuse completed staging for CSV, without another HTTP request:
python -m scripts.collect_events --state .exports/run.sqlite \
  --output .exports/events.csv --format csv --page-size 17
```

Filters: `--organization-id`, `--attempted-account`, `--actor-id`, `--event-type`.
Resume requires original URL, page size, filters, and token. New snapshots need new
state files; expiry never silently restarts. Output paths/formats and retry settings
may change. Parent directories must exist. HTTPS is required except for localhost;
URL credentials and redirects are rejected. Proxy environment settings are ignored.

Defaults (seconds): `--connect-timeout 5`, `--read-timeout 30`, `--attempts 5`,
`--max-delay 30`, `--wait-budget 120`. Attempts accept 1–10; timeout/wait values must
be positive and at most 300. Wait budget is per page. Connection failures, timeouts,
remote protocol failures, and HTTP 500/502/503/504 use bounded exponential jitter.
429 honors valid numeric/HTTP-date `Retry-After`; waits beyond the budget stop with
an instruction to resume later. Authorization/permanent status errors, bad JSON/schema,
changed metadata, duplicate IDs, invalid order/counts, and repeated cursors stop
immediately. Responses are capped at 32 MiB. Progress contains counts, retry delays,
elapsed time, and state; it excludes bearer secrets, response bodies, and exception text.

SQLite mode-0600 state holds event payloads keyed by `event_id`, ordinals, visited
cursors, and progress. A local exclusive file lock prevents concurrent writers.
Events and next cursor commit together with FULL synchronous durability. Crashes
before commit re-fetch that page; crashes afterward start the next. The first export
ID is durable before HTTP, handling a lost initial response. State includes a token
digest for configuration matching; treat it and event data as private.

Complete staging is published through a same-directory temporary file, fsync, atomic
rename, and directory fsync. The completion manifest is published last the same way,
recording snapshot/export identity, expiry, filters, count, format, canonical-content
hash, and file hash. Accept output only with a matching manifest/hash. Failed writes
retain committed staging; rerun regenerates output. JSONL retains raw field values.
CSV serializes objects as JSON and prefixes an apostrophe for strings starting with
`=`, `+`, `-`, or `@`, including after whitespace. This is a display transformation.
Exit codes: 0 complete, 1 failed, 2 deliberately paused, 130 interrupted.

## Verification evidence

Full backend: **312 passed, zero skipped** against dedicated PostgreSQL.
Frontend: **12 passed**, typecheck and build passed. A fresh runtime-only Python
package installation (without development dependencies) ran both collector and
credential-management command entry points successfully. Coverage
includes credential boundaries, expiry/revocation, filter/owner binding, empty and
multipage snapshots, timestamp ties, concurrent first requests/late commits, immutable
retention, cleanup/page locking, transaction rollback, network/429/5xx/permanent errors,
malformed responses, duplicate IDs, repeated cursors, real process death before/after
SQLite commit, disk/output failures, and protected state paths. Existing detector,
case, and application regressions pass. The benchmark helper now understands Section
4 case fields and snapshot-protected reset; a 1,000-event many/hot-entity benchmark
passed reference parity.

Live acceptance used isolated database `section6_7b77c350_test`, migrations 001–008
and a no-op second pass, API port 8007, and a temporary private token revoked afterward.
The collector paused at 34 of the 200 Splunk fixture records; an older event was
inserted. Resume matched the original 200 IDs and every canonical field against both
the server snapshot and original fixture. A new export included 201. A separate
collector was SIGKILLed with 17 durable records, then resumed to exactly 201. Expiring
a paused export returned 410 with no completed output. JSONL and CSV were generated.

Saved synthetic evidence:

- [Acceptance assertions](exports/section6_acceptance.json)
- [Actual restart transcript](exports/section6_restart.txt)
- [Completed JSONL](exports/section6_events.jsonl)
- [Completion manifest](exports/section6_events.manifest.json)

The completed API JSONL was imported into pinned **Splunk 10.4.3** in a separate
dataset. All 200 events and nine independent R1 expectations matched Python and SPL:
exact IDs, counts, ordered evidence, and microsecond timestamps. Guarded reimport
stayed at 200; shuffled/replayed input at 200/400 preserved results; conflicting
content was rejected. Four auxiliary searches matched. See [live verification](../splunk/results/section6/verification.json)
and [comparison](../splunk/results/section6/comparison.json).

## Limits

This is a synthetic local lab. Snapshot creation/storage scales with matching event
count; there is no global/per-credential snapshot quota. Expired headers and revoked
credential records remain indefinitely. Collector locking uses POSIX flock (macOS/Linux).
Staging needs disk for the full export. Completed local copies can be regenerated
after server expiry; incomplete ones need a new snapshot. No continuous change feed,
automatic HEC forwarding, new server rate limiter, or public deployment is included.
Database owners can bypass controls; preserve the existing backup policy.
