# Technical Specification

This document defines the project's security model, event contract, detections, and
engineering rules. It is a design specification until the corresponding behavior is
implemented and tested.

## Application and threat model

The application stores fictional text documents for two organizations. Its primary assets
are user accounts, organization membership and roles, document data, security telemetry,
and alert evidence.

### Actors

- **Member:** reads and updates documents they own.
- **Organization administrator:** manages documents and membership only within their
  organization.
- **Lab analyst:** reads global security events and alerts and manages investigations.
- **Unauthenticated user:** may attempt authentication but has no application access.
- **Trusted collector:** may submit fixture or external events through a separate,
  credential-protected ingestion path.

Likely abuse includes password guessing, password spraying, cross-organization access,
document enumeration, improper role changes, and unusual download activity. The main
trust boundaries are the browser/API boundary, organization boundary, analyst boundary,
trusted collector boundary, and later the local/AWS boundary.

Authorization is enforced server-side on every request. Hiding controls in React is not
an authorization control. Tests must prove that members and organization administrators
cannot access global events or alerts through direct API calls.

Authentication must use a maintained authentication and password-hashing library or an
established identity provider. The chosen mechanism, session lifecycle, and logout
behavior must be recorded here before authentication is implemented. Custom cryptography
is prohibited.

For v0.1, account lockout is intentionally omitted so failed-login telemetry can exercise
R1. This is a documented preventive-control gap, not a recommended production design.
The relationship between lockout thresholds and R1 must be reconsidered before adding
lockout.

## Event data contract

All timestamps are timezone-aware and normalized to UTC. Requiredness may vary by event
type, but validation must reject inconsistent combinations.

The implemented schema version is the exact JSON string `"1.0"`. Numeric versions,
coercion, and unknown strings are rejected.

| Field | Meaning |
| --- | --- |
| `event_id` | Globally unique event identifier used for replay protection |
| `occurred_at` | Event time in UTC |
| `ingested_at` | Time the platform accepted the event |
| `source` | `application`, `fixture`, or `cloudtrail` |
| `event_type` | Controlled event name |
| `organization_id` | Organization scope, nullable only when no scope can be established |
| `actor_id` | Authenticated actor, or null for an unknown failed-login account |
| `attempted_account` | Canonical fictional login identifier used for login correlation |
| `target_actor_id` | Account affected by a role change |
| `previous_role` | Typed role before a role change |
| `new_role` | Typed role after a role change |
| `session_id` | Opaque session identifier, never the session cookie or token |
| `source_ip` | Request source as observed by the server or trusted proxy |
| `resource_type` | Controlled type such as `document`, `alert`, or `admin_route` |
| `resource_id` | Resource involved, when available |
| `outcome` | `success`, `denied`, or `failure` |
| `request_id` | Identifier linking activity from the same request |
| `schema_version` | Version of this contract |
| `metadata` | Small, allow-listed context that has no first-class field |

Initial application event types:

- `login_failed`
- `login_succeeded`
- `access_denied`
- `document_downloaded`
- `role_changed`

`access_denied` is generic so attempts against documents, analyst APIs, and administrative
routes share one security concept. R2 considers only events where
`resource_type=document`.

`document_downloaded` means a successful request to a distinct, explicit document download
route. Reading a document detail page is not a download. The route records the event only
after server-side authorization succeeds. When S3 is added, an application-issued
presigned URL records authorization and URL issuance; it does not prove that the object was
downloaded.

Do not log passwords, password hashes, tokens, cookies, document content, or unrestricted
request bodies. Constrain string and metadata sizes, canonicalize attempted accounts
consistently, and sanitize control characters before display or export.

In local Docker Compose, the API may observe the container bridge gateway rather than
distinct client IPs. IP-diverse scenarios therefore use trusted fixtures and must be
identified as synthetic.

## Persistence model

- `users`: organization membership, role, canonical login identifier, and authentication
  data.
- `documents`: owner, organization, text content, and timestamps.
- `security_events`: validated event contract with a unique constraint on `event_id`.
- `alerts`: rule ID and version, deterministic key, entity, time range, reason, severity,
  status, and disposition.
- `alert_events`: many-to-many evidence links between alerts and security events.
- `case_notes`: alert, analyst author, timestamp, and note text.
- `detection_runs`: run ID, rule versions, start/end time, evaluated event-time range,
  events scanned, alerts created, alerts updated or suppressed, and run outcome.

Indexes follow actual query patterns: event time plus each grouping field used by a rule.
Database access uses parameterized SQL or an ORM.

**Implemented in Days 5–6** ([`backend/migrations/001_initial.sql`](../backend/migrations/001_initial.sql)):
`security_events`, `alerts`, `alert_events`, and `detection_runs`, using raw parameterized
`psycopg` SQL rather than an ORM.

- `security_events` stores every contract field. `event_id` is the primary key; controlled
  values, the schema version, and the metadata shape are `CHECK` constraints; `source_ip`
  is `INET`; timestamps are `TIMESTAMPTZ`. Indexes cover `(occurred_at, event_id)` for
  ordered scans and `(organization_id, attempted_account, occurred_at)` for account
  investigation.
- `alerts` uses the R1 deterministic key as its primary key (`alert_key`). Detection
  refreshes rule-derived fields; `status` is analyst-owned and never overwritten.
- `alert_events` has a composite primary key `(alert_key, event_id)`, a typed
  `evidence_role`, and foreign keys to both tables, so evidence cannot reference a missing
  event.
- `detection_runs` records rule version, configuration, timing, status, scanned event-time
  range, alert outcome counts, and a failure message.
- `users`, `documents`, `case_notes`, and disposition fields remain planned.

## Pipeline and trust boundaries

1. Normal application routes derive identity, organization, outcome, request ID, and source
   details from server-controlled state.
2. Successful business changes and their audit events are committed in one transaction.
3. Denied requests create durable audit events even though no business change occurs.
4. Trusted batch ingestion validates fixtures or external events and relies on a scoped
   collector credential. It is separate from ordinary browser routes.
5. The detector reads validated events, records a `detection_runs` row, and writes
   deterministic alerts and evidence links.
6. The investigation API returns events, alerts, and case data only to the lab analyst or
   an explicitly scoped read-only collector.
7. A later export sends the same stored events to Splunk for manual SPL comparison.

Ordinary clients may not assert actor identity, organization, source IP, or request outcome.
Proxy headers are trusted only when the application is configured behind a known proxy.
The browser-facing API never accepts arbitrary security events.

The implemented collector boundary (`POST /internal/events/batch`) accepts only `fixture`
and `cloudtrail` sources; `application` events are reserved for server routes. The server
assigns `ingested_at`, and a client-supplied value is rejected. Lab authentication uses two
distinct static bearer tokens from the environment, compared with
`secrets.compare_digest`: the collector token may only ingest, and the analyst token may
only read. This is a lab mechanism, not the final identity design, which must be chosen
before Days 7–9.

For state-changing routes, failure to persist the audit event fails the business
transaction. For denied requests, an audit-write failure is surfaced and measured, but
the platform does not claim tamper-proof or lossless logging. The implementation must
document any remaining failure mode.

## Detection specification template

Every rule records its hypothesis, required fields, grouping, window boundaries,
threshold, severity rationale, evidence, deterministic identity, suppression, benign
causes, blind spots, and independently written tests. Thresholds are configurable lab
choices, not validated industry defaults.

### R1 — Failed logins followed by success (v0.1, implemented)

- **Hypothesis:** repeated failures followed by a successful login may indicate account
  compromise.
- **Required fields:** event type, organization, canonical attempted account, outcome,
  event time, event ID; source IP is retained when present.
- **Grouping:** organization and canonical account.
- **Window:** for each success at time `t`, examine failures in `[t-10m, t)`.
- **Threshold:** at least five failures followed by the success.
- **Severity:** medium; the sequence warrants review but commonly results from user error.
- **Evidence:** the success, all qualifying failures, source IPs, and session ID.
- **Identity:** rule ID/version, threshold, exact window duration in microseconds, and the
  success event ID.
- **Suppression:** deterministic identity prevents re-alerting for the same success.
- **Benign causes:** mistyped passwords, saved stale credentials, or a shared client.
- **Blind spots:** slow guessing, password spraying across many accounts, missing events,
  account canonicalization errors, and shared IP attribution.
- **ATT&CK:** T1110.001 Password Guessing, when the observed behavior supports that
  interpretation.
- **Tests:** below/at/above threshold, exact start boundary, failure at `t`, different
  accounts and organizations, duplicate events, missing IP, shuffled input, and replay.

A separate practice query groups by source IP and counts distinct attempted accounts to
demonstrate password-spray reasoning; it is not part of R1.

The Days 3–4 implementation is a pure batch function called by
`python -m scripts.detect_r1`. It sorts validated events by event time and event ID,
deduplicates source-equivalent replayed records while ignoring collection time, and
retains the earliest `ingested_at`. Conflicting records passed directly to the detector
raise an error because the pure function has no line-level rejection channel. Each
qualifying success creates a distinct alert; differently configured runs cannot collide
because threshold and window are part of the key. Results contain the deterministic
identity, configuration, and ordered evidence needed by the persistence layer.

Days 5–6 add `python -m scripts.run_detection`, which loads stored events, calls the same
pure function, and saves each alert by its key: new keys are inserted, existing keys whose
evidence changed are updated with their links replaced, and identical results are left
untouched. A late failure inside an existing window therefore extends the same alert
instead of creating a second one.

### R2 — Repeated denied document access (v0.1)

- **Hypothesis:** attempts to reach many unauthorized documents may indicate enumeration
  or broken client authorization.
- **Required fields:** `access_denied`, actor, organization, document resource type and ID,
  event time, and event ID.
- **Grouping:** actor and organization.
- **Window:** rolling five-minute interval with documented inclusive boundaries.
- **Threshold:** at least five distinct document IDs.
- **Severity:** medium; repeated denials are suspicious but not evidence of data exposure.
- **Evidence:** all qualifying denials and requested resource identifiers, without document
  content or unauthorized tenant details.
- **Identity:** one stored episode key per actor, organization, rule version, and episode
  start.
- **Suppression:** maintain one open episode during a configurable cooldown and extend its
  evidence with qualifying events.
- **Benign causes:** stale links, old clients, bookmarks, or recently changed membership.
- **Blind spots:** repeated attempts against one document, unauthenticated enumeration,
  identity changes, and missing denial telemetry.
- **ATT&CK:** no forced mapping; the event alone does not establish a specific technique.
- **Tests:** repeated same document, five distinct documents, cross-organization separation,
  exact window boundaries, episode extension, cooldown expiry, shuffled input, and replay.

### R3 — Privilege change followed by downloads (v1.0)

- **Hypothesis:** downloads shortly after a role increase may indicate misuse of newly
  granted privileges.
- **Required fields:** successful role change, previous/new role, target actor, changing
  actor, downloads, session ID, resources, times, and event IDs.
- **Grouping:** target actor and organization; the changing administrator remains evidence.
- **Window:** downloads in `[role-change time, role-change time + 10m]`.
- **Threshold:** one defined role increase followed by configurable download activity.
- **Severity:** high because privilege and data access are correlated, though neither
  proves compromise.
- **Evidence:** role-change event, administrator, affected account, qualifying downloads,
  and sessions.
- **Identity:** rule ID/version plus role-change event ID and episode key.
- **Suppression:** one episode per role increase, extending evidence during the window.
- **Benign causes:** approved onboarding, temporary access, or administrator-assisted work.
- **Blind spots:** role changes outside the platform, delayed use, pre-existing sessions,
  and legitimate increases.
- **ATT&CK:** T1098 Account Manipulation and T1078 Valid Accounts only when the evidence and
  investigation support those interpretations.
- **Tests:** every role transition, decreases/no change, wrong target account, exact
  boundaries, multiple administrators, and replay.

The role ordering is explicitly defined before implementation. A role change by itself is
not called privilege escalation.

### R4 — High download volume (v1.0)

- **Hypothesis:** rapid access to many distinct documents may warrant exfiltration review.
- **Required fields:** successful downloads, actor, organization, session, resource ID,
  time, and event ID.
- **Grouping:** actor, organization, and session, with an actor-level companion view.
- **Window:** rolling five minutes.
- **Threshold:** at least twenty distinct documents.
- **Severity:** high due to potential data impact, not certainty of malicious intent.
- **Evidence:** qualifying downloads, distinct count, resources, and sessions.
- **Identity:** stored episode key per actor, organization, rule version, and episode start.
- **Suppression:** one open episode during a documented cooldown; extend its evidence.
- **Benign causes:** approved exports, migration, backup, or bulk review.
- **Blind spots:** slow collection, access through unlogged channels, multiple accounts,
  issued-but-unused S3 URLs, and unavailable S3 data events.
- **ATT&CK:** no forced mapping; volume alone cannot prove collection or exfiltration.
- **Tests:** repeated same document, threshold boundaries, multiple sessions, multiple
  organizations, cooldown behavior, shuffled input, and replay.

This is threshold-based detection, not machine learning or behavioral baselining.

## Event-time and replay policy

v0.1 processes batches sorted by `occurred_at`, then `event_id`, for deterministic results.
Naive timestamps are invalid. A malformed record is quarantined with a reason while valid
records continue; it must not silently erase the rest of the batch.

Within one batch, records with the same event ID are source-equivalent when every
normalized field except `ingested_at` matches. Equivalent replays collapse to the record
with the earliest collection time and are reported separately from rejected records. If
source content conflicts, every occurrence of that ID is excluded and rejected, including
later records that match an earlier version. Unrelated valid records continue processing.
Strict CLI mode fails for rejected or conflicting input, not for an equivalent replay.

Across requests, PostgreSQL enforces the same policy. A stored event ID that arrives again
with identical source content is counted as a replay and not stored twice; the first
`ingested_at` is kept. The same ID with different content rejects the entire ingestion
batch with `409 Conflict`, because the authoritative evidence would otherwise depend on
arrival order.

Incremental processing re-evaluates a configurable overlapping lookback. Unique event IDs,
deterministic alert identities, and evidence-link constraints prevent duplicates. Events
older than the late-event allowance require an explicit backfill command. The project does
not claim unlimited late-event support or exactly-once streaming.

Fixture expected results are written by hand before running a detector. Tests must not
generate their expected result by calling the logic under test.

## Proposed API

| Method and path | Access |
| --- | --- |
| `POST /auth/login` | Public credential exchange |
| `GET/POST /documents` | Authenticated, organization and ownership scoped |
| `GET/PATCH /documents/{id}` | Authenticated, server-authorized |
| `GET /documents/{id}/download` | Authenticated, server-authorized; emits download event |
| `POST /internal/events/batch` | Trusted collector only |
| `GET /security/events?cursor=...` | Lab analyst or scoped read-only collector |
| `GET /security/alerts` | Lab analyst only |
| `GET /security/alerts/{id}` | Lab analyst only |
| `PATCH /security/alerts/{id}` | Lab analyst only; records state-change actor |
| `POST /security/alerts/{id}/notes` | Lab analyst only |

Exact routes may change with implementation, but their authorization boundaries may not
weaken silently. Cursor pagination uses stable ordering and documents how concurrent
inserts affect traversal.

Implemented in Days 5–6: `POST /internal/events/batch`, `GET /security/events` (filters and
a bounded `limit`; cursor pagination remains planned), `GET /security/alerts`, and
`GET /security/alerts/{alert_key}`. Security reads currently accept only the analyst
credential; a scoped read-only collector credential is not implemented.

## Engineering rules

- Detection functions remain independent of HTTP and database code. The CLI and worker
  call the same rule logic.
- Start with explicit batch execution, then add scheduling. Do not introduce streaming
  infrastructure.
- Synthetic fixtures cover benign, suspicious, malformed, duplicate, shuffled, and exact
  boundary cases. Expected outcomes are independently specified.
- Every feature includes at least one invalid or denied case and one regression test for
  its authorization boundary.
- Secrets never enter source control. `.env.example` contains names and non-secret values
  only.
- External calls use timeouts and bounded retries. Writes are retried only with a defined
  idempotency mechanism.
- Work proceeds in small feature-sized changes. After each change: run it, inspect real
  output, test benign and invalid input, and explain the assumptions.
- AI may scaffold, explain, review, and suggest debugging paths. The author personally
  attempts the parser, R1, one SQL query, the API collector, and an authorization test.
- Each work session records three short lines: built; verified; still unclear.

A feature is done only when it runs from documented commands, enforces authorization
through direct requests, produces inspectable evidence or output, handles malformed input,
has meaningful behavioral tests, and states its limitations.

## Planned evidence documents

During implementation, `docs/` will gain only evidence-bearing artifacts:

- A one-page threat model, started before event implementation and refined later
- One v0.1 investigation of the suspicious login scenario
- A benign alert investigation and one CloudTrail investigation for v1.0

These should be concise records of observed behavior, not additional speculative manuals.
