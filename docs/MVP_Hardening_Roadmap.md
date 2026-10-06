# Detection Project: MVP Hardening, Splunk, and API Automation

October 1, 2026; completion evidence updated October 3, 2026.

H0–H2 checks are complete: [baseline and recovery](docs/hardening_baseline.md),
[R2 reconciliation](docs/hardening_section2.md), and the current full regression suite.
The initial-state descriptions below are historical; current implementation status
is recorded in the completion notes and [timeline](MVP_Completion_Timeline.md).

## 1. Goal and scope

Turn the existing FastAPI/PostgreSQL/React lab into a reliable, explainable detection project, then deepen the same workflow with Splunk and a Python API collector. Preserve R1/R2 behavior while improving recovery, processing, investigation, and reproducibility.

This plan is grounded in the seven supplied project documents, not a fresh source-code audit. “Implemented” below means documented as implemented; the first milestone verifies the actual repository. All new paths, commands, schemas, and effort estimates are proposals.

Allocate roughly 70% of effort to hardening and 30% to Splunk/API automation. Treat this as a flexible budget, not a reason to rush correctness. Keep applying with the completed MVP while working through these milestones.

## 2. Current baseline: preserve work you already completed

| Capability | Documented current state | Next action |
| --- | --- | --- |
| Parser and contract | UTC normalization, schema checks, size limits, duplicate/conflict handling | Preserve; add only uncovered cases |
| Ingestion | Server assigns ingestion time; source boundary; atomic batches; replay detection | Verify concurrent conflicts and total body limits |
| Authentication/authorization | Argon2id, hashed opaque sessions, revocation/expiry, server-side tenant/role checks | Re-run direct API matrix; protect new routes |
| Audit transactions | Successful document changes and their audit records commit together | Verify failure paths beyond the existing test |
| R1/R2 | Pure functions, deterministic keys, evidence, boundaries and replay tests | Preserve exact semantics; address late R2 identity changes |
| Detector runs | Start row committed; alerts/evidence/success in one transaction; failure recorded separately | Add crash recovery, concurrency tests, operational visibility |
| Investigation UI | Alert list/detail, reasons, ordered raw evidence | Add case changes, notes, dispositions, bounded reads |
| Reproducibility | Migrations, seed/reset/scenario scripts, fresh-checkout acceptance | Re-run; make reset safer; verify hosted CI |
| Tests | Release notes report 134 backend tests and 7 frontend tests passing locally | Record current results; do not assume these counts remain current |
| Release evidence | R1 investigation and demo script exist | Confirm recorded demo and actual GitHub CI run |

Important corrections to the earlier advice: you already have deterministic alerting and rollback tests. The three-transaction runner is a sensible design for a lab. A `detection_runs` row tracks one detector execution, not the state of each event. Your largest open correctness issue is the documented R2 behavior where late data changes the first threshold-crossing event and leaves an older alert behind.

## 3. Milestone order and effort

Estimates are focused implementation hours after the baseline audit; learning may take longer. If a task is already proven, mark it complete rather than rebuild it.

| Milestone | Priority | Estimate | Completion evidence |
| --- | --- | --- | --- |
| H0. Establish baseline | Required first | 2–3 h | Current test run, gap list, reproduced demo |
| H1. Recovery and transaction reliability | Required | 4–6 h | Failure/crash/concurrency tests |
| H2. R2 late-data correctness | Required before incremental R2 | 5–8 h | Canonical alerts and preserved case history |
| H3. Efficient runner and bounded processing | Required staged improvement | 7–12 h | R1 incremental parity, R2 safe fallback, benchmark |
| H4. Security and API limits | Required | 3–5 h | Direct API matrix, bounded requests/results |
| H5. Case workflow and release evidence | Required | 4–6 h | Benign and suspicious cases, clean setup, CI/demo |
| S1. Splunk and R1 parity | Next integration | 6–9 h | SPL files, exported fixture, comparison report |
| A1. Paginated Python collector | Next integration | 6–9 h | Restart/retry tests and exact export comparison |
| Optional depth | After gates pass | Separate budget | Stateful R2, pooling, HEC delivery, deployment |

Core estimate: approximately 37–58 hours. A practical schedule is 4–6 weeks at about 10 hours per week, adjusted to your course load. Tests belong in each milestone; do not defer them to the end.

## 4. H0 — Establish a trustworthy baseline

**Purpose:** distinguish verified strengths from actual gaps.

- [x] Run existing backend tests against the dedicated test database; confirm database suites actually execute.
- [x] Run frontend tests, typecheck, and build; preserve the existing 401/403/404 behavior.
- [x] Follow the README in a clean environment: migrate, seed, suspicious scenario, both rules, rerun, reset, benign scenario.
- [x] Check the GitHub Actions result for the current revision. A workflow file and local commands are not proof of a successful hosted run.
- [x] Record revision, versions, commands, test outcomes, expected alert/evidence IDs, and known failures in `docs/hardening_baseline.md`.
- [x] Reproduce R2's late-arrival key change with a hand-written fixture; make the failure visible before changing the design.
- [x] Update stale documentation: the latest technical spec permits null-organization login groups; early Days 1–4 notes do not. Current auth uses analyst sessions, not the old static analyst token.

**Done:** the current behavior can be reproduced and every remaining task is classified as fix, verify, or new capability. No new integration begins while a basic authorization or evidence-integrity regression is unresolved.

## 5. H1 — Recovery, atomic writes, and concurrent execution

### Keep the existing transaction structure

1. Commit a run row with `running` status.
2. Execute the rule and save its alerts/evidence; mark that run successful in the same commit.
3. On failure, roll back step 2, then record the failed outcome in a new transaction.

When checkpointing arrives, the checkpoint must commit with step 2. A checkpoint is a durable record of successfully processed progress. Moving it before alert persistence can permanently skip work.

### Add the missing failure cases

- [x] Inject failure after the first alert save, during evidence replacement, and immediately before commit. No partial alert/evidence changes should survive.
- [x] Test an existing alert update that fails: its previous evidence and analyst fields remain intact.
- [x] Kill the runner after the initial run record commits. On restart, identify the abandoned run safely.
- [x] If PostgreSQL is unavailable while recording failure, emit a sanitized structured log and nonzero exit status. The original row may remain `running`; do not claim every crash becomes `failed` immediately.
- [x] Add recovery under an exclusive runner lock. Mark an old `running` row abandoned only after establishing its worker is no longer active; age alone is insufficient. A lease/heartbeat is optional if the simpler single-worker lock is adequate.
- [x] Run two detectors concurrently. Define whether the second waits with a timeout or exits as busy. Confirm evidence and counts remain consistent.
- [x] Initially preserve the existing lock unless measurements show a problem. If replacing it with a runner advisory lock, make every detector/backfill entry point participate and test connection-loss behavior.
- [x] Record rule/configuration, run ID, evaluated range, loaded event count, created/updated/unchanged counts, duration, and sanitized failure category.
- [x] Show per-rule outcome: R1 success followed by R2 failure is partial overall success, not a single successful pipeline run.

**Done:** retries recover without partial writes or duplicate alerts; abandoned work is visible; failure leaves processing progress unchanged. Interview explanation: “I separated run observability from atomic detector results, and tested the crash window between them.”

## 6. H2 — Fix R2 late-event identity and preserve investigation history

**Problem:** the current key includes the event that first crosses the threshold. An earlier denial arriving later can change that event; full recomputation then creates another key while retaining the obsolete alert. Late events can also connect episodes previously separated by a cooldown gap.

### Recommended first implementation: recompute and reconcile

- [x] Keep the existing pure R2 function as the reference behavior.
- [x] For an affected actor/organization and rule configuration, recompute its complete available denial history first. This is deliberately conservative; it avoids inventing incomplete episode state.
- [x] Compare recomputed episodes with persisted episodes for that same scope. Initially do this inside the existing full-batch run if affected-entity tracking is not ready.
- [x] Separate “current detection result” from analyst status. Add an active/superseded detection flag and replacement links; superseded does not mean the analyst closed a case.
- [x] Preserve old alerts, evidence, notes, author identity, and dispositions as historical records. Hide superseded results from the default active list but make replacement history inspectable.
- [x] Use shared evidence and full recomputation to establish replacement relationships. Permit multiple old alerts to point to a merged result. Do not merge merely because timestamps overlap.
- [x] If a replacement inherits conflicting analyst conclusions, retain both histories and mark the current result as needing review. Do not silently choose one conclusion.
- [x] Commit new results, replacement links, and supersession together. Never supersede alerts outside the evaluated entity/configuration or from a partial history.
- [x] Preserve idempotency: running reconciliation twice produces the same active set and no extra history entries.

### Required fixtures

| Fixture | Required outcome |
| --- | --- |
| Late denial adds evidence but crossing stays the same | Same active key, evidence extends |
| Late denial moves crossing earlier | New canonical result; old result linked and superseded |
| Late denial bridges two episodes | Current result matches full recomputation; both histories remain accessible |
| Duplicate replay | No new episode or history change |
| Different rule configuration | Separate results; no accidental supersession |
| Analyst has already closed the old alert | Historical conclusion preserved; replacement requires review |
| Reconciliation fails halfway | No partial supersession or evidence changes |

**Done:** current results match full-history R2 output while historical case work remains accessible. A stable persisted episode UUID is an optional later redesign; it still needs a policy for merges and late-data corrections.

## 7. H3 — Improve processing without changing detections

### H3a. Measure and reduce unnecessary work first

- [x] Benchmark synthetic 1k, 10k, and 100k event datasets, with both many entities and one heavily active entity. Record hardware, dataset seed/distribution, elapsed time, peak memory, rows read, and alert count.
- [x] Push event-type and grouping filters into SQL. R1 needs login events; R2 needs document-denial events. Avoid loading unrelated document-change events.
- [x] Examine query plans before adding indexes. Consider rule-specific indexes only when the measured query benefits.
- [x] Keep the full-batch path as a correctness reference and backfill mechanism.
- [x] If repeated Python scans dominate, use a sliding window/deque or indexed timestamps while preserving all evidence IDs and exact boundaries. Output itself can be large when many successes share failures; do not promise constant memory.

### H3b. Add bounded incremental R1

Suggested lab policy: one-minute schedule, ten-minute R1 window, fifteen-minute allowed lateness. These are configurable project choices, not industry defaults.

Let `C` be the previous successful run's event-time upper bound, `U` the new run's fixed upper bound, `L` allowed lateness, and `W` the rule window.

- Re-evaluate candidate successes in `[C-L, U]`.
- Load failures back to `C-L-W`; count only `[success-W, success)` for each candidate.
- Commit alert/evidence changes and new checkpoint `U` atomically.
- The initial run requires an explicit baseline range/full run; a missing checkpoint must not silently assume the last few minutes.
- After an outage, start from the old `C`, not simply `now - lookback`. Catch-up may be large; split into consecutive chunks while retaining required context.
- Use a consistent database snapshot for a run. Data committed afterward is handled by overlap or backfill according to the stated lateness policy.
- Document lateness as the delay until data is visible for processing. A timestamp assigned before a long transaction commits is not proof that the detector could see it.
- Detect/report events outside the lateness allowance and provide an explicit backfill route. Preserve them in storage; do not silently discard them.
- Reject or flag implausibly future-dated input using a documented policy; do not let it advance checkpoints.
- Scope checkpoints by rule version and configuration. A changed threshold/window needs explicit initialization or backfill.

**Tests:** failure before checkpoint commit; restart; downtime longer than lookback; boundary late arrivals; delayed transaction commit; same-timestamp events; changed configuration; and parity against the full-batch reference on datasets within the declared policy.

### H3c. Keep R2 safe while improving it in stages

A five-minute lookback plus fifteen-minute cooldown is insufficient by itself. Denials every ten minutes can extend one episode for hours; a short slice loses its original crossing and evidence.

First release: retain full R2 history processing, or recompute complete histories only for affected entities once a reliable change feed exists. Clearly label this as partial incremental processing: R1 is bounded; R2 retains a scaling limitation.

Optional next stage: persist per-entity episode state, opening context, last denial, evidence references, and checkpoint atomically. Late arrivals must trigger reconciliation from a safe earlier boundary through all potentially affected episodes. Compare every intermediate result with full recomputation. Do not truncate R2 history merely to obtain a better benchmark.

**Done:** correctness parity passes; R1 reads less history on steady-state runs; performance measurements support the claimed improvement; R2's actual processing model and remaining limits are documented.

**Completion record — October 2, 2026:** H3a–H3c are implemented and verified in
[Section 3](docs/hardening_section3.md), including raw benchmark/query-plan artifacts,
atomic checkpoint and delayed-commit tests, full-reference parity, and explicit
R2 scaling limits. The requirements above remain the record of the intended design.

## 8. H4 — Security boundaries, bounded APIs, and operational hygiene

### Required local-lab hardening

- [x] Re-run the credential matrix for every new route: missing/invalid credentials, member, organization admin, analyst, write collector, and future read-only collector.
- [x] Preserve 403 for same-organization ownership denial and uniform 404 for foreign/nonexistent documents. Assert response bodies and evidence do not leak foreign tenant details.
- [x] Verify logout, expiry, changed roles, and revoked sessions through direct requests.
- [x] Test simultaneous ingestion of identical IDs and conflicting content. One authoritative event must remain; a conflicting batch must not partially commit.
- [x] Add a total request-body byte cap in addition to the existing 500-event/field limits. Test chunked bodies rather than relying only on Content-Length.
- [x] Bound document/note input and list/evidence responses. Add pagination to alert lists and large evidence views; keep summary counts explicit so a page is not mistaken for complete evidence.
- [x] Move alert filters into SQL when paginating. Filtering only the current page gives misleading results.
- [x] Log run/request IDs and safe error categories; test that passwords, bearer tokens, hashes, document text, and unrestricted payloads never appear in logs or exports.
- [x] Keep parameterized SQL, strict metadata validation, and server-assigned identity/source fields.
- [x] Protect reset with an explicit lab environment check and target identity confirmation as well as `--yes`. Keep test database isolation.
- [x] Test migrations against both an empty database and the prior schema. Document a backup/restore command and perform one restore drill before changing evidence schemas.
- [x] Define a lab retention policy: retain evidence referenced by active/historical cases; do not add silent automatic deletion.

### Conditional work before public hosting

Add HTTPS, appropriate cookie/CSRF design if changing browser authentication, restrictive deployment configuration, login throttling, and reviewed security headers. The current local sessionStorage design has a documented XSS exposure. A public deployment is a separate milestone.

If adding login throttling, define how blocked attempts appear in telemetry and adjust scenarios so they still test R1 intentionally. Avoid silently breaking the five-failures-then-success demonstration. Connection pooling is optional until connection setup is measured as a bottleneck.

**Done:** new features preserve all access boundaries, requests and responses are bounded, and operational commands have clear failure/recovery behavior.

## 9. H5 — Finish the case workflow and package the evidence

- [x] Add analyst-only status changes: `new`, `investigating`, `closed`; use a nullable disposition until a decision exists, then `benign`, `suspicious`, or `inconclusive`.
- [x] Require a disposition and concise rationale when closing. Define reopening behavior and retain the previous decision history.
- [x] Add bounded notes with server-derived author and timestamp. Record status/disposition changes in an append-only case activity table.
- [x] Update case state and its history in one transaction. Add a revision field or equivalent optimistic concurrency check so two analysts cannot silently overwrite one another.
- [x] Keep detector-owned fields separate from analyst-owned fields. A rerun must preserve status, notes, and disposition.
- [x] When new evidence arrives on a closed case, preserve the conclusion but surface a “new evidence requires review” indicator.
- [x] Explain R2's opening threshold separately from episode-wide distinct count; an extended episode can span more than five minutes.
- [x] Write a benign case that actually triggers an alert. The existing below-threshold benign scenarios prove no-alert behavior; they do not demonstrate triage of a false positive.
- [x] Complete one suspicious R1 case and one benign R2 case: hypothesis, evidence IDs, timeline, competing explanations, conclusion, missing data, and rule limitations.
- [x] Update the one-page threat model and known limitations. Record one actual bug, fix, and regression test.
- [x] Repeat fresh-checkout acceptance and capture the 2–3 minute demo. Include a successful GitHub CI run for the final revision.
  Clean acceptance and the recorded demo passed; `f3fe14a6` passed [GitHub Actions run 37150851207](https://github.com/kerry-linn/project_detection/actions/runs/37150851207).

**Hardening release gate:** all critical access/evidence/recovery tests pass; active R2 results survive late-data correction; processing claims match implementation; a reviewer can reproduce, inspect, and disposition alerts without manual database edits.

Completion evidence: [Section 4 verification and operating policy](docs/hardening_section4.md).

## 10. S1 — Splunk: reproduce and explain R1

**Goal:** demonstrate one SIEM query language against the exact events used by Python. Keep the core lab runnable independently.

### Build sequence

1. Select a supported Splunk learning/local environment; verify current platform support and license capabilities at setup time. Manual searches are sufficient.
2. Export canonical synthetic events as JSONL with event IDs, UTC event time, configuration, dataset identifier, and a manifest containing event count and file hash.
3. Import once into an isolated lab dataset. Configure `_time` from `occurred_at`, preserve original timestamp text/precision, and verify field extraction and null organization values.
4. Write searches for one account's timeline, failures by account/IP, denied resources by actor, and raw evidence lookup by event ID.
5. Implement R1 equivalent to Python: same organization/account; one result per success; at least five failures in `[t-10m, t)`; no reset after success; repeated imports must not inflate counts.
6. Export results and compare success IDs, entity keys, failure counts, and evidence ID sets against independently specified expected fixtures and Python output.
7. Save SPL, setup notes, sample outputs, and an investigation in `splunk/` and `docs/investigations/`.

### Parity traps to test explicitly

- Fixed ten-minute buckets are not equivalent to a rolling window anchored to every success.
- A failure exactly at success time must be excluded even if it sorts earlier by event ID.
- A failure exactly ten minutes earlier must be included.
- Null organizations must remain valid groups, especially the tenant-less analyst account.
- Different accounts/organizations must not combine; canonicalization must match Python.
- Duplicate indexing, time parsing, result/window limits, and timestamp precision can change results.
- Multiple successes may legitimately produce multiple alerts with overlapping evidence.

Use Splunk's documented time-window commands as implementation building blocks, but verify their behavior in the selected version. Do not present an untested `streamstats` expression as exact parity. If microsecond boundaries cannot be represented faithfully in the chosen environment, document the mismatch and narrow the equivalence claim.

**Artifacts:** `splunk/r1_failed_login_success.spl`, activity/evidence searches, `splunk/README.md`, `fixtures/expected/splunk_r1.json`, and `docs/splunk_parity.md`.

**Done:** every declared comparison case matches, or an explicit unresolved discrepancy blocks the parity claim. R2 SPL and automatic HEC forwarding are optional extensions after R1.

## 11. A1 — API automation: reliable paginated event export

**Goal:** a Python read-only client that can stop, retry, and resume without losing or duplicating exported events within its declared dataset semantics. This collector reads the separate `/security/events/export` route; it is distinct from the existing write-ingestion collector.

### A1a. Credential and API contract

- [x] Add a separately scoped machine credential for event reads only, with hashed secret storage, revocation, and an expiry/rotation procedure.
- [x] Prove it cannot write events, read documents, change cases, or inherit the analyst's entire role.
- [x] Return `items`, `next_cursor`, and a snapshot/export identifier. Validate page limits and cursor shape; bind cursors to the original filter set and authorization scope.
- [x] Keep deterministic keyset ordering and a tie-breaker. An offset is fragile when rows arrive during collection.

### Recommended first snapshot design

For this lab, materialize the matching event IDs and their ordinal positions in a database export snapshot using one consistent transaction. Page by `(snapshot_id, ordinal)` and expire snapshots after a documented interval. Events are treated as immutable; prevent deletion of referenced snapshot data until expiry.

Newly committed events belong to the next export. This makes restart and parity testing straightforward at lab scale, at the cost of extra storage and snapshot creation work. If a snapshot expires, return an explicit error; the client begins a new export rather than silently mixing datasets.

Do not assume `(occurred_at, event_id)`, `(ingested_at, event_id)`, or a maximum sequence value alone freezes a dataset. Late events can sort behind the cursor, and a transaction can allocate an ID before another transaction commits. A future continuous collector needs overlap/deduplication or a reliable durable change-feed design in addition to pagination.

### A1b. Client behavior

- [x] Configure base URL, credential, filters, page size, connect/read timeouts, output, and resume state.
- [x] Use bounded exponential backoff with jitter for transient connection failures and selected 5xx responses; honor valid `Retry-After` on 429 within a maximum wait/retry budget.
- [x] Stop on 401/403 with a clear message. Do not repeatedly retry malformed payloads, permanent 4xx responses, or expired snapshots.
- [x] Validate every page, required fields, duplicate/conflicting event IDs, and cursor progress; reject a repeated cursor rather than loop forever.
- [x] Store received events keyed by `event_id` and the next cursor in one local SQLite transaction. SQLite is a lightweight checkpoint/output staging file here, not another deployed service.
- [x] On restart, resume that snapshot/cursor. A crash before commit re-fetches the page; a crash after commit resumes the next one.
- [x] Generate JSONL/CSV from staging after collection; write to a temporary file and atomically rename it. Include a manifest with filters, snapshot, count, and completion status.
- [x] Keep original raw values in JSONL. If exporting spreadsheet-oriented CSV, neutralize formula-leading cells and document that display transformation.
- [x] Print pages, records, retries, elapsed time, and final state without logging credentials.

### A1c. Required acceptance tests

| Test | Expected behavior |
| --- | --- |
| Empty, one-page, many-page snapshots | Correct terminal state and exact unique event count |
| Equal timestamps across page boundaries | No missing events |
| Timeout/429/transient 5xx | Bounded retries, then success or explicit failure |
| Invalid/revoked credential | Immediate actionable failure |
| Invalid JSON/schema or repeated cursor | Explicit stop; no corrupt checkpoint |
| Kill before/after page commit | Resume produces identical event-ID set and content |
| Concurrent insert with old event time | Excluded from frozen snapshot; present in the next export |
| Snapshot expiry/filter change | Explicit restart requirement |
| Disk full/output failure | No false completion; prior committed state recoverable |

**Artifacts:** `scripts/collect_events.py`, API contract documentation, collector tests, interrupted-run transcript, and export manifest.

**Done:** compare exported event IDs and canonical content with the server snapshot, not only row counts. Feed the resulting JSONL into the same Splunk parity exercise.

Optional HEC forwarding comes later: retries can duplicate delivery, so retain event IDs and explicitly reconcile indexed output. Verify the selected Splunk product's acknowledgment support; an HTTP response alone is not a universal end-to-end delivery guarantee.

A1 is complete. Implementation, local/live acceptance, and final-code hosted CI
(`7d16da1c`, [run 37169171992](https://github.com/kerry-linn/project_detection/actions/runs/37169171992))
are recorded in [Section 6](docs/hardening_section6.md).

## 12. Compact regression matrix

Retain existing tests and add missing behaviors. Expected evidence IDs should be written independently of detector output.

| Area | Non-negotiable cases |
| --- | --- |
| Parser | Invalid JSON/UTF-8/schema/timezone, optional missing vs invalid, metadata/size limits, equivalent replay, A/B/A conflict |
| R1 | 4/5/6 failures, exact lower/upper boundaries, null org, canonical account, multiple successes, shuffled input, duplicate replay |
| R2 | 4/5/6 distinct documents, repeat one document, non-document denial, tenant/actor isolation, exact 5m/15m boundaries, long episode, late crossing/merge |
| Persistence | Evidence FK integrity, partial-write rollback, concurrent replay/conflict, unchanged reruns, preserved analyst state |
| Runner | Crash, DB outage, stale-run recovery, overlapping runs, checkpoint failure, downtime catch-up, backfill |
| API/UI | Direct role matrix, revocation, 403/404 handling, cursor validation, bounded evidence, filter correctness, stale case update |
| Integration | Suspicious alerts, benign no-alert, benign triggering alert, fresh install/upgrade, real CI |
| Splunk/client | Exact evidence comparison, timestamp ties, duplicates, page restart, transient errors, concurrent arrivals |

## 13. First three work sessions

**Session 1:** run H0, capture current results, reproduce the R2 late-event defect, and write its expected canonical result by hand.

**Session 2:** add H1 failure/crash tests, fix any actual gaps, and explain the three transactions without notes.

**Session 3:** design and implement the smallest R2 reconciliation migration and tests. Preserve history before introducing incremental R2 state.

End each session with three lines: built; verified; still unclear. Reserve 20–30 minutes to explain or reimplement a small piece independently: an evidence join, sliding window, retry loop, or authorization check.

## 14. Stop conditions and later scope

Stop hardening when the release gate is met; do not keep expanding infrastructure to feel “production ready.” Keep Kafka, Kubernetes, Redis, a second SIEM, ML, threat-intelligence enrichment, and broad AWS deployment out of this cycle.

After Splunk parity and API export are demonstrated, consider R3/R4 and a small CloudTrail/S3 extension from the original roadmap. Stateful incremental R2, connection pooling, public hosting, and automatic Splunk forwarding should each have a measured or educational reason.

Potential interview claims, only after verified: atomic detection/checkpoint recovery; reconciliation of late R2 episodes while preserving case history; measured reduction in R1 scan volume; SPL parity on named fixtures; and checkpointed read-only API collection. Describe synthetic lab results as lab results.

## 15. Source basis

Project documents reviewed: `TECHNICAL(1).md`, `DAYS_12_14.md`, `DAYS_10_11(1).md`, `DAYS_7_9(4).md`, `DAYS_5_6(3).md`, `DAYS_1_4(4).md`, and `security_project_roadmap(20261001-135950).txt`. The latest technical/release documents take precedence over historical walkthrough descriptions. None of the proposed tasks above has been implemented or tested as part of creating this roadmap.

Official Splunk references consulted October 1, 2026:

- [SPL streamstats reference](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.0/search-commands/streamstats): time-window behavior and command limits to validate during parity work.
- [HEC indexer acknowledgment](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.0/get-data-with-http-event-collector/about-http-event-collector-indexer-acknowledgment): optional delivery verification; check the selected product/version before implementation.

The architecture choices, effort estimates, and acceptance gates are project-specific recommendations. Current pricing, installation eligibility, and licensing were not established by this planning exercise.
