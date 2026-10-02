# Section 3 — Processing efficiency

Implementation record, October 2, 2026. This follows the Section 2 correction and
the separate readability cleanup (`580f158`). Earlier walkthroughs and reports
remain historical records. Scope: H3a–H3c in the [roadmap](../MVP_Hardening_Roadmap.md).

## Plan and outcome

1. Measure the old full-history loader and R1 scan at 1k, 10k, and 100k events,
   for both 100 accounts and one busy account.
2. Move rule eligibility filters into SQL. Retain full R2 episode histories.
3. Add explicit full and incremental R1 modes, snapshot-aware lateness reporting,
   atomic checkpoints, and catch-up chunks. Test failure and restart boundaries.
4. Remove R1's repeated scans of expired failures after measuring the busy-account
   cost. Review query plans before selecting an index.
5. Compare every benchmark result with the full reference, rerun application
   checks, and record the policy and remaining limits.

These steps are implemented. No HTTP routes, authentication rules, JSON event
fields, alert identities, evidence roles, or R2 reconciliation rules changed.
Migrations 005 and 006 add internal processing state and one measured index.

## Operator policy

Apply migrations, then initialize the exact R1 configuration with a full run:

```bash
python -m scripts.migrate
python -m scripts.run_detection --rule r1 --r1-mode full
python -m scripts.run_detection --rule r1 --r1-mode incremental
```

The default remains `full`, including `python -m scripts.run_detection` with no
arguments. Full mode evaluates all eligible login history through the run's fixed
database time and establishes a baseline. It is also the explicit backfill command.
There is no silent initialization to “the last few minutes.” Incremental mode
without a matching baseline fails with `checkpoint_required` and exits nonzero.

The suggested lab cadence is once per minute; this section adds no scheduler.
Defaults are a ten-minute rule window, fifteen minutes of allowed lateness, and
one-hour catch-up chunks. Configure these with `--window-minutes`,
`--allowed-lateness-minutes`, and `--chunk-minutes`. Threshold is still
`--threshold`. These are lab choices, not validated industry defaults.

For a previous successful upper bound **C**, current fixed upper bound **U**,
allowed lateness **L**, and rule window **W**:

- Candidate successes are in **[C − L, U]**.
- Failure context starts at **C − L − W**. The pure rule still counts only
  failures in **[success − W, success)** for the same organization/account.
- Successes exactly at a shared chunk boundary belong to the earlier chunk.
  Failure context overlaps chunks. An event with the same timestamp as a success
  cannot count as its preceding failure, regardless of event-ID ordering.
- Downtime resumes from the saved C. All consecutive chunks use one snapshot and
  one work transaction. Chunking bounds the time span loaded at once; a crash
  rolls back the entire catch-up and retries from C.
- Checkpoint identity includes rule ID, version, threshold, and exact window.
  Changing these or the lateness allowance requires another full run. Changing
  chunk size does not change the results or require initialization.

### Late commits and events outside the overlap

Lateness includes the delay until a database transaction becomes visible.
`ingested_at` can precede its commit, so it cannot safely identify newly visible
events. Migration 005 records the inserting top-level transaction as
`processing_xid`; a checkpoint records a PostgreSQL visibility snapshot.

The next run searches committed login rows whose transaction was absent from the
previous snapshot. Newly visible rows with event time **strictly before C − L**
increase `late_events_detected` and set durable `backfill_required=true`.
Rows exactly at C − L remain within the overlap. The flag is conservative: an old
failure can be flagged even when some affected successes still fall in the overlap.
Stored events are retained in either case.

The run continues to process its declared range and may succeed with that flag.
Operators must inspect it; success does not promise historical completeness when
`backfill_required` is true. Run explicit full R1 with the same configuration to
recompute all visible history and clear the flag atomically. A later incremental
run still detects transactions that committed after that full run's snapshot.

The database transaction uses **REPEATABLE READ**. All event loads and chunks see
one committed view even if ingestion commits while detection is running.
PostgreSQL's top-level `xid8` and snapshot functions support testing transaction
visibility; the lower snapshot bound narrows the lookup without treating transaction
IDs as commit order. See the official [snapshot-function documentation](https://www.postgresql.org/docs/17/functions-info.html#FUNCTIONS-PG-SNAPSHOT)
and [isolation documentation](https://www.postgresql.org/docs/17/transaction-iso.html#XACT-REPEATABLE-READ).

### Future timestamps

R1 defers **every login event after U**, reports `future_events_deferred`, and keeps
the event stored. There is no future tolerance that advances C. U comes from the
database statement clock when capturing the snapshot, never from the maximum event
timestamp. Deferred events become eligible as database time reaches them. A database
clock earlier than C fails incremental processing with `checkpoint_clock_regression`.
The file-only pure detector remains event-time based without a wall-clock cutoff.
R2 retains its existing full accepted-history behavior and has no checkpoint.

## Transaction and recovery walkthrough

1. The existing session advisory lock excludes every other detector and backfill.
2. Commit the `running` row separately, after marking abandoned workers.
3. Start the work transaction in REPEATABLE READ; take the existing alerts table
   lock; capture U and visibility; validate the checkpoint and prepare the range.
4. Load each chunk, evaluate R1, and save its alerts/evidence. Analyst status is
   preserved by the existing upsert.
5. Write the new checkpoint, including the backfill flag. Mark the run succeeded.
   **Alerts, evidence, checkpoint, and run success commit together.**
6. On an exception, roll back that work and record failure separately. Killing
   the process bypasses Python cleanup, but PostgreSQL rolls back uncommitted
   results. The next lock owner marks the old run abandoned and starts from C.

For example, C=12:00, L=15m, W=10m gives candidate successes from 11:45 and
failure context from 11:35. If the next run begins at 14:00, it processes the
whole gap in chunks. A success at 12:45 is evaluated once with its complete
12:35–12:45 failure context. A newly committed success at 11:44:59 requires
backfill; a success at 11:45 is included. A failure at the success's exact time
is excluded. Follow these cases in
[test_incremental_r1.py](../tests/test_incremental_r1.py).

## Code map and syntax additions

- [r1_processing.py](../backend/r1_processing.py): policy validation, snapshot,
  lateness/future checks, and consecutive event batches.
- [checkpoints.py](../backend/repositories/checkpoints.py): scoped checkpoint
  reads and writes; the caller owns the transaction and runner lock.
- [events.py](../backend/repositories/events.py): SQL eligibility/range filters;
  the general `load_events` remains available for full reference comparisons.
- [detection_runner.py](../backend/detection_runner.py): transaction ownership,
  chunk evaluation, persistence, progress accounting, and recovery.
- [R1 detector](../detections/failed_login_success.py): a per-entity `deque`
  drops expired failures before examining each success. Sorting and the explicit
  upper-bound check preserve all evidence IDs and tie semantics.
- [migration 005](../backend/migrations/005_r1_checkpoints.sql) and
  [migration 006](../backend/migrations/006_r1_visibility_index.sql): processing
  state, reporting columns, and the measured visibility index.
- [benchmark_detection.py](../scripts/benchmark_detection.py): isolated data,
  retained old R1 scan, measurements, plans, and parity checks.

`yield` makes `event_batches` a generator: it hands one chunk to the runner and
resumes when the runner asks for the next. It does not commit between chunks.
`Literal["full", "incremental"]` describes allowed values to a type checker;
`__post_init__` also validates them at runtime. `deque.popleft()` removes the
oldest entry without shifting every remaining entry. The PostgreSQL `::pg_snapshot`
cast gives a parameter the snapshot type; `::text` makes snapshots straightforward
to round-trip through psycopg. `ON CONFLICT ... DO UPDATE` updates the exact
checkpoint key inside the caller's transaction. The earlier
[study guide](CODEBASE_WALKTHROUGH.md) explains context managers, `finally`,
frozen dataclasses, `replace`, evidence sets, authentication, R2, and the frontend.

## Benchmark method and evidence

Hardware: Apple M4, 16 GiB RAM, macOS 26.6.2 arm64. Python 3.14.7;
PostgreSQL 17.11 in local Docker. Seed **3101**, six-second spacing, ending at
2026-01-01 00:00 UTC: 50% failed logins, 10% successful logins, 30% document
denials, 10% document updates. A group of ten events contains five failures,
one success, three denials, and one update. The “many” distribution cycles
through 100 accounts; “hot” uses one. Document IDs sample twenty values.

The benchmark uses a unique disposable schema in a database ending in `_test`.
It applies migrations, uses COPY outside the measurement to load data, and drops
only that schema. It never resets the normal application/test tables. Event
generation is checked against the parser. Reproduce with:

```bash
python -m scripts.benchmark_detection --phase baseline --output /tmp/r1-baseline.json
python -m scripts.benchmark_detection --phase optimized \
  --compare /tmp/r1-baseline.json --output /tmp/r1-optimized.json
```

Two measurements are kept separate:

- **Evaluation:** load rows plus pure detection. Baseline uses the old unfiltered
  loader and repeated R1 failure scan retained in the benchmark; optimized uses
  SQL eligibility filters and the deque. Both full evaluations include all history.
  Result SHA-256 values cover every alert dataclass field, including ordered evidence.
- **Persistence:** run the real R1 runner against the isolated database, first full,
  then incremental after ten more events and one simulated minute. Only the snapshot
  wall clock is fixed to the synthetic timeline; database snapshots, transactions,
  queries, locks, and writes are real. Every stored alert field and evidence-role
  pair is compared with full recomputation after the incremental run.

Times are single local observations with warm database caches, not service-level
targets. `peak_python_mib` uses tracemalloc; it excludes PostgreSQL, native driver
buffers, and interpreter RSS. `events_read` counts rows returned to Python, not
database pages or rows visited internally. Raw EXPLAIN ANALYZE/BUFFERS plans make
that distinction visible. Stored `events_scanned` sums loaded chunk rows, including
repeated failure context; detected/outcome counts evaluate each candidate success once.

Raw results: [baseline JSON](benchmarks/section3_baseline.json) and
[optimized JSON](benchmarks/section3_optimized.json). Their revision is the parent
commit and `dirty_worktree` records that Section 3 was measured before commit.
Each dataset has exact counts, timing, memory, plans, and parity outcomes.

### Recorded measurements

For each dataset below, times and Python peaks describe full evaluation, before → after. R1 alert counts remain 100, 1,000, and 10,000 at the three sizes. R2 remains zero alerts for the sparse many-account pattern and one long episode for the busy account.

- **1,000, many:** R1 0.022 → 0.016 s, 1.37 → 0.81 MiB; R2 0.019 → 0.007 s, 1.37 → 0.43 MiB.
- **1,000, hot:** R1 0.023 → 0.016 s, 1.37 → 0.81 MiB; R2 0.019 → 0.006 s, 1.37 → 0.43 MiB.
- **10,000, many:** R1 0.214 → 0.148 s, 13.69 → 8.04 MiB; R2 0.203 → 0.067 s, 13.69 → 4.24 MiB.
- **10,000, hot:** R1 0.248 → 0.151 s, 13.67 → 8.03 MiB; R2 0.193 → 0.065 s, 13.67 → 4.24 MiB.
- **100,000, many:** R1 2.344 → 1.466 s, 136.92 → 80.40 MiB; R2 2.008 → 0.654 s, 136.92 → 42.39 MiB.
- **100,000, hot:** R1 7.203 → 1.485 s, 136.74 → 80.29 MiB; R2 1.959 → 0.659 s, 136.74 → 42.34 MiB.

SQL filtering reduces R1 rows returned from N to 0.6N and R2 to 0.3N. Every full-result digest matches the baseline. R2 retains all 30,000 denials in the 100k busy-account dataset; none of its long episode is sliced away.

The persisted incremental runs each read **146 events**, evaluate **16 alerts** (one created, fifteen unchanged), and match the complete reference after ten new mixed events. Final stored counts are 101, 1,001, and 10,001. Their Python peaks range from 0.206 to 0.258 MiB and elapsed times from 0.018 to 0.049 s. At 100k, full initialization loads 60,000 login events and takes 16.48 s / 80.41 MiB (many) or 35.07 s / 122.86 MiB (hot), including writes. Initialization and steady state perform different amounts of work; these are not interchangeable throughput measurements.

### Index decision

Before migration 006, the 100k many-account visibility check visited 2,304 shared buffers and took 7.643 ms. The partial transaction-ID index reduced that to two buffers and 0.007 ms; the busy-account check changed from 7.711 to 0.009 ms. These measurements were taken before selecting the index, then reproduced with the final schema. The recorded steady-state query has no old newly-visible rows, which is the common empty-audit case.

The existing event-time index already serves the 100k bounded range in about 0.062 ms. No additional event-time or R2 index was added. At smaller sizes the planner sometimes chooses the new partial index for other queries and their timing can vary or worsen; the claim is the measured visibility-check improvement, not universal speedup. Full scans and output-size costs remain.


## Limits and operating assumptions

- R1 is incremental only when explicitly selected. Full initialization/backfill
  remains proportional to history. R2 always reads complete eligible denial
  histories; its episode memory and persistence still grow with the episode.
- Time chunks are not fixed row limits. A very dense hour, many accounts with no
  success, or many successes sharing failures can still use substantial memory.
  Long downtime also means one long transaction and lock hold, even with chunks.
- A long-lived transaction can hold the snapshot lower bound back and make
  visibility checks scan more transactions. The measured index helps normal
  steady-state runs; it cannot eliminate that cost.
- Events are append-only through the application. Manual database mutation,
  deletion, logical replication, or restoring transaction IDs into another cluster
  is outside the incremental visibility guarantee. After a restore or manual
  repair, run full R1 before resuming incremental processing. Do not reuse an old
  snapshot against a different cluster. No retention/streaming mechanism is added.
- `backfill_required` and future counts are CLI/database operational signals;
  this section adds no dashboard or automatic backfill. Duplicate ingestion still
  leaves the original event and transaction identity unchanged.
- A migration adds a transaction-ID column to existing rows. Pause runners and
  allow time/space for the table rewrite and index build on a larger installation.
  Existing data is tested through migration and full initialization.

## Verification record

- SQL filtering: 88 persistence/recovery/API/application/scenario tests passed.
- Incremental processing: initialization/configuration changes, inclusive overlap,
  chunk boundaries and same-time successes, future input, clock regression,
  delayed commits (including savepoints), replay, null organizations, backfill,
  analyst status, rollback at three write boundaries, and killed-worker restart.
- Pure optimization: independent full-window scan parity and existing parser/rule
  boundary tests. R2 includes a persisted episode extended over four hours.
- Migration: prior-schema events survive; the new checkpoint starts empty and
  requires full initialization. Fresh schemas are exercised in tests/benchmarks.
- All six benchmark cases match full-result digests and persisted R1 recomputation.

Final local checks on October 2, 2026:

- `python -m pytest --tb=short -rs`: **174 passed, no skips**, against PostgreSQL.
- `npm test`: **9 passed**; `npm run typecheck` and `npm run build`: passed.
- `git diff --check`: passed; documentation links resolve.
- Diff review: detection grouping, exact evidence windows, alert keys, authorization,
  analyst status preservation, and R2 historical reconciliation are unchanged.
  Processing ranges, internal schema, snapshot isolation, and reported metrics
  change deliberately as described here. No Section 4–6 features were introduced.

Built: SQL filtering, incremental R1, atomic visibility-aware checkpoints, and benchmarks.
Verified: recovery/boundary/parity/migration tests and complete backend/frontend checks.
Still limited: dense chunks, long transactions/downtime, full-history R2, and operator-driven backfill.
