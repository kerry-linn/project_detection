# MVP Improvement Timeline

Based on MVP_Hardening_Roadmap • October 1, 2026

**Pace:** roughly 8–10 focused hours per week over six weeks. The roadmap estimates 37–58 total hours; allow extra time for learning and debugging. Week labels are targets, not deadlines. Finish each section's checks before moving on, and mark already-verified work complete.

## Timeline at a glance

| Target | Section | Estimated effort | Main result |
| --- | --- | --- | --- |
| Week 1 | 1. Baseline and failure recovery | 6–9 hours | Reproducible MVP with tested recovery |
| Week 2 | 2. R2 late-event correctness | 5–8 hours | Correct current alerts with preserved history |
| Week 3 | 3. Processing efficiency | 7–12 hours | Incremental R1 and measured improvement |
| Week 4 | 4. Security and investigation workflow | 7–11 hours | Hardened, investigatable MVP |
| Week 5 | 5. Splunk | 6–9 hours | R1 SPL compared against Python |
| Week 6 | 6. API automation | 6–9 hours | Reliable paginated event export |

## Section 1 — Baseline and failure recovery

**Reference:** H0–H1 • **Target:** Week 1

- [x] Run backend/frontend checks and reproduce suspicious and benign scenarios from a clean setup.
- [x] Confirm GitHub CI actually passes; record existing strengths and remaining gaps.
- [x] Test failures during alert/evidence writes and confirm complete rollback.
- [x] Test a killed runner, database failure, and two concurrent runners; make abandoned or failed runs visible.
- [x] Confirm reruns preserve existing evidence and analyst status without duplicate alerts.

**Done when:** setup is repeatable, failures leave no partial results, and recovery behavior is documented.

**Save:** a short baseline report and failure/recovery test results.

## Section 2 — R2 late-event correctness

**Reference:** H2 • **Target:** Week 2

- [x] Reproduce the problem where a late denial changes the first threshold-crossing event and creates a different alert key.
- [x] Recompute complete affected histories and reconcile current results with stored alerts.
- [x] Mark replaced alerts as superseded and link their replacements; preserve evidence and any existing analyst history.
- [x] Test earlier threshold crossings, merged episodes, duplicate replay, and rollback during reconciliation.

**Done when:** the active alert set matches full-history detection, reruns remain stable, and older results remain inspectable.

**Save:** a before/after fixture and regression tests explaining the fix.

## Section 3 — Processing efficiency

**Reference:** H3 • **Target:** Week 3; extend if needed

- [x] Measure runtime, memory, and events read on increasing synthetic datasets.
- [x] Filter relevant event types in SQL and review query plans before adding indexes.
- [x] Add incremental R1 with a checkpoint, overlapping lookback, and explicit late-event/backfill policy.
- [x] Commit checkpoint progress with alert/evidence writes; test crashes, restart, and long downtime.
- [x] Compare results with the existing full-batch detector.

**R2 boundary:** keep full-history processing initially. Its episodes can extend for hours, so a short lookback alone can lose context. Stateful incremental R2 is a later extension.

**Done when:** R1 reads less history while returning the same expected results, and R2 remains correct.

**Save:** benchmark results and a concise processing-policy note.

Completed October 2, 2026: [Section 3 policy, benchmarks, and verification](docs/hardening_section3.md).
R1 full initialization/backfill remains available; incremental mode is explicit.
Final checks: 174 backend tests with no skips, 9 frontend tests, typecheck, and build.

## Section 4 — Security and investigation workflow

**Reference:** H4–H5 • **Target:** Week 4; extend if needed

- [ ] Verify direct API authorization, session expiry/revocation, and cross-tenant behavior, including all new routes.
- [ ] Bound request sizes and list/evidence responses; paginate large results and apply filters server-side.
- [ ] Verify concurrent ingestion, secret-free logs, safer reset behavior, migrations, and backup/restore.
- [ ] Add analyst status changes, notes, dispositions, and change history; prevent silent overwrites between analysts.
- [ ] Preserve case decisions during detection reruns and flag new evidence for review.
- [ ] Complete one suspicious investigation and one benign investigation that actually triggered an alert.
- [ ] Refresh README/limitations, repeat clean setup, verify CI, and record the short demo.

**Done when:** a reviewer can reproduce, investigate, and disposition alerts; access controls and recovery tests pass.

**Save:** two investigation reports, updated setup documentation, and a 2–3 minute demo.

**Milestone reached: hardened MVP.** Proceed to integrations after critical correctness and authorization failures are resolved.

## Section 5 — Splunk

**Reference:** S1 • **Target:** Week 5

- [ ] Choose a supported Splunk environment and export the same synthetic events used by Python.
- [ ] Verify event timestamps, field extraction, null organizations, and duplicate handling.
- [ ] Write account activity, failed-login, denied-resource, and evidence searches.
- [ ] Recreate R1 in SPL using its exact rolling window and grouping rules.
- [ ] Compare triggering success IDs, failure counts, and evidence IDs against Python and expected fixtures; investigate discrepancies.

**Done when:** the declared comparison cases match and any precision or platform limitations are documented.

**Save:** SPL queries, setup instructions, sample results, and a short comparison report.

## Section 6 — API automation

**Reference:** A1 • **Target:** Week 6

- [ ] Add a scoped read-only credential and cursor pagination over a stable export snapshot.
- [ ] Build the Python client to fetch every page and validate responses.
- [ ] Add timeouts, bounded retries/backoff, rate-limit handling, and clear permanent-error behavior.
- [ ] Save received events and resume progress together so interruption cannot skip a page.
- [ ] Export JSONL/CSV and test interrupted runs, repeated cursors, expired snapshots, and concurrent new events.
- [ ] Compare exported event IDs/content with the source snapshot, then reuse the export in Splunk.

**Done when:** retrying or restarting produces a complete export without missing or duplicate events within the documented snapshot policy.

**Save:** collector script, tests, example export, and a restart demonstration.

## Use this routine for every section

1. Read the matching detailed roadmap section.
2. Pick one small change and define its expected behavior.
3. Implement it and run relevant regression tests.
4. Record what changed, how you verified it, and what remains unclear.
5. Commit the completed change before beginning the next task.

**Later backlog:** stateful incremental R2, R3/R4, CloudTrail/S3, automatic Splunk forwarding, and public deployment. Keep these outside the six-section completion target.
