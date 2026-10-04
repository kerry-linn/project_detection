# Section 5: Splunk R1 parity

October 3, 2026. The comparison target is full batch Python R1 over the exported
canonical fixture. Incremental checkpoints are outside this comparison.

## Current verification status

Implementation, Python verification, and live Splunk acceptance are complete.
On October 3, Splunk 10.4.3 matched all nine independently expected R1 results over
200 events, including exact ordered evidence. All indexed timestamps matched integer
microseconds. Guarded reimport retained 200 rows; shuffled and deliberate duplicate
imports produced identical results at 200 and 400 rows. Conflicting content produced
only an error result. All four auxiliary searches passed their content/count checks.
The complete evidence is in `splunk/results/verification.json` and `r1.json`.

Live testing fixed three setup/semantic gaps: recursive ownership enforcement could
not change the read-only app mount; the default exec user could not read Splunk's CA;
and automatic extraction represented JSON null as the string `"null"`. The helper
now uses the Splunk service account and documented CA compatibility settings; SPL
uses `json_extract_exact` before grouping nullable fields. The null-organization
fixture exposed the mismatch and now passes on the real platform.

The pinned image was downloaded successfully:
`splunk/splunk:10.4.3`, digest
`sha256:cc3a3efe2509fa31f67d4aa20dde7118886babf9a0930f197ef996d513c44834`.
Docker reported version 29.6.1, ARM64, and approximately 8 GB of VM memory.
Host free space fell from approximately 12 GiB to 1.4–2 GiB after the image pull.
The Compose service now caps Splunk at two CPUs and 4 GB of RAM. Its Web port is
bound to `127.0.0.1:18000`; management access remains inside the container.

## Dataset and independent expectations

The bundle combines the accepted events from `days_1_2.jsonl` with the shuffled
`fixtures/splunk_r1_boundaries.jsonl`: **200 unique events and nine expected alerts**.
The original fixture's malformed line is recorded and rejected. Two equivalent
source replays are collapsed; no rejected event is imported.

The expected results were specified from the scenarios without calling the detector:

- `evt-009`: the original hand checked five-failure case.
- `threshold-5-success` and `threshold-6-success`: threshold five and six; threshold
  four is absent.
- `z-bounds-success` and `z-bounds-same-time`: include the exact lower boundary and
  its next microsecond, two tied failures ordered by ID, and the microsecond before
  success. Exclude the microsecond before the lower boundary, exact success time,
  and its next microsecond.
- `z-bounds-next`: one microsecond later, the original exact lower boundary expires
  and the failure at the previous success timestamp becomes eligible.
- `null-org-success`: a true null organization; the real organization named `0:`
  remains separate and below threshold.
- `casefold-success`: Python's Unicode casefold combines canonical account variants.
- `dense-success`: all 125 qualifying failures survive evidence construction.

Additional three-plus-two cases assert account and tenant isolation. Shuffled source
lines and later duplicate collection times preserve the canonical export. Fixed UTC
microsecond timestamps and event IDs define evidence ordering.

## Acceptance evidence

Local command:

```bash
python -m pytest tests/test_splunk_parity.py tests/test_failed_login_success.py --tb=short
```

Result: **30 passed**. These tests cover export/hash validation, independent expected
results, exact source normalization, shuffled export, ordered comparison failures,
indexed content/time/multiplicity validation, guarded import, partial/uncertain
imports, recovery after an interrupted completed import, and search warning handling.
They do not execute SPL or substitute for a real Splunk run.

`../splunk/results/python_r1.json` contains full Python reference results.
`../splunk/artifacts/manifest.json` records the exact dataset and file hashes.
The live runner saved actual SPL results, conflict output, and a verification
report. All required live outcomes passed:

1. Every indexed `occurred_at` matches at integer microsecond precision.
2. Primary raw count is 200; guarded reimport leaves it at 200.
3. Shuffled ingestion gives the same nine results and ordered evidence.
4. Deliberate replay in an isolated dataset raises raw count from 200 to 400 while
   R1 still gives exactly the same nine results.
5. An additional conflicting event ID produces an explicit error and no valid
   partial detection result.
6. Splunk, full Python, and independent expected results match on success IDs,
   entity, failure count, and ordered failure/evidence IDs.

## Limits and follow-up

The query is restricted to at most 1,000 unique events per dataset. Search warnings
or errors invalidate verification, including memory or result truncation. Timestamp
parsing and evidence construction were confirmed on the pinned version.
The import guard is a local serialized helper, not a distributed ingestion guarantee.
There is no R2 SPL, automatic forwarding, or API export collector in Section 5.

See [setup and the annotated SPL explanation](../splunk/README.md), including the
601-second candidate window, the exact 600-second final boundary, and why fixed
ten-minute buckets differ. Sections 4–5 passed hosted backend/frontend CI for
`f3fe14a6` in [GitHub Actions run 37150851207](https://github.com/kerry-linn/project_detection/actions/runs/37150851207).

Section 6 repeated this live exercise using completed API-collector JSONL; all
200 events and nine R1 results matched. See [the export report](hardening_section6.md)
and `splunk/results/section6/verification.json`.
