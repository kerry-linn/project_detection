# Section 5: Splunk R1 lab

This optional lab compares SPL with **full batch** Python R1 on exactly the exported
fixture. The application and incremental runner remain independently runnable.
Only synthetic fixture data is imported. The default configuration is threshold 5,
window 600,000,000 microseconds, rule version 1.0.

## Local setup

Use Docker Desktop with Linux AMD64 emulation on an ARM Mac. The official image is
pinned to `splunk/splunk:10.4.3`; this is a local learning environment, not a claim
that native macOS ARM Splunk Enterprise is supported. Check `docker info`,
`docker system df`, and host free space before pulling the roughly 1.7 GB compressed
image; unpacking it and creating its volumes require substantially more space.
Do not prune unrelated Docker data to make room without reviewing it.

Copy `splunk/.env.example` to `splunk/.env`, set a unique strong password, and
restrict it with `chmod 600 splunk/.env`. Git ignores this file. Startup accepts
Splunk's license/general terms through the official container environment settings.
The service caps resources at two CPUs and 4 GB RAM. The image starts with its
bundled license; verify the current license permits searches.
`SPLUNK_HOME_OWNERSHIP_ENFORCEMENT=false` prevents the startup ownership task from
retrying against the read-only application mount. The image and named data volumes
already belong to the Splunk user; keep those writable and the host configuration read-only.
No paid subscription, scheduled alerting, or HEC receiver is required.

From the repository root:

```bash
mkdir -p splunk/.runtime
python -m scripts.splunk_dataset export fixtures/days_1_2.jsonl fixtures/splunk_r1_boundaries.jsonl --allow-rejections
docker compose --env-file splunk/.env -f splunk/compose.yaml up -d
docker compose --env-file splunk/.env -f splunk/compose.yaml ps
python -m scripts.splunk_lab import
python -m scripts.splunk_lab verify
```

Wait for container health before importing. Splunk Web is at
<http://127.0.0.1:18000>, account `admin`, password from `splunk/.env`.
Management port 8089 stays inside the container. The helper runs as the Splunk user
and sends credentials from the container environment over container-loopback HTTPS,
trusting its local Splunk CA. Python's strict X.509 extension check is disabled for
the bundled v1 CA, and hostname matching is disabled for the generated certificate;
certificate-chain and expiry verification remain enabled. Credentials are
not placed in command arguments or result artifacts.

`app/local/props.conf` supplies the `detection_lab:json` sourcetype: one JSON object
per line, JSON search-time field extraction, `TIME_PREFIX` selecting `occurred_at`,
`TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6NZ`, `TZ = UTC`, and
`ADD_EXTRA_TIME_FIELDS = subseconds`. All exported times have exactly six fractional
digits and `Z`. `%6N` is Splunk's documented microsecond parser. Configurations are
installed before indexing; changing them requires a fresh dataset/index to retest
already indexed timestamps. Do not assume a config edit repairs existing data.

The initial fixture contains one deliberately malformed input line. The explicit
`--allow-rejections` records that rejection in the manifest; it is not imported.
Equivalent source duplicates are collapsed by the existing parser, retaining the
earliest collection time. A conflict across input files fails export. The bundle
contains 200 unique events and nine independently expected R1 results.

## Data and importer contract

`artifacts/events.jsonl` contains canonical event fields plus `dataset_id` and
`dataset_content_sha256`. The latter hashes the canonical event-only JSONL, avoiding
a self-referential file hash. `manifest.json` separately hashes the exact exported
file and records input hashes, rejected/duplicate counts, and rule configuration.
The loader validates both hashes, canonical values, unique IDs, and event ordering.

The import helper queries the isolated `detection_lab_s1` index before submission.
It validates every existing raw record, dataset identity/content hash, event ID,
raw count, and indexed timestamp. A complete exact match is a no-op. Any partial,
conflicting, or replayed primary dataset fails; counts alone cannot establish a match.
A local file lock serializes helper invocations. A pending marker is written before
submission and remains on interruption. If no rows are visible after an uncertain
submission, retry stops instead of submitting another copy. Once a complete import
becomes visible, a retry validates it and clears the marker.

This guard applies to this single-workstation helper. Other writers can bypass it;
it is not an exactly-once Splunk ingestion service. Resolve uncertain/partial imports
by inspecting the original index and using a new dataset ID when necessary, not by
blindly deleting the pending marker. Never reset the main application database for
this exercise.

`verify` checks guarded reimport, then creates a unique dataset in the separate
`detection_lab_s1_replay` index. It imports shuffled records, deliberately imports
those records twice, and compares results before/after raw counts double. Finally
it inserts one conflicting event and requires an explicit SPL error. These synthetic
replay datasets remain available for inspection; both lab indexes have a 100 MB
size cap. They are disposable lab results, not the application's evidence archive.

## Reading the R1 SPL

Replace `__INDEX__` and `__DATASET__` with the index and dataset ID when pasting a
search into Splunk Web. The helper substitutes only validated identifiers. All
searches use an explicit time range covering the fixture, rather than the UI's
usual recent-time default.

1. **Identity and duplicates.** `eventstats dc(_raw) BY event_id` detects conflicting
   canonical records. `dedup event_id` collapses repeated indexing. Any conflict
   blocks the detection branch and returns an error row; it never arbitrarily
   selects a competing event as valid evidence.
2. **Grouping.** The parser already trims/casefolds accounts, including Unicode
   `Straße` → `strasse`. SPL uses those exported values unchanged. Nullable grouping fields are extracted with `json_extract_exact` so JSON null
   stays distinct from the literal string `"null"`. A null organization maps to `0:` and every real ID maps to `1:` plus its original value. Thus the real
   organization named `0:` remains distinct from null.
3. **Candidate collection.** `sort 0` establishes event-time order without the default
   sort row cap. `streamstats time_window=601s values(failure_token)` retains candidate
   failures per entity. The extra second provides a conservative candidate window;
   it does not define the detector's final boundary. Failures are never reset after
   a success, so multiple successes can legitimately reuse evidence.
4. **Exact boundary check.** For each success, expand candidate failures and derive
   integer epoch microseconds from their canonical timestamp text: whole UTC seconds
   plus six fractional digits. Filter explicitly with
   `failure_us >= success_us - 600000000 AND failure_us < success_us`. This avoids
   depending on floating subtraction or tie ordering to exclude a simultaneous
   failure. Indexed `_time` is independently verified before this query runs.
5. **Evidence.** Tokens combine fixed-width UTC time and event ID. `values` removes
   duplicates; `mvsort` orders by time then ID. Extract IDs, count them, apply threshold
   5, and append the triggering success. `values` avoids `list`'s usual 100-value
   evidence limit; the 125-failure fixture checks this explicitly. The comparator
   compares ordered arrays without repairing a search's ordering.
6. **Limits.** The lab permits at most 1,000 unique events per dataset, below the
   usual 10,000-event `streamstats` limit. `mvexpand` has a memory limit; any warning
   or error rejects verification. Search statistics, memory, and platform limits
   still constrain larger datasets. This SPL is a bounded fixture parity exercise,
   not a performance or unlimited-production-history claim. The verification report
   is authoritative for what actually ran on the pinned version.

A ten-minute time bucket is not this rule. In the boundary fixture, the success at
13:00:00 uses failures from 12:50:00 through 12:59:59.999999; it lands in the next
fixed bucket. Grouping failures and successes by their own `bin span=10m` buckets
would separate that success from valid evidence. The success one microsecond later
also has a different lower boundary despite sharing the same bucket. R1's window is
anchored independently to every success.

The auxiliary queries cover account timelines, failures by account/IP, denied
resources by actor, and raw evidence by ID. They assume the import/content validation
has passed. Edit the example account/evidence IDs as needed; retain the dataset scope.

## Reuse the Section 6 API export

The same fixture expectations can verify a completed collector export of the 200-event
fixture dataset. Keep results separate from the original Section 5 run:

```bash
python -m scripts.splunk_dataset export docs/exports/section6_events.jsonl --output splunk/.runtime/section6-api-bundle --dataset-id section6-api-example
python -m scripts.splunk_lab verify --bundle splunk/.runtime/section6-api-bundle --results splunk/results/section6
```

`--bundle` must be inside the mounted `splunk/artifacts` or `splunk/.runtime` directory.
This verification uses the existing independent fixture expectations; an arbitrary
application export needs its own expected results. [Section 6 evidence](../docs/hardening_section6.md)
records the live API-export comparison already performed.

## Results and cleanup

`results/r1.json` saves actual SPL rows. `results/verification.json` records version,
hashes, precision checks, guarded counts, deliberate replay counts, and comparison.
The full Python reference is the pure `detect_failed_logins_followed_by_success`
function evaluated over the exported canonical events. No database checkpoint or
incremental runner is involved. Independent expectations live in
`fixtures/expected/splunk_r1.json`.

```bash
python -m scripts.splunk_dataset compare splunk/results/r1.json
python -m pytest tests/test_splunk_parity.py tests/test_failed_login_success.py
# Stop this optional lab and retain its volumes:
docker compose --env-file splunk/.env -f splunk/compose.yaml stop
```

Do not describe fixture parity as verified until the real container verification
succeeds. See [the comparison report](../docs/splunk_parity.md) for actual outcomes.

References: [timestamp parsing and %6N](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.0/configure-timestamps/configure-timestamp-recognition),
[streamstats and its limits](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.0/search-commands/streamstats),
[official Docker image](https://hub.docker.com/r/splunk/splunk/tags?page=1).
