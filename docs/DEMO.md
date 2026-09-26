# v0.1 Demo Script (2–3 minutes)

The demo tells the security story end to end: real application activity, a server-side
authorization decision, a trusted event, a detection, and an analyst reading the raw
evidence. It does not tour the code.

Record the screen locally and publish the video outside the repository (for example an
unlisted video or a portfolio page); do not commit the video file. Add the link to the
README once published.

## Before recording

Complete the setup in the [README](../README.md#set-up-from-a-fresh-checkout), then:

```bash
uvicorn backend.api:create_app --factory          # terminal 1
cd frontend && npm run dev                        # terminal 2
python -m scripts.reset_telemetry --yes           # terminal 3: empty telemetry
```

Open http://127.0.0.1:5173 in a fresh browser window. Keep terminal 3 visible for the
detector step. Every seeded account signs in with `SEED_USER_PASSWORD`.

## Timeline

| Time | On screen | Say |
| --- | --- | --- |
| 0:00 | Login page | "This is a security monitoring lab built around a small document-sharing app. The app produces its own security events, Python rules detect suspicious patterns, and an analyst investigates in this UI." |
| 0:15 | Sign in as `bob@alpha.example.test`; open `doc-alpha-004` | "Bob is a normal member. He can read his own document." |
| 0:25 | Enter `/documents/doc-alpha-001`, `-002`, `-003`, `-005` in the address bar: each shows **Not authorized**. Enter `/documents/doc-beta-001`: **Not found** | "Now he probes documents he doesn't own. The server denies each one and records an `access_denied` event. The other tenant's document looks exactly like a missing one." |
| 0:45 | Enter `/alerts`: **Not authorized** | "Bob can't reach the analyst view either; FastAPI enforces that, not the React navigation." |
| 0:50 | Sign out. Try `alice@alpha.example.test` with a wrong password five times, then the right one | "Alice's account gets five failed logins and then a successful one. Every attempt is recorded by the server." |
| 1:05 | Terminal 3: `python -m scripts.run_detection` | "The detector reads stored events. R1 created one alert, R2 created one." Run it again: "A rerun creates nothing: alerts have deterministic keys, so replays don't duplicate them." |
| 1:15 | Sign out; sign in as `analyst@lab.example.test`; **Alerts** list | "The lab analyst is the only role that can read security records." |
| 1:25 | Open the R1 alert | "R1: at least five failures for the same account in the ten minutes before a success." |
| 1:40 | Scroll the evidence table: five `failed_login` rows, then `successful_login` | "I can count the evidence myself: five failures, then the success. The alert says a threshold was crossed, not that Alice is compromised." |
| 1:55 | Back; filter **Rule** to R2; open Bob's alert | "R2 counts distinct denied documents in five minutes, not raw requests." |
| 2:10 | Point at **Requested resources** and the evidence rows' resource and `reason` metadata | "Five distinct documents: four `not_owner` denials in his organization and one `cross_organization`. Bob only saw a 404 for that one; the evidence tells the analyst what really happened. Five requests for a single document would not fire this rule." |
| 2:30 | Alert detail facts (alert key, window) | "Alerts are evidence-linked and replay-safe. PostgreSQL stores facts, the Python rules decide what is suspicious, and the analyst decides what it means." |

## Faster take

To skip typing the activity, generate it through the same application routes and start
the recording at the detector step:

```bash
python -m scripts.reset_telemetry --yes
python -m scripts.generate_scenarios suspicious
```

Showing Bob's denials and Alice's logins live in the browser tells the story better, so
prefer the full timeline when possible.

## Expected results

Checked against a clean database before recording (see
[Days 12–14](DAYS_12_14.md#release-acceptance)):

- First detector run: R1 `alerts_created: 1`, R2 `alerts_created: 1`.
- Second run: both `alerts_created: 0`, `alerts_unchanged: 1`.
- R1 evidence: five `failed_login` rows followed by one `successful_login`, oldest first.
- R2 evidence: `doc-alpha-001`, `doc-alpha-002`, `doc-alpha-003`, `doc-alpha-005`,
  `doc-beta-001`, match count 5 of threshold 5.
- Behind the Vite proxy every event records `source_ip = 127.0.0.1`.

If an extra alert appears, the telemetry was not reset before the take.
