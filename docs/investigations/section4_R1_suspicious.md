# Investigation: Suspicious R1 login sequence

Recorded October 2, 2026 from the isolated clean-install database through the live API.
The captioned demo records the analyst entering the note and decision in the React UI.
All data and exercise context are synthetic.

Alert: `R1_FAILED_LOGINS_FOLLOWED_BY_SUCCESS:1.0:threshold=5:window_us=600000000:app-8877d4bb-306e-4c99-b683-862e9afd3ba4`.
Entity: `org-alpha` / `alice@alpha.example.test`.
Status: **closed / suspicious**, revision 2.

## Hypothesis and evidence

Five failed logins within ten minutes before a success warrant account-compromise review.

Observed count: 5; threshold: 5; linked events: 6.
Timeline (UTC), copied from persisted evidence:

- 2026-10-02T16:16:04.012380Z: `app-662f9a69-7274-4ad8-b9b6-30c64210efaf` — failed_login, failure.
- 2026-10-02T16:16:04.052483Z: `app-4d4dd28b-5528-4af0-8cfd-ade678cc9567` — failed_login, failure.
- 2026-10-02T16:16:04.096051Z: `app-f08ed440-9732-497a-8ea4-0a943b105642` — failed_login, failure.
- 2026-10-02T16:16:04.140005Z: `app-c7f629fb-acb1-47bd-997a-bfa3b85a050f` — failed_login, failure.
- 2026-10-02T16:16:04.181223Z: `app-294f6216-ee92-451e-b6ec-e4d3449fea44` — failed_login, failure.
- 2026-10-02T16:16:04.227834Z: `app-8877d4bb-306e-4c99-b683-862e9afd3ba4` — successful_login, success.

## Competing explanations and conclusion

An automated guessing attempt and a stale-credential client both fit this sequence.
The rapid timing is less consistent with manual typing. Loopback identifies neither
the person nor the device, and the same address does not establish one actor.
Disposition: suspicious for follow-up, not proven compromise. The known script is
ground truth for the exercise; the simulated triage assesses the observed sequence.

Persisted analyst rationale:

> Five rapid failures followed by success warrant account-owner review; compromise is not proven by this synthetic lab telemetry.

## Missing data and rule limits

Account-owner confirmation, device/client attribution, historical behavior, and post-login activity are missing. R1 misses slow guessing and password spraying across accounts.

The API stored the note and decision with server author `lab-analyst` and timestamps.
A subsequent detector rerun preserved both entries, disposition, rationale, and revision.
Raw captured alert/evidence/history is in [section4_evidence.json](section4_evidence.json).

## Reproduce

After a deliberate guarded reset, run `python -m scripts.generate_scenarios triage`
and `python -m scripts.run_detection` twice. Sign in as analyst, inspect this rule,
add a note, then close with the disposition and rationale. IDs and times change per run.
