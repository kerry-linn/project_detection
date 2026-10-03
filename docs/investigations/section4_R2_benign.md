# Investigation: Benign R2 stale-bookmark exercise

Recorded October 2, 2026 from the isolated clean-install database through the live API.
The captioned demo records the analyst entering the note and decision in the React UI.
All data and exercise context are synthetic.

Alert: `R2_REPEATED_DENIED_DOCUMENT_ACCESS:1.0:threshold=5:window_us=300000000:cooldown_us=900000000:org-alpha:user-bob:app-8c9c95c5-8ff3-4e2f-8ee8-19a47556b4f2`.
Entity: `org-alpha` / `user-bob`.
Status: **closed / benign**, revision 2.

## Hypothesis and evidence

Five distinct denied documents within five minutes may indicate enumeration or stale client links.

Observed count: 5; threshold: 5; linked events: 5.
Timeline (UTC), copied from persisted evidence:

- 2026-10-02T16:16:04.284867Z: `app-e3f69d08-5c65-45a3-8bf7-54dc065a097b` — denied_document_access, denied, requested `retired-bookmark-1`.
- 2026-10-02T16:16:04.298561Z: `app-3862114e-3dcc-4879-a8b5-097a81574f79` — denied_document_access, denied, requested `retired-bookmark-2`.
- 2026-10-02T16:16:04.310322Z: `app-45d2d221-44fb-4dfe-9297-b005d48de9c3` — denied_document_access, denied, requested `retired-bookmark-3`.
- 2026-10-02T16:16:04.321032Z: `app-c95b0814-8ecf-449b-b4b9-07fc7c612907` — denied_document_access, denied, requested `retired-bookmark-4`.
- 2026-10-02T16:16:04.332453Z: `app-8c9c95c5-8ff3-4e2f-8ee8-19a47556b4f2` — denied_document_access, denied, requested `retired-bookmark-5`.

## Competing explanations and conclusion

All five resources were `retired-bookmark-1` through `retired-bookmark-5`, with
`reason=not_found` and denied outcomes. Enumeration can produce the same pattern.
The separate exercise context identifies these as deliberately stale bookmarks
requested by the controlled `benign-alert` scenario. That known context supports
a benign disposition; the event names or 404 responses alone do not prove intent.
This crosses R2’s threshold and demonstrates false-positive triage, unlike the
below-threshold `benign` scenario. No successful access to these resources is shown.

Persisted analyst rationale:

> Approved synthetic stale-bookmark exercise; five nonexistent resources returned 404. Benign intent comes from exercise context, not the threshold alone.

## Missing data and rule limits

Outside this controlled exercise, owner confirmation, bookmark provenance, and surrounding client activity would be required. R2 misses repeated access to one resource and slow probing. Its opening five-minute threshold differs from an episode that later extends across cooldown intervals.

The API stored the note and decision with server author `lab-analyst` and timestamps.
A subsequent detector rerun preserved both entries, disposition, rationale, and revision.
Raw captured alert/evidence/history is in [section4_evidence.json](section4_evidence.json).

## Reproduce

After a deliberate guarded reset, run `python -m scripts.generate_scenarios triage`
and `python -m scripts.run_detection` twice. Sign in as analyst, inspect this rule,
add a note, then close with the disposition and rationale. IDs and times change per run.
