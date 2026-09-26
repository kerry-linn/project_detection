# Investigation: Repeated Failed Logins Followed by Success

A lab investigation of one R1 alert. Every observation below was captured from a clean
fresh-checkout run on 2026-09-26 (see
[Days 12–14](../DAYS_12_14.md#release-acceptance)); nothing was edited by hand. The
activity was generated with `python -m scripts.generate_scenarios suspicious`, so the
ground truth is known to be a script. The point is to reason from the evidence as if it
were not.

## Alert

| Field | Value |
| --- | --- |
| Rule | `R1_FAILED_LOGINS_FOLLOWED_BY_SUCCESS` v1.0 |
| Alert key | `R1_FAILED_LOGINS_FOLLOWED_BY_SUCCESS:1.0:threshold=5:window_us=600000000:app-dbe50b9e-728e-4348-bebc-2c5570514700` |
| Severity / status | medium / new |
| Entity | `org-alpha` / `alice@alpha.example.test` (actor `user-alice`) |
| Reason | 5 failed logins for alice@alpha.example.test in org-alpha were followed by a successful login |
| Threshold check | 5 failures (threshold 5) in the 10 minutes before the success |
| Window | 2026-09-26 15:21:03.515 → 15:31:03.515 UTC |
| Source IPs | `127.0.0.1` |
| Session created | `sess-705e15d9-cf4f-4356-af50-1b2d6b3f2cfe` |

## Detection hypothesis

Multiple authentication failures for one account followed by a success may indicate that
someone guessed or obtained the password. R1 groups by organization and canonical
account, counts failures in `[t − 10 min, t)` before each successful login at `t`, and
alerts at five or more.

## Observed evidence

Oldest first, as shown on the alert detail page. All events have `source=application`,
meaning the server recorded its own authentication decision; none came from the
collector.

| Occurred (UTC) | Event ID | Role | Outcome | Metadata |
| --- | --- | --- | --- | --- |
| 15:31:03.312 | `app-91a246d9-…` | failed_login | failure | `reason=invalid_password` |
| 15:31:03.350 | `app-c00745c6-…` | failed_login | failure | `reason=invalid_password` |
| 15:31:03.386 | `app-8dac90aa-…` | failed_login | failure | `reason=invalid_password` |
| 15:31:03.429 | `app-c37e6a61-…` | failed_login | failure | `reason=invalid_password` |
| 15:31:03.470 | `app-ae164131-…` | failed_login | failure | `reason=invalid_password` |
| 15:31:03.515 | `app-dbe50b9e-…` | successful_login | success | session `sess-705e15d9-…` |

Every event came from `127.0.0.1` and each has its own `request_id`.

## Analysis

- **The threshold was met exactly.** Five failures fell inside the window, all
  immediately before the success. At four the rule would not fire; the benign acceptance
  run confirmed that.
- **The failures were against a real account.** `invalid_password` rather than
  `unknown_account` means the login name was correct and only the password was wrong.
  Credential stuffing from a leaked list usually also hits accounts that do not exist;
  there are no `unknown_account` failures anywhere in this dataset.
- **The timing is not human.** All six attempts took 203 milliseconds, 36–45 ms apart.
  Nobody retypes a password five times in a fifth of a second. This points to an
  automated client: a script, a service with stale saved credentials, or a guessing tool
  that found the password on its sixth attempt.
- **The source IP does not identify anyone.** `127.0.0.1` is loopback: in this lab
  every request arrives through a local process. In production the same field could
  also be a shared NAT or proxy address. One IP does not mean one person.
- **Nothing happened after the login in this dataset.** The detector scanned 12 events
  in total. Bob's scenario (one login and five denials) and these six account for all of
  them, so the new session had done nothing by the time the detector ran.

## Possible explanations

| Explanation | Supported by | Weakened by |
| --- | --- | --- |
| User mistyped the password | Correct account name; success soon after | 40 ms spacing is far too fast for typing |
| Client or service with stale saved credentials, then updated | Machine-speed retries; correct account name | Stale clients usually keep failing rather than succeed six attempts later |
| Automated password guessing that succeeded | Machine-speed attempts; success right after failures | Only five guesses; a real guessing run is usually longer |
| Credential stuffing | Automated timing | Only one account targeted; no `unknown_account` failures |

## Conclusion

**Suspicious; not proven compromise.** The alert correctly reports that the R1 threshold
was crossed, and the sub-second automated timing makes simple user error unlikely. The
events alone cannot tell a misconfigured client from a successful guess. In a real
environment I would escalate to the account owner and treat the session as untrusted
until confirmed. The ground truth here is a lab script, which is consistent with the
"automated client" reading.

## Additional data I would want

- Historical login activity for this account: is this timing or client normal for it?
- User agent or device information, which the lab does not record.
- A real, attributable client address instead of loopback, with geolocation and ASN
  context.
- Everything the new session did afterwards: document reads, updates, or denials by
  `user-alice` after 15:31:03.515.
- Whether other accounts saw failures from the same source in the same period (password
  spraying, which R1 does not detect by design).
- Confirmation from the account owner.

## What this telemetry cannot prove

- Who was behind the attempts, or that they were one person.
- That the successful login came from the same client as the failures, beyond the
  shared loopback address.
- Intent. The same pattern fits a broken integration and an attacker.
- Anything the lab does not record: attempts that never reached the application,
  events lost to an audit-write failure, or activity outside this application.

## Reproduce

```bash
python -m scripts.reset_telemetry --yes
python -m scripts.generate_scenarios suspicious
python -m scripts.run_detection
```

Then sign in as `analyst@lab.example.test` and open the R1 alert. Event IDs, session IDs,
and times will differ on every run; the structure, counts, and reason will not.
