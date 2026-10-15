# GhostLayer AuthWatch

**Offline authentication-log triage with explainable, time-windowed alerts.**

Built for Mohammad Salah’s cybersecurity engineering portfolio · GhostLayer Defense

AuthWatch reads normalized JSONL authentication events and produces JSON evidence for repeated failures, multiple accounts targeted by one source, and a success after repeated failures against the same account. It makes no network requests and never attempts a login.

## Quick start

Requires Python 3.11+; no dependencies to install. Run from this repository:

```sh
python authwatch.py examples/events.jsonl
python authwatch.py examples/events.jsonl --threshold 5 --window 300 --spray-users 3
python -m unittest discover -s tests -v
```

The included synthetic dataset yields **9 events and 3 alerts**: repeated failures, success after failures, and multiple accounts targeted. See [the exact sample output](examples/report.json).

## Input contract

One JSON object per line; blank lines are ignored. Extra fields are ignored. Invalid input aborts with a line number rather than quietly skipping evidence.

```json
{"timestamp":"2026-01-01T12:00:00Z","source_ip":"192.0.2.10","username":"training-admin","outcome":"failure"}
```

| Field | Requirement |
| --- | --- |
| timestamp | ISO 8601 with timezone; converted to UTC |
| source_ip | Valid IPv4 or IPv6 address |
| username | Nonempty, case-sensitive string |
| outcome | `failure` or `success` |

## Detection behavior

| Rule | Trigger | Suggested next step |
| --- | --- | --- |
| repeated_failures | Source reaches the configured failure threshold within the window | Check user activity, MFA, and source context |
| multiple_accounts_targeted | Source fails against the configured number of distinct accounts | Investigate possible spraying; verify shared NAT or SSO behavior |
| success_after_failures | Same account and source succeeds after threshold failures | Verify with the user and inspect session/MFA evidence |

Events are sorted by timestamp. Window boundaries are inclusive. Source-level alerts fire on threshold crossing and rearm when the active rule clears. Success closes that account’s failure sequence from that source. Severity is a triage hint, not a finding of compromise. Exit code: `0` completed analysis, `2` input/configuration error.

## Limits and engineering decisions

- This version accepts the normalized schema above, not raw Windows Event XML, SSH syslog, or vendor exports. An adapter must preserve timestamps and source semantics.
- A shared IP can create false positives. Distributed low-rate attempts and attacks across sources may be missed. Multiple failed accounts alone do not prove password spraying.
- All events are held in memory for ordering. Use bounded batches for large exports; no persistent alert state spans runs.
- Alerts contain account names and IP addresses from the input. Handle reports as sensitive evidence. Examples use documentation-only address ranges and fictional accounts.

Read [DEVELOPMENT.md](DEVELOPMENT.md) for provenance, [CONTRIBUTING.md](CONTRIBUTING.md) for changes, and [SECURITY.md](SECURITY.md) for private reports. MIT licensed.
