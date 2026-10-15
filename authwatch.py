"""Offline authentication-event triage. Python 3.11+, standard library only."""
import argparse
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
import ipaddress
import json
from pathlib import Path
import sys


def load_events(path):
    events = []
    with Path(path).open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
                stamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
                if stamp.tzinfo is None or stamp.utcoffset() is None:
                    raise ValueError("timestamp must include a timezone")
                address = str(ipaddress.ip_address(row["source_ip"]))
                user = row["username"]
                if not isinstance(user, str) or not user.strip():
                    raise ValueError("username must be a nonempty string")
                if row["outcome"] not in ("failure", "success"):
                    raise ValueError("outcome must be failure or success")
                events.append({"timestamp": stamp.astimezone(timezone.utc),
                               "source_ip": address, "username": user,
                               "outcome": row["outcome"]})
            except (KeyError, ValueError, TypeError, AttributeError) as exc:
                raise ValueError(f"line {number}: invalid event: {exc}") from exc
    return sorted(events, key=lambda row: row["timestamp"])


def analyze(events, threshold=5, window_seconds=300, spray_users=3):
    if threshold < 1 or window_seconds < 1 or spray_users < 2:
        raise ValueError("threshold/window must be positive; spray-users must be >= 2")
    failures = defaultdict(deque)
    previous_rules = defaultdict(set)
    alerts = []
    for row in sorted(events, key=lambda item: item["timestamp"]):
        source = row["source_ip"]
        recent = failures[source]
        cutoff = row["timestamp"] - timedelta(seconds=window_seconds)
        while recent and recent[0]["timestamp"] < cutoff:
            recent.popleft()
        active = set()
        if row["outcome"] == "failure":
            recent.append(row)
            if len(recent) >= threshold:
                active.add("repeated_failures")
            if len({event["username"] for event in recent}) >= spray_users:
                active.add("multiple_accounts_targeted")
            for rule in sorted(active - previous_rules[source]):
                alerts.append({"rule": rule, "source_ip": source,
                               "timestamp": row["timestamp"].isoformat(),
                               "failure_count": len(recent),
                               "distinct_users": len({event["username"] for event in recent}),
                               "severity": "medium"})
            previous_rules[source] = active
        else:
            same_user = [event for event in recent if event["username"] == row["username"]]
            if len(same_user) >= threshold:
                alerts.append({"rule": "success_after_failures", "source_ip": source,
                               "username": row["username"],
                               "timestamp": row["timestamp"].isoformat(),
                               "failure_count": len(same_user), "severity": "high"})
            # A success closes this user's failure sequence, leaving other users intact.
            failures[source] = deque(event for event in recent if event["username"] != row["username"])
            remaining = failures[source]
            previous_rules[source] = ({"repeated_failures"} if len(remaining) >= threshold else set())
            if len({event["username"] for event in remaining}) >= spray_users:
                previous_rules[source].add("multiple_accounts_targeted")
    return {"event_count": len(events), "alert_count": len(alerts), "alerts": alerts}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path, help="normalized JSONL events")
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window", type=int, default=300, help="sliding window in seconds, inclusive")
    parser.add_argument("--spray-users", type=int, default=3)
    args = parser.parse_args(argv)
    try:
        result = analyze(load_events(args.events), args.threshold, args.window, args.spray_users)
    except (OSError, ValueError) as exc:
        print(f"authwatch: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
