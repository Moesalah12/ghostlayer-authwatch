import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from authwatch import analyze, load_events, main


def event(seconds, outcome="failure", user="moe", ip="192.0.2.10"):
    return {"timestamp": datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds),
            "outcome": outcome, "username": user, "source_ip": ip}


class DetectionTests(unittest.TestCase):
    def test_success_requires_same_account_and_source(self):
        rows = [event(i) for i in range(5)] + [event(5, "success", user="other"), event(6, "success")]
        result = analyze(rows)
        successes = [a for a in result["alerts"] if a["rule"] == "success_after_failures"]
        self.assertEqual(len(successes), 1)
        self.assertEqual(successes[0]["username"], "moe")

    def test_window_boundary_is_inclusive(self):
        self.assertEqual(analyze([event(0), event(300)], threshold=2)["alert_count"], 1)
        self.assertEqual(analyze([event(0), event(301)], threshold=2)["alert_count"], 0)

    def test_spray_deduplicates_until_reset(self):
        rows = [event(i, user=str(i)) for i in range(4)]
        alerts = analyze(rows, threshold=20)["alerts"]
        self.assertEqual([a["rule"] for a in alerts], ["multiple_accounts_targeted"])

    def test_different_sources_not_combined(self):
        self.assertEqual(analyze([event(0), event(1, ip="192.0.2.11")], threshold=2)["alert_count"], 0)

    def test_rearms_after_expiry_and_success(self):
        rows = [event(i) for i in range(5)] + [event(5, "success"), event(6, "success")]
        rows += [event(600+i) for i in range(5)]
        rules = [a["rule"] for a in analyze(rows)["alerts"]]
        self.assertEqual(rules.count("success_after_failures"), 1)
        self.assertEqual(rules.count("repeated_failures"), 2)

    def test_invalid_configuration(self):
        for kwargs in ({"threshold": 0}, {"window_seconds": 0}, {"spray_users": 1}):
            with self.assertRaises(ValueError):
                analyze([], **kwargs)

    def test_loader_timezone_sort_and_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            row = {"timestamp": "2026-01-01T01:00:00+01:00", "source_ip": "2001:db8::1", "username": "moe", "outcome": "success"}
            path.write_text(json.dumps(row), encoding="utf-8")
            self.assertEqual(load_events(path)[0]["timestamp"].hour, 0)
            for field, value in (("timestamp", "2026-01-01T00:00:00"), ("source_ip", "bad"), ("username", ""), ("outcome", "bad")):
                bad = dict(row, **{field: value})
                path.write_text(json.dumps(bad), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "line 1"):
                    load_events(path)

    def test_out_of_order(self):
        rows = [event(i) for i in range(5)]
        self.assertEqual(analyze(rows), analyze(list(reversed(rows))))


if __name__ == "__main__":
    unittest.main()
