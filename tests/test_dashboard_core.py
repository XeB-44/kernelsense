import json
import tempfile
import unittest
from pathlib import Path

from dashboard_core import load_events, load_process_snapshots, parse_timestamp, tail_lines


class DashboardCoreTests(unittest.TestCase):
    def test_tail_lines_handles_large_file_and_caps_line_count(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.log"
            path.write_text("\n".join(f"line-{i}" for i in range(50)) + "\n", encoding="utf-8")
            self.assertEqual(tail_lines(path, max_lines=5), [f"line-{i}" for i in range(45, 50)])

    def test_load_events_skips_invalid_json_and_normalizes_severity(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "events.jsonl"
            path.write_text(
                '{"timestamp":"2026-10-22T12:00:00+00:00","severity":"WARNING","message":"config changed"}\n'
                'this-is-not-json\n'
                '{"timestamp":"2026-10-22T12:00:01+00:00","severity":"unexpected","message":"note"}\n',
                encoding="utf-8",
            )
            events = load_events(path)
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0]["severity"], "info")
            self.assertEqual(events[1]["severity"], "warning")
            self.assertTrue(events[0]["event_id"])

    def test_load_process_snapshots_keeps_only_process_arrays(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "process.jsonl"
            records = [
                {"timestamp": "2026-10-22T12:00:00+00:00", "processes": [{"pid": 1, "name": "init"}]},
                {"timestamp": "2026-10-22T12:01:00+00:00", "processes": "bad"},
                {"timestamp": "2026-10-22T12:02:00+00:00", "processes": [{"pid": 2, "name": "bash"}]},
            ]
            path.write_text("\n".join(json.dumps(row) for row in records) + "\n", encoding="utf-8")
            snapshots = load_process_snapshots(path)
            self.assertEqual(len(snapshots), 2)
            self.assertEqual(snapshots[-1]["processes"][0]["pid"], 2)

    def test_parse_timestamp_accepts_iso_and_rejects_bad_input(self):
        self.assertIsNotNone(parse_timestamp("2026-10-22T12:00:00+00:00"))
        self.assertIsNone(parse_timestamp("not-a-time"))

    def test_missing_log_is_graceful(self):
        with tempfile.TemporaryDirectory() as temp:
            missing = Path(temp) / "missing.jsonl"
            self.assertEqual(load_events(missing), [])
            self.assertEqual(load_process_snapshots(missing), [])


if __name__ == "__main__":
    unittest.main()
