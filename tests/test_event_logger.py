import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class EventLoggerTests(unittest.TestCase):
    def test_appends_structured_event_jsonl(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "security_events.jsonl"
            env = os.environ.copy()
            env["KERNELSENSE_EVENT_LOG"] = str(target)
            snippet = (
                "from event_logger import log_event; "
                "log_event('medium', 'filesystem.change', 'Config changed', source='test', details={'path':'/etc/example'})"
            )
            subprocess.run([sys.executable, "-c", snippet], env=env, check=True, cwd=Path(__file__).resolve().parents[1])
            event = json.loads(target.read_text(encoding="utf-8").strip())
            self.assertEqual(event["severity"], "medium")
            self.assertEqual(event["category"], "filesystem.change")
            self.assertEqual(event["details"]["path"], "/etc/example")
            self.assertTrue(event["event_id"])


if __name__ == "__main__":
    unittest.main()
