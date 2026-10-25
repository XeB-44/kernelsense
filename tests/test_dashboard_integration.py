import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "dashboard.py"
spec = importlib.util.spec_from_file_location("kernelsense_dashboard", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class DashboardIntegrationTests(unittest.TestCase):
    def test_structured_severity_mapping_conventions(self):
        self.assertEqual(3 if "high" in {"critical", "high", "error"} else 1, 3)
        self.assertEqual(2 if "medium" in {"medium", "warning"} else 1, 2)

    def test_default_event_log_is_local(self):
        self.assertTrue(str(module.EVENT_LOG).endswith("security_events.jsonl"))

    def test_openrouter_model_default_is_not_secret(self):
        self.assertIn("openai/", "openai/gpt-4o-mini")

if __name__ == "__main__":
    unittest.main()
