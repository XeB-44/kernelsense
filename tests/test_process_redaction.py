import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "all-processes_monitoring.py"
spec = importlib.util.spec_from_file_location("process_monitor_module", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


class ProcessRedactionTests(unittest.TestCase):
    def test_flag_followed_by_secret_is_redacted(self):
        result = module.redact_command_line(["tool", "--api-key", "SENSITIVE_VALUE", "--port", "8501"])
        self.assertEqual(result, ["tool", "--api-key", "<redacted>", "--port", "8501"])

    def test_inline_sensitive_flag_is_redacted(self):
        result = module.redact_command_line(["tool", "--password=super-secret", "safe"])
        self.assertEqual(result, ["tool", "--password=<redacted>", "safe"])

    def test_common_token_shapes_are_redacted(self):
        result = module.redact_command_line(["tool", "ghp_abcdefghijklmnopqrstuvwxyz123456", "Bearer private-token"])
        self.assertEqual(result, ["tool", "<redacted>", "<redacted>"])

    def test_empty_command_line(self):
        self.assertEqual(module.redact_command_line(None), [])


if __name__ == "__main__":
    unittest.main()
