"""CLI failure and setup regression tests without network access."""
import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent import main
from agent_core import AgentError


class CliTests(unittest.TestCase):
    def test_api_failure_preserves_existing_report_and_partial_trace(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            output = Path(directory) / "report.json"
            trace = Path(directory) / "trace.jsonl"
            original = '{"repository":"previous","violations":[]}\n'
            output.write_text(original)
            sdk = SimpleNamespace(OpenAI=lambda **kwargs: SimpleNamespace(api_key="test-key"))
            def fail(*args, **kwargs):
                kwargs["trace"]({"event": "audit_started"})
                raise AgentError("Provider quota exhausted")
            with patch.dict(sys.modules, {"openai": sdk}), \
                 patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}), \
                 patch("agent.RepositoryTools"), patch("agent.run_audit", side_effect=fail), \
                 redirect_stderr(io.StringIO()):
                status = main(["--repo", "https://github.com/example/demo",
                               "--output", str(output), "--trace", str(trace)])
            self.assertEqual(status, 1)
            self.assertEqual(output.read_text(), original)
            self.assertIn("audit_failed", trace.read_text())
            self.assertNotIn("test-key", trace.read_text())

    def test_missing_key_fails_before_clone(self):
        with patch.dict(os.environ, {}, clear=True), \
             patch("agent.RepositoryTools") as clone, redirect_stderr(io.StringIO()):
            status = main(["--repo", "https://github.com/example/demo", "--output", "unused.json"])
        self.assertEqual(status, 2)
        clone.assert_not_called()

    def test_invalid_retry_setting_fails_before_clone(self):
        sdk = SimpleNamespace(OpenAI=lambda **kwargs: None)
        with patch.dict(sys.modules, {"openai": sdk}), \
             patch.dict(os.environ, {"OPENAI_API_KEY": "test-key", "AUDIT_MAX_RATE_RETRIES": "oops"}), \
             patch("agent.RepositoryTools") as clone, redirect_stderr(io.StringIO()) as stderr:
            status = main(["--repo", "https://github.com/example/demo", "--output", "unused.json"])
        self.assertEqual(status, 1)
        self.assertIn("AUDIT_MAX_RATE_RETRIES must be an integer", stderr.getvalue())
        clone.assert_not_called()


if __name__ == "__main__":
    unittest.main()

