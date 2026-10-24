"""Regression tests for live-run failures: evidence, quotas, and wasted inspection."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from agent_core import (AgentError, EvidenceError, _rate_limit_delay,
                        run_audit, validate_report)
from test_agent import FakeClient, FakeTools, response, tool_call


class ReliabilityTests(unittest.TestCase):
    def finding(self, evidence="2: allow = true", line=2):
        return {"rule_id": "CFG-TEST", "category": "configuration", "severity": "medium",
                "file": "service.tf", "line": line, "description": "Example unsafe setting",
                "evidence": evidence, "recommendation": "Restrict the demonstrated setting"}

    def validate(self, item, source):
        return validate_report({"repository": FakeTools.repository_url, "violations": [item]},
                               FakeTools.repository_url,
                               observed_lines={"service.tf": set(source)},
                               observed_source={"service.tf": source})

    def test_rejects_invented_source_even_when_line_was_read(self):
        with self.assertRaisesRegex(EvidenceError, "does not match"):
            self.validate(self.finding(), {2: "allow = false"})

    def test_rejects_comment_only_and_empty_resource_evidence(self):
        for evidence, source in [
            ("2: # allow = true", {2: "# allow = true"}),
            ('1: resource "service" "example" {\n2: # unsafe\n3: }',
             {1: 'resource "service" "example" {', 2: "# unsafe", 3: "}"})]:
            with self.subTest(evidence=evidence), self.assertRaises(EvidenceError):
                self.validate(self.finding(evidence), source)

    def test_accepts_exact_operative_evidence_and_requires_cited_anchor(self):
        self.assertEqual(self.validate(self.finding(), {2: "allow = true"})["violations"][0]["line"], 2)
        with self.assertRaisesRegex(EvidenceError, "include the cited line"):
            self.validate(self.finding("1: allow = true"), {1: "allow = true", 2: "other = false"})

    def rate_error(self, message="", retry_after=None):
        error = RuntimeError("must not expose raw error")
        error.status_code = 429
        error.body = {"error": {"message": message}}
        if retry_after is not None:
            error.response = SimpleNamespace(headers={"retry-after": retry_after})
        return error

    def test_rate_delay_honors_headers_and_short_provider_delays(self):
        self.assertEqual(_rate_limit_delay(self.rate_error(retry_after="12.5"), 120), 13.5)
        self.assertEqual(_rate_limit_delay(self.rate_error("Please try again in 1m16.464s."), 120), 77.464)
        for value in ("nan", "inf", "-1", "10000"):
            self.assertIsNone(_rate_limit_delay(self.rate_error(retry_after=value), 120))
        self.assertIsNone(_rate_limit_delay(self.rate_error("Please try again in 10h3m4s."), 120))
        self.assertIsNone(_rate_limit_delay(self.rate_error("quota exhausted"), 120))

    def test_429_resumes_same_request_without_repeating_tools(self):
        tools = FakeTools()
        empty = response(content=json.dumps({"repository": tools.repository_url, "violations": []}))
        client = FakeClient([
            response(calls=[tool_call("list_files", {}, "list")]),
            response(calls=[tool_call("read_file", {"path": "README.md"}, "read")]),
            self.rate_error(retry_after="1"), empty])
        events = []
        with patch("agent_core.time.sleep") as sleep:
            report = run_audit(client, tools, "test-model", trace=events.append)
        self.assertEqual(report["violations"], [])
        self.assertEqual(client.requests[2], client.requests[3])
        self.assertEqual(len(tools.observed), 2)
        sleep.assert_called_once_with(2)
        self.assertTrue(any(e["event"] == "rate_limit_wait" for e in events))

    def test_repeated_429_stops_at_audit_retry_budget(self):
        error = self.rate_error(retry_after="0")
        client = FakeClient([error, error, error])
        with patch("agent_core.time.sleep") as sleep, self.assertRaisesRegex(AgentError, "HTTP 429"):
            run_audit(client, FakeTools(), "test-model", max_rate_retries=2)
        self.assertEqual(sleep.call_count, 2)

    def test_duplicate_tool_request_is_not_executed_again(self):
        tools = FakeTools()
        client = FakeClient([
            response(calls=[tool_call("list_files", {}, "first")]),
            response(calls=[tool_call("list_files", {}, "repeat")]),
            response(calls=[tool_call("read_file", {"path": "README.md"}, "read")]),
            response(content=json.dumps({"repository": tools.repository_url, "violations": []}))])
        run_audit(client, tools, "test-model")
        self.assertEqual(tools.observed.count("list_files"), 1)
        self.assertIn("Identical call already observed", client.requests[2]["messages"][-1]["content"])
        self.assertIn("tool_calls_remaining", client.requests[2]["messages"][1]["content"])

    def test_supported_draft_gets_independent_review_before_completion(self):
        class ConfigTools(FakeTools):
            def list_files(self):
                return {"files": [{"path": "service.tf", "bytes": 30}], "count": 1}
            def read_file(self, path):
                return {"path": path, "content": "2: allow = true"}
        tools = ConfigTools()
        draft = response(content=json.dumps({"repository": tools.repository_url,
                                              "violations": [self.finding()]}))
        revised = self.finding()
        revised["severity"] = "low"
        reviewed = response(content=json.dumps({"repository": tools.repository_url,
                                                 "violations": [revised]}))
        client = FakeClient([
            response(calls=[tool_call("list_files", {}, "list")]),
            response(calls=[tool_call("read_file", {"path": "service.tf"}, "read")]),
            draft, reviewed])
        events = []
        result = run_audit(client, tools, "test-model", trace=events.append)
        self.assertEqual(result["violations"][0]["severity"], "low")
        self.assertEqual(len(client.requests), 4)
        self.assertNotIn("tools", client.requests[-1])
        self.assertIn("independently", client.requests[-1]["messages"][1]["content"])
        self.assertTrue(any(event["event"] == "review_started" for event in events))
        self.assertEqual(events[-1]["event"], "audit_completed")

    def test_bad_evidence_returns_to_investigation_for_actual_configuration(self):
        class ConfigTools(FakeTools):
            def list_files(self):
                return {"files": [{"path": "service.tf", "bytes": 30}], "count": 1}
            def read_file(self, path, start_line=1, end_line=None):
                return {"path": path, "content": "1: # allow = true" if start_line == 1
                        else "2: allow = true"}
        tools = ConfigTools()
        bad = self.finding("1: # allow = true", 1)
        good = self.finding()
        valid = response(content=json.dumps({"repository": tools.repository_url, "violations": [good]}))
        client = FakeClient([
            response(calls=[tool_call("list_files", {}, "list")]),
            response(calls=[tool_call("read_file", {"path": "service.tf"}, "comment")]),
            response(content=json.dumps({"repository": tools.repository_url, "violations": [bad]})),
            response(calls=[tool_call("read_file", {"path": "service.tf", "start_line": 2}, "actual")]),
            valid, valid])
        result = run_audit(client, tools, "test-model")
        self.assertEqual(result["violations"][0]["evidence"], "2: allow = true")
        self.assertIn("tools", client.requests[3])


    def test_equivalent_default_reads_and_complete_inventory_are_not_reexecuted(self):
        tools = FakeTools()
        client = FakeClient([
            response(calls=[tool_call("list_files", {}, "first")]),
            response(calls=[tool_call("list_files", {"offset": 0, "limit": 300}, "overlap")]),
            response(calls=[tool_call("read_file", {"path": "README.md"}, "read")]),
            response(calls=[tool_call("read_file", {"path": "README.md", "start_line": 1,
                                                   "end_line": 80}, "same_read")]),
            response(content=json.dumps({"repository": tools.repository_url, "violations": []}))])
        run_audit(client, tools, "test-model")
        self.assertEqual(tools.observed, ["list_files", ("read_file", "README.md", 1, None)])
        self.assertIn("Identical call already observed", client.requests[2]["messages"][-1]["content"])
        self.assertIn("Identical call already observed", client.requests[4]["messages"][-1]["content"])

    def test_unavailable_file_feedback_includes_path_and_new_inspection_candidates(self):
        from tools import InspectionError
        class SizedTools(FakeTools):
            def list_files(self):
                return {"files": [{"path": "oversized.tf", "bytes": 200000, "readable_size": False},
                                  {"path": "runtime.tf", "bytes": 100},
                                  {"path": "safe.py", "bytes": 100}], "count": 3}
            def read_file(self, path, **kwargs):
                self.observed.append(path)
                if path == "runtime.tf":
                    raise InspectionError("Binary files cannot be read as text")
                return {"path": path, "content": "1: setting = False"}
        tools = SizedTools()
        client = FakeClient([
            response(calls=[tool_call("list_files", {}, "list")]),
            response(calls=[tool_call("read_file", {"path": "oversized.tf"}, "large")]),
            response(calls=[tool_call("read_file", {"path": "runtime.tf"}, "binary")]),
            response(calls=[tool_call("read_file", {"path": "runtime.tf", "start_line": 20}, "again")]),
            response(calls=[tool_call("read_file", {"path": "safe.py"}, "valid")]),
            response(content=json.dumps({"repository": tools.repository_url, "violations": []}))])
        events = []
        run_audit(client, tools, "test-model", trace=events.append)
        self.assertEqual(tools.observed, ["runtime.tf", "safe.py"])
        error_result = json.loads(client.requests[2]["messages"][-1]["content"])
        self.assertEqual(error_result["path"], "oversized.tf")
        self.assertIn("safe.py", error_result["unread_candidates"])
        failures = [event for event in events if event["event"] == "tool_result" and not event["ok"]]
        self.assertEqual([event["path"] for event in failures],
                         ["oversized.tf", "runtime.tf", "runtime.tf"])

    def test_missing_file_claim_requires_all_inventory_pages(self):
        item = self.finding()
        item.update(file=None, line=None, evidence="No README in the inventory",
                    description="Missing project documentation")
        with self.assertRaisesRegex(AgentError, "complete list_files inventory"):
            validate_report({"repository": FakeTools.repository_url, "violations": [item]},
                            FakeTools.repository_url, inventory_complete=False)

    def test_small_context_preserves_latest_source_and_bounded_progress(self):
        class ManyFiles(FakeTools):
            def list_files(self):
                return {"files": [{"path": f"service_{i}.py", "bytes": 6000}
                                  for i in range(8)], "count": 8}
            def read_file(self, path):
                return {"path": path, "content": "1: " + "x" * 5800,
                        "start_line": 1, "end_line": 1, "total_lines": 1, "truncated": False}
        tools = ManyFiles()
        replies = [response(calls=[tool_call("list_files", {}, "list")])]
        replies.extend(response(calls=[tool_call("read_file", {"path": f"service_{i}.py"},
                                                  f"read_{i}")]) for i in range(8))
        replies.append(response(content=json.dumps({"repository": tools.repository_url,
                                                     "violations": []})))
        client = FakeClient(replies)
        run_audit(client, tools, "test-model", max_context_chars=14000)
        from agent_core import _request_size
        self.assertTrue(all(_request_size(request) <= 14000 for request in client.requests))
        self.assertIn("service_7.py", client.requests[-1]["messages"][-1]["content"])
        self.assertIn('"files_read_count":8', client.requests[-1]["messages"][1]["content"])


if __name__ == "__main__":
    unittest.main()

