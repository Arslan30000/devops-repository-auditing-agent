import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent_core import AgentError, run_audit, validate_report, _bounded_request, _request_size
from tools import RepositoryTools


def response(content=None, calls=None):
    return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(
        content=content, tool_calls=calls or []))])


def tool_call(name, arguments, identifier):
    return SimpleNamespace(id=identifier, function=SimpleNamespace(
        name=name, arguments=json.dumps(arguments)))


class FakeTools:
    repository_url = "https://github.com/example/project"

    def __init__(self):
        self.observed = []

    def list_files(self):
        self.observed.append("list_files")
        return {"files": [{"path": "README.md", "bytes": 20}], "count": 1}

    def read_file(self, path, start_line=1, end_line=None):
        self.observed.append(("read_file", path, start_line, end_line))
        line = start_line
        return {"path": path, "content": f"{line}: # Example", "truncated": False}


class FakeClient:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.requests = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.requests.append(deepcopy(kwargs))
        reply = next(self.replies)
        if isinstance(reply, Exception):
            raise reply
        return reply


class AgentTests(unittest.TestCase):
    def test_context_compaction_preserves_complete_latest_tool_exchange(self):
        request = {"model": "test-model", "messages": [
            {"role": "system", "content": "rules"},
            {"role": "user", "content": "audit"},
            {"role": "assistant", "tool_calls": [{"id": "old"}]},
            {"role": "tool", "tool_call_id": "old", "content": "x" * 4_000},
            {"role": "assistant", "tool_calls": [{"id": "latest"}]},
            {"role": "tool", "tool_call_id": "latest", "content": "1: important evidence"},
        ]}
        original = deepcopy(request)
        bounded = _bounded_request(request, 1_000, keep_latest_tools=True)
        self.assertLessEqual(_request_size(bounded), 1_000)
        self.assertEqual(bounded["messages"][0:2], request["messages"][0:2])
        self.assertEqual(bounded["messages"][2:], request["messages"][-2:])
        self.assertEqual(request, original)

    def test_oversized_latest_observation_fails_without_hiding_evidence(self):
        request = {"messages": [{"role": "system", "content": "rules"},
                                {"role": "user", "content": "audit"},
                                {"role": "assistant", "tool_calls": [{"id": "latest"}]},
                                {"role": "tool", "tool_call_id": "latest", "content": "x" * 2_000}]}
        with self.assertRaises(AgentError):
            _bounded_request(request, 1_000, keep_latest_tools=True)

    def test_413_retries_with_a_smaller_valid_context(self):
        tools = FakeTools()
        error = RuntimeError("request too large")
        error.status_code = 413
        client = FakeClient([
            response(calls=[tool_call("list_files", {}, "call_1")]),
            response(calls=[tool_call("read_file", {"path": "README.md"}, "call_2")]),
            response(calls=[tool_call("read_file", {"path": "README.md"}, "call_3")]),
            error,
            response(content=json.dumps({"repository": tools.repository_url, "violations": []})),
            response(content=json.dumps({"repository": tools.repository_url, "violations": []})),
        ])
        def large_read(path):
            return {"path": path, "content": "1: " + "evidence " * 450}
        with patch.object(tools, "read_file", side_effect=large_read):
            report = run_audit(client, tools, "test-model")
        self.assertEqual(report["violations"], [])
        self.assertLess(_request_size(client.requests[4]), _request_size(client.requests[3]))
        self.assertEqual(client.requests[4]["max_completion_tokens"], 2_048)
        self.assertIn("call_3", json.dumps(client.requests[4]["messages"]))

    def test_provider_error_preserves_reason_and_redacts_key(self):
        key = "test-provider-key"
        error = RuntimeError("Do not print the raw exception")
        error.status_code = 429
        error.body = {"error": {"message": f"Token limit reached using {key}; retry in 20s",
                                "failed_generation": "private repository content"}}
        client = FakeClient([])
        client.api_key = key
        with patch.object(client.chat.completions, "create", side_effect=error):
            with self.assertRaises(AgentError) as raised:
                run_audit(client, FakeTools(), "test-model")
        message = str(raised.exception)
        self.assertIn("HTTP 429", message)
        self.assertIn("Token limit reached", message)
        self.assertIn("retry in 20s", message)
        self.assertNotIn(key, message)
        self.assertNotIn("private repository content", message)

    def test_network_error_does_not_dump_raw_exception(self):
        client = FakeClient([])
        with patch.object(client.chat.completions, "create", side_effect=RuntimeError("private data")):
            with self.assertRaises(AgentError) as raised:
                run_audit(client, FakeTools(), "test-model")
        self.assertIn("network", str(raised.exception))
        self.assertNotIn("private data", str(raised.exception))

    def test_model_selects_follow_up_tools_and_reports_json(self):
        tools = FakeTools()
        client = FakeClient([
            response(calls=[tool_call("list_files", {}, "call_1")]),
            response(calls=[tool_call("read_file", {"path": "README.md"}, "call_2")]),
            response(content=json.dumps({"repository": tools.repository_url, "violations": []})),
            response(content=json.dumps({"repository": tools.repository_url, "violations": []})),
        ])
        result = run_audit(client, tools, "test-model")
        self.assertEqual(result["violations"], [])
        self.assertEqual(tools.observed, ["list_files", ("read_file", "README.md", 1, None)])
        self.assertEqual(client.requests[0]["tool_choice"], "required")
        self.assertEqual(client.requests[1]["messages"][-1]["tool_call_id"], "call_1")
        self.assertEqual(client.requests[2]["messages"][-1]["tool_call_id"], "call_2")
        for request in client.requests[:-1]:
            self.assertIn("tools", request)
            self.assertNotIn("response_format", request)
        self.assertEqual(client.requests[-1]["response_format"], {"type": "json_object"})
        self.assertNotIn("tools", client.requests[-1])
        self.assertNotIn("tool_choice", client.requests[-1])
        instructions = client.requests[-1]["messages"][-1]["content"]
        self.assertIn(tools.repository_url, instructions)
        self.assertIn('"required": ["repository", "violations"]', instructions)
        self.assertIn('"README.md": [[1, 1]]', instructions)

    def test_exhausted_report_retries_show_specific_reason(self):
        tools = FakeTools()
        wrong = response(content='{"repository":"wrong","violations":[]}')
        client = FakeClient([
            response(calls=[tool_call("list_files", {}, "call_1")]),
            response(calls=[tool_call("read_file", {"path": "README.md"}, "call_2")]),
            wrong, wrong, wrong, wrong, wrong, wrong,
        ])
        with self.assertRaises(AgentError) as raised:
            run_audit(client, tools, "test-model")
        self.assertIn("after 3 attempts", str(raised.exception))
        self.assertIn("Report repository or violations array is invalid", str(raised.exception))
        self.assertIn("tool calls: 2; files read: 1", str(raised.exception))

    def test_invalid_report_is_retried_not_written_as_success(self):
        tools = FakeTools()
        client = FakeClient([
            response(calls=[tool_call("list_files", {}, "call_1")]),
            response(calls=[tool_call("read_file", {"path": "README.md"}, "call_2")]),
            response(content='{"repository":"wrong","violations":[]}'),
            response(content='{"repository":"wrong","violations":[]}'),
            response(content=json.dumps({"repository": tools.repository_url, "violations": []})),
            response(content=json.dumps({"repository": tools.repository_url, "violations": []})),
        ])
        self.assertEqual(run_audit(client, tools, "test-model")["violations"], [])
        self.assertIn("Correct the JSON report schema", client.requests[4]["messages"][-1]["content"])

    def test_tool_budget_exhaustion_requests_json_without_tools(self):
        tools = FakeTools()
        client = FakeClient([
            response(calls=[tool_call("list_files", {}, "call_1")]),
            response(calls=[tool_call("read_file", {"path": "README.md"}, "call_2")]),
            response(content=json.dumps({"repository": tools.repository_url, "violations": []})),
        ])
        with patch("agent_core.MAX_TOOL_CALLS", 2):
            self.assertEqual(run_audit(client, tools, "test-model")["violations"], [])
        self.assertEqual(client.requests[-1]["response_format"], {"type": "json_object"})
        self.assertNotIn("tools", client.requests[-1])
        self.assertNotIn("tool_choice", client.requests[-1])

    def test_rejects_malformed_violation(self):
        with self.assertRaises(AgentError):
            validate_report({"repository": FakeTools.repository_url,
                             "violations": [{"rule_id": "SEC-001"}]}, FakeTools.repository_url)

    def test_redacts_assignment_in_report(self):
        item = {"rule_id": "SEC-001", "category": "security", "severity": "high",
                "file": "config.py", "line": 2, "description": "Password assigned in code",
                "evidence": "password=sample-value", "recommendation": "Read it from environment"}
        report = validate_report({"repository": FakeTools.repository_url,
                                  "violations": [item]}, FakeTools.repository_url)
        self.assertEqual(report["violations"][0]["evidence"], "password=[REDACTED]")

    def test_unread_source_line_prompts_follow_up(self):
        tools = FakeTools()
        item = {"rule_id": "CFG-001", "category": "configuration", "severity": "medium",
                "file": "README.md", "line": 12, "description": "Machine-specific path",
                "evidence": "A local path is embedded at line 12", "recommendation": "Use a relative path"}
        proposed = json.dumps({"repository": tools.repository_url, "violations": [item]})
        client = FakeClient([
            response(calls=[tool_call("list_files", {}, "call_1")]),
            response(content=proposed),
            response(content=proposed),
            response(calls=[tool_call("read_file", {"path": "README.md", "start_line": 12,
                                                  "end_line": 12}, "call_2")]),
            response(content=proposed),
            response(content=proposed),
        ])
        report = run_audit(client, tools, "test-model")
        self.assertEqual(report["violations"][0]["line"], 12)
        self.assertEqual(tools.observed[-1], ("read_file", "README.md", 12, 12))

    def test_rejects_invalid_category_and_unread_file(self):
        item = {"rule_id": "CFG-001", "category": "unknown", "severity": "medium",
                "file": "config.py", "line": 2, "description": "Local path",
                "evidence": "Machine path", "recommendation": "Use environment"}
        with self.assertRaises(AgentError):
            validate_report({"repository": FakeTools.repository_url, "violations": [item]},
                            FakeTools.repository_url)
        item["category"] = "configuration"
        with self.assertRaises(AgentError):
            validate_report({"repository": FakeTools.repository_url, "violations": [item]},
                            FakeTools.repository_url, observed_lines={})

    def test_rejects_unhashable_model_values_cleanly(self):
        item = {"rule_id": "CFG-001", "category": ["configuration"], "severity": ["low"],
                "file": None, "line": None, "description": "Bad value", "evidence": "Bad value",
                "recommendation": "Fix it"}
        with self.assertRaises(AgentError):
            validate_report({"repository": FakeTools.repository_url, "violations": [item]},
                            FakeTools.repository_url)

    def test_early_empty_report_requires_investigation(self):
        tools = FakeTools()
        client = FakeClient([
            response(calls=[tool_call("list_files", {}, "call_1")]),
            response(content=json.dumps({"repository": tools.repository_url, "violations": []})),
            response(content=json.dumps({"repository": tools.repository_url, "violations": []})),
            response(calls=[tool_call("read_file", {"path": "README.md"}, "call_2")]),
            response(content=json.dumps({"repository": tools.repository_url, "violations": []})),
            response(content=json.dumps({"repository": tools.repository_url, "violations": []})),
        ])
        self.assertEqual(run_audit(client, tools, "test-model")["violations"], [])
        self.assertIn("Inspect repository", client.requests[3]["messages"][-1]["content"])

    def test_real_tools_follow_up_and_report_evidence(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            root = Path(directory)
            (root / "README.md").write_text("# Demo\n", encoding="utf-8")
            (root / "settings.py").write_text("DEBUG = True\n", encoding="utf-8")
            tools = RepositoryTools("https://github.com/example/demo")
            tools.root = root
            finding = {
                "rule_id": "CFG-001", "category": "configuration", "severity": "low",
                "file": "settings.py", "line": 1,
                "description": "Debug mode is enabled in the default configuration",
                "evidence": "The default settings file sets DEBUG to True.",
                "recommendation": "Read the debug setting from an environment variable and default it to False.",
            }
            client = FakeClient([
                response(calls=[tool_call("list_files", {}, "call_1")]),
                response(calls=[tool_call("search_code", {"pattern": "DEBUG"}, "call_2")]),
                response(calls=[tool_call("read_file", {"path": "settings.py"}, "call_3")]),
                response(content=json.dumps({"repository": tools.repository_url,
                                             "violations": [finding]})),
                response(content=json.dumps({"repository": tools.repository_url,
                                             "violations": [finding]})),
            ])
            with patch.object(tools, "_files", return_value=["README.md", "settings.py"]):
                report = run_audit(client, tools, "test-model")
            self.assertEqual(report["violations"], [finding])
            observations = [json.loads(request["messages"][-1]["content"])
                            for request in client.requests[1:4]]
            self.assertEqual(observations[1]["matches"], [{"file": "settings.py", "line": 1}])
            self.assertIn("1: DEBUG = True", observations[2]["content"])


if __name__ == "__main__":
    unittest.main()
