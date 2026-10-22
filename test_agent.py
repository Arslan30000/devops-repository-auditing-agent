import json
import unittest
from copy import deepcopy
from types import SimpleNamespace

from agent_core import AgentError, run_audit, validate_report


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

    def read_file(self, path):
        self.observed.append(("read_file", path))
        return {"path": path, "content": "1: # Example", "truncated": False}


class FakeClient:
    def __init__(self, replies):
        self.replies = iter(replies)
        self.requests = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.requests.append(deepcopy(kwargs))
        return next(self.replies)


class AgentTests(unittest.TestCase):
    def test_model_selects_follow_up_tools_and_reports_json(self):
        tools = FakeTools()
        client = FakeClient([
            response(calls=[tool_call("list_files", {}, "call_1")]),
            response(calls=[tool_call("read_file", {"path": "README.md"}, "call_2")]),
            response(content=json.dumps({"repository": tools.repository_url, "violations": []})),
        ])
        result = run_audit(client, tools, "test-model")
        self.assertEqual(result["violations"], [])
        self.assertEqual(tools.observed, ["list_files", ("read_file", "README.md")])
        self.assertEqual(client.requests[0]["tool_choice"], "required")
        self.assertEqual(client.requests[1]["messages"][-1]["tool_call_id"], "call_1")
        self.assertEqual(client.requests[2]["messages"][-1]["tool_call_id"], "call_2")

    def test_invalid_report_is_retried_not_written_as_success(self):
        tools = FakeTools()
        client = FakeClient([
            response(calls=[tool_call("list_files", {}, "call_1")]),
            response(content='{"repository":"wrong","violations":[]}'),
            response(content=json.dumps({"repository": tools.repository_url, "violations": []})),
        ])
        self.assertEqual(run_audit(client, tools, "test-model")["violations"], [])
        self.assertIn("Correct the JSON report schema", client.requests[2]["messages"][-1]["content"])

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


if __name__ == "__main__":
    unittest.main()
