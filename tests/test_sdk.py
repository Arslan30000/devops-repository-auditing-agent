"""Exercise actual SDK serialization and HTTP error handling with an in-memory server."""
import json
import unittest
from unittest.mock import patch

try:
    import httpx
    from openai import OpenAI
except ImportError:
    OpenAI = None

from agent_core import run_audit
from test_agent import FakeTools


@unittest.skipIf(OpenAI is None, "Install requirements.txt to run SDK transport integration")
class SdkIntegrationTests(unittest.TestCase):
    def test_real_sdk_tool_loop_recovers_from_http_429(self):
        requests = []
        tools = FakeTools()
        def answer(request):
            body = json.loads(request.content)
            requests.append(body)
            if len(requests) == 2:
                return httpx.Response(429, headers={"retry-after": "0"},
                                      json={"error": {"message": "Temporary token rate limit"}})
            if len(requests) == 1:
                message = {"role": "assistant", "content": None, "tool_calls": [{
                    "id": "list", "type": "function",
                    "function": {"name": "list_files", "arguments": "{}"}}]}
            elif len(requests) == 3:
                message = {"role": "assistant", "content": None, "tool_calls": [{
                    "id": "read", "type": "function",
                    "function": {"name": "read_file",
                                 "arguments": json.dumps({"path": "README.md"})}}]}
            else:
                message = {"role": "assistant", "content": json.dumps({
                    "repository": tools.repository_url, "violations": []})}
            return httpx.Response(200, json={"id": "completion-test", "object": "chat.completion",
                "created": 1, "model": "test-model", "choices": [{
                    "index": 0, "message": message,
                    "finish_reason": "tool_calls" if message.get("tool_calls") else "stop"}]})
        events = []
        with httpx.Client(transport=httpx.MockTransport(answer)) as http_client:
            with OpenAI(api_key="unit-test-not-a-real-key", base_url="https://unit.invalid/v1",
                        http_client=http_client, max_retries=0) as client:
                with patch("agent_core.time.sleep") as sleep:
                    report = run_audit(client, tools, "test-model", trace=events.append)
        self.assertEqual(report["violations"], [])
        self.assertEqual(requests[1], requests[2])
        self.assertEqual(tools.observed, ["list_files", ("read_file", "README.md", 1, None)])
        self.assertTrue(all("response_format" not in body for body in requests))
        sleep.assert_called_once_with(1)
        self.assertEqual(events[-1]["event"], "audit_completed")
        self.assertNotIn("unit-test-not-a-real-key", json.dumps(events))


if __name__ == "__main__":
    unittest.main()

