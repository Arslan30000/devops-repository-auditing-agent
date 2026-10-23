"""Reproduce the sample report with an offline, scripted model and real tools."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_core import run_audit  # noqa: E402
from tools import RepositoryTools  # noqa: E402


def call(name: str, arguments: dict, identifier: str) -> SimpleNamespace:
    return SimpleNamespace(id=identifier, function=SimpleNamespace(
        name=name, arguments=json.dumps(arguments)))


class ScriptedClient:
    """Supply a deterministic tool sequence for a reproducible offline example."""

    def __init__(self, repository: str):
        self.repository = repository
        self.turn = 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **kwargs: object) -> SimpleNamespace:
        sequence = [
            (None, [call("list_files", {}, "list")]),
            (None, [call("search_code", {"pattern": "DEBUG"}, "search")]),
            (None, [call("read_file", {"path": "settings.py"}, "read")]),
            (json.dumps({"repository": self.repository, "violations": [{
                "rule_id": "CFG-001", "category": "configuration", "severity": "low",
                "file": "settings.py", "line": 1,
                "description": "Debug mode is enabled in the default configuration",
                "evidence": "The default settings file sets DEBUG to True.",
                "recommendation": "Read the debug setting from an environment variable and default it to False.",
            }]}), []),
        ]
        # The first report is a draft; a separate request emits JSON without tools.
        sequence.append(sequence[-1])
        content, calls = sequence[self.turn]
        self.turn += 1
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(
            content=content, tool_calls=calls))])


def main() -> None:
    repository = "https://github.com/example/demo"
    with tempfile.TemporaryDirectory(prefix="devops-sample-",
                                     dir=Path(__file__).resolve().parents[1]) as directory:
        root = Path(directory)
        (root / "README.md").write_text("# Example service\n", encoding="utf-8")
        (root / "settings.py").write_text("DEBUG = True\n", encoding="utf-8")
        tools = RepositoryTools(repository)
        tools.root = root
        with patch.object(tools, "_files", return_value=["README.md", "settings.py"]):
            report = run_audit(ScriptedClient(repository), tools, "offline-scripted-model")
    destination = Path(__file__).resolve().parents[1] / "sample_report.json"
    destination.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {destination}")


if __name__ == "__main__":
    main()
