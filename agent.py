"""Unattended command-line entry point for my DevOps repository auditor."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from agent_core import AgentError, run_audit
from tools import InspectionError, RepositoryTools


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit a public GitHub repository")
    parser.add_argument("--repo", required=True, help="HTTPS github.com/owner/repository URL")
    parser.add_argument("--output", required=True, help="JSON report path")
    args = parser.parse_args(argv)
    if not os.environ.get("OPENAI_API_KEY"):
        print("Error: set OPENAI_API_KEY before running the agent", file=sys.stderr)
        return 2
    try:
        from openai import OpenAI

        client = OpenAI(api_key=os.environ["OPENAI_API_KEY"], max_retries=2)
        with RepositoryTools(args.repo) as tools:
            report = run_audit(client, tools, os.environ.get("OPENAI_MODEL", "gpt-4.1-mini"))
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        # An incomplete or invalid report never replaces an existing result.
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent,
                                         prefix=".audit-", suffix=".json", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        temporary.replace(output)
        return 0
    except (InspectionError, AgentError, OSError, ImportError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
