"""Unattended command-line entry point for the DevOps repository auditor."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from agent_core import AgentError, run_audit, _safe_detail
from tools import InspectionError, RepositoryTools


def _environment_limit(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise AgentError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise AgentError(f"{name} must be between {minimum} and {maximum}")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit a public GitHub repository")
    parser.add_argument("--repo", required=True, help="HTTPS github.com/owner/repository URL")
    parser.add_argument("--output", required=True, help="JSON report path")
    parser.add_argument("--trace", help="Optional JSONL inspection trace (metadata only, no source text)")
    args = parser.parse_args(argv)
    if not os.environ.get("OPENAI_API_KEY"):
        print("Error: set OPENAI_API_KEY before running the agent", file=sys.stderr)
        return 2
    trace_stream = None
    trace_callback = None
    client = None
    try:
        from openai import OpenAI

        context_limit = _environment_limit("AUDIT_MAX_CONTEXT_CHARS", 20_000, 8_000, 500_000)
        output_limit = _environment_limit("AUDIT_MAX_COMPLETION_TOKENS", 2_048, 256, 32_768)
        client = OpenAI(api_key=os.environ["OPENAI_API_KEY"], max_retries=2)
        if args.trace:
            trace_path = Path(args.trace)
            if trace_path.resolve() == Path(args.output).resolve():
                raise AgentError("Trace and report paths must differ")
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            trace_stream = trace_path.open("w", encoding="utf-8")
            def trace_callback(event: dict) -> None:
                trace_stream.write(json.dumps(event, ensure_ascii=False) + "\n")
                trace_stream.flush()
        with RepositoryTools(args.repo) as tools:
            report = run_audit(client, tools, os.environ.get("OPENAI_MODEL", "gpt-4.1-mini"),
                               max_context_chars=context_limit, max_completion_tokens=output_limit,
                               trace=trace_callback)
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
        if trace_stream is not None:
            try:
                trace_stream.write(json.dumps({"event": "audit_failed",
                    "error": _safe_detail(str(exc), client)}) + "\n")
            except OSError:
                pass
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        if trace_stream is not None:
            trace_stream.close()


if __name__ == "__main__":
    raise SystemExit(main())
