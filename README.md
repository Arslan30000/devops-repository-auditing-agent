# DevOps Repository Auditing Agent

I am building a Python agent that audits public GitHub repositories and reports evidence-based DevOps violations. This repository is my submission for Assignment 2 in MLOps & Production AI Engineering.

## Progress

I am delivering the project in four committed stages:

1. Repository setup and safe inspection tools (complete).
2. LLM-directed agent loop and strict JSON report (this stage).
3. Broader DevOps reasoning, evidence validation, and reliability.
4. End-to-end tests, authentic sample report, and final documentation.

At this stage, `tools.py` implements `list_files`, `read_file`, `search_code`, and `git_log`. It clones a public repository into a temporary directory and never writes to the target. It rejects unsafe URLs and paths, skips binary files and symlinks, and bounds the amount of data returned. `agent_core.py` runs an explicit LLM/tool loop: the model chooses a tool, my code dispatches it, and the observation returns to the model for follow-up decisions. I reject malformed reports instead of silently writing them.

## Development

```bash
python -m venv .venv
# Activate .venv for my shell, then:
python -m pip install -r requirements.txt
python -m unittest test_tools -v
python -m unittest test_agent -v
```

I set `OPENAI_API_KEY` in my shell environment and may override `OPENAI_MODEL` (default: `gpt-4.1-mini`). I do not commit credentials. I run the unattended CLI as follows:

```bash
python agent.py --repo https://github.com/owner/repository --output report.json
```

The command exits nonzero on invalid input, clone/API failures, or invalid model output. A successful run writes `repository` and `violations` in JSON; an empty array means no supported violations. I will expand inspection coverage and evidence checks in stage 3. I will move the current root-level tests into `tests/` during final packaging.
