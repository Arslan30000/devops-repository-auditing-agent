# DevOps Repository Auditing Agent

I am building a Python agent that audits public GitHub repositories and reports evidence-based DevOps violations. This repository is my submission for Assignment 2 in MLOps & Production AI Engineering.

## Progress

I am delivering the project in four stages:

1. Repository setup and safe inspection tools (this stage).
2. LLM-directed agent loop and strict JSON report.
3. Broader DevOps reasoning, evidence validation, and reliability.
4. End-to-end tests, authentic sample report, and final documentation.

At this stage, `tools.py` implements `list_files`, `read_file`, `search_code`, and `git_log`. It clones a public repository into a temporary directory and never writes to the target. It rejects unsafe URLs and paths, skips binary files and symlinks, and bounds the amount of data returned. The CLI is planned for stage 2, so the final assignment command is not available yet.

## Development

```bash
python -m venv .venv
# Activate .venv for my shell, then:
python -m pip install -r requirements.txt
python -m unittest test_tools -v
```

I will keep API credentials in my local `.env` or environment, never in commits. `.env.example` lists the planned variables. I will move the current root-level tests into `tests/` during final packaging.
