# DevOps Repository Auditing Agent

A Python agent that audits public GitHub repositories for evidence-backed software engineering and DevOps problems. It clones a repository into a temporary directory, lets an LLM choose inspection tools and follow-up checks, and writes a machine-readable JSON report. It does not execute code from the audited repository or change that repository.

## Requirements

- Python 3.10 or newer and Git on `PATH`.
- Network access to GitHub and the configured LLM API endpoint.
- An API key for OpenAI or an OpenAI-compatible provider, with access to a model that supports Chat Completions, function tools, and JSON mode. The default model is `gpt-4.1-mini`; set `OPENAI_MODEL` to another compatible model if necessary. API usage may incur charges or be subject to free-plan limits.

The target must be a public repository with a URL in the form `https://github.com/owner/repository`. Private repositories, local directories, and other Git hosts are outside the CLI's scope.

## Install and configure

Clone this project, then open a terminal in its root directory:

```bash
git clone https://github.com/Arslan30000/devops-repository-auditing-agent.git
cd devops-repository-auditing-agent
python3 -m venv .venv
```

On Windows, use `python -m venv .venv` for the last command if `python3` is unavailable.

Activate the virtual environment and install the dependency:

| Shell | Activation command |
| --- | --- |
| Linux/macOS bash or zsh | `source .venv/bin/activate` |
| Windows PowerShell | `.venv\Scripts\Activate.ps1` |
| Windows Command Prompt | `.venv\Scripts\activate.bat` |

```bash
python -m pip install -r requirements.txt
```

Set the API key in the current terminal. `.env.example` lists the variable names; the program reads environment variables directly and does not load `.env` automatically. Never commit a real key.

```bash
# Linux/macOS bash or zsh
export OPENAI_API_KEY="your-api-key"
export OPENAI_MODEL="gpt-4.1-mini"  # optional
```

```powershell
# Windows PowerShell
$env:OPENAI_API_KEY = "your-api-key"
$env:OPENAI_MODEL = "gpt-4.1-mini"  # optional
```

For Windows Command Prompt, use `set OPENAI_API_KEY=your-api-key` and, optionally, `set OPENAI_MODEL=gpt-4.1-mini`. If PowerShell blocks activation, use `.venv\Scripts\python.exe` in place of `python` without activating the environment.

For GroqCloud, use the Groq key as `OPENAI_API_KEY`, set `OPENAI_BASE_URL=https://api.groq.com/openai/v1`, and set `OPENAI_MODEL=openai/gpt-oss-20b` or another available compatible model. The 20B model was used for the successful live sample below. In bash, these can be saved in a local, ignored `.env` file:

```dotenv
OPENAI_API_KEY="your-groq-api-key"
OPENAI_BASE_URL="https://api.groq.com/openai/v1"
OPENAI_MODEL="openai/gpt-oss-20b"
```

Load that file in each new bash terminal before running:

```bash
set -a
source .env
set +a
```

The agent requests tools during investigation. Model reports are validated against observed source. Nonempty drafts receive a separate evidence, severity, and remediation review before acceptance. If formatting is needed, a separate JSON-mode request receives the observations as data in a fresh conversation without active tool messages or declarations. Providers do not need to support tools and JSON mode in one request. Provider errors include a redacted reason, HTTP status when available, and the investigation/reporting phase. Free-plan token/request limits can prevent a larger audit from completing.

Provider generation errors that indicate an unparseable tool call during investigation are retried at most twice with a reminder to make one native call using valid schema-matching JSON. The rejected generation is never executed or copied into the conversation. Other HTTP 400 configuration errors fail immediately, and repeated parsing failures still exit nonzero.

For a smaller input budget on Groq's free plan, set these optional environment variables (or add them to the ignored `.env` and reload it):

```bash
export AUDIT_MAX_CONTEXT_CHARS=14000
export AUDIT_MAX_COMPLETION_TOKENS=2048
```

Temporary HTTP 429 limits are retried without restarting the audit. The agent honors numeric `Retry-After` headers or explicit provider durations, adds one second, prints a wait notice, and resumes the same request. Defaults allow five retries per request with each requested wait below 120 seconds. Unknown reset times, long daily-quota waits, and exhausted retry budgets fail clearly.

```dotenv
AUDIT_MAX_RATE_WAIT_SECONDS=120
AUDIT_MAX_RATE_RETRIES=5
```

Set either value to `0` to disable waiting. The maximum configurable wait is 600 seconds and retry count is 10. These settings do not increase provider quotas.

The default serialized request budget is 20,000 characters and the response limit is 2,048 tokens. The input budget counts the messages and tool definitions; it is a character bound, not an exact provider token count. Older complete tool exchanges may be omitted to fit the budget, while the latest tool exchange is kept during investigation. A progress ledger retains read-file paths, unread candidates, recent failures, and the remaining tool budget. Identical tool calls are rejected with feedback. Final formatting prioritizes source observations from cited files. The model is told to re-read targeted evidence when needed. HTTP 413 responses trigger up to two retries with a smaller context. File reads default to 80 lines and at most 6,000 output characters; larger files remain available through explicit follow-up ranges. Smaller budgets can reduce inspection coverage, and these settings do not bypass per-minute or daily quotas. Higher-limit accounts can increase the budgets. A response cut off at its output limit fails explicitly rather than being saved as a completed report.

## Run an audit

```bash
python agent.py --repo https://github.com/owner/repository --output report.json
```

Replace `owner/repository` with the actual public repository. The output path may include a directory, for example `--output reports/audit.json`. The command runs without prompts. It writes a completed report atomically and exits with code 0; on a fatal clone, API, input, or report-validation error it prints a useful error to stderr and exits nonzero without replacing an existing report.

Open `report.json` with a text editor or parse it with Python:

```bash
python -m json.tool report.json
```

The top-level object contains `repository` and `violations`. Each violation includes `rule_id`, `category`, `severity`, `file`, `line`, `description`, `evidence`, and `recommendation`. Severity is `critical`, `high`, `medium`, or `low`. An empty `violations` array means no supported finding was reported; it is not a guarantee that the repository has no defects. `file` and `line` are JSON `null` when not applicable. See `sample_report.json` for the live result and `examples/offline_sample_report.json` for an example containing a finding.

To diagnose inspection coverage, add an optional trace path:

```bash
python agent.py --repo https://github.com/owner/repository --output report.json --trace reports/audit-trace.jsonl
```

The JSONL trace records model phases, request sizes, successful/failed tool names, read-file paths and line counts, validation rejections, review initiation, rate-limit waits, and completion counts. Completion also records tool-budget exhaustion, failed-tool count, and rate-limit retry count. It excludes source text, search strings, raw model generations, and API keys. It is flushed during the run so partial progress remains available on failure. The trace and report paths must differ.

Before accepting any report, the agent must read file content and inspect at least five distinct discovered source/configuration candidates, or all such candidates when fewer than five exist. Files marked too large to read are excluded from this minimum. Candidate paths are recognized by common source/configuration extensions and filenames; this is a minimum coverage check, not a vulnerability scanner or proof of a complete audit. The LLM still chooses the files, ranges, and follow-up tools. A training repository's intentional insecure examples remain in scope; findings should describe the example's risk without alleging a real production incident.

## How the agent works

1. `agent.py` validates the required key, opens a temporary clone through `RepositoryTools`, invokes the agent, and saves the validated JSON.
2. `agent_core.py` sends the repository goal and tool definitions to the model. The model selects tools; Python dispatches each call and returns its result to the model. The model can request follow-up calls based on prior observations.
3. `tools.py` provides `list_files` (paged tracked-file inventory), `read_file` (numbered text ranges), `search_code` (literal search returning locations), and `git_log` (recent commit metadata). The model interprets these observations and proposes findings.
4. Report validation requires file and line citations to have been observed through `read_file`, checks the schema and allowed values, rejects duplicates, and redacts recognized credential patterns. The agent must discover files and read content before completing a report.

The investigation prompt covers repository hygiene, dependencies, code quality, testing, CI, security, configuration, collaboration, and build/release where relevant. It asks the model to consider equivalent practices, avoid unsupported claims and false positives, and recommend specific fixes. No prebuilt agent orchestration framework is used.

## Development and verification

Run the automated tests from the project root:

```bash
python -m unittest discover -s tests -v
```

The tests cover URL and path restrictions, bounded tool observations, redaction, model-directed follow-up calls, rejection and retry of invalid reports, and a fixture-based agent run using the real file-reading and search methods. A symlink test is skipped only on a filesystem that cannot create symlinks.

The checked-in `sample_report.json` contains authentic output from a live CLI audit of `https://github.com/pypa/sampleproject` using GroqCloud's `openai/gpt-oss-20b`. That run reported no supported violations. This verifies a completed live run and valid JSON output; it does not establish that the repository has no defects or measure recall on injected defects. Model results and the target's default branch can change between runs. To produce a fresh live report:

```bash
python agent.py --repo https://github.com/pypa/sampleproject --output reports/sampleproject.json
```

Generate a separate deterministic offline example without an API key:

```bash
python examples/generate_sample.py
```

This writes `examples/offline_sample_report.json` through the actual agent/report-validation code path over a local fixture with a scripted model and tracked-file inventory. Its `github.com/example/demo` URL is illustrative. Running the offline example preserves the authentic live `sample_report.json`.

## Safety and limits

- Only `https://github.com/owner/repository` URLs are accepted. The clone is temporary and read-only with respect to the remote; target code, tests, and workflows are not run.
- File listing, reads, searches, tool calls, and model turns have limits. Oversized or binary files, symlinks, and unsafe paths are not read. An excessively large repository or repeated model failure returns an error rather than an invented result.
- Tool output and report text redact common key formats and obvious secret assignments. Redaction cannot recognize every possible credential format; avoid sharing reports containing sensitive repository data without reviewing them.
- The agent cannot verify hosted settings such as branch protection from repository files. A model may still miss a defect or misjudge a practice; review findings before acting on them.

## Evidence validation and review

For file-specific findings, evidence must quote exact numbered source lines returned by `read_file` and include the cited line. Python rejects invented snippets, comment-only configuration evidence, and empty resource-block evidence, then asks the model to investigate further. Nonempty drafts receive a separate model review of source evidence, context, defaults, severity, and recommendations. Reviewed output is validated again. These checks establish source provenance; they cannot prove that every interpretation is correct.

GitHub Actions runs the offline suite and example generator on Python 3.10 and 3.12 for pushes and pull requests, with read-only permissions and no API credentials. Regression tests cover fabricated/comment-only evidence, draft review, duplicate calls, temporary rate-limit recovery, bounded retries, and CLI failures preserving existing reports.

## Live validation before use

Offline tests use scripted model replies. They verify control flow, safety boundaries, and validation; they do not measure live detection precision or recall. After loading the ignored `.env`, run one audit at a time:

```bash
python -m unittest discover -s tests -v
python agent.py --repo https://github.com/pypa/sampleproject --output reports/healthy-check.json --trace reports/healthy-check-trace.jsonl
python agent.py --repo https://github.com/bridgecrewio/terragoat --output reports/infrastructure-check.json --trace reports/infrastructure-check-trace.jsonl
python -m json.tool reports/healthy-check.json
python -m json.tool reports/infrastructure-check.json
tail -n 1 reports/healthy-check-trace.jsonl
tail -n 1 reports/infrastructure-check-trace.jsonl
```

`pypa/sampleproject` is a packaging-oriented comparison: unbounded reusable-library metadata or publishing from main alone should not trigger findings. `bridgecrewio/terragoat` contains intentionally insecure infrastructure examples; findings must cite actual settings rather than educational comments. These are public examples, not fixed evaluation answer keys, and their contents can change.

For each finding, inspect the cited source and complete surrounding block. Confirm effective behavior, defaults/overrides, severity, and remediation. Check duplicates and false positives, then compare with expected defects to assess missed findings. A nonempty report alone does not establish accuracy.

A successful trace ends in `audit_completed`. Review `tool_budget_exhausted`, `files_read`, and `failed_tool_calls` to understand coverage. Failed runs leave older reports unchanged, so use new output names when comparing runs. Let temporary rate-limit waits resume the same process. Long daily-quota resets require available quota or another compatible provider.

The authentic checked-in live sample predates the latest evidence/retry improvements. The revised implementation has offline regression coverage; a fresh live run is necessary to validate the selected provider. Perfect detection on unseen repositories is not guaranteed.
