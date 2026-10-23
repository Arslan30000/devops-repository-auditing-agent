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

The agent requests tools during investigation. A valid model-written report is accepted after local validation. If formatting is needed, a separate JSON-mode request receives the observations as data in a fresh conversation without active tool messages or declarations. Providers do not need to support tools and JSON mode in one request. Provider errors include a redacted reason, HTTP status when available, and the investigation/reporting phase. Free-plan token/request limits can prevent a larger audit from completing.

For a smaller input budget on Groq's free plan, set these optional environment variables (or add them to the ignored `.env` and reload it):

```bash
export AUDIT_MAX_CONTEXT_CHARS=14000
export AUDIT_MAX_COMPLETION_TOKENS=2048
```

The default serialized request budget is 20,000 characters and the response limit is 2,048 tokens. The input budget counts the messages and tool definitions; it is a character bound, not an exact provider token count. Older complete tool exchanges may be omitted to fit the budget, while the latest tool exchange is kept during investigation. The model is told to re-read targeted evidence when needed. HTTP 413 responses trigger up to two retries with a smaller context. File reads default to 80 lines and at most 6,000 output characters; larger files remain available through explicit follow-up ranges. Smaller budgets can reduce inspection coverage, and these settings do not bypass per-minute or daily quotas. Higher-limit accounts can increase the budgets. A response cut off at its output limit fails explicitly rather than being saved as a completed report.

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

## How the agent works

1. `agent.py` validates the required key, opens a temporary clone through `RepositoryTools`, invokes the agent, and saves the validated JSON.
2. `agent_core.py` sends the repository goal and tool definitions to the model. The model selects tools; Python dispatches each call and returns its result to the model. The model can request follow-up calls based on prior observations.
3. `tools.py` provides `list_files` (paged tracked-file inventory), `read_file` (numbered text ranges), `search_code` (literal search returning locations), and `git_log` (recent commit metadata). The model interprets these observations and proposes findings.
4. Report validation requires file and line citations to have been observed through `read_file`, checks the schema and allowed values, rejects duplicates, and redacts recognized credential patterns. The agent must discover files and inspect content or history before completing a report.

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
