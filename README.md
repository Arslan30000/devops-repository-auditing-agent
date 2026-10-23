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
python -m venv .venv
```

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

For GroqCloud, use the Groq key as `OPENAI_API_KEY`, set `OPENAI_BASE_URL=https://api.groq.com/openai/v1`, and set `OPENAI_MODEL=openai/gpt-oss-120b` or another available compatible model. In bash, these can be saved in a local, ignored `.env` file:

```dotenv
OPENAI_API_KEY="your-groq-api-key"
OPENAI_BASE_URL="https://api.groq.com/openai/v1"
OPENAI_MODEL="openai/gpt-oss-120b"
```

Load that file in each new bash terminal before running:

```bash
set -a
source .env
set +a
```

The agent requests tools during investigation and JSON mode in a separate final request, so providers do not need to support both in one request. Provider errors include a redacted reason and HTTP status when available. Free-plan token/request limits can prevent a larger audit from completing.

## Run an audit

```bash
python agent.py --repo https://github.com/owner/repository --output report.json
```

Replace `owner/repository` with the actual public repository. The output path may include a directory, for example `--output reports/audit.json`. The command runs without prompts. It writes a completed report atomically and exits with code 0; on a fatal clone, API, input, or report-validation error it prints a useful error to stderr and exits nonzero without replacing an existing report.

Open `report.json` with a text editor or parse it with Python:

```bash
python -m json.tool report.json
```

The top-level object contains `repository` and `violations`. Each violation includes `rule_id`, `category`, `severity`, `file`, `line`, `description`, `evidence`, and `recommendation`. Severity is `critical`, `high`, `medium`, or `low`. An empty `violations` array means no supported finding was reported; it is not a guarantee that the repository has no defects. `file` and `line` are JSON `null` when not applicable. See `sample_report.json` for the exact shape.

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

Regenerate the example report without an API key:

```bash
python examples/generate_sample.py
```

`sample_report.json` is output from the actual agent/report-validation code path over a small local fixture using a deterministic scripted model and tracked-file inventory. The example URL is illustrative; this offline demonstration is not a live audit of `github.com/example/demo`. A real audit requires the API key and public repository URL shown above.

## Safety and limits

- Only `https://github.com/owner/repository` URLs are accepted. The clone is temporary and read-only with respect to the remote; target code, tests, and workflows are not run.
- File listing, reads, searches, tool calls, and model turns have limits. Oversized or binary files, symlinks, and unsafe paths are not read. An excessively large repository or repeated model failure returns an error rather than an invented result.
- Tool output and report text redact common key formats and obvious secret assignments. Redaction cannot recognize every possible credential format; avoid sharing reports containing sensitive repository data without reviewing them.
- The agent cannot verify hosted settings such as branch protection from repository files. A model may still miss a defect or misjudge a practice; review findings before acting on them.
