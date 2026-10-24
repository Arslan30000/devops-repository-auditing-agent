"""Safe, bounded, read-only inspection of a public GitHub repository."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


MAX_FILE_BYTES = 128_000
MAX_FILES = 3_000
MAX_LIST_PAGE = 300
MAX_MATCHES = 100
MAX_SEARCH_BYTES = 8_000_000
MAX_OUTPUT_CHARS = 6_000
MAX_READ_LINES = 300
DEFAULT_READ_LINES = 80
GIT_TIMEOUT = 90
_SEGMENT = re.compile(r"^[A-Za-z0-9_.-]+$")
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\b\s*[:=]\s*)"
    r"([^\s,;#]+)"
)
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_BLOCK = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.DOTALL)
_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{20,}|gsk_[A-Za-z0-9_-]{20,}|xai-[A-Za-z0-9_-]{20,})\b")


def _redact(text: str) -> str:
    def hide_block(match: re.Match[str]) -> str:
        return "[REDACTED PRIVATE KEY MATERIAL]" + "\n" * match.group().count("\n")

    text = _PEM_BLOCK.sub(hide_block, text)
    if _PRIVATE_KEY.search(text):
        text = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY MATERIAL]", text)
    return _TOKEN.sub("[REDACTED TOKEN]", _SENSITIVE_ASSIGNMENT.sub(r"\1[REDACTED]", text))


class InspectionError(Exception):
    """An inspection could not be completed reliably."""


def normalize_github_url(url: str) -> str:
    """Accept only a public GitHub repository URL, without URL credentials."""
    if not isinstance(url, str) or len(url) > 300:
        raise InspectionError("Expected a GitHub repository URL")
    parts = urlsplit(url)
    if (parts.scheme != "https" or parts.netloc.lower() != "github.com"
            or parts.query or parts.fragment or parts.username or parts.password):
        raise InspectionError("Use an HTTPS github.com/owner/repository URL")
    segments = parts.path.strip("/").split("/")
    if len(segments) != 2:
        raise InspectionError("URL must identify one GitHub repository")
    owner, repo = segments
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not all(_SEGMENT.fullmatch(item) and item not in {".", ".."}
               for item in (owner, repo)):
        raise InspectionError("Invalid GitHub owner or repository name")
    return f"https://github.com/{owner}/{repo}"


class RepositoryTools:
    """Clone into a temporary directory and expose only bounded observations."""

    def __init__(self, repository_url: str):
        self.repository_url = normalize_github_url(repository_url)
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self.root: Path | None = None

    def __enter__(self) -> RepositoryTools:
        self._temporary = tempfile.TemporaryDirectory(prefix="devops-audit-")
        self.root = Path(self._temporary.name) / "repository"
        try:
            # No hooks or checked-out code are executed. The target stays unchanged.
            git_options = ["-c", f"core.hooksPath={os.devnull}"]
            if os.name == "nt":
                # Git for Windows can use OpenSSL when Schannel revocation is unavailable.
                git_options.extend(["-c", "http.sslBackend=openssl"])
            subprocess.run(
                ["git", *git_options, "clone", "--quiet",
                 "--no-checkout", "--", self.repository_url + ".git", str(self.root)],
                check=True, capture_output=True, text=True, timeout=GIT_TIMEOUT,
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0",
                     "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
            )
            subprocess.run(
                ["git", "-C", str(self.root), *git_options,
                 "checkout", "--quiet", "--force"],
                check=True, capture_output=True, text=True, timeout=GIT_TIMEOUT,
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0",
                     "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
            self.__exit__(None, None, None)
            raise InspectionError("Could not clone the public repository (check URL, access, and timeout)") from exc
        return self

    def __exit__(self, *_args: object) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()
        self._temporary = None
        self.root = None

    def _root(self) -> Path:
        if self.root is None:
            raise InspectionError("Repository is not open")
        return self.root

    def _files(self) -> list[str]:
        root = self._root()
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True, check=True, timeout=15,
        )
        paths = [p.decode("utf-8", "replace") for p in result.stdout.split(b"\0") if p]
        if len(paths) > MAX_FILES:
            raise InspectionError(f"Repository exceeds {MAX_FILES} tracked files")
        return paths

    def list_files(self, offset: int = 0, limit: int = 100) -> dict:
        """Page through tracked file names and sizes without reading contents."""
        if (type(offset) is not int or offset < 0 or type(limit) is not int or
                not 1 <= limit <= MAX_LIST_PAGE):
            raise InspectionError("Invalid file-list page")
        root = self._root()
        tracked = self._files()
        files = []
        for name in tracked[offset:offset + limit]:
            path = root / name
            if path.is_file() and not path.is_symlink():
                size = path.stat().st_size
                entry = {"path": name, "bytes": size}
                if size > MAX_FILE_BYTES:
                    entry["readable_size"] = False
                files.append(entry)
        next_offset = offset + limit if offset + limit < len(tracked) else None
        return {"files": files, "count": len(tracked), "next_offset": next_offset}

    def read_file(self, path: str, start_line: int = 1, end_line: int | None = None) -> dict:
        """Read a bounded range of a tracked regular text file with numbered lines."""
        root = self._root()
        if (type(start_line) is not int or start_line < 1 or
                (end_line is not None and (type(end_line) is not int or end_line < start_line))):
            raise InspectionError("Invalid line range")
        if end_line is not None and end_line - start_line >= MAX_READ_LINES:
            raise InspectionError(f"Read at most {MAX_READ_LINES} lines at a time")
        if not isinstance(path, str) or path not in self._files():
            raise InspectionError("File is not tracked in this repository")
        candidate = root / path
        if candidate.is_symlink() or not candidate.is_file() or not candidate.resolve().is_relative_to(root.resolve()):
            raise InspectionError("File is not a safe regular file")
        if candidate.stat().st_size > MAX_FILE_BYTES:
            raise InspectionError(f"File exceeds {MAX_FILE_BYTES} bytes")
        data = candidate.read_bytes()
        if b"\0" in data:
            raise InspectionError("Binary files cannot be read as text")
        lines = _redact(data.decode("utf-8", "replace")).splitlines()
        last = min(len(lines), end_line or start_line + DEFAULT_READ_LINES - 1)
        output = []
        used = 0
        for index in range(start_line, last + 1):
            numbered = f"{index}: {lines[index - 1]}"
            if used + len(numbered) + 1 > MAX_OUTPUT_CHARS:
                break
            output.append(numbered)
            used += len(numbered) + 1
        if not output and start_line <= len(lines):
            raise InspectionError("A source line exceeds the output budget; inspect another file")
        actual_end = start_line + len(output) - 1
        return {"path": path, "content": "\n".join(output), "start_line": start_line,
                "end_line": actual_end, "total_lines": len(lines),
                "truncated": actual_end < len(lines)}

    def search_code(self, pattern: str) -> dict:
        """Search tracked text files for a literal, case-insensitive string."""
        if not isinstance(pattern, str) or not 1 <= len(pattern) <= 120:
            raise InspectionError("Search pattern must contain 1 to 120 characters")
        root = self._root()
        matches = []
        searched_bytes = 0
        for name in self._files():
            path = root / name
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
                continue
            if searched_bytes + path.stat().st_size > MAX_SEARCH_BYTES:
                return {"matches": matches, "truncated": True,
                        "note": "Search byte budget reached; inspect relevant files directly"}
            data = path.read_bytes()
            searched_bytes += len(data)
            if b"\0" in data:
                continue
            for line_number, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
                if pattern.casefold() in line.casefold():
                    # Do not return source lines: they might contain credentials.
                    matches.append({"file": name, "line": line_number})
                    if len(matches) == MAX_MATCHES:
                        return {"matches": matches, "truncated": True}
        return {"matches": matches, "truncated": False}

    def git_log(self) -> dict:
        """Return a bounded metadata-only commit history."""
        result = subprocess.run(
            ["git", "-C", str(self._root()), "log", "-n", "20",
             "--format=%h%x09%as%x09%s"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        commits = []
        for row in result.stdout.splitlines():
            fields = row.split("\t", 2)
            if len(fields) == 3:
                commits.append({"hash": fields[0], "date": fields[1],
                                "subject": _redact(fields[2][:200])})
        return {"commits": commits}


TOOL_DESCRIPTIONS = {
    "list_files": "Page through tracked repository paths and sizes. Optional offset/limit, at most 300 per page.",
    "read_file": "Read up to 300 numbered lines of a tracked text file. Arguments: path, optional start_line/end_line.",
    "search_code": "Find line locations containing a literal string. Arguments: pattern.",
    "git_log": "Inspect recent commit metadata. No arguments.",
}

