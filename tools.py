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
MAX_MATCHES = 100
MAX_OUTPUT_CHARS = 30_000
GIT_TIMEOUT = 90
_SEGMENT = re.compile(r"^[A-Za-z0-9_.-]+$")
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\b\s*[:=]\s*)"
    r"([^\s,;#]+)"
)
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def _redact(text: str) -> str:
    if _PRIVATE_KEY.search(text):
        return "[REDACTED PRIVATE KEY MATERIAL]"
    return _SENSITIVE_ASSIGNMENT.sub(r"\1[REDACTED]", text)


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
    """I clone into a temporary directory and expose only bounded observations."""

    def __init__(self, repository_url: str):
        self.repository_url = normalize_github_url(repository_url)
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self.root: Path | None = None

    def __enter__(self) -> RepositoryTools:
        self._temporary = tempfile.TemporaryDirectory(prefix="devops-audit-")
        self.root = Path(self._temporary.name) / "repository"
        try:
            # No hooks or checked-out code are executed. The target stays unchanged.
            subprocess.run(
                ["git", "-c", "core.hooksPath=/dev/null", "clone", "--quiet",
                 "--no-checkout", "--", self.repository_url + ".git", str(self.root)],
                check=True, capture_output=True, text=True, timeout=GIT_TIMEOUT,
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0",
                     "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull},
            )
            subprocess.run(
                ["git", "-C", str(self.root), "-c", "core.hooksPath=/dev/null",
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

    def list_files(self) -> dict:
        """List tracked files, with byte sizes, without reading their contents."""
        root = self._root()
        files = []
        for name in self._files():
            path = root / name
            if path.is_file() and not path.is_symlink():
                files.append({"path": name, "bytes": path.stat().st_size})
        return {"files": files, "count": len(files)}

    def read_file(self, path: str) -> dict:
        """Read a tracked regular text file with numbered lines."""
        root = self._root()
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
        text = data.decode("utf-8", "replace")
        numbered = "\n".join(f"{index}: {_redact(line)}" for index, line in enumerate(text.splitlines(), 1))
        return {"path": path, "content": numbered[:MAX_OUTPUT_CHARS],
                "truncated": len(numbered) > MAX_OUTPUT_CHARS}

    def search_code(self, pattern: str) -> dict:
        """Search tracked text files for a literal, case-insensitive string."""
        if not isinstance(pattern, str) or not 1 <= len(pattern) <= 120:
            raise InspectionError("Search pattern must contain 1 to 120 characters")
        root = self._root()
        matches = []
        for name in self._files():
            path = root / name
            if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
                continue
            data = path.read_bytes()
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
    "list_files": "Discover tracked repository paths and sizes. No arguments.",
    "read_file": "Read a tracked text file with line numbers. Arguments: path.",
    "search_code": "Find line locations containing a literal string. Arguments: pattern.",
    "git_log": "Inspect recent commit metadata. No arguments.",
}

