import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import InspectionError, RepositoryTools, normalize_github_url


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.root = Path(self.temporary.name)
        (self.root / "README.md").write_text("hello world\nTODO: add CI\n", encoding="utf-8")
        (self.root / "secret.txt").write_text("password=do-not-echo\n", encoding="utf-8")
        self.tools = RepositoryTools("https://github.com/example/project")
        self.tools.root = self.root
        self.tracked = patch.object(self.tools, "_files", return_value=["README.md", "secret.txt"])
        self.tracked.start()

    def tearDown(self):
        self.tracked.stop()
        self.temporary.cleanup()

    def test_rejects_unsafe_urls(self):
        for url in (
            "http://github.com/example/project", "https://github.com.evil.test/example/project",
            "https://user:token@github.com/example/project", "https://github.com/example/project/tree/main",
            "https://github.com/example/..", "https://github.com/example/project?x=1",
        ):
            with self.subTest(url=url), self.assertRaises(InspectionError):
                normalize_github_url(url)

    def test_normalizes_url(self):
        self.assertEqual(normalize_github_url("https://github.com/example/project.git/"),
                         "https://github.com/example/project")

    def test_tools_return_bounded_observations(self):
        self.assertEqual(self.tools.list_files()["count"], 2)
        page = self.tools.list_files(offset=0, limit=1)
        self.assertEqual(len(page["files"]), 1)
        self.assertEqual(page["next_offset"], 1)
        self.assertEqual(self.tools.list_files(offset=1, limit=1)["next_offset"], None)
        self.assertIn("2: TODO: add CI", self.tools.read_file("README.md")["content"])
        self.assertEqual(self.tools.search_code("password"), {
            "matches": [{"file": "secret.txt", "line": 1}], "truncated": False,
        })
        self.assertIn("password=[REDACTED]", self.tools.read_file("secret.txt")["content"])

    def test_line_ranges_and_private_key_redaction(self):
        (self.root / "config.txt").write_text(
            "heading\n-----BEGIN PRIVATE KEY-----\nbase64-secret-material\n"
            "-----END PRIVATE KEY-----\ntrailer\n", encoding="utf-8")
        with patch.object(self.tools, "_files", return_value=["config.txt"]):
            result = self.tools.read_file("config.txt", start_line=2, end_line=5)
        self.assertEqual((result["start_line"], result["end_line"], result["total_lines"]),
                         (2, 5, 5))
        self.assertNotIn("base64-secret-material", result["content"])
        self.assertIn("5: trailer", result["content"])
        with self.assertRaises(InspectionError):
            self.tools.read_file("README.md", start_line=10, end_line=2)

    def test_rejects_paths_outside_tracked_files(self):
        for path in ("../outside", ".git/config", "missing"):
            with self.subTest(path=path), self.assertRaises(InspectionError):
                self.tools.read_file(path)
        with self.assertRaises(InspectionError):
            self.tools.list_files(limit=301)

    def test_rejects_symlink(self):
        try:
            (self.root / "link").symlink_to(self.root / "README.md")
        except OSError:
            self.skipTest("This filesystem does not permit symlinks")
        with patch.object(self.tools, "_files", return_value=["link"]):
            with self.assertRaises(InspectionError):
                self.tools.read_file("link")


if __name__ == "__main__":
    unittest.main()
