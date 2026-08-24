from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from scan_repo import _scan_history_secrets, main  # noqa: E402


@unittest.skipUnless(shutil.which("git"), "Git is required for history integration tests")
class HistoryScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.git("init", "-q")
        self.git("config", "user.email", "shipproof@example.test")
        self.git("config", "user.name", "ShipProof Test")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str) -> None:
        completed = subprocess.run(  # noqa: S603 - fixed Git test harness
            ["git", "-C", str(self.root), *arguments],  # noqa: S607 - fixed test executable
            capture_output=True,
            text=True,
            shell=False,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def commit(self, message: str = "fixture") -> None:
        self.git("add", ".")
        self.git("commit", "-q", "-m", message)

    @staticmethod
    def synthetic_github_token() -> str:
        return "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

    def test_history_preserves_commit_file_and_line_provenance(self) -> None:
        (self.root / "secret.py").write_text(
            f'token = "{self.synthetic_github_token()}"\n', encoding="utf-8"
        )
        (self.root / "last.py").write_text("value = 1\n", encoding="utf-8")
        self.commit()

        findings, commits = _scan_history_secrets(self.root)
        token_findings = [finding for finding in findings if finding.rule_id == "SP006"]
        self.assertEqual(commits, 1)
        self.assertEqual(len(token_findings), 1)
        self.assertEqual(token_findings[0].path, "secret.py")
        self.assertEqual(token_findings[0].line, 1)
        self.assertRegex(token_findings[0].history_commit or "", r"^[0-9a-f]{40}$")

    def test_gitignore_env_pattern_is_not_a_tracked_env_finding(self) -> None:
        (self.root / ".gitignore").write_text(".env\n", encoding="utf-8")
        self.commit()
        findings, _ = _scan_history_secrets(self.root)
        self.assertNotIn("SP220", {finding.rule_id for finding in findings})

    def test_actual_env_path_is_reported(self) -> None:
        (self.root / ".env").write_text("SAFE_PLACEHOLDER=value\n", encoding="utf-8")
        self.commit()
        findings, _ = _scan_history_secrets(self.root)
        env_findings = [finding for finding in findings if finding.rule_id == "SP220"]
        self.assertEqual(len(env_findings), 1)
        self.assertEqual(env_findings[0].path, ".env")

    def test_suffix_specific_secret_rule_does_not_escape_scope(self) -> None:
        value = "".join(("A1b2", "C3d4", "E5f6", "G7h8", "I9j0"))
        (self.root / "app.py").write_text(f'password = "{value}"\n', encoding="utf-8")
        self.commit()
        findings, _ = _scan_history_secrets(self.root)
        self.assertNotIn("SP067", {finding.rule_id for finding in findings})

    def test_history_findings_participate_in_baseline_suppression(self) -> None:
        (self.root / "secret.py").write_text(
            f'token = "{self.synthetic_github_token()}"\n', encoding="utf-8"
        )
        self.commit()
        findings, _ = _scan_history_secrets(self.root)
        token_finding = next(finding for finding in findings if finding.rule_id == "SP006")
        baseline = self.root / "baseline.json"
        baseline.write_text(
            json.dumps({"version": 1, "fingerprints": [token_finding.fingerprint]}),
            encoding="utf-8",
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(
                [
                    str(self.root),
                    "--history",
                    "--baseline",
                    str(baseline),
                    "--format",
                    "json",
                    "--fail-on",
                    "none",
                ]
            )
        report = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertNotIn("SP006", {item["rule_id"] for item in report["findings"]})
        self.assertGreaterEqual(report["summary"]["suppressed"], 1)


class HistoryFailureTests(unittest.TestCase):
    def test_non_repository_fails_closed(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(ValueError, "requires a Git worktree"),
        ):
            _scan_history_secrets(Path(directory))

    def test_missing_git_fails_closed(self) -> None:
        with (
            patch("scan_repo.shutil.which", return_value=None),
            self.assertRaisesRegex(ValueError, "git was not found"),
        ):
            _scan_history_secrets(ROOT)


if __name__ == "__main__":
    unittest.main()
