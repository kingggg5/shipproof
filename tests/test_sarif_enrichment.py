from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from scan_repo import build_sarif_report, find_rule  # noqa: E402

SCANNER = SCRIPTS / "scan_repo.py"


def make_finding(rule_id: str):
    from scan_repo import make_finding

    rule = find_rule(rule_id)
    return make_finding(rule, "src/app.py", 1, "evidence")


class SecuritySeverityTests(unittest.TestCase):
    def test_severity_maps_to_github_ranking_property(self) -> None:
        report = build_sarif_report([make_finding("SP001"), make_finding("SP305")])
        rules = {rule["id"]: rule for rule in report["runs"][0]["tool"]["driver"]["rules"]}
        critical = next(r for r in rules.values() if r["id"] == "SP001")
        medium = rules["SP305"]
        self.assertEqual(critical["properties"]["security-severity"], "9.5")
        self.assertEqual(medium["properties"]["security-severity"], "5.5")

    def test_unknown_severity_falls_back_to_neutral_score(self) -> None:
        from dataclasses import replace

        base = make_finding("SP001")
        odd = replace(base, severity="info")
        report = build_sarif_report([odd])
        rule = report["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["properties"]["security-severity"], "5.0")


class StrideTagTests(unittest.TestCase):
    def test_known_cwe_gets_dominant_stride_leg_first(self) -> None:
        # SP103 -> CWE-89 (SQL injection) -> tampering dominant
        report = build_sarif_report([make_finding("SP103")])
        tags = report["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
        self.assertIn("stride:T", tags)
        self.assertLess(tags.index("stride:T"), tags.index("stride:I"))

    def test_missing_cwe_still_carries_default_legs(self) -> None:
        from dataclasses import replace

        base = make_finding("SP001")
        bare = replace(base, cwe="")
        report = build_sarif_report([bare])
        tags = report["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
        self.assertTrue(any(tag.startswith("stride:") for tag in tags))


class RunContextTests(unittest.TestCase):
    def test_automation_details_present(self) -> None:
        from scan_repo import VERSION

        report = build_sarif_report([])
        self.assertEqual(report["runs"][0]["automationDetails"]["id"], f"shipproof/{VERSION}")

    def test_git_repository_binds_provenance(self) -> None:
        import os
        import shutil

        git_exe = shutil.which("git")
        if git_exe is None:
            self.skipTest("git not available")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run([git_exe, "init", "-q"], cwd=root, check=True)  # noqa: S603
            env = {
                **os.environ,
                "GIT_AUTHOR_NAME": "t",
                "GIT_AUTHOR_EMAIL": "t@example.com",
                "GIT_COMMITTER_NAME": "t",
                "GIT_COMMITTER_EMAIL": "t@example.com",
            }
            subprocess.run(  # noqa: S603
                [git_exe, "-C", str(root), "commit", "--allow-empty", "-q", "-m", "init"],
                check=True,
                env=env,
            )
            report = build_sarif_report([], root=root)
            provenance = report["runs"][0].get("versionControlProvenance")
            self.assertIsNotNone(provenance)
            self.assertTrue(provenance[0]["revisionId"])
            self.assertTrue(provenance[0]["branch"])

    def test_non_git_directory_omits_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = build_sarif_report([], root=Path(tmp))
            self.assertNotIn("versionControlProvenance", report["runs"][0])


class CliSarifOutputTests(unittest.TestCase):
    def test_cli_emits_enriched_sarif(self) -> None:
        import os

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "app.py"
            target.write_text('import os\nos.system(f"rm -rf {path}")\n', encoding="utf-8")
            completed = subprocess.run(  # noqa: S603
                [sys.executable, str(SCANNER), tmp, "--format", "sarif"],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                shell=False,
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            )
            payload = json.loads(completed.stdout)
            run = payload["runs"][0]
            rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
            self.assertIn("SP054", rule_ids)
            sp054 = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "SP054")
            self.assertEqual(sp054["properties"]["security-severity"], "8.0")
            self.assertIn("stride:T", sp054["properties"]["tags"])


if __name__ == "__main__":
    unittest.main()
