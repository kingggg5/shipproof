from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).parents[1] / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from scan_repo import (  # noqa: E402
    VERSION,
    build_sarif_report,
    deduplicate_and_suppress_findings,
    find_python_ast_issues,
    find_regex_issues,
    is_excluded,
    iter_scannable_files,
    normalize_exclude_patterns,
)


class ScanRepoTests(unittest.TestCase):
    def findings(self, name: str, source: str):
        path = Path(name)
        candidates = find_regex_issues(path, name, source)
        if path.suffix == ".py":
            candidates.extend(find_python_ast_issues(name, source))
        return deduplicate_and_suppress_findings(candidates)[0]

    def test_secret_is_redacted(self):
        secret = "AKIA" + "A" * 16
        findings = self.findings("settings.py", f'cloud_key = "{secret}"\n')
        aws = next(item for item in findings if item.rule_id == "SP002")
        self.assertEqual(aws.severity, "critical")
        self.assertNotIn(secret, aws.evidence)

    def test_placeholder_secret_is_ignored(self):
        findings = self.findings(".env", 'API_KEY="replace_me_with_your_key"\n')
        self.assertFalse(any(item.rule_id == "SP003" for item in findings))

    def test_request_timeout_is_ast_checked(self):
        findings = self.findings(
            "client.py", "import requests\nrequests.get(url)\nrequests.post(url, timeout=2)\n"
        )
        timeout_lines = [item.line for item in findings if item.rule_id == "SP304"]
        self.assertEqual(timeout_lines, [2])

    def test_multiline_interpolated_sql_is_ast_checked(self):
        findings = self.findings(
            "repository.py",
            'database.execute(\n    f"SELECT id FROM users WHERE email = {email}"\n)\n',
        )
        self.assertEqual([item.rule_id for item in findings], ["SP103"])

    def test_bound_sql_parameters_are_not_flagged(self):
        findings = self.findings(
            "repository.py",
            'database.execute("SELECT id FROM users WHERE email = ?", (email,))\n',
        )
        self.assertFalse(any(item.rule_id == "SP103" for item in findings))

    def test_sensitive_fastapi_route_requires_visible_authorization(self):
        findings = self.findings(
            "app.py",
            """from fastapi import Depends, FastAPI
app = FastAPI()
def require_admin(): ...
@app.get('/admin/users')
def unsafe(): ...
@app.get('/admin/audit', dependencies=[Depends(require_admin)])
def safe(): ...
""",
        )
        auth_lines = [item.line for item in findings if item.rule_id == "SP108"]
        self.assertEqual(auth_lines, [4])

    def test_route_page_size_requires_request_boundary_maximum(self):
        findings = self.findings(
            "app.py",
            """from fastapi import FastAPI, Query
app = FastAPI()
@app.get('/items')
def unsafe(limit: int = 50): ...
@app.get('/bounded')
def safe(page_size: int = Query(50, ge=1, le=100)): ...
""",
        )
        pagination_lines = [item.line for item in findings if item.rule_id == "SP305"]
        self.assertEqual(pagination_lines, [4])

    def test_blocking_sleep_only_flags_async_context(self):
        source = "import time\ndef sync():\n    time.sleep(1)\nasync def async_job():\n    time.sleep(1)\n"
        findings = self.findings("jobs.py", source)
        sleep_lines = [item.line for item in findings if item.rule_id == "SP303"]
        self.assertEqual(sleep_lines, [5])

    def test_nested_sync_function_is_not_treated_as_async(self):
        source = "import time\nasync def outer():\n    def sync():\n        time.sleep(1)\n"
        findings = self.findings("jobs.py", source)
        self.assertFalse(any(item.rule_id == "SP303" for item in findings))

    def test_combined_cors_risk(self):
        source = "allow_" + 'origins=["*"]\nallow_' + "credentials=True\n"
        findings = self.findings("api.py", source)
        self.assertTrue(any(item.rule_id == "SP107" for item in findings))

    def test_baseline_suppresses_exact_fingerprint(self):
        source = "result = " + "ev" + "al(value)\n"
        findings = self.findings("app.py", source)
        active, suppressed = deduplicate_and_suppress_findings(findings, {findings[0].fingerprint})
        self.assertEqual(active, [])
        self.assertEqual(suppressed, 1)

    def test_fingerprint_survives_line_movement(self):
        source = "result = " + "ev" + "al(value)\n"
        first = self.findings("app.py", source)[0]
        moved = self.findings("app.py", "\n\n" + source)[0]
        self.assertEqual(first.fingerprint, moved.fingerprint)

    def test_sarif_uses_supported_version(self):
        source = "result = " + "ev" + "al(value)\n"
        findings = self.findings("app.py", source)
        payload = build_sarif_report(findings)
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["runs"][0]["results"][0]["ruleId"], "SP101")
        self.assertEqual(payload["runs"][0]["tool"]["driver"]["version"], VERSION)
        json.dumps(payload)

    def test_identical_text_multiple_lines_reported(self):
        source = (
            "def a():\n    result = ev" + "al(value)\n\n\ndef b():\n    result = ev" + "al(value)\n"
        )
        findings = self.findings("app.py", source)
        eval_lines = [item.line for item in findings if item.rule_id == "SP101"]
        self.assertEqual(eval_lines, [2, 6])

    def test_baseline_suppresses_multiple_identical_findings(self):
        source = (
            "def a():\n    result = ev" + "al(value)\n\n\ndef b():\n    result = ev" + "al(value)\n"
        )
        candidates = find_regex_issues(Path("app.py"), "app.py", source)
        fp = candidates[0].fingerprint
        active, suppressed = deduplicate_and_suppress_findings(candidates, {fp})
        self.assertEqual(active, [])
        self.assertEqual(suppressed, 2)

    def test_pure_comments_are_ignored_for_code_rules(self):
        source = "# never call ev" + "al(value) here\nresult = ev" + "al(value)\n"
        findings = self.findings("app.py", source)
        eval_lines = [item.line for item in findings if item.rule_id == "SP101"]
        self.assertEqual(eval_lines, [2])

    def test_javascript_regexp_exec_is_not_dynamic_code_execution(self):
        findings = self.findings("cli.mjs", "const match = /Python (\\d+)/.exec(version);\n")
        self.assertFalse(any(item.rule_id == "SP101" for item in findings))

    def test_secrets_in_comments_are_still_flagged(self):
        secret = "AKIA" + "B" * 16
        source = f'# old_key = "{secret}"\n'
        findings = self.findings("app.py", source)
        self.assertTrue(any(item.rule_id == "SP002" for item in findings))

    def test_documentation_is_scanned_only_for_secrets(self):
        secret = "AKIA" + "C" * 16
        findings = self.findings("notes.md", f"Never call eval here. Leaked key: {secret}\n")
        self.assertEqual([item.rule_id for item in findings], ["SP002"])

    def test_ignored_directories_are_pruned_before_traversal(self):
        subdirectories = ["node_modules", "src", "bin", ".git"]
        with patch("scan_repo.os.walk", return_value=[("/repo", subdirectories, [])]):
            self.assertEqual(list(iter_scannable_files(Path("/repo"), 1_000)), [])
        self.assertEqual(subdirectories, ["bin", "src"])

    def test_exclude_patterns_prune_a_directory_tree(self):
        patterns = normalize_exclude_patterns(["generated/**", "reports/*.json"])
        self.assertTrue(is_excluded("generated", patterns))
        self.assertTrue(is_excluded("generated/api/client.py", patterns))
        self.assertTrue(is_excluded("reports/scan.json", patterns))
        self.assertFalse(is_excluded("src/api.py", patterns))

    def test_exclude_patterns_reject_parent_traversal(self):
        with self.assertRaisesRegex(ValueError, "unsafe exclude pattern"):
            normalize_exclude_patterns(["../secrets/**"])


if __name__ == "__main__":
    unittest.main()
