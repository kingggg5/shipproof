from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).parents[1] / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from scan_repo import finalize_findings, python_ast_findings, regex_findings, sarif_report  # noqa: E402


class ScanRepoTests(unittest.TestCase):
    def findings(self, name: str, source: str):
        path = Path(name)
        candidates = regex_findings(path, name, source)
        if path.suffix == ".py":
            candidates.extend(python_ast_findings(name, source))
        return finalize_findings(candidates)[0]

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
        findings = self.findings("client.py", "import requests\nrequests.get(url)\nrequests.post(url, timeout=2)\n")
        timeout_lines = [item.line for item in findings if item.rule_id == "SP304"]
        self.assertEqual(timeout_lines, [2])

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
        source = "allow_" + "origins=[\"*\"]\nallow_" + "credentials=True\n"
        findings = self.findings("api.py", source)
        self.assertTrue(any(item.rule_id == "SP107" for item in findings))

    def test_baseline_suppresses_exact_fingerprint(self):
        source = "result = " + "ev" + "al(value)\n"
        findings = self.findings("app.py", source)
        active, suppressed = finalize_findings(findings, {findings[0].fingerprint})
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
        payload = sarif_report(findings)
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["runs"][0]["results"][0]["ruleId"], "SP101")
        json.dumps(payload)


if __name__ == "__main__":
    unittest.main()
