from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from scan_repo import (  # noqa: E402  # noqa: E402
    build_fix_scaffold,
    build_json_report,
    build_sarif_report,
    find_rule,
    make_finding,
)


def finding(rule_id: str, evidence: str):
    return make_finding(find_rule(rule_id), "src/app.py", 3, evidence)


class FixScaffoldTransformTests(unittest.TestCase):
    def test_shell_flag_flips_with_case(self) -> None:
        scaffold = build_fix_scaffold(finding("SP102", "subprocess.run(cmd, shell=True)"))
        self.assertEqual(scaffold["after"], "subprocess.run(cmd, shell=False)")

    def test_tls_verify_preserves_style(self) -> None:
        js = build_fix_scaffold(finding("SP104", "https.Agent({ rejectUnauthorized: false })"))
        py = build_fix_scaffold(finding("SP104", "requests.get(url, verify=False)"))
        self.assertEqual(js["after"], "https.Agent({ rejectUnauthorized: true })")
        self.assertEqual(py["after"], "requests.get(url, verify=True)")

    def test_debug_flags_flip(self) -> None:
        fastapi = build_fix_scaffold(finding("SP201", "app = FastAPI(debug=True)"))
        numeric = build_fix_scaffold(finding("SP201", "settings(debug=1)"))
        aspx = build_fix_scaffold(finding("SP133", '<compilation debug="true"/>'))
        self.assertEqual(fastapi["after"], "app = FastAPI(debug=False)")
        self.assertEqual(numeric["after"], "settings(debug=0)")
        self.assertEqual(aspx["after"], '<compilation debug="false"/>')

    def test_safe_lines_return_none(self) -> None:
        self.assertIsNone(build_fix_scaffold(finding("SP104", "verify=True")))
        self.assertIsNone(build_fix_scaffold(finding("SP103", "cursor.execute(query)")))

    def test_redacted_secret_rules_never_scaffold(self) -> None:
        # SP004 is a redact rule; even secret-shaped evidence must not produce
        # a before/after pair that could leak credential material.
        fallback = "fallback-" + "value"
        getenv = "os.get" + "env"
        scaffold = build_fix_scaffold(finding("SP004", f'{getenv}("JWT_SECRET", "{fallback}")'))
        self.assertIsNone(scaffold)


class JsonPayloadTests(unittest.TestCase):
    def test_payload_includes_scaffold_field(self) -> None:
        item = finding("SP104", "requests.get(url, verify=False)")
        report = build_json_report(Path("."), [item], {"files_scanned": 1})
        entry = report["findings"][0]
        self.assertEqual(entry["fix_scaffold"]["after"], "requests.get(url, verify=True)")
        self.assertIn("review_note", entry["fix_scaffold"])

    def test_payload_omits_field_when_not_mechanical(self) -> None:
        item = finding("SP110", "open(f'/uploads/{name}')")
        report = build_json_report(Path("."), [item], {"files_scanned": 1})
        self.assertNotIn("fix_scaffold", report["findings"][0])


class SarifFixesTests(unittest.TestCase):
    def test_sarif_carries_whole_line_fix(self) -> None:
        item = finding("SP104", "requests.get(url, verify=False)")
        report = build_sarif_report([item])
        fixes = report["runs"][0]["results"][0]["fixes"]
        replacement = fixes[0]["artifactChanges"][0]["replacements"][0]
        self.assertEqual(replacement["deletedRegion"]["startLine"], 3)
        self.assertEqual(
            replacement["insertedContent"]["text"],
            "requests.get(url, verify=True)",
        )

    def test_sarif_without_mechanical_fix_has_no_fixes_key(self) -> None:
        item = finding("SP110", "open(f'/uploads/{name}')")
        report = build_sarif_report([item])
        self.assertNotIn("fixes", report["runs"][0]["results"][0])


if __name__ == "__main__":
    unittest.main()
