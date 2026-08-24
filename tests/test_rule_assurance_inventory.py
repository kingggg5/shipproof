from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from rule_assurance_report import (  # noqa: E402
    BASELINE_PATH,
    build_report,
    is_placeholder_case,
    render_markdown,
)


class RuleAssuranceInventoryTests(unittest.TestCase):
    def test_inventory_covers_every_executable_rule_and_metadata(self) -> None:
        report = build_report()
        summary = report["summary"]
        self.assertEqual(summary["executable_rules"], len(report["rules"]))
        self.assertEqual(
            summary["executable_rules"],
            summary["complete"] + summary["partial"] + summary["uncontracted"],
        )
        self.assertEqual(summary["metadata_debt"], 0)
        self.assertEqual(len({item["rule_id"] for item in report["rules"]}), len(report["rules"]))

    def test_runtime_secret_contracts_count_but_placeholder_lookalikes_do_not(self) -> None:
        report = build_report()
        private_key = next(item for item in report["rules"] if item["rule_id"] == "SP001")
        self.assertEqual(
            private_key["declared_counts"],
            {
                "positive": 2,
                "negative": 2,
                "adversarial": 1,
            },
        )
        self.assertEqual(
            private_key["counts"],
            {
                "positive": 2,
                "negative": 2,
                "adversarial": 1,
            },
        )
        self.assertEqual(private_key["missing_contract"], [])
        self.assertTrue(is_placeholder_case({"source": "SAFE_NEGATIVE_SP001"}, "negative"))
        self.assertTrue(is_placeholder_case({"source": "SAFE_ADVERSARIAL_SP001"}, "adversarial"))
        self.assertTrue(is_placeholder_case({"source_hex": ""}, "negative"))
        self.assertTrue(is_placeholder_case({"source_hex": "20200a"}, "adversarial"))
        self.assertTrue(is_placeholder_case({"source_parts": ["", "  "]}, "negative"))
        self.assertFalse(is_placeholder_case({"source_hex": "7072696e74283129"}, "positive"))
        self.assertFalse(
            is_placeholder_case({"path": "fixture.sqlite", "content_hex": ""}, "positive")
        )

    def test_transitional_baseline_is_exact_and_new_rules_cannot_add_silent_debt(self) -> None:
        report = build_report()
        self.assertTrue(BASELINE_PATH.is_file())
        self.assertTrue(report["gate"]["passed"], json.dumps(report["gate"], indent=2))
        baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        self.assertEqual(len(baseline["partial_contract_ids"]), report["summary"]["partial"])
        self.assertEqual(
            len(baseline["uncontracted_ids"]),
            report["summary"]["uncontracted"],
        )

    def test_report_is_deterministic_and_the_published_summary_is_derived(self) -> None:
        first = build_report()
        second = build_report()
        self.assertEqual(first, second)
        published = (ROOT / "docs" / "rule-assurance.md").read_text(encoding="utf-8")
        self.assertEqual(published, render_markdown(first))

    def test_json_check_command_is_machine_readable(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/rule_assurance_report.py", "--format", "json", "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertTrue(report["gate"]["passed"])


if __name__ == "__main__":
    unittest.main()
