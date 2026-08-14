from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
ENGINEERING_SCRIPTS = ROOT / "skills" / "engineer-production-systems" / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ENGINEERING_SCRIPTS))

from check_budget import evaluate_resource_budget  # noqa: E402
from scan_repo import build_json_report, scan_repository  # noqa: E402


class DemoFlowTests(unittest.TestCase):
    def test_before_and_after_match_the_checked_in_contract(self):
        demo_root = ROOT / "examples" / "demo-api"
        contract = json.loads((demo_root / "expected-findings.json").read_text(encoding="utf-8"))
        before, before_stats = scan_repository(demo_root / "fixtures" / "before")
        after, after_stats = scan_repository(demo_root / "fixtures" / "after")

        self.assertEqual(sorted(item.rule_id for item in before), sorted(contract["before"]))
        self.assertEqual([item.rule_id for item in after], contract["after"])
        self.assertEqual(build_json_report(demo_root, before, before_stats)["verdict"], "BLOCK")
        self.assertEqual(
            build_json_report(demo_root, after, after_stats)["verdict"],
            "PASS_WITH_EVIDENCE",
        )

    def test_fixture_repositories_match_their_security_contract(self):
        fixture_root = ROOT / "fixtures"
        contract = json.loads((fixture_root / "expected-findings.json").read_text(encoding="utf-8"))
        for repository_name, expected_rules in contract.items():
            with self.subTest(repository=repository_name):
                findings, _ = scan_repository(fixture_root / repository_name)
                self.assertEqual(
                    sorted(item.rule_id for item in findings),
                    sorted(expected_rules),
                )

    def test_performance_fixture_intentionally_blocks(self):
        fixture = ROOT / "fixtures" / "performance-regression"
        payloads = [
            json.loads((fixture / name).read_text(encoding="utf-8"))
            for name in ("baseline.json", "current.json", "budget.json")
        ]
        report = evaluate_resource_budget(*payloads)
        self.assertFalse(report["passed"])
        self.assertEqual(report["verdict"], "BLOCK")


if __name__ == "__main__":
    unittest.main()
