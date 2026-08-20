from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from scan_repo import (  # noqa: E402
    RULE_EXPLANATIONS,
    RULES,
    deduplicate_and_suppress_findings,
    find_python_ast_issues,
    find_regex_issues,
)


class RuleQualityContractV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads((ROOT / "tests" / "rule_cases_v2.json").read_text("utf-8"))
        cls.cases = {entry["rule_id"]: entry for entry in cls.manifest["rules"]}
        cls.rules = {
            rule.rule_id: rule for rule in RULES if int(rule.rule_id.removeprefix("SP")) >= 651
        }

    @staticmethod
    def detected_rule_ids(path_value: str, source: str) -> set[str]:
        path = Path(path_value)
        findings = find_regex_issues(path, path.as_posix(), source)
        if path.suffix.lower() == ".py":
            findings.extend(find_python_ast_issues(path.as_posix(), source))
        active, _ = deduplicate_and_suppress_findings(findings)
        return {finding.rule_id for finding in active}

    def test_every_v2_rule_has_complete_quality_evidence(self) -> None:
        self.assertEqual(self.manifest["quality_contract_version"], 2)
        self.assertEqual(set(self.cases), set(self.rules))
        for rule_id, rule in self.rules.items():
            with self.subTest(rule_id=rule_id):
                entry = self.cases[rule_id]
                self.assertEqual(entry["expected_severity"], rule.severity)
                self.assertEqual(entry["expected_confidence"], rule.confidence)
                self.assertIs(entry["blocking_eligible"], False)
                self.assertGreaterEqual(len(entry["positive"]), 3)
                self.assertGreaterEqual(len(entry["negative"]), 5)
                self.assertGreaterEqual(len(entry["adversarial"]), 2)
                self.assertGreaterEqual(len(entry["false_positive_analysis"]), 120)

                explanation = RULE_EXPLANATIONS[rule_id]
                self.assertTrue(
                    all(explanation.get(key) for key in ("why", "attack", "false_positive", "test"))
                )

                self.assertGreaterEqual(len(entry["sources"]), 2)
                source_hosts = set()
                for source in entry["sources"]:
                    parsed = urlparse(source["url"])
                    self.assertEqual(parsed.scheme, "https")
                    self.assertTrue(parsed.netloc)
                    self.assertGreaterEqual(len(source["claim"]), 40)
                    source_hosts.add(parsed.netloc)
                self.assertGreaterEqual(len(source_hosts), 2)

    def test_positive_negative_and_adversarial_contracts(self) -> None:
        for rule_id, entry in self.cases.items():
            for case in entry["positive"]:
                with self.subTest(rule_id=rule_id, polarity="positive", path=case["path"]):
                    self.assertIn(
                        rule_id,
                        self.detected_rule_ids(case["path"], case["source"]),
                    )
            for case in entry["negative"]:
                with self.subTest(rule_id=rule_id, polarity="negative", path=case["path"]):
                    self.assertNotIn(
                        rule_id,
                        self.detected_rule_ids(case["path"], case["source"]),
                    )
            for case in entry["adversarial"]:
                with self.subTest(rule_id=rule_id, polarity="adversarial", path=case["path"]):
                    self.assertGreaterEqual(len(case["rationale"]), 40)
                    detected = rule_id in self.detected_rule_ids(case["path"], case["source"])
                    self.assertEqual(detected, case["expected"])

    def test_expansion_plan_reserves_exactly_one_thousand_contiguous_ids(self) -> None:
        plan = (ROOT / "docs" / "rule-expansion-1000.md").read_text("utf-8")
        allocation = plan.split("## Primary research registry", 1)[0]
        ranges = [
            (int(start), int(end), int(count))
            for start, end, count in re.findall(
                r"\| `SP(\d+)\N{EN DASH}SP(\d+)` \| (\d+) \|", allocation
            )
        ]
        self.assertEqual(len(ranges), 10)
        self.assertEqual(ranges[0][0], 651)
        self.assertEqual(ranges[-1][1], 1650)
        self.assertEqual(sum(count for _start, _end, count in ranges), 1_000)
        for index, (start, end, count) in enumerate(ranges):
            self.assertEqual(end - start + 1, count)
            if index:
                self.assertEqual(start, ranges[index - 1][1] + 1)


if __name__ == "__main__":
    unittest.main()
