from __future__ import annotations

import json
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

MANIFEST = ROOT / "tests" / "rule_cases_promoted.json"


def detected_rule_ids(path_value: str, source: str) -> set[str]:
    path = Path(path_value)
    findings = find_regex_issues(path, path.as_posix(), source)
    if path.suffix.lower() == ".py":
        findings.extend(find_python_ast_issues(path.as_posix(), source))
    active, _ = deduplicate_and_suppress_findings(findings)
    return {finding.rule_id for finding in active}


class PromotedRuleQualityTests(unittest.TestCase):
    """Enforce the promotion evidence contract for SP051-SP080.

    Mirrors tests/rule_cases_v2.json discipline: executed positive/negative
    fixtures, adversarial look-alikes with expected outcomes and rationale,
    documented false-positive boundaries, primary sources, and complete
    explanation metadata.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        cls.cases = {entry["rule_id"]: entry for entry in cls.manifest["rules"]}
        cls.promoted = {
            rule.rule_id: rule for rule in RULES if 51 <= int(rule.rule_id.removeprefix("SP")) <= 80
        }

    def test_manifest_covers_exactly_the_promoted_range(self) -> None:
        self.assertEqual(self.manifest["quality_contract_version"], 1)
        self.assertEqual(set(self.cases), set(self.promoted))

    def test_metadata_matches_scanner(self) -> None:
        for rule_id, entry in self.cases.items():
            with self.subTest(rule_id=rule_id):
                rule = self.promoted[rule_id]
                self.assertEqual(entry["expected_severity"], rule.severity)
                self.assertEqual(entry["expected_confidence"], rule.confidence)
                self.assertEqual(entry["cwe"], rule.cwe)

    def test_explanations_are_complete(self) -> None:
        for rule_id in self.cases:
            explanation = RULE_EXPLANATIONS[rule_id]
            with self.subTest(rule_id=rule_id):
                self.assertTrue(
                    all(explanation.get(key) for key in ("why", "attack", "false_positive", "test"))
                )

    def test_false_positive_boundary_is_documented(self) -> None:
        for rule_id, entry in self.cases.items():
            with self.subTest(rule_id=rule_id):
                self.assertGreaterEqual(len(entry["false_positive_analysis"]), 120)

    def test_sources_are_primary_and_explained(self) -> None:
        for rule_id, entry in self.cases.items():
            with self.subTest(rule_id=rule_id):
                hosts = set()
                for source in entry["sources"]:
                    parsed = urlparse(source["url"])
                    self.assertEqual(parsed.scheme, "https")
                    self.assertTrue(parsed.netloc)
                    self.assertGreaterEqual(len(source["claim"]), 40)
                    hosts.add(parsed.netloc)
                self.assertGreaterEqual(len(hosts), 2)

    def test_positive_fixtures_fire(self) -> None:
        for rule_id, entry in self.cases.items():
            for case in entry["cases"]["positive"]:
                with self.subTest(rule_id=rule_id, polarity="positive"):
                    self.assertIn(
                        rule_id,
                        detected_rule_ids(case["path"], case["source"]),
                        case["source"],
                    )

    def test_negative_fixtures_stay_silent(self) -> None:
        for rule_id, entry in self.cases.items():
            for case in entry["cases"]["negative"]:
                with self.subTest(rule_id=rule_id, polarity="negative"):
                    self.assertNotIn(
                        rule_id,
                        detected_rule_ids(case["path"], case["source"]),
                        case["source"],
                    )

    def test_adversarial_cases_match_expected_outcomes(self) -> None:
        for rule_id, entry in self.cases.items():
            for case in entry["cases"]["adversarial"]:
                with self.subTest(rule_id=rule_id):
                    self.assertGreaterEqual(len(case["rationale"]), 40)
                    detected = rule_id in detected_rule_ids(case["path"], case["source"])
                    self.assertEqual(
                        detected,
                        case["expected"],
                        f"{case['source']} expected={case['expected']}",
                    )


if __name__ == "__main__":
    unittest.main()
