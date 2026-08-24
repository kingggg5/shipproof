from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT / "tests"))

from scan_repo import (  # noqa: E402
    RULE_EXPLANATIONS,
    RULES,
    deduplicate_and_suppress_findings,
    find_regex_issues,
)
from secret_positive_fixtures import positive_source  # noqa: E402

MANIFEST = ROOT / "tests" / "rule_cases_secrets.json"


def detected(path_value: str, source: str) -> set[str]:
    p = Path(path_value)
    findings = find_regex_issues(p, p.as_posix(), source)
    active, _ = deduplicate_and_suppress_findings(findings)
    return {f.rule_id for f in active}


class SecretRuleQualityTests(unittest.TestCase):
    """Evidence contract for SP001-SP050 secrets lane."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        cls.cases = {e["rule_id"]: e for e in cls.manifest["rules"]}
        cls.secrets = {
            r.rule_id: r for r in RULES if r.redact and 1 <= int(r.rule_id.removeprefix("SP")) <= 50
        }

    def test_manifest_covers_all_redacting_secret_rules(self) -> None:
        self.assertEqual(set(self.cases), set(self.secrets))

    def test_metadata_matches_scanner(self) -> None:
        for rid, entry in self.cases.items():
            rule = self.secrets[rid]
            with self.subTest(rid=rid):
                self.assertEqual(entry["expected_severity"], rule.severity)
                self.assertEqual(entry["expected_confidence"], rule.confidence)

    def test_explanations_complete(self) -> None:
        for rid in self.cases:
            with self.subTest(rid=rid):
                exp = RULE_EXPLANATIONS[rid]
                self.assertTrue(
                    all(exp.get(k) for k in ("why", "attack", "false_positive", "test"))
                )

    def test_sources_are_https_with_claims(self) -> None:
        for rid, entry in self.cases.items():
            with self.subTest(rid=rid):
                hosts = set()
                for s in entry["sources"]:
                    parsed = urlparse(s["url"])
                    self.assertEqual(parsed.scheme, "https")
                    self.assertGreaterEqual(len(s["claim"]), 40)
                    hosts.add(parsed.netloc)
                self.assertGreaterEqual(len(hosts), 2)

    def test_positive_fixtures_fire(self) -> None:
        """Every redacting secret rule has an executable synthetic positive."""
        for rid, entry in self.cases.items():
            for case in entry["cases"]["positive"]:
                source = case["source"]
                if source == "covered_by_suite":
                    source = positive_source(rid)
                path = "fixture.json" if rid == "SP005" else case["path"]
                hits = detected(path, source)
                self.assertIn(rid, hits, source[:80])

    def test_placeholder_entries_resolve_to_real_fixtures(self) -> None:
        """Legacy manifest references are only valid when a fixture is executable."""
        for rid, entry in self.cases.items():
            for case in entry["cases"]["positive"]:
                if case["source"] == "covered_by_suite":
                    self.assertTrue(positive_source(rid))

    def test_negative_fixtures_stay_silent(self) -> None:
        for rid, entry in self.cases.items():
            for case in entry["cases"]["negative"]:
                with self.subTest(rid=rid):
                    hits = detected(case["path"], case["source"])
                    self.assertNotIn(rid, hits, case["source"][:80])

    def test_adversarial_matches_expected(self) -> None:
        for rid, entry in self.cases.items():
            for case in entry["cases"].get("adversarial", []):
                with self.subTest(rid=rid):
                    self.assertGreaterEqual(len(case.get("rationale", "")), 40)
                    detected_bool = rid in detected(case["path"], case["source"])
                    self.assertEqual(detected_bool, case["expected"], case["source"][:80])


if __name__ == "__main__":
    unittest.main()
