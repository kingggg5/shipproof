from __future__ import annotations

import json
import subprocess
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
from secret_positive_fixtures import contract_source, positive_source  # noqa: E402

MANIFEST = ROOT / "tests" / "rule_cases_secrets.json"


def findings_for(path_value: str, source: str):
    p = Path(path_value)
    findings = find_regex_issues(p, p.as_posix(), source)
    active, _ = deduplicate_and_suppress_findings(findings)
    return active


def detected(path_value: str, source: str) -> set[str]:
    return {finding.rule_id for finding in findings_for(path_value, source)}


def fixture_source(case: dict[str, object], rule_id: str) -> str:
    fixture = case.get("source_fixture")
    if isinstance(fixture, dict) and fixture.get("provider") == "secret-runtime":
        case_id = fixture.get("case")
        if not isinstance(case_id, str):
            raise AssertionError(f"invalid runtime fixture for {rule_id}")
        return contract_source(rule_id, case_id)
    source = case.get("source")
    if not isinstance(source, str):
        raise AssertionError(f"missing fixture source for {rule_id}")
    return positive_source(rule_id) if source == "covered_by_suite" else source


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
        self.assertEqual(self.manifest["schema_version"], 2)
        self.assertEqual(self.manifest["quality_contract_version"], 2)
        self.assertEqual(set(self.cases), set(self.secrets))

    def test_generated_manifest_is_current(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/build_secret_rule_contracts.py", "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

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
        """Every secret rule has two executable findings with exact v2 metadata."""
        for rid, entry in self.cases.items():
            for case in entry["cases"]["positive"]:
                source = fixture_source(case, rid)
                matches = [
                    finding
                    for finding in findings_for(case["path"], source)
                    if finding.rule_id == rid
                ]
                with self.subTest(rid=rid, path=case["path"]):
                    self.assertEqual(len(matches), 1, source[:80])
                    finding = matches[0]
                    self.assertEqual(finding.severity, entry["expected_severity"])
                    self.assertEqual(finding.path, case["path"])
                    self.assertEqual(finding.line, case["expected_line"])
                    self.assertEqual(finding.detection, case["expected_detection"])
                    self.assertEqual(finding.proof_level, case["expected_proof_level"])
                    self.assertEqual(finding.fingerprint, case["expected_fingerprint"])

    def test_runtime_fixture_references_are_closed_and_executable(self) -> None:
        for rid, entry in self.cases.items():
            for polarity in ("positive", "negative", "adversarial"):
                for case in entry["cases"][polarity]:
                    fixture = case.get("source_fixture")
                    self.assertEqual(fixture.get("provider"), "secret-runtime")
                    self.assertTrue(fixture_source(case, rid))

    def test_negative_fixtures_stay_silent(self) -> None:
        for rid, entry in self.cases.items():
            for case in entry["cases"]["negative"]:
                with self.subTest(rid=rid):
                    source = fixture_source(case, rid)
                    hits = detected(case["path"], source)
                    self.assertNotIn(rid, hits, source[:80])

    def test_adversarial_matches_expected(self) -> None:
        for rid, entry in self.cases.items():
            for case in entry["cases"].get("adversarial", []):
                with self.subTest(rid=rid):
                    self.assertGreaterEqual(len(case.get("rationale", "")), 40)
                    source = fixture_source(case, rid)
                    detected_bool = rid in detected(case["path"], source)
                    self.assertEqual(detected_bool, case["expected"], source[:80])


if __name__ == "__main__":
    unittest.main()
