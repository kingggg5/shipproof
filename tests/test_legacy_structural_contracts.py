from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
SCANNER_SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
CONTRACT_DIR = ROOT / "tests" / "rule-contracts"
sys.path.insert(0, str(SCANNER_SCRIPTS))

from scan_repo import (  # noqa: E402
    FILE_LEVEL_RULE_IDS,
    RULES,
    deduplicate_and_suppress_findings,
    find_python_ast_issues,
    find_regex_issues,
    scan_single_file,
)


def rule_number(rule_id: str) -> int:
    return int(rule_id.removeprefix("SP"))


def source_for(case: dict[str, Any]) -> str:
    return bytes.fromhex(case["source_hex"]).decode("utf-8")


def findings_for(entry: dict[str, Any], case: dict[str, Any]):
    if "content_hex" in case:
        content = bytes.fromhex(case["content_hex"])
        with tempfile.TemporaryDirectory() as directory:
            local_path = Path(directory) / Path(case["path"]).name
            local_path.write_bytes(content)
            return [
                finding
                for finding in scan_single_file(
                    local_path,
                    case["path"],
                    1_000_000,
                    frozenset(entry["frameworks"]),
                )
                if finding.rule_id == entry["rule_id"]
            ]
    path = Path(case["path"])
    source = source_for(case)
    findings = find_regex_issues(
        path,
        case["path"],
        source,
        detected_frameworks=frozenset(entry["frameworks"]),
    )
    if path.suffix.lower() == ".py":
        findings.extend(find_python_ast_issues(case["path"], source))
    active, _ = deduplicate_and_suppress_findings(findings)
    return [finding for finding in active if finding.rule_id == entry["rule_id"]]


class LegacyStructuralContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.index = json.loads((CONTRACT_DIR / "structural-index.json").read_text(encoding="utf-8"))
        cls.manifests = []
        cls.entries: dict[str, dict[str, Any]] = {}
        for row in cls.index["manifests"]:
            path = CONTRACT_DIR / row["path"]
            payload = json.loads(path.read_text(encoding="utf-8"))
            cls.manifests.append((row, payload))
            for entry in payload["rules"]:
                if entry["rule_id"] in cls.entries:
                    raise AssertionError(f"duplicate contract for {entry['rule_id']}")
                cls.entries[entry["rule_id"]] = entry
        cls.rules = {
            rule.rule_id: rule
            for rule in RULES
            if 101 <= rule_number(rule.rule_id) <= 650 and rule.rule_id in FILE_LEVEL_RULE_IDS
        }

    def test_index_hashes_counts_and_partitions_are_exact(self) -> None:
        self.assertEqual(self.index["schema_version"], 1)
        self.assertEqual(self.index["quality_contract_version"], 2)
        indexed_paths = set()
        total = 0
        for row, payload in self.manifests:
            with self.subTest(path=row["path"]):
                path = CONTRACT_DIR / row["path"]
                indexed_paths.add(row["path"])
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), row["sha256"])
                self.assertEqual(payload["schema_version"], 2)
                self.assertEqual(payload["quality_contract_version"], 2)
                self.assertEqual(payload["engine"], row["engine"])
                self.assertEqual(payload["ecosystem"], row["ecosystem"])
                self.assertEqual(len(payload["rules"]), row["rule_count"])
                total += row["rule_count"]
        disk_paths = {
            path.name
            for pattern in ("structural-*.v2.json", "artifact-*.v2.json")
            for path in CONTRACT_DIR.glob(pattern)
        }
        self.assertEqual(indexed_paths, disk_paths)
        self.assertEqual(total, len(self.entries))

    def test_contracts_cover_every_legacy_file_level_rule(self) -> None:
        self.assertEqual(set(self.entries), set(self.rules))

    def test_metadata_and_minimum_polarity_contract(self) -> None:
        for rule_id, entry in self.entries.items():
            rule = self.rules[rule_id]
            cases = entry["cases"]
            with self.subTest(rule_id=rule_id):
                self.assertEqual(entry["expected_severity"], rule.severity)
                self.assertEqual(entry["expected_confidence"], rule.confidence)
                self.assertEqual(entry["cwe"], rule.cwe)
                self.assertTrue(entry["false_positive_analysis"])
                expected_positives = 2 if rule.severity in {"critical", "high"} else 1
                self.assertGreaterEqual(len(cases["positive"]), expected_positives)
                self.assertGreaterEqual(len(cases["negative"]), 2)
                self.assertGreaterEqual(len(cases["adversarial"]), 1)

    def test_positive_cases_assert_exact_finding_contract(self) -> None:
        for rule_id, entry in self.entries.items():
            for case in entry["cases"]["positive"]:
                matches = findings_for(entry, case)
                with self.subTest(rule_id=rule_id, path=case["path"]):
                    self.assertEqual(len(matches), 1)
                    finding = matches[0]
                    self.assertEqual(finding.severity, entry["expected_severity"])
                    self.assertEqual(finding.confidence, case["expected_confidence"])
                    self.assertEqual(finding.path, case["path"])
                    self.assertEqual(finding.line, case["expected_line"])
                    self.assertEqual(finding.detection, case["expected_detection"])
                    self.assertEqual(finding.proof_level, case["expected_proof_level"])
                    self.assertEqual(finding.fingerprint, case["expected_fingerprint"])

    def test_negative_and_adversarial_cases_stay_silent(self) -> None:
        for rule_id, entry in self.entries.items():
            for polarity in ("negative", "adversarial"):
                for case in entry["cases"][polarity]:
                    with self.subTest(rule_id=rule_id, polarity=polarity):
                        if polarity == "adversarial":
                            self.assertIs(case["expected"], False)
                            self.assertGreaterEqual(len(case["rationale"]), 80)
                        self.assertEqual(findings_for(entry, case), [])

    def test_builder_is_deterministic_and_current(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/build_legacy_structural_contracts.py", "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
