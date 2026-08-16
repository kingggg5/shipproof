from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from scan_repo import build_sarif_report, scan_repository  # noqa: E402

GOLDEN_FIXTURE = ROOT / "fixtures" / "golden-contract"
GOLDEN_EXPECTATION = ROOT / "fixtures" / "expected-golden-scan.json"
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


class GoldenContractTests(unittest.TestCase):
    """Compatibility contract: the scanner output for the golden fixture is stable."""

    def golden_fields(self, finding):
        return {
            "rule_id": finding.rule_id,
            "path": finding.path,
            "line": finding.line,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "detection": finding.detection,
            "proof_level": finding.proof_level,
            "evidence": finding.evidence,
            "fingerprint": finding.fingerprint,
        }

    def test_direct_python_scan_matches_golden_report(self):
        findings, stats = scan_repository(GOLDEN_FIXTURE)
        expected = json.loads(GOLDEN_EXPECTATION.read_text(encoding="utf-8"))
        self.assertEqual(expected["summary"]["files_scanned"], stats["files_scanned"])
        self.assertEqual(expected["summary"]["suppressed"], stats["suppressed"])
        produced = [self.golden_fields(item) for item in findings]
        self.assertEqual(produced, expected["findings"])

    def test_sarif_results_map_every_finding(self):
        findings, _ = scan_repository(GOLDEN_FIXTURE)
        sarif = build_sarif_report(findings)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "ShipProof")
        results = run["results"]
        self.assertEqual(len(results), len(findings))
        rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        self.assertEqual(rule_ids, {item.rule_id for item in findings})
        for result, finding in zip(results, findings, strict=True):
            self.assertEqual(result["ruleId"], finding.rule_id)
            self.assertEqual(result["level"], SARIF_LEVEL[finding.severity])
            self.assertEqual(result["properties"]["severity"], finding.severity)
            self.assertEqual(result["properties"]["confidence"], finding.confidence)
            self.assertEqual(result["properties"]["detection"], finding.detection)
            self.assertEqual(result["properties"]["proof_level"], finding.proof_level)
            location = result["locations"][0]["physicalLocation"]
            self.assertEqual(location["artifactLocation"]["uri"], finding.path)
            self.assertEqual(location["region"]["startLine"], finding.line)
            self.assertEqual(result["partialFingerprints"]["shipproof/v1"], finding.fingerprint)


if __name__ == "__main__":
    unittest.main()
