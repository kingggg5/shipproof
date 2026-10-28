from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "application_sarif", ROOT / "scripts/application-sarif.py"
)
projection = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(projection)
CATEGORIES = ["shipproof", ".github/workflows/security.yml:shipproof-sarif"]


def report(scopes=("app", "test"), complete=True):
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ShipProof",
                        "rules": [{"id": "SP103", "properties": {"security-severity": "8.0"}}],
                    }
                },
                "invocations": [{"executionSuccessful": complete}],
                "results": [
                    {
                        "ruleId": "SP103",
                        "level": "error",
                        "partialFingerprints": {"shipproof/v1": f"fingerprint-{i}"},
                        "properties": {"scope": scope},
                    }
                    for i, scope in enumerate(scopes)
                ],
            }
        ],
    }


class ApplicationSarifTests(unittest.TestCase):
    def test_app_severity_fingerprints_and_rules_stay_active(self):
        full = report()
        original = copy.deepcopy(full)
        result = projection.application_report(full, CATEGORIES)
        self.assertEqual(full, original)
        self.assertEqual(
            {r["automationDetails"]["id"] for r in result["runs"]}, {c + "/" for c in CATEGORIES}
        )
        for run in result["runs"]:
            self.assertEqual(run["results"], full["runs"][0]["results"][:1])
            self.assertEqual(run["tool"], full["runs"][0]["tool"])
            self.assertEqual(run["properties"]["test_results_in_full_report"], 1)

    def test_unknown_or_missing_scope_is_never_excluded(self):
        full = report(("unknown", None, "test"))
        full["runs"][0]["results"][1].pop("properties")
        result = projection.application_report(full, ["shipproof"])
        self.assertEqual(result["runs"][0]["results"], full["runs"][0]["results"][:2])

    def test_incomplete_evidence_stays_incomplete(self):
        result = projection.application_report(report(complete=False), CATEGORIES)
        self.assertTrue(
            all(r["invocations"] == [{"executionSuccessful": False}] for r in result["runs"])
        )

    def test_invalid_report_cannot_become_an_empty_success(self):
        for payload in (
            {},
            {"version": "2.1.0", "runs": []},
            {"version": "2.1.0", "runs": [None]},
            {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Other"}}, "results": []}]},
        ):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                projection.application_report(payload, CATEGORIES)
        invalid = report()
        invalid["runs"][0]["results"][0]["properties"] = None
        with self.assertRaises(ValueError):
            projection.application_report(invalid, CATEGORIES)

    def test_cli_preserves_original_full_report(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "full.json", Path(directory) / "app.json"
            data = json.dumps(report(("test",))).encode()
            source.write_bytes(data)
            self.assertEqual(
                projection.main([str(source), str(output), "--category", "shipproof"]), 0
            )
            self.assertEqual(source.read_bytes(), data)
            self.assertEqual(json.loads(output.read_text())["runs"][0]["results"], [])

    def test_existing_output_and_input_are_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "full.json", Path(directory) / "app.json"
            source.write_text(json.dumps(report()), encoding="utf-8")
            output.write_text("keep", encoding="utf-8")
            self.assertEqual(
                projection.main([str(source), str(output), "--category", "shipproof"]), 2
            )
            self.assertEqual(output.read_text(), "keep")
            self.assertEqual(
                projection.main([str(source), str(source), "--category", "shipproof"]), 2
            )

    def test_invalid_and_over_budget_input_fail_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "full.json", Path(directory) / "app.json"
            source.write_bytes(b"not json")
            self.assertEqual(
                projection.main([str(source), str(output), "--category", "shipproof"]), 2
            )
            self.assertFalse(output.exists())
            with patch.object(projection, "MAX_BYTES", 2):
                self.assertEqual(
                    projection.main([str(source), str(output), "--category", "shipproof"]), 2
                )
            self.assertFalse(output.exists())

    def test_category_misconfiguration_fails_closed(self):
        for categories in (
            [],
            ["same", "same"],
            ["same", "same/"],
            [""],
            ["/"],
            ["bad\ncategory"],
            ["a", "b", "c"],
        ):
            with self.subTest(categories=categories), self.assertRaises(ValueError):
                projection.application_report(report(), categories)


if __name__ == "__main__":
    unittest.main()
