from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
BUDGET_SCRIPTS = ROOT / "skills" / "engineer-production-systems" / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(BUDGET_SCRIPTS))

from capacity_model import CapacityInputs, build_capacity_model  # noqa: E402
from check_budget import evaluate_resource_budget  # noqa: E402
from cost_model import main as cost_main  # noqa: E402
from impact_graph import main as impact_main  # noqa: E402
from invariants import main as invariants_main  # noqa: E402
from scan_repo import build_decision_trace, build_json_report  # noqa: E402


class EvidenceSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = {
            path.name: json.loads(path.read_text(encoding="utf-8"))
            for path in (ROOT / "schemas").glob("*.schema.json")
        }
        cls.registry = Registry().with_resources(
            (
                schema["$id"],
                Resource.from_contents(schema),
            )
            for schema in cls.schemas.values()
        )

    def assert_valid(self, schema_name: str, report: dict[str, object]) -> None:
        schema = self.schemas[schema_name]
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, registry=self.registry).validate(report)

    def test_every_evidence_schema_is_valid_draft_2020_12(self):
        for name, schema in self.schemas.items():
            with self.subTest(schema=name):
                self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
                Draft202012Validator.check_schema(schema)

    def test_evidence_envelope_accepts_semver_prerelease(self):
        self.assert_valid(
            "evidence-envelope.schema.json",
            {
                "schema_version": "1.0",
                "tool": {
                    "name": "ShipProof",
                    "version": "1.0.0-rc.1+build.2",
                    "command": "test",
                },
                "verdict": "CONDITIONAL",
                "limitations": ["fixture"],
            },
        )

    def test_scan_budget_and_capacity_reports_match_their_schemas(self):
        scan = build_json_report(
            ROOT, [], {"files_scanned": 0, "suppressed": 0}, include_tests=False
        )
        trace = build_decision_trace(
            [],
            {"files_scanned": 0, "suppressed": 0},
            fail_on="high",
            include_tests=False,
            max_file_bytes=1_000_000,
            min_confidence=None,
            exclude_patterns=[],
            baseline_fingerprints=0,
            changed_candidates=None,
            findings_before_confidence_filter=0,
        )
        scan_with_trace = build_json_report(
            ROOT,
            [],
            {"files_scanned": 0, "suppressed": 0},
            include_tests=False,
            decision_trace=trace,
        )
        budget = evaluate_resource_budget(
            {"latency": 10},
            {"latency": 11},
            {"latency": {"direction": "lower", "max_regression_percent": 20}},
        )
        capacity = build_capacity_model(CapacityInputs(users=100))
        self.assert_valid("scan-report.schema.json", scan)
        self.assert_valid("scan-report.schema.json", scan_with_trace)
        self.assert_valid("budget-report.schema.json", budget)
        self.assert_valid("capacity-report.schema.json", capacity)

    def test_experimental_json_reports_match_versioned_schemas(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "service.py").write_text("def ping():\n    return 'pong'\n", encoding="utf-8")

            cost_output = io.StringIO()
            with contextlib.redirect_stdout(cost_output):
                self.assertEqual(
                    cost_main([str(root), "--context-tokens", "1000", "--format", "json"]),
                    0,
                )
            impact_output = io.StringIO()
            with contextlib.redirect_stdout(impact_output):
                self.assertEqual(
                    impact_main(["service.py", "--root", str(root), "--format", "json"]),
                    0,
                )
            invariants_output = io.StringIO()
            with contextlib.redirect_stdout(invariants_output):
                self.assertEqual(invariants_main([str(root), "--format", "json"]), 0)

        self.assert_valid("cost-report.schema.json", json.loads(cost_output.getvalue()))
        self.assert_valid("impact-report.schema.json", json.loads(impact_output.getvalue()))
        self.assert_valid("invariants-report.schema.json", json.loads(invariants_output.getvalue()))


if __name__ == "__main__":
    unittest.main()
