from __future__ import annotations

import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:
    Draft202012Validator = None
    Registry = None
    Resource = None

ROOT = Path(__file__).parents[1]
CONTRACT_DIRECTORY = ROOT / "fixtures" / "command-contracts"
EXPECTED_COMMANDS = {
    "budget-report",
    "capacity-report",
    "check-report",
    "cost-report",
    "evidence-report",
    "impact-report",
    "invariants-report",
    "scan-report",
}


class CommandContractCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = {
            path.stem.removesuffix(".schema"): json.loads(path.read_text(encoding="utf-8"))
            for path in (ROOT / "schemas").glob("*-report.schema.json")
        }
        cls.contracts = {
            path.name.removesuffix(".v1.json"): json.loads(path.read_text(encoding="utf-8"))
            for path in CONTRACT_DIRECTORY.glob("*-report.v1.json")
        }
        if Registry is not None and Resource is not None:
            all_schemas = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (ROOT / "schemas").glob("*.schema.json")
            ]
            cls.registry = Registry().with_resources(
                (schema["$id"], Resource.from_contents(schema))
                for schema in all_schemas
                if "$id" in schema
            )
        else:
            cls.registry = None

    def test_every_public_evidence_command_has_a_versioned_fixture(self) -> None:
        self.assertEqual(set(self.contracts), EXPECTED_COMMANDS)
        self.assertTrue(EXPECTED_COMMANDS.issubset(self.schemas))

    def test_v1_fixtures_remain_accepted_by_current_schemas(self) -> None:
        if Draft202012Validator is None or self.registry is None:
            self.skipTest("jsonschema/referencing not installed; skipping schema validation")
        for command, report in self.contracts.items():
            with self.subTest(command=command):
                schema = self.schemas[command]
                Draft202012Validator(schema, registry=self.registry).validate(report)

    def test_compatibility_fixtures_keep_the_evidence_envelope(self) -> None:
        package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
        for command, report in self.contracts.items():
            with self.subTest(command=command):
                self.assertEqual(report["schema_version"], "1.0")
                self.assertEqual(report["tool"]["name"], "ShipProof")
                self.assertEqual(report["tool"]["version"], package["version"])
                self.assertEqual(report["tool"]["command"], command.removesuffix("-report"))
                self.assertIn(report["verdict"], {"PASS_WITH_EVIDENCE", "BLOCK", "CONDITIONAL"})
                self.assertTrue(report["limitations"])


if __name__ == "__main__":
    unittest.main()
