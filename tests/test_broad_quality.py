from __future__ import annotations

import ast
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
sys.path.insert(0, str(ROOT / "scripts"))
import python_runtime_checks  # noqa: E402
import rule_explanations  # noqa: E402
import scan_repo  # noqa: E402
from build_broad_quality_contracts import NEW_IDS, records  # noqa: E402


class BroadQualityTests(unittest.TestCase):
    def test_all_authored_cases_through_offline_walker(self):
        for row in records():
            for polarity in ("positive", "negative", "adversarial"):
                for case in row[polarity]:
                    with self.subTest(
                        rule=row["rule_id"], polarity=polarity, source=case["source"]
                    ):
                        with tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            (root / case["path"]).write_text(case["source"], encoding="utf-8")
                            with patch(
                                "subprocess.run",
                                side_effect=AssertionError("source execution forbidden"),
                            ):
                                findings, stats = scan_repo.scan_repository(root)
                        self.assertTrue(stats["completeness"]["is_complete"], stats)
                        expected = (
                            case["expected"]
                            if polarity == "adversarial"
                            else polarity == "positive"
                        )
                        hits = [hit for hit in findings if hit.rule_id == row["rule_id"]]
                        self.assertEqual(len(hits), int(expected), case["source"])
                        if hits and row["rule_id"] in NEW_IDS:
                            self.assertEqual(
                                (hits[0].proof_level, hits[0].tier), ("L1", "advisory")
                            )

    def test_explanation_api_is_reexported_pure_data(self):
        self.assertIs(scan_repo.RULE_EXPLANATIONS, rule_explanations.RULE_EXPLANATIONS)
        source = Path(rule_explanations.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        self.assertTrue(all(isinstance(node, (ast.Expr, ast.AnnAssign)) for node in tree.body))
        self.assertEqual(ast.literal_eval(tree.body[-1].value), scan_repo.RULE_EXPLANATIONS)

    def test_generators_current(self):
        result = subprocess.run(  # noqa: S603 - fixed local generator
            [sys.executable, str(ROOT / "scripts/build_broad_quality_contracts.py"), "--check"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_advisory_policy_is_not_changed_by_gate_floor(self):
        for row in records():
            if row["rule_id"] not in NEW_IDS:
                continue
            finding = scan_repo.make_finding(
                scan_repo.find_rule(row["rule_id"]),
                row["positive"][0]["path"],
                1,
                "fixture",
                "structural",
            )
            for floor in ("L0", "L1", "L2"):
                for severity in ("low", "medium", "high", "critical"):
                    self.assertFalse(
                        scan_repo.gate_failed([finding], severity, block_min_proof=floor)
                    )

    def test_retired_default_pool_rule_is_not_reused(self):
        self.assertNotIn("SP348", scan_repo.RULE_INDEX)
        self.assertNotIn("SP348", scan_repo.RULE_EXPLANATIONS)
        for source in (
            "from concurrent.futures import ThreadPoolExecutor\npool = ThreadPoolExecutor()\n",
            "import concurrent.futures\nwith concurrent.futures.ThreadPoolExecutor() as pool:\n    future = pool.submit(str, 1)\n",
            "from concurrent.futures import ThreadPoolExecutor\npool = ThreadPoolExecutor(max_workers=None)\n",
        ):
            findings = scan_repo.lint_source_snippet(source, "pool.py")
            self.assertNotIn("SP348", {finding.rule_id for finding in findings})

    def test_node_budget_is_explicit_incomplete_coverage(self):
        source = "import logging.config\nlogging.config.listen(9030,verify=None).start()\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "listener.py").write_text(source, encoding="utf-8")
            with patch.object(python_runtime_checks, "MAX_NODES", 5):
                _findings, stats = scan_repo.scan_repository(root)
            self.assertFalse(stats["completeness"]["is_complete"])

    def test_irrelevant_python_does_not_consume_api_analysis_budget(self):
        tree = ast.parse('import json\nmessage = "logging.create_task"\n' + "value = 1\n" * 100)
        with patch.object(python_runtime_checks, "MAX_NODES", 5):
            self.assertEqual(python_runtime_checks.observations(tree), [])

    def test_scope_ignores_and_normalized_evidence(self):
        for row in records():
            if row["rule_id"] not in NEW_IDS:
                continue
            case = row["positive"][0]
            prefix = "#" if case["path"].endswith(".py") else "//"
            source = case["source"]
            findings = [
                f
                for f in scan_repo.lint_source_snippet(source, case["path"])
                if f.rule_id == row["rule_id"]
            ]
            self.assertEqual(len(findings), 1)
            finding = findings[0]
            moved = next(
                f
                for f in scan_repo.lint_source_snippet("\n\n" + source, case["path"])
                if f.rule_id == row["rule_id"]
            )
            self.assertEqual(finding.fingerprint, moved.fingerprint)
            self.assertEqual(finding.line + 2, moved.line)
            self.assertNotIn(source.strip(), finding.evidence)
            lines = source.splitlines()
            lines.insert(
                finding.line - 1, f"{prefix} shipproof-ignore {row['rule_id']} reviewed fixture"
            )
            self.assertNotIn(
                row["rule_id"],
                {f.rule_id for f in scan_repo.lint_source_snippet("\n".join(lines), case["path"])},
            )
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "tests").mkdir()
                (root / "tests" / case["path"]).write_text(source, encoding="utf-8")
                findings, _stats = scan_repo.scan_repository(root)
                self.assertTrue(all(f.scope == "test" for f in findings))

    def test_cli_json_sarif_parity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for row in records():
                if row["rule_id"] in NEW_IDS:
                    case = row["positive"][0]
                    (root / (row["rule_id"] + Path(case["path"]).suffix)).write_text(
                        case["source"], encoding="utf-8"
                    )
            reports = []
            for prefix, output_format in (
                (
                    [
                        sys.executable,
                        str(ROOT / "skills/audit-production-readiness/scripts/scan_repo.py"),
                    ],
                    "json",
                ),
                (["node", str(ROOT / "bin/shipproof.mjs"), "scan"], "json"),
                (["node", str(ROOT / "bin/shipproof.mjs"), "scan"], "sarif"),
            ):
                result = subprocess.run(  # noqa: S603 - fixed own scanner over authored inputs
                    [
                        *prefix,
                        str(root),
                        "--format",
                        output_format,
                        "--fail-on",
                        "low",
                        "--block-min-proof",
                        "L0",
                    ],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                reports.append(json.loads(result.stdout))

            def keys(report):
                return sorted(
                    (f["rule_id"], f["fingerprint"], f["tier"]) for f in report["findings"]
                )

            self.assertEqual(keys(reports[0]), keys(reports[1]))
            self.assertEqual({f["rule_id"] for f in reports[0]["findings"]}, NEW_IDS)
            self.assertEqual({f["ruleId"] for f in reports[2]["runs"][0]["results"]}, NEW_IDS)


if __name__ == "__main__":
    unittest.main()
