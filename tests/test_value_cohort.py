from __future__ import annotations

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
import js_config_checks  # noqa: E402
import polyglot_checks  # noqa: E402
import scan_repo  # noqa: E402
from build_value_contracts import NEW_IDS, records  # noqa: E402


class ValueCohortTests(unittest.TestCase):
    def test_authored_cases_through_real_offline_walker(self):
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
                                "subprocess.run", side_effect=AssertionError("no target execution")
                            ):
                                findings, stats = scan_repo.scan_repository(root)
                        hits = [f for f in findings if f.rule_id == row["rule_id"]]
                        expected = (
                            case["expected"]
                            if polarity == "adversarial"
                            else polarity == "positive"
                        )
                        self.assertEqual(len(hits), int(expected), case["source"])
                        self.assertTrue(stats["completeness"]["is_complete"])
                        if hits:
                            self.assertEqual(
                                (hits[0].proof_level, hits[0].tier), ("L1", "advisory")
                            )

    def test_generator_current(self):
        result = subprocess.run(  # noqa: S603 - fixed owned generator
            [sys.executable, str(ROOT / "scripts/build_value_contracts.py"), "--check"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_retired_default_assumptions_are_not_reused(self):
        for rule_id in ("SP347", "SP350"):
            self.assertNotIn(rule_id, scan_repo.RULE_INDEX)
            self.assertNotIn(rule_id, scan_repo.RULE_EXPLANATIONS)
        for source in (
            "import asyncio\nasync def run():\n    return await asyncio.gather(first(), second())\n",
            "import asyncio\nasync def run():\n    try:\n        await asyncio.gather(first(), second())\n    except ValueError:\n        log_failure()\n",
            "from sqlalchemy import create_engine\nengine = create_engine(url)\n",
            "from sqlalchemy import create_engine\nengine = create_engine(url, pool_size=5, max_overflow=10)\n",
        ):
            self.assertFalse(
                {"SP347", "SP350"}.intersection(
                    f.rule_id for f in scan_repo.lint_source_snippet(source, "app.py")
                )
            )

    def test_timer_product_is_exact_and_bounded(self):
        self.assertEqual(
            js_config_checks.constant_product(["30", "*", "24", "*", "60", "*", "60", "*", "1000"]),
            2592000000,
        )
        self.assertEqual(js_config_checks.constant_product(["0", "*", "1000"]), 0)
        for values in (
            [],
            ["2", "**", "32"],
            ["delay"],
            ["9" * 5000],
            ["9007199254740991", "*", "2"],
            ["1", "*"] * 20,
        ):
            self.assertIsNone(js_config_checks.constant_product(values))

    def test_stringification_does_not_hide_a_later_real_rust_operation(self):
        body = "std::num::NonZeroU32::new_unchecked(0)"
        source = f"let text = stringify!({body});\nlet actual = unsafe {{ {body} }};"
        hits = [
            f for f in scan_repo.lint_source_snippet(source, "value.rs") if f.rule_id == "SP699"
        ]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].line, 2)
        nested = "stringify!(" * 60 + body + ")" * 60
        self.assertEqual(polyglot_checks.signature_spans(nested, "rust"), [])

    def test_advisory_gate_floors_stay_nonblocking(self):
        for rule_id in NEW_IDS:
            finding = scan_repo.make_finding(
                scan_repo.find_rule(rule_id), "app.ts", 1, "evidence", "structural"
            )
            for floor in ("L0", "L1", "L2"):
                for severity in ("low", "medium", "high", "critical"):
                    self.assertFalse(
                        scan_repo.gate_failed([finding], severity, block_min_proof=floor)
                    )

    def test_reports_and_fix_context_do_not_echo_neighboring_data(self):
        marker = "private-cohort-context-marker"
        for row in records():
            case = row["positive"][0]
            prefix = "#" if case["path"].endswith(".py") else "//"
            source = case["source"] + f"\n{prefix} {marker}\n"
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / case["path"]).write_text(source, encoding="utf-8")
                finding = next(
                    f for f in scan_repo.scan_repository(root)[0] if f.rule_id == row["rule_id"]
                )
                for output in (
                    finding.evidence,
                    json.dumps(scan_repo.build_sarif_report([finding], root)),
                    scan_repo.render_fix_prompts(
                        root, [finding], as_json=True, context_level="full"
                    ),
                ):
                    self.assertNotIn(marker, output)

    def test_scope_ignore_and_fingerprint_movement(self):
        for row in records():
            case = row["positive"][0]
            source, filename = case["source"], case["path"]
            original = next(
                f
                for f in scan_repo.lint_source_snippet(source, filename)
                if f.rule_id == row["rule_id"]
            )
            moved = next(
                f
                for f in scan_repo.lint_source_snippet("\n\n" + source, filename)
                if f.rule_id == row["rule_id"]
            )
            self.assertEqual(original.fingerprint, moved.fingerprint)
            self.assertEqual(original.line + 2, moved.line)
            lines = source.splitlines()
            prefix = "#" if filename.endswith(".py") else "//"
            lines.insert(
                original.line - 1, f"{prefix} shipproof-ignore {row['rule_id']} reviewed fixture"
            )
            self.assertNotIn(
                row["rule_id"],
                {f.rule_id for f in scan_repo.lint_source_snippet("\n".join(lines), filename)},
            )
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "tests").mkdir()
                (root / "tests" / filename).write_text(source, encoding="utf-8")
                findings, _stats = scan_repo.scan_repository(root)
                self.assertTrue(all(f.scope == "test" for f in findings))

    def test_python_node_and_sarif_parity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for row in records():
                if row["rule_id"] in NEW_IDS:
                    case = row["positive"][0]
                    (root / case["path"]).write_text(case["source"], encoding="utf-8")
            reports = []
            for prefix, format_name in (
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
                result = subprocess.run(  # noqa: S603 - own CLI over authored data
                    [
                        *prefix,
                        str(root),
                        "--format",
                        format_name,
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
