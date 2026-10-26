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
import luau_quality_checks  # noqa: E402
import polyglot_checks  # noqa: E402
import scan_repo  # noqa: E402
from build_luau_community_contracts import NEW_IDS, records  # noqa: E402

IDS = NEW_IDS | {"SP707"}


class LuauCommunityTests(unittest.TestCase):
    def test_all_original_cases_through_real_offline_walker(self):
        for row in records():
            for kind in ("positive", "negative", "adversarial"):
                for case in row[kind]:
                    with (
                        self.subTest(rule=row["rule_id"], kind=kind, source=case["source"]),
                        tempfile.TemporaryDirectory() as directory,
                    ):
                        root = Path(directory)
                        (root / case["path"]).write_text(case["source"], encoding="utf-8")
                        with patch(
                            "subprocess.run",
                            side_effect=AssertionError("do not execute scanned Luau"),
                        ):
                            findings, stats = scan_repo.scan_repository(root)
                        hits = [f for f in findings if f.rule_id == row["rule_id"]]
                        expected = case["expected"] if kind == "adversarial" else kind == "positive"
                        self.assertEqual(len(hits), int(expected), case["source"])
                        self.assertTrue(stats["completeness"]["is_complete"])
                        if hits:
                            self.assertEqual(
                                (hits[0].proof_level, hits[0].tier), ("L1", "advisory")
                            )

    def test_generators_are_current_together(self):
        for name in (
            "build_luau_community_contracts.py",
            "build_io_ownership_contracts.py",
            "build_web_database_contracts.py",
            "build_legacy_structural_contracts.py",
        ):
            completed = subprocess.run(  # noqa: S603 - fixed owned generator
                [sys.executable, str(ROOT / "scripts" / name), "--check"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)

    def test_advisories_do_not_change_any_gate_floor(self):
        for rule_id in IDS:
            finding = scan_repo.make_finding(
                scan_repo.find_rule(rule_id), "module.luau", 1, "evidence", "structural"
            )
            for floor in ("L0", "L1", "L2"):
                for severity in ("low", "medium", "high", "critical"):
                    self.assertFalse(
                        scan_repo.gate_failed([finding], severity, block_min_proof=floor)
                    )

    def test_scope_ignores_line_moves_and_fingerprints(self):
        for row in records():
            case = row["positive"][0]
            source, path = case["source"], case["path"]
            original = next(
                f
                for f in scan_repo.lint_source_snippet(source, path)
                if f.rule_id == row["rule_id"]
            )
            moved = next(
                f
                for f in scan_repo.lint_source_snippet("\n\n" + source, path)
                if f.rule_id == row["rule_id"]
            )
            self.assertEqual(original.fingerprint, moved.fingerprint)
            self.assertEqual(original.line + 2, moved.line)
            lines = source.splitlines()
            lines.insert(
                original.line - 1, f"-- shipproof-ignore {row['rule_id']} reviewed fixture"
            )
            self.assertNotIn(
                row["rule_id"],
                {f.rule_id for f in scan_repo.lint_source_snippet("\n".join(lines), path)},
            )
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "tests").mkdir()
                (root / "tests" / path).write_text(source, encoding="utf-8")
                self.assertTrue(all(f.scope == "test" for f in scan_repo.scan_repository(root)[0]))

    def test_reports_and_fix_prompts_keep_context_private(self):
        marker = "private-luau-context-marker"
        for row in records():
            case = row["positive"][0]
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / case["path"]).write_text(
                    case["source"] + f"\n-- {marker}\n", encoding="utf-8"
                )
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

    def test_python_cli_json_and_sarif_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for row in records():
                (root / (row["rule_id"] + ".luau")).write_text(
                    row["positive"][0]["source"], encoding="utf-8"
                )
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
                completed = subprocess.run(  # noqa: S603 - own CLI over original fixtures
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
                self.assertEqual(completed.returncode, 0, completed.stderr)
                reports.append(json.loads(completed.stdout))

            def keys(report):
                return sorted(
                    (f["rule_id"], f["path"], f["fingerprint"], f["tier"])
                    for f in report["findings"]
                    if f["rule_id"] in IDS
                )

            self.assertEqual(keys(reports[0]), keys(reports[1]))
            self.assertEqual({row[0] for row in keys(reports[0])}, IDS)
            self.assertEqual(
                IDS.intersection(f["ruleId"] for f in reports[2]["runs"][0]["results"]), IDS
            )

    def test_integer_bounds_and_opaque_budget_behavior(self):
        self.assertEqual(luau_quality_checks.integer(["-", "2147483648"]), -(2**31))
        for values in (
            ["2147483648"],
            ["9" * 5000],
            ["1", ".", "5"],
            ["limit"],
            ["0", "xFF"],
            ["-", "2147483649"],
        ):
            self.assertIsNone(luau_quality_checks.integer(values))
        with (
            patch.object(polyglot_checks, "MAX_TOKENS", 12),
            self.assertRaises(polyglot_checks.LexicalLimitError),
        ):
            polyglot_checks.signature_spans("math.clamp(x,10,2);" * 10, "lua")
        for source in ("--[=[ math.clamp(x,10,2)", "local text=`{unterminated"):
            with self.subTest(source=source), self.assertRaises(polyglot_checks.LexicalLimitError):
                polyglot_checks.signature_spans(source, "lua")

    def test_both_lua_suffixes_use_the_same_signature(self):
        for row in records():
            for suffix in ("lua", "luau"):
                self.assertIn(
                    row["rule_id"],
                    {
                        f.rule_id
                        for f in scan_repo.lint_source_snippet(
                            row["positive"][0]["source"], "module." + suffix
                        )
                    },
                )


if __name__ == "__main__":
    unittest.main()
