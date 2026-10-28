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
import scan_repo  # noqa: E402
from build_io_ownership_contracts import records  # noqa: E402

IDS = {"SP336", "SP703", "SP705", "SP707"}


class IOOwnershipTests(unittest.TestCase):
    def test_authored_cases_use_real_offline_walker(self):
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
                            side_effect=AssertionError("do not execute scanned code"),
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

    def test_generator_and_migrated_legacy_contracts_are_current(self):
        for name in (
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

    def test_no_advisory_changes_a_gate_floor(self):
        for rule_id in IDS:
            finding = scan_repo.make_finding(
                scan_repo.find_rule(rule_id), "app.ts", 1, "evidence", "structural"
            )
            for floor in ("L0", "L1", "L2"):
                for severity in ("low", "medium", "high", "critical"):
                    self.assertFalse(
                        scan_repo.gate_failed([finding], severity, block_min_proof=floor)
                    )

    def test_secret_context_is_not_in_reports_or_fix_prompts(self):
        marker = "private-io-context-marker"
        for row in records():
            case = row["positive"][0]
            prefix = "--" if case["path"].endswith((".lua", ".luau", ".sql")) else "//"
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / case["path"]).write_text(
                    case["source"] + f"\n{prefix} {marker}\n", encoding="utf-8"
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

    def test_line_moves_ignores_and_test_scope(self):
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
            prefix = "--" if path.endswith((".lua", ".luau", ".sql")) else "//"
            lines = source.splitlines()
            lines.insert(
                original.line - 1, f"{prefix} shipproof-ignore {row['rule_id']} reviewed fixture"
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

    def test_cli_json_sarif_and_python_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for row in records():
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
                completed = subprocess.run(  # noqa: S603 - own CLI over authored fixture data
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

    def test_zod_and_named_error_owners_are_not_node_stream_proof(self):
        self.assertNotIn("SP367", scan_repo.RULE_INDEX)
        for source in (
            "import {z} from 'zod'; const schema=z.number(); const result=z.coerce.number().pipe(schema);",
            "readStream.on('error',report); destination.on('error',report); readStream.pipe(destination);",
            "const source=customStream; source.pipe(destination);",
        ):
            self.assertFalse(
                {"SP336", "SP367"}.intersection(
                    f.rule_id for f in scan_repo.lint_source_snippet(source, "app.ts")
                )
            )

    def test_javascript_and_luau_suffixes_use_same_boundaries(self):
        cases = {row["rule_id"]: row["positive"][0]["source"] for row in records()}
        for suffix in ("js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"):
            self.assertIn(
                "SP336",
                {f.rule_id for f in scan_repo.lint_source_snippet(cases["SP336"], "app." + suffix)},
            )
        for suffix in ("lua", "luau"):
            self.assertIn(
                "SP707",
                {
                    f.rule_id
                    for f in scan_repo.lint_source_snippet(cases["SP707"], "store.server." + suffix)
                },
            )


if __name__ == "__main__":
    unittest.main()
