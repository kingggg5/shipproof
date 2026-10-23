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
import polyglot_checks  # noqa: E402
import scan_repo  # noqa: E402
from build_luau_typescript_contracts import NEW_IDS, records, remote  # noqa: E402


class LuauTypeScriptTests(unittest.TestCase):
    def test_authored_contracts_through_offline_walker(self):
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
                                side_effect=AssertionError("no execution during scan"),
                            ):
                                findings, stats = scan_repo.scan_repository(root)
                        self.assertTrue(stats["completeness"]["is_complete"], stats)
                        hits = [f for f in findings if f.rule_id == row["rule_id"]]
                        expected = (
                            case["expected"]
                            if polarity == "adversarial"
                            else polarity == "positive"
                        )
                        self.assertEqual(len(hits), int(expected), case["source"])
                        if hits:
                            self.assertEqual(
                                (hits[0].tier, hits[0].proof_level), ("advisory", "L1")
                            )

    def test_generator_current(self):
        result = subprocess.run(  # noqa: S603 - fixed local generator
            [sys.executable, str(ROOT / "scripts/build_luau_typescript_contracts.py"), "--check"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_new_rules_are_advisory_at_every_gate(self):
        for rule_id in NEW_IDS:
            finding = scan_repo.make_finding(
                scan_repo.find_rule(rule_id), "app.ts", 1, "test", "structural"
            )
            for severity in ("critical", "high", "medium", "low"):
                for floor in ("L0", "L1", "L2"):
                    self.assertFalse(
                        scan_repo.gate_failed([finding], severity, block_min_proof=floor)
                    )

    def test_lua_suffix_scope_and_ignores(self):
        for row in records():
            if row["rule_id"] not in {"SP690", "SP691"}:
                continue
            source = row["positive"][0]["source"]
            for suffix in (".lua", ".luau"):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root / "tests").mkdir()
                    (root / ("tests/remote" + suffix)).write_text(source, encoding="utf-8")
                    findings, stats = scan_repo.scan_repository(root)
                    hits = [f for f in findings if f.rule_id == row["rule_id"]]
                    self.assertEqual(len(hits), 1)
                    self.assertEqual(hits[0].scope, "test")
                    self.assertTrue(stats["completeness"]["is_complete"])
            ignored = source.replace(
                "\n" + ("require(data)" if row["rule_id"] == "SP690" else "data:Destroy()"),
                "\n-- shipproof-ignore "
                + row["rule_id"]
                + " reviewed mock\n"
                + ("require(data)" if row["rule_id"] == "SP690" else "data:Destroy()"),
            )
            self.assertNotIn(
                row["rule_id"],
                {
                    f.rule_id
                    for f in scan_repo.find_regex_issues(
                        Path("remote.luau"), "remote.luau", ignored
                    )
                },
            )
            self.assertNotIn(
                row["rule_id"],
                {
                    f.rule_id
                    for f in scan_repo.find_regex_issues(Path("notes.txt"), "notes.txt", source)
                },
            )

    def test_fingerprint_and_evidence_minimization(self):
        for row in records():
            if row["rule_id"] not in NEW_IDS:
                continue
            case = row["positive"][0]
            path = Path(case["path"])
            a = next(
                f
                for f in scan_repo.find_regex_issues(path, str(path), case["source"])
                if f.rule_id == row["rule_id"]
            )
            b = next(
                f
                for f in scan_repo.find_regex_issues(path, str(path), "\n\n" + case["source"])
                if f.rule_id == row["rule_id"]
            )
            self.assertEqual(a.fingerprint, b.fingerprint)
            self.assertEqual(a.line + 2, b.line)
            self.assertNotIn("payload", a.evidence)
            self.assertNotIn("require(data)", a.evidence)

    def test_polyglot_limits_are_coverage_errors_not_clean_scans(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "remote.luau").write_text(remote("require(data)"), encoding="utf-8")
            with patch.object(polyglot_checks, "MAX_TOKENS", 12):
                _findings, stats = scan_repo.scan_repository(root)
            self.assertFalse(stats["completeness"]["is_complete"])

    def test_luau_interpolation_boundaries_and_limits(self):
        for source in (
            "local value = `outer {`nested {1}`}`",
            'local value = `data { {a = "}"} } end`',
            "local value = `data {[=[ } ` ]=]} end`",
            "local value = `data { --[=[ } ` ]=]\n 1 } end`",
            "local value = `data { -- } ignored\n 1 } end`",
        ):
            self.assertEqual(polyglot_checks.signature_spans(source, "lua"), [])
        for source in (
            "local value = `data {1`",
            "local value = `data {[=[ unterminated`",
            "`{" * 34 + "1" + "}`" * 34,
            "`{" + "{" * 130 + "1" + "}" * 131 + "`",
        ):
            with self.assertRaises(polyglot_checks.LexicalLimitError):
                polyglot_checks.signature_spans(source, "lua")

    def test_many_local_remote_bindings_remain_bounded_and_quiet_when_guarded(self):
        source = "\n".join(
            remote("if not allowed(player, data) then return end\ndata:Destroy()").replace(
                "remote", f"remote{index}"
            )
            for index in range(250)
        )
        self.assertLess(len(polyglot_checks.tokens(source, "lua")), polyglot_checks.MAX_TOKENS)
        self.assertEqual(polyglot_checks.signature_spans(source, "lua"), [])

    def test_cli_python_json_sarif_parity(self):
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
                result = subprocess.run(  # noqa: S603 - fixed scanner with synthetic fixtures
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

            def project(report):
                return sorted(
                    (f["rule_id"], f["fingerprint"], f["tier"]) for f in report["findings"]
                )

            self.assertEqual(project(reports[0]), project(reports[1]))
            self.assertEqual({f["rule_id"] for f in reports[0]["findings"]}, NEW_IDS)
            self.assertEqual({f["ruleId"] for f in reports[2]["runs"][0]["results"]}, NEW_IDS)


if __name__ == "__main__":
    unittest.main()
