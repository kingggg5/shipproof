from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))

import polyglot_checks  # noqa: E402
from scan_repo import (  # noqa: E402
    build_json_report,
    build_sarif_report,
    find_regex_issues,
    find_rule,
    gate_failed,
    make_finding,
    scan_repository,
)


class RobloxRustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        payload = json.loads((ROOT / "tests/rule_cases_v2.json").read_text(encoding="utf-8"))
        cls.records = [r for r in payload["rules"] if r["rule_id"] in {"SP671", "SP672", "SP673"}]

    def scan_case(self, row: dict, case: dict):
        with tempfile.TemporaryDirectory(prefix="shipproof-polyglot-") as directory:
            root = Path(directory)
            path = root / case["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(case["source"], encoding="utf-8")
            findings, stats = scan_repository(root)
            return [f for f in findings if f.rule_id == row["rule_id"]], stats

    def test_all_authored_cases_run_through_the_real_walker(self):
        self.assertEqual(len(self.records), 3)
        for row in self.records:
            for polarity in ("positive", "negative", "adversarial"):
                for case in row[polarity]:
                    with self.subTest(rule=row["rule_id"], polarity=polarity, path=case["path"]):
                        findings, stats = self.scan_case(row, case)
                        self.assertTrue(stats["completeness"]["is_complete"])
                        expected = (
                            polarity == "positive"
                            if polarity != "adversarial"
                            else case["expected"]
                        )
                        self.assertEqual(bool(findings), expected, case["source"])
                        if expected:
                            self.assertEqual(len(findings), 1)
                            self.assertEqual(findings[0].tier, "advisory")
                            self.assertEqual(findings[0].proof_level, "L1")

    def test_new_and_previous_advisories_never_block_on_any_proof_floor(self):
        for rule_id in [f"SP{i}" for i in range(666, 674)]:
            finding = make_finding(find_rule(rule_id), "app.luau", 1, "evidence", "structural")
            self.assertEqual(finding.tier, "advisory")
            for proof in ("L0", "L1", "L2"):
                for fail_on in ("critical", "high", "medium", "low"):
                    self.assertFalse(
                        gate_failed(
                            [replace(finding, proof_level=proof)], fail_on, block_min_proof="L0"
                        )
                    )

    def test_anchors_and_fingerprints_survive_line_movement(self):
        source = (
            'local http = game:GetService("HttpService")\nloadstring(http:GetAsync(endpoint))()\n'
        )
        before = find_regex_issues(Path("loader.luau"), "loader.luau", source)
        after = find_regex_issues(Path("loader.luau"), "loader.luau", "-- moved\n" + source)
        self.assertEqual(before[0].rule_id, "SP671")
        self.assertEqual((before[0].line, before[0].column), (2, 1))
        self.assertEqual(after[0].line, 3)
        self.assertEqual(before[0].fingerprint, after[0].fingerprint)

    def test_lua_ignore_and_scope_work(self):
        source = "-- shipproof-ignore SP672 reviewed test console\nremote.OnServerEvent:Connect(function(player, code) loadstring(code)() end)\n"
        findings = find_regex_issues(Path("handler.lua"), "handler.lua", source)
        self.assertNotIn("SP672", {f.rule_id for f in findings})
        row = self.records[1]
        case = dict(row["positive"][0], path="fixtures/handler.luau")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tests").mkdir()
            (root / "tests/handler.luau").write_text(case["source"], encoding="utf-8")
            findings, _ = scan_repository(root)
            self.assertTrue(findings)
            self.assertTrue(all(f.scope == "test" for f in findings))

    def test_rust_tls_checks_literal_settings_and_binding(self):
        for method in ("danger_accept_invalid_certs", "tls_danger_accept_invalid_hostnames"):
            for path in ("reqwest::Client", "reqwest::blocking::Client"):
                source = f"let client = {path}::builder().{method}(true).build()?;\n"
                findings = find_regex_issues(Path("tls.rs"), "tls.rs", source)
                hits = [f for f in findings if f.rule_id == "SP104"]
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0].tier, "advisory")
                self.assertFalse(gate_failed(hits, "low", block_min_proof="L0"))
                for safe in (
                    source.replace("(true)", "(false)"),
                    source.replace("reqwest::", "custom::reqwest::"),
                    "/* " + source + " */",
                    'let example = r###"' + source + '"###;',
                    "mod reqwest {}\n" + source,
                    source.replace(".build()", f".{method}(false).build()"),
                    source.replace(".build()", f".{method}(config).build()"),
                    source.replace(".build()", ""),
                ):
                    self.assertNotIn(
                        "SP104",
                        {f.rule_id for f in find_regex_issues(Path("tls.rs"), "tls.rs", safe)},
                    )

    def test_custom_dart_trust_store_stays_silent(self):
        source = "final context = SecurityContext(withTrustedRoots: false);\ncontext.setTrustedCertificates('approved.pem');\n"
        self.assertNotIn(
            "SP104", {f.rule_id for f in find_regex_issues(Path("tls.dart"), "tls.dart", source)}
        )

    def test_unfinished_literal_and_token_budget_report_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for filename, source in (
                ("app.luau", "--[=[ unfinished"),
                ("app.rs", 'let text = r###"unfinished'),
            ):
                file = root / filename
                file.write_text(source, encoding="utf-8")
                findings, stats = scan_repository(root)
                self.assertFalse(stats["completeness"]["is_complete"])
                self.assertIn("parser_limit", stats["completeness"]["reasons"])
                self.assertTrue(
                    gate_failed(
                        findings,
                        "high",
                        completeness=stats["completeness"],
                        fail_on_incomplete=True,
                    )
                )
                file.unlink()
            (root / "tokens.rs").write_text("let x = 1;\n" * 20, encoding="utf-8")
            with patch.object(polyglot_checks, "MAX_TOKENS", 20):
                _, stats = scan_repository(root)
                self.assertFalse(stats["completeness"]["is_complete"])
            with (
                patch.object(polyglot_checks, "MAX_TOKENS", 2),
                self.assertRaises(polyglot_checks.LexicalLimitError),
            ):
                polyglot_checks.tokens("[=[x]=] [=[y]=] [=[z]=]", "lua")

    def test_json_and_sarif_preserve_advisory_proof_and_anchor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case = self.records[0]["positive"][0]
            (root / case["path"]).write_text(case["source"], encoding="utf-8")
            findings, stats = scan_repository(root)
            report = build_json_report(root, findings, stats)
            self.assertEqual(report["findings"][0]["tier"], "advisory")
            self.assertEqual(report["findings"][0]["proof_level"], "L1")
            sarif = build_sarif_report(findings, root)
            region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
            self.assertEqual(region["startLine"], 2)
            self.assertEqual(region["startColumn"], 1)

    def test_contract_generator_is_current(self):
        result = subprocess.run(  # noqa: S603 - fixed local generator and interpreter
            [sys.executable, str(ROOT / "scripts/build_roblox_rust_contracts.py"), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_node_cli_matches_python_on_luau_advisories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case = self.records[1]["positive"][0]
            (root / case["path"]).write_text(case["source"], encoding="utf-8")
            common = [
                str(root),
                "--format",
                "json",
                "--fail-on",
                "medium",
                "--block-min-proof",
                "L0",
            ]
            outputs = []
            for command in (
                [
                    sys.executable,
                    str(ROOT / "skills/audit-production-readiness/scripts/scan_repo.py"),
                    *common,
                ],
                ["node", str(ROOT / "bin/shipproof.mjs"), "scan", *common],
            ):
                result = subprocess.run(  # noqa: S603 - fixed test commands and temporary source path
                    command,
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                report = json.loads(result.stdout)
                outputs.append(
                    [(r["rule_id"], r["fingerprint"], r["tier"]) for r in report["findings"]]
                )
            self.assertEqual(outputs[0], outputs[1])
            self.assertEqual(outputs[0][0][0], "SP672")


if __name__ == "__main__":
    unittest.main()
