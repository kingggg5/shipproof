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
import scan_repo  # noqa: E402
import sql_checks  # noqa: E402
from build_web_database_contracts import NEW_IDS, RETIRED_IDS, records  # noqa: E402


class WebDatabaseTests(unittest.TestCase):
    def test_authored_contracts_through_real_offline_walker(self):
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
                                side_effect=AssertionError("never execute a scanned project"),
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

    def test_contract_generator_is_current(self):
        completed = subprocess.run(  # noqa: S603 - fixed owned contract generator
            [sys.executable, str(ROOT / "scripts/build_web_database_contracts.py"), "--check"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)

    def test_retired_absence_claims_are_not_reused(self):
        self.assertFalse(RETIRED_IDS.intersection(scan_repo.RULE_INDEX))
        self.assertFalse(RETIRED_IDS.intersection(scan_repo.RULE_EXPLANATIONS))
        for source, path in (
            ("import {Pool} from 'pg'; const pool = new Pool({});", "pool.ts"),
            ("import {Pool} from 'pg'; const pool = new Pool({max:10});", "pool.ts"),
            ("server.listen(8080);", "server.ts"),
            ("app.get('/', async (req, res) => { res.send(await load()); });", "route.ts"),
            ("import {useEffect} from 'react'; useEffect(() => { auditCommit(); });", "effect.tsx"),
            ("BEGIN; SET LOCAL statement_timeout = 5000; SELECT 1; COMMIT;", "safe.sql"),
            ("SET statement_timeout = 5000; BEGIN; SELECT 1; COMMIT;", "safe.sql"),
        ):
            self.assertFalse(
                RETIRED_IDS.intersection(
                    f.rule_id for f in scan_repo.lint_source_snippet(source, path)
                )
            )

    def test_advisory_stays_nonblocking_at_every_floor(self):
        for rule_id in NEW_IDS:
            finding = scan_repo.make_finding(
                scan_repo.find_rule(rule_id), "app.ts", 1, "evidence", "structural"
            )
            for floor in ("L0", "L1", "L2"):
                for severity in ("low", "medium", "high", "critical"):
                    self.assertFalse(
                        scan_repo.gate_failed([finding], severity, block_min_proof=floor)
                    )

    def test_image_import_does_not_trigger_unrelated_pg_or_stream_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "image.ts").write_text(
                "import image from './icon.jpg'; export const asset = image;", encoding="utf-8"
            )
            with patch.object(
                js_config_checks,
                "signature_spans",
                side_effect=AssertionError("unrelated image import must not enter API signatures"),
            ):
                findings, stats = scan_repo.scan_repository(root)
            self.assertEqual(findings, [])
            self.assertTrue(stats["completeness"]["is_complete"])

    def test_scope_ignore_anchors_and_fingerprints(self):
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
            prefix = "--" if filename.endswith(".sql") else "//"
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

    def test_minimal_reports_and_fix_prompts_do_not_echo_data(self):
        marker = "private-database-context-marker"
        for row in records():
            case = row["positive"][0]
            prefix = "--" if case["path"].endswith(".sql") else "//"
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
                    self.assertNotIn("db.example", output)

    def test_python_node_json_and_sarif_parity(self):
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
                        "critical",
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
                    (f["rule_id"], f["fingerprint"], f["tier"])
                    for f in report["findings"]
                    if f["rule_id"] in NEW_IDS
                )

            self.assertEqual(keys(reports[0]), keys(reports[1]))
            self.assertEqual({row[0] for row in keys(reports[0])}, NEW_IDS)
            self.assertEqual(
                NEW_IDS.intersection(f["ruleId"] for f in reports[2]["runs"][0]["results"]), NEW_IDS
            )

    def test_sql_lexer_bounds_and_unavailable_evidence(self):
        for source in (
            "/* unclosed",
            "SELECT 'unclosed",
            'SELECT "unclosed',
            "DO $body$ unclosed",
            "SELECT 'a\\b'",
            "\\connect other",
            "SELECT (1",
            "SELECT 1)",
            "/*" * 129 + "*/" * 129,
        ):
            with self.subTest(source=source[:100]), self.assertRaises(sql_checks.LexicalLimitError):
                sql_checks.signature_spans(source)
        with (
            patch.object(sql_checks, "MAX_TOKENS", 3),
            self.assertRaises(sql_checks.LexicalLimitError),
        ):
            sql_checks.tokens("SELECT 1, 2, 3")
        self.assertEqual(sql_checks.tokens("-- comment without newline"), [])
        self.assertEqual(sql_checks.tokens("/* nested /* child */ parent */"), [])
        self.assertEqual(
            sql_checks.tokens("SELECT 'doubled '' quote', E'escaped\\' quote';")[-1][0], ";"
        )
        for value in ("not a literal", "$invalid", "'a\\b'"):
            self.assertIsNone(sql_checks.literal_body(value))
        self.assertEqual(sql_checks.signature_spans("; ; SELECT 1;"), [])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "migration.sql").write_text(
                "BEGIN; CREATE INDEX CONCURRENTLY idx ON a(id); /* unclosed", encoding="utf-8"
            )
            findings, stats = scan_repo.scan_repository(root)
            self.assertNotIn("SP705", {f.rule_id for f in findings})
            self.assertFalse(stats["completeness"]["is_complete"])

    def test_pg_url_analysis_is_bounded_and_does_not_connect(self):
        self.assertTrue(
            js_config_checks.pg_tls_override("postgres://db.example/app?sslmode=require")
        )
        for value in (
            "https://db.example/app?sslmode=require",
            "postgres://db.example:bad/app?sslmode=require",
            "postgres://db.example:65536/app?sslmode=require",
            "postgres://[invalid/app?sslmode=require",
            "postgres://db.example/app?sslmode=require#ignored",
            "postgres://db.example/app?" + "&".join(f"k{n}=v" for n in range(65)),
        ):
            self.assertFalse(js_config_checks.pg_tls_override(value))


if __name__ == "__main__":
    unittest.main()
