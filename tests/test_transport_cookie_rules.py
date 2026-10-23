from __future__ import annotations

import json
import shutil
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
from build_transport_cookie_contracts import cookie_records, records  # noqa: E402


class TransportCookieRulesTests(unittest.TestCase):
    def test_every_case_through_repository_walker(self):
        for row in records() + cookie_records():
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
                                side_effect=AssertionError("scan must stay offline"),
                            ):
                                findings, stats = scan_repo.scan_repository(root)
                        self.assertTrue(stats["completeness"]["is_complete"])
                        hits = [hit for hit in findings if hit.rule_id == row["rule_id"]]
                        expected = (
                            case["expected"]
                            if polarity == "adversarial"
                            else polarity == "positive"
                        )
                        self.assertEqual(len(hits), int(expected))
                        if hits:
                            self.assertEqual(
                                (hits[0].tier, hits[0].proof_level, hits[0].detection),
                                ("advisory", "L1", "structural"),
                            )
                            for floor in ("critical", "high", "medium", "low"):
                                for proof in ("L0", "L1", "L2"):
                                    self.assertFalse(
                                        scan_repo.gate_failed(hits, floor, block_min_proof=proof)
                                    )

    def test_suffixes_and_literal_lookalikes(self):
        for row in records():
            source = row["positive"][0]["source"]
            for suffix in scan_repo.JS_CONFIG_SUFFIXES | {".cs", ".dart", ".md", ".py"}:
                name = "transport" + suffix
                findings = scan_repo.find_regex_issues(Path(name), name, source)
                self.assertEqual(
                    row["rule_id"] in {hit.rule_id for hit in findings},
                    suffix in scan_repo.JS_CONFIG_SUFFIXES,
                )
        source = cookie_records()[0]["positive"][0]["source"]
        for suffix in (".ts", ".dart", ".md"):
            name = "cookies" + suffix
            self.assertNotIn(
                "SP056",
                {hit.rule_id for hit in scan_repo.find_regex_issues(Path(name), name, source)},
            )
        self.assertNotIn(
            "SP056",
            {
                hit.rule_id
                for hit in scan_repo.find_regex_issues(
                    Path("app.cs"), "app.cs", 'custom.cookie("session", value);'
                )
            },
        )

    def test_redaction_suppression_and_stable_fingerprints(self):
        for row in records() + cookie_records():
            case = row["positive"][0]
            marker = "private-cookie-transport-marker"
            source = (
                case["source"]
                .replace("value, new", f'"{marker}", new')
                .replace("minVersion:", f"passphrase:'{marker}',minVersion:")
            )
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / case["path"]
                path.write_text(source, encoding="utf-8")
                left = next(
                    hit
                    for hit in scan_repo.scan_repository(root)[0]
                    if hit.rule_id == row["rule_id"]
                )
                path.write_text("// line moved\n" + source, encoding="utf-8")
                right = next(
                    hit
                    for hit in scan_repo.scan_repository(root)[0]
                    if hit.rule_id == row["rule_id"]
                )
                self.assertEqual(left.fingerprint, right.fingerprint)
                self.assertEqual(left.line + 1, right.line)
                for output in (
                    left.evidence,
                    json.dumps(scan_repo.build_sarif_report([left], root)),
                    scan_repo.render_fix_prompts(root, [left], as_json=True, context_level="full"),
                ):
                    self.assertNotIn(marker, output)
                lines = source.splitlines()
                lines.insert(
                    left.line - 1, f"// shipproof-ignore {row['rule_id']} reviewed external policy"
                )
                path.write_text("\n".join(lines), encoding="utf-8")
                self.assertNotIn(
                    row["rule_id"], {hit.rule_id for hit in scan_repo.scan_repository(root)[0]}
                )

    def test_builder_is_deterministic(self):
        process = subprocess.run(
            [sys.executable, "scripts/build_transport_cookie_contracts.py", "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_unsupported_and_oversized_expressions_stay_unresolved(self):
        for row in records() + cookie_records():
            case = row["positive"][0]
            path = Path(case["path"])
            source = case["source"]
            padding = ",".join("item" for _ in range(300))
            if path.suffix == ".cs":
                source = source.replace(
                    "new CookieOptions {", "new CookieOptions { Extras = new[] {" + padding + "},"
                )
            else:
                source = source.replace("({", "({extras:[" + padding + "],")
            with self.subTest(rule=row["rule_id"]):
                self.assertNotIn(
                    row["rule_id"],
                    {hit.rule_id for hit in scan_repo.find_regex_issues(path, path.name, source)},
                )
            for prefix in ("/* unterminated\n", "const example = `unresolved ${value}`;\n"):
                if path.suffix == ".cs" and prefix.startswith("const"):
                    prefix = 'var example = $"unresolved {value}";\n'
                self.assertNotIn(
                    row["rule_id"],
                    {
                        hit.rule_id
                        for hit in scan_repo.find_regex_issues(
                            path, path.name, prefix + case["source"]
                        )
                    },
                )

    def test_http_identity_and_node_python_parity(self):
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node is required for CLI parity")
        source = "import https from 'node:https';\nhttps.request({minVersion:'TLSv1',agent:customAgent});"
        self.assertNotIn(
            "SP686",
            {hit.rule_id for hit in scan_repo.find_regex_issues(Path("app.ts"), "app.ts", source)},
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for row in records() + cookie_records():
                case = row["positive"][0]
                (root / (row["rule_id"] + Path(case["path"]).suffix)).write_text(
                    case["source"], encoding="utf-8"
                )
            findings, _ = scan_repo.scan_repository(root)
            process = subprocess.run(  # noqa: S603 - resolved test runtime; no shell or scanned code
                [node, "bin/shipproof.mjs", "scan", str(root), "--format", "json"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            actual = json.loads(process.stdout)["findings"]
            self.assertEqual(
                sorted((hit["rule_id"], hit["fingerprint"]) for hit in actual),
                sorted((hit.rule_id, hit.fingerprint) for hit in findings),
            )


if __name__ == "__main__":
    unittest.main()
