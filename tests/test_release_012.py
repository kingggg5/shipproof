from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
import php_advisories  # noqa: E402
from scan_repo import (  # noqa: E402
    MINIMIZED_EVIDENCE_RULE_IDS,
    build_json_report,
    build_sarif_report,
    find_regex_issues,
    find_rule,
    gate_failed,
    make_finding,
    read_finding_context,
    render_fix_prompts,
    render_markdown_report,
    render_terminal_report,
    scan_repository,
)


class Release012Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        manifest = json.loads((ROOT / "tests/rule_cases_v2.json").read_text(encoding="utf-8"))
        cls.records = [
            row for row in manifest["rules"] if row["rule_id"] in {"SP668", "SP670", "SP683"}
        ]

    def test_all_three_contracts_through_real_file_walker(self):
        self.assertEqual(len(self.records), 3)
        for row in self.records:
            for polarity in ("positive", "negative", "adversarial"):
                for case in row[polarity]:
                    with self.subTest(rule=row["rule_id"], source=case["source"]):
                        with tempfile.TemporaryDirectory(
                            prefix="shipproof-release012-"
                        ) as directory:
                            root = Path(directory)
                            (root / case["path"]).write_text(case["source"], encoding="utf-8")
                            findings, stats = scan_repository(root)
                        expected = (
                            case["expected"]
                            if polarity == "adversarial"
                            else polarity == "positive"
                        )
                        hits = [
                            finding for finding in findings if finding.rule_id == row["rule_id"]
                        ]
                        self.assertEqual(bool(hits), expected)
                        self.assertTrue(stats["completeness"]["is_complete"])
                        if expected:
                            self.assertEqual(len(hits), 1)
                            self.assertEqual(hits[0].tier, "advisory")
                            self.assertEqual(
                                hits[0].proof_level, "L0" if row["rule_id"] == "SP668" else "L1"
                            )

    def test_php_branch_cutoffs_and_unsupported_versions_are_explicit(self):
        for (major, minor), fixed in php_advisories.FIXED_PATCHES.items():
            with self.subTest(branch=(major, minor)):
                self.assertEqual(
                    php_advisories.version_status(f"{major}.{minor}.{fixed - 1}"), "predates_fix"
                )
                self.assertEqual(
                    php_advisories.version_status(f"{major}.{minor}.{fixed}"), "fixed_upstream"
                )
                self.assertEqual(
                    php_advisories.version_status(f"{major}.{minor}.{fixed + 1}"), "fixed_upstream"
                )
        for version in ("5.6.40", "7.4.33", "8.0.30", "8.1.33"):
            self.assertEqual(php_advisories.version_status(version), "unsupported_upstream")
        for version in (
            "5.3.29",
            "6.0.0",
            "8.6.0RC3",
            "9.0.0",
            "8.4",
            "^8.4.26",
            "8.4.26-1ubuntu1",
            "8.4.00026",
            "8.4." + "9" * 5000,
        ):
            self.assertEqual(php_advisories.version_status(version), "unknown")

    def test_php_stage_aliases_and_continuations_do_not_invent_runtime(self):
        expected = ("8.4.26", 1)
        self.assertEqual(
            php_advisories.docker_runtime("FROM php:8.4.26-fpm AS base\nFROM base AS final\n"),
            expected,
        )
        self.assertIsNone(
            php_advisories.docker_runtime(
                "FROM php:8.4.26-fpm AS build\nFROM nginx:1.27\nCOPY --from=build /app /app\n"
            )
        )
        self.assertEqual(
            php_advisories.docker_runtime(
                "FROM php:8.4.27-fpm\nRUN echo hi \\\nFROM php:8.4.26-fpm\n"
            ),
            ("8.4.27", 1),
        )
        self.assertEqual(
            php_advisories.docker_runtime(
                "FROM php:8.4.27-fpm\nRUN echo hi \\\n# comment\nFROM php:8.4.26-fpm\n"
            ),
            ("8.4.27", 1),
        )
        self.assertIsNone(php_advisories.docker_runtime("FROM php:8.4.26-fpm\nFROM ${UNKNOWN}\n"))
        self.assertIsNone(
            php_advisories.docker_runtime(
                "FROM php:8.4.26-fpm AS duplicate\nFROM duplicate AS duplicate\n"
            )
        )
        self.assertEqual(
            php_advisories.docker_runtime("# escape=`\nFROM `\nphp:8.4.26-fpm\n"), ("8.4.26", 2)
        )
        # Parser directives after ordinary comments are ignored by Docker.
        self.assertEqual(
            php_advisories.docker_runtime(
                "# description\n# escape=`\nFROM php:8.4.27-fpm\nRUN echo hi \\\nFROM php:8.4.26-fpm\n"
            ),
            ("8.4.27", 3),
        )

    def test_php_cve_findings_are_offline_nonexecuting_and_never_block(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".php-version").write_text("8.4.26\n", encoding="utf-8")
            with patch(
                "subprocess.run", side_effect=AssertionError("external process not allowed")
            ):
                findings, _ = scan_repository(root)
            hits = [finding for finding in findings if finding.rule_id == "SP683"]
            self.assertEqual(len(hits), 1)
            for severity in ("low", "medium", "high", "critical"):
                self.assertFalse(gate_failed(hits, severity, block_min_proof="L0"))
            self.assertIn("CVE-2026-109618", hits[0].message)
            self.assertIn("CVE-2026-109619", hits[0].message)
            self.assertIn("vendor", hits[0].remediation)
            sarif = build_sarif_report(hits, root)
            self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "SP683")

    def test_ini_mitigations_are_not_mistaken_for_a_runtime_patch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".php-version").write_text("8.4.26\n", encoding="utf-8")
            (root / "php.ini").write_text(
                "session.upload_progress.enabled=0\nmemory_limit=-1\n", encoding="utf-8"
            )
            findings, _ = scan_repository(root)
            self.assertIn("SP683", {finding.rule_id for finding in findings})

    def test_inline_ignore_and_shift_stable_fingerprint(self):
        before = find_regex_issues(Path(".php-version"), ".php-version", "8.4.26\n")
        after = find_regex_issues(Path(".php-version"), ".php-version", "# moved\n8.4.26\n")
        left = next(finding for finding in before if finding.rule_id == "SP683")
        right = next(finding for finding in after if finding.rule_id == "SP683")
        self.assertEqual(left.fingerprint, right.fingerprint)
        ignored = find_regex_issues(
            Path("Dockerfile"),
            "Dockerfile",
            "# shipproof-ignore SP683 vendor backport verified\nFROM php:8.4.26-fpm\n",
        )
        self.assertNotIn("SP683", {finding.rule_id for finding in ignored})

    def test_php_node_cli_parity_and_both_cve_references(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".tool-versions").write_text("php 8.3.35\n", encoding="utf-8")
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
                done = subprocess.run(  # noqa: S603 - fixed local bridge tests
                    command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=False
                )
                self.assertEqual(done.returncode, 0, done.stderr)
                findings = json.loads(done.stdout)["findings"]
                outputs.append(
                    [
                        (finding["rule_id"], finding["fingerprint"], finding["tier"])
                        for finding in findings
                    ]
                )
            self.assertEqual(outputs[0], outputs[1])
            self.assertEqual(outputs[0][0][0], "SP683")

    def test_release_contracts_are_reproducible(self):
        done = subprocess.run(  # noqa: S603 - fixed local generator
            [sys.executable, str(ROOT / "scripts/build_release_012_contracts.py"), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(done.returncode, 0, done.stderr or done.stdout)

    def test_new_advisory_evidence_never_echoes_raw_line_secrets(self):
        canary = "synthetic-only-" + hashlib.sha256(b"advisory-redaction-test").hexdigest()
        for rule_id in MINIMIZED_EVIDENCE_RULE_IDS:
            with self.subTest(rule=rule_id):
                item = make_finding(
                    find_rule(rule_id),
                    "app.ts",
                    1,
                    "observed code; private=" + canary,
                    "structural",
                )
                self.assertNotIn(canary, item.evidence)
                self.assertNotIn(canary, json.dumps(read_finding_context(ROOT, item)))

    def test_version_comments_jwt_arguments_and_nearby_lines_are_not_exported(self):
        canary = "synthetic-only-" + hashlib.sha256(b"not-a-real-key-local-fixture").hexdigest()
        cases = [
            (".php-version", "8.4.26 # private_key=" + canary + "\n", {"SP683"}, "8.4.26"),
            (
                "auth.ts",
                "import jwt from 'jsonwebtoken';\nconst nearbyPrivate = '"
                + canary
                + "';\njwt.verify(token, '"
                + canary
                + "', {ignoreExpiration: true, allowInvalidAsymmetricKeyTypes: true});\n",
                {"SP675", "SP676"},
                "ignoreExpiration=true",
            ),
        ]
        for filename, source, rule_ids, expected_proof in cases:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / filename).write_text(source, encoding="utf-8")
                all_findings, stats = scan_repository(root)
                findings = [item for item in all_findings if item.rule_id in rule_ids]
                self.assertEqual({item.rule_id for item in findings}, rule_ids)
                outputs = [
                    json.dumps(build_json_report(root, all_findings, stats)),
                    json.dumps(build_sarif_report(all_findings, root)),
                    render_markdown_report(root, all_findings, stats),
                    render_terminal_report(root, all_findings, stats),
                    render_fix_prompts(root, all_findings, as_json=True, context_level="full"),
                ]
                self.assertTrue(any(expected_proof in item.evidence for item in findings))
                for output in outputs:
                    self.assertNotIn(canary, output)


if __name__ == "__main__":
    unittest.main()
