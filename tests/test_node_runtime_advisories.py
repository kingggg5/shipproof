"""Real-file and adapter contracts for declared Node runtime advisories."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
import node_advisories  # noqa: E402
import polyglot_checks  # noqa: E402
import scan_repo  # noqa: E402


class NodeRuntimeAdvisoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        manifest = json.loads((ROOT / "tests/rule_cases_v2.json").read_text(encoding="utf-8"))
        cls.rows = [row for row in manifest["rules"] if row["rule_id"] in {"SP684", "SP685"}]

    def test_all_declarations_through_real_walker(self):
        self.assertEqual(len(self.rows), 2)
        for row in self.rows:
            for polarity, minimum in (("positive", 3), ("negative", 5), ("adversarial", 2)):
                self.assertGreaterEqual(len(row[polarity]), minimum)
                for case in row[polarity]:
                    with (
                        self.subTest(rule=row["rule_id"], case=case),
                        tempfile.TemporaryDirectory() as directory,
                    ):
                        root = Path(directory)
                        path = root / case["path"]
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text(case["source"], encoding="utf-8")
                        findings, stats = scan_repo.scan_repository(root)
                        self.assertTrue(stats["completeness"]["is_complete"])
                        hits = [item for item in findings if item.rule_id == row["rule_id"]]
                        expected = case.get("expected", polarity == "positive")
                        self.assertEqual(len(hits), int(expected))
                        for hit in hits:
                            self.assertEqual(hit.proof_level, "L1")
                            self.assertEqual(hit.tier, "advisory")
                            self.assertEqual(hit.severity, row["expected_severity"])

    def test_branch_comparison_and_eol_do_not_overlap(self):
        for major, (minor, patch_number) in node_advisories.FIXED_RELEASES.items():
            self.assertEqual(
                node_advisories.version_rule(f"{major}.{minor}.{patch_number - 1}"), "SP684"
            )
            self.assertEqual(node_advisories.version_rule(f"{major}.{minor - 1}.9999"), "SP684")
            self.assertIsNone(node_advisories.version_rule(f"{major}.{minor}.{patch_number}"))
            self.assertIsNone(node_advisories.version_rule(f"{major}.{minor + 1}.0"))
        for major in node_advisories.ENDED_BRANCHES:
            self.assertEqual(node_advisories.version_rule(f"{major}.0.0"), "SP685")
        for value in (
            "24.22.0-ubuntu1",
            "24.22.0+vendor",
            "24.022.0",
            "24.22." + "9" * 5000,
            "27.0.0",
            "16.0.0",
        ):
            self.assertIsNone(node_advisories.version_rule(value))

    def test_offline_advisory_never_becomes_blocking_at_lower_floors(self):
        for version, expected_rule in (("24.22.0", "SP684"), ("20.19.0", "SP685")):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / ".node-version").write_text(version, encoding="utf-8")
                with patch(
                    "subprocess.run",
                    side_effect=AssertionError("network/process execution is not allowed"),
                ):
                    findings, stats = scan_repo.scan_repository(root)
                hits = [item for item in findings if item.rule_id in {"SP684", "SP685"}]
                self.assertEqual([hit.rule_id for hit in hits], [expected_rule])
                self.assertTrue(stats["completeness"]["is_complete"])
                for severity in ("critical", "high", "medium", "low"):
                    for proof in ("L0", "L1", "L2"):
                        self.assertFalse(
                            scan_repo.gate_failed(hits, severity, block_min_proof=proof)
                        )

    def test_comments_never_leak_into_evidence_or_full_fix_context(self):
        marker = "private-deployment-comment-do-not-copy"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".nvmrc").write_text("24.22.0 # " + marker + "\n", encoding="utf-8")
            findings, _ = scan_repo.scan_repository(root)
            hits = [finding for finding in findings if finding.rule_id == "SP684"]
            self.assertEqual(len(hits), 1)
            for rendered in (
                hits[0].evidence,
                json.dumps(scan_repo.build_sarif_report(hits, root)),
                scan_repo.render_fix_prompts(root, hits, as_json=True, context_level="full"),
            ):
                self.assertNotIn(marker, rendered)

    def test_line_move_fingerprint_and_reviewed_suppression(self):
        before = scan_repo.find_regex_issues(Path(".nvmrc"), ".nvmrc", "24.22.0\n")
        after = scan_repo.find_regex_issues(Path(".nvmrc"), ".nvmrc", "# moved\n24.22.0\n")
        left = next(item for item in before if item.rule_id == "SP684")
        right = next(item for item in after if item.rule_id == "SP684")
        self.assertEqual(left.fingerprint, right.fingerprint)
        self.assertEqual((left.line, right.line), (1, 2))
        ignored = scan_repo.find_regex_issues(
            Path(".nvmrc"), ".nvmrc", "# shipproof-ignore SP684 vendor backport verified\n24.22.0\n"
        )
        self.assertNotIn("SP684", {item.rule_id for item in ignored})

    def test_builder_is_deterministic(self):
        result = subprocess.run(
            [sys.executable, "scripts/build_node_runtime_contracts.py", "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_token_offsets_and_error_limits_are_preserved(self):
        source = " \t\r\n\u00a0\u2003\x1cvalue\n\t (42)"
        expected = [
            (word, source.index(word), source.index(word) + len(word))
            for word in ("value", "(", "42", ")")
        ]
        for language in ("lua", "rust", "go"):
            self.assertEqual(polyglot_checks.tokens(source, language), expected)
            with self.assertRaises(polyglot_checks.LexicalLimitError):
                polyglot_checks.tokens("\t " * 10000 + '"unterminated', language)
            with self.assertRaises(polyglot_checks.LexicalLimitError):
                polyglot_checks.tokens("value; " * 26000, language)

    def test_many_blank_lines_stay_within_memory_budget(self):
        source = "\n" * 100_000 + "24.22.1\n"
        was_tracing = tracemalloc.is_tracing()
        tracemalloc.start()
        baseline, _peak = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        try:
            self.assertEqual(node_advisories.advisory_declarations(Path(".nvmrc"), source), [])
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            if not was_tracing:
                tracemalloc.stop()
        self.assertLess(
            peak - baseline,
            4_000_000,
            "100KB version file exceeds the 4MB parser allocation budget",
        )

    def test_case_variant_filenames_do_not_claim_runtime_identity(self):
        for filename in (".NVMRC", ".NODE-VERSION"):
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / filename).write_text("24.22.0\n", encoding="utf-8")
                findings, stats = scan_repo.scan_repository(root)
                self.assertEqual(stats["files_scanned"], 1)
                self.assertFalse(any(item.rule_id in {"SP684", "SP685"} for item in findings))


if __name__ == "__main__":
    unittest.main()
