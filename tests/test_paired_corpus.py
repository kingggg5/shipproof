"""Paired evaluation must not turn original true signals into quiet successes."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from paired_corpus import (  # noqa: E402
    canonical_sha,
    load_plan,
    remediate_copy,
    validate_report,
)


class PairedCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = load_plan()
        cls.report = json.loads(
            (ROOT / "benchmarks/clean-corpus-baseline.json").read_text(encoding="utf-8")
        )

    def test_all_original_packages_pins_and_positive_sites_remain(self):
        quiet = validate_report(self.report)
        self.assertEqual(len(self.report["packages"]), 30)
        self.assertEqual(self.report["summary"]["files"], 867)
        self.assertEqual(quiet["summary"]["files"], 867)
        self.assertEqual(sum(len(item["expected_findings"]) for item in self.plan["packages"]), 54)
        self.assertEqual(
            sum(receipt["positive_observed"] for receipt in self.report["paired"]["receipts"]), 54
        )
        manifest = json.loads((ROOT / "benchmarks/clean-corpus.json").read_text(encoding="utf-8"))
        self.assertEqual(canonical_sha(manifest), self.plan["manifest_canonical_sha256"])
        entries = {entry["package"]: entry for entry in self.plan["packages"]}
        for spec in manifest["packages"]:
            if spec.get("source_sha256"):
                self.assertEqual(spec["source_sha256"], entries[spec["name"]]["source_sha256"])

    def test_original_findings_are_not_filtered_or_reclassified_as_quiet(self):
        original_highs = [
            f
            for p in self.report["packages"]
            for f in p["app_finding_records"]
            if f["severity"] in {"high", "critical"}
        ]
        self.assertEqual(len(original_highs), 54)
        self.assertEqual(sum(f["rule_id"] == "SP203" for f in original_highs), 51)
        self.assertEqual(self.report["summary"]["blocked_count"], 1)
        self.assertEqual(self.report["paired"]["quiet"]["summary"]["blocked_count"], 0)

    def test_missing_duplicate_or_renamed_packages_are_invalid(self):
        for kind in ("missing", "duplicate", "renamed"):
            report = copy.deepcopy(self.report)
            rows = report["paired"]["quiet"]["packages"]
            if kind == "missing":
                rows.pop()
            elif kind == "duplicate":
                rows[-1] = rows[0]
            else:
                rows[-1]["package"] = "replacement"
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                validate_report(report)

    def test_lost_original_positive_or_changed_severity_fails(self):
        for mutation in ("drop", "severity", "line", "scope"):
            report = copy.deepcopy(self.report)
            package = next(p for p in report["packages"] if p["package"] == "chi")
            index = next(
                i for i, f in enumerate(package["app_finding_records"]) if f["rule_id"] == "SP377"
            )
            if mutation == "drop":
                package["app_finding_records"].pop(index)
                package["app_findings"] -= 1
            else:
                field, value = {
                    "severity": ("severity", "low"),
                    "line": ("line", 1),
                    "scope": ("scope", "test"),
                }[mutation]
                package["app_finding_records"][index][field] = value
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_report(report)

    def test_source_receipts_coverage_and_summaries_are_bound(self):
        for mutation in (
            "original_digest",
            "quiet_digest",
            "receipt",
            "files",
            "profile",
            "coverage",
            "missing_ledger",
            "truncation",
            "summary",
            "unavailable",
            "plan",
        ):
            report = copy.deepcopy(self.report)
            package = report["packages"][0]
            quiet = report["paired"]["quiet"]["packages"][0]
            if mutation == "original_digest":
                package["source_sha256"] = "0" * 64
            elif mutation == "quiet_digest":
                quiet["source_sha256"] = "0" * 64
            elif mutation == "receipt":
                report["paired"]["receipts"][0]["positive_observed"] += 1
            elif mutation == "files":
                package["files"] = quiet["files"] = 0
            elif mutation == "profile":
                quiet["scan_profile"] = "application"
            elif mutation == "coverage":
                package["completeness"]["parser_limit"] = 1
            elif mutation == "missing_ledger":
                package["completeness"] = quiet["completeness"] = {}
            elif mutation == "truncation":
                quiet["app_findings"] += 1
            elif mutation == "summary":
                report["paired"]["quiet"]["summary"]["files"] = 0
            elif mutation == "unavailable":
                report["unavailable"] = ["missing Go"]
            else:
                report["paired"]["plan_canonical_sha256"] = "0" * 64
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_report(report)

    def test_plan_rejects_path_escape_suppression_and_changed_manifest(self):
        for mutation in ("path", "suppression", "manifest", "variant"):
            plan = copy.deepcopy(self.plan)
            entry = next(item for item in plan["packages"] if item["edits"])
            if mutation == "path":
                entry["edits"][0]["path"] = "../escape.py"
            elif mutation == "suppression":
                entry["edits"][0]["replacements"][0]["after_hex"] = (
                    b"# shipproof:ignore SP102".hex()
                )
            elif mutation == "variant":
                entry["source_sha256_variants"] = ["0" * 64]
            else:
                plan["manifest_canonical_sha256"] = "0" * 64
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "plan.json"
                path.write_text(json.dumps(plan), encoding="utf-8")
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    load_plan(path)

    def test_copy_changes_exact_reviewed_bytes_but_never_the_original(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            source = workspace / "sample"
            source.mkdir()
            before, after = b"flag = True\n", b"flag = False\n"
            (source / "app.py").write_bytes(before)

            def digest(root):
                return hashlib.sha256((root / "app.py").read_bytes()).hexdigest()

            original_hash, fixed_hash = (
                hashlib.sha256(before).hexdigest(),
                hashlib.sha256(after).hexdigest(),
            )
            original = {
                "package": "sample",
                "source_sha256": original_hash,
                "files": 1,
                "scan_profile": "library",
                "completeness": {},
                "app_finding_records": [],
            }
            entry = {
                "source_sha256": original_hash,
                "remediated_source_sha256": fixed_hash,
                "expected_findings": [],
                "edits": [
                    {
                        "path": "app.py",
                        "before_sha256": original_hash,
                        "after_sha256": fixed_hash,
                        "replacements": [
                            {"before_hex": before.hex(), "after_hex": after.hex(), "count": 1}
                        ],
                    }
                ],
            }

            def scan(spec, target, *, verify_source):
                self.assertFalse(verify_source)
                self.assertEqual((target / "app.py").read_bytes(), after)
                return {**original, "source_sha256": digest(target)}

            quiet, receipt = remediate_copy(
                {"name": "sample"}, source, workspace, original, entry, scan, digest
            )
            self.assertEqual((source / "app.py").read_bytes(), before)
            self.assertEqual(quiet["source_sha256"], fixed_hash)
            self.assertEqual(receipt["source_sha256"], original_hash)
            entry["edits"][0]["replacements"][0]["count"] = 2
            with self.assertRaisesRegex(ValueError, "occurrence"):
                remediate_copy({"name": "sample"}, source, workspace, original, entry, scan, digest)
            self.assertEqual((source / "app.py").read_bytes(), before)
            self.assertEqual(list(workspace.glob("shipproof-paired-*")), [])


if __name__ == "__main__":
    unittest.main()
