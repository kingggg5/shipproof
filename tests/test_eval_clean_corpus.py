from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "eval-clean-corpus.py"
SPEC = importlib.util.spec_from_file_location("eval_clean_corpus", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load clean-corpus evaluation harness")
eval_clean_corpus = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = eval_clean_corpus
SPEC.loader.exec_module(eval_clean_corpus)

LABELS = importlib.util.spec_from_file_location(
    "finding_labels", ROOT / "scripts" / "finding_labels.py"
)
if LABELS is None or LABELS.loader is None:
    raise RuntimeError("could not load finding label helpers")
finding_labels = importlib.util.module_from_spec(LABELS)
sys.modules[LABELS.name] = finding_labels
LABELS.loader.exec_module(finding_labels)


class CleanCorpusManifestTests(unittest.TestCase):
    def test_rejected_pair_keeps_the_original_raw_report(self):
        specification = {"name": "sample", "ecosystem": "python"}
        raw = {
            "package": "sample",
            "app_finding_records": [{"rule_id": "SP203", "severity": "high"}],
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(eval_clean_corpus, "install_python_package", return_value=Path(directory)),
            patch.object(eval_clean_corpus, "scan_package", return_value=raw),
            patch.object(
                eval_clean_corpus,
                "remediate_copy",
                side_effect=ValueError("original positives changed"),
            ),
        ):
            result = eval_clean_corpus.evaluate(specification, Path(directory), remediation={})
            self.assertEqual(result["app_finding_records"], raw["app_finding_records"])
            self.assertIn("original positives changed", result["_pair_error"])
            self.assertNotIn("_quiet", result)

    def test_checked_in_manifest_pins_the_documented_packages(self):
        manifest = eval_clean_corpus.load_manifest(ROOT / "benchmarks" / "clean-corpus.json")
        names = [item["name"] for item in manifest["packages"]]
        self.assertGreaterEqual(len(names), 30)
        self.assertEqual(len(set(names)), len(names))
        self.assertIn("flask", names)
        self.assertIn("ajv", names)
        self.assertIn("chi", names)
        self.assertIn("anyhow", names)
        ecosystems = {item["ecosystem"] for item in manifest["packages"]}
        self.assertEqual(ecosystems, {"python", "javascript", "go", "rust"})

    def test_manifest_rejects_unpinned_versions_and_path_escape(self):
        payload = {
            "schema_version": 1,
            "packages": [
                {
                    "name": "flask",
                    "ecosystem": "python",
                    "version": "latest",
                    "pypi": "Flask",
                    "import_name": "../flask",
                    "license_spdx": "BSD-3-Clause",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exact pin"):
                eval_clean_corpus.load_manifest(path)

    def test_manifest_rejects_go_module_escape(self):
        payload = {
            "schema_version": 1,
            "packages": [
                {
                    "name": "chi",
                    "ecosystem": "go",
                    "version": "v5.2.2",
                    "module": "github.com/go-chi/../evil",
                    "license_spdx": "MIT",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "module"):
                eval_clean_corpus.load_manifest(path)

    def test_digest_covers_only_scannable_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            (root / "__pycache__").mkdir()
            (root / "__pycache__" / "app.cpython-312.pyc").write_bytes(b"\x00\x01")
            first = eval_clean_corpus.sha256_scannable(root)
            (root / "__pycache__" / "other.pyc").write_bytes(b"changed")
            self.assertEqual(first, eval_clean_corpus.sha256_scannable(root))
            (root / "app.py").write_text("value = 2\n", encoding="utf-8")
            self.assertNotEqual(first, eval_clean_corpus.sha256_scannable(root))

    def test_digest_mismatch_is_invalid_evidence(self):
        specification = {
            "name": "sample",
            "ecosystem": "python",
            "version": "1.0.0",
            "pypi": "sample",
            "import_name": "sample",
            "license_spdx": "MIT",
            "source_sha256": "0" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            package = workspace / "sample-src"
            package.mkdir()
            (package / "mod.py").write_text("value = 1\n", encoding="utf-8")
            (package / "LICENSE").write_text("MIT\n", encoding="utf-8")
            with (
                patch.object(eval_clean_corpus, "install_python_package", return_value=package),
                self.assertRaisesRegex(RuntimeError, "source digest"),
            ):
                eval_clean_corpus.evaluate(specification, workspace)

    def test_missing_go_or_cargo_is_invalid_evidence(self):
        specification = {
            "name": "chi",
            "ecosystem": "go",
            "version": "v5.2.2",
            "module": "github.com/go-chi/chi/v5",
            "license_spdx": "MIT",
        }
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            with (
                patch.object(eval_clean_corpus.shutil, "which", return_value=None),
                self.assertRaisesRegex(RuntimeError, "go toolchain"),
            ):
                eval_clean_corpus.install_go_package(specification, workspace)
            rust = {
                "name": "anyhow",
                "ecosystem": "rust",
                "version": "1.0.99",
                "crate": "anyhow",
                "license_spdx": "MIT",
            }
            with (
                patch.object(eval_clean_corpus.shutil, "which", return_value=None),
                self.assertRaisesRegex(RuntimeError, "cargo toolchain"),
            ):
                eval_clean_corpus.install_rust_package(rust, workspace)


class FindingLabelTests(unittest.TestCase):
    def test_checked_in_medium_labels_load(self):
        records = finding_labels.load_label_records(ROOT / "benchmarks" / "labels")
        self.assertEqual(len(records), 10)
        self.assertTrue(all(item["label"] == "false_positive" for item in records))
        self.assertTrue(all(item["corpus"] == "clean-corpus" for item in records))

    def test_unreviewed_findings_are_not_scored_as_truth(self):
        labels = finding_labels.index_labels(
            [
                {
                    "corpus": "clean-corpus",
                    "package": "flask",
                    "revision": "3.1.3",
                    "fingerprint": "abc123def456",
                    "rule_id": "SP140",
                    "label": "false_positive",
                    "proof_level": "L0",
                    "application_scope": True,
                    "shipproof_version": "0.10.0",
                }
            ]
        )
        report = finding_labels.score_findings(
            [
                {
                    "fingerprint": "abc123def456",
                    "rule_id": "SP140",
                    "severity": "high",
                    "proof_level": "L0",
                },
                {
                    "fingerprint": "ffffffffffffffff",
                    "rule_id": "SP101",
                    "severity": "high",
                    "proof_level": "L0",
                },
            ],
            labels,
            corpus="clean-corpus",
            package="flask",
            revision="3.1.3",
        )
        self.assertEqual(report["unreviewed"], 1)
        self.assertEqual(report["by_rule"]["SP140"]["false_positive"], 1)
        self.assertEqual(report["by_rule"]["SP140"]["precision"], 0.0)
        self.assertNotIn("SP101", report["by_rule"])

    def test_duplicate_label_keys_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "labels.jsonl"
            record = {
                "corpus": "clean-corpus",
                "package": "flask",
                "revision": "3.1.3",
                "fingerprint": "abc123def456",
                "rule_id": "SP140",
                "label": "false_positive",
                "proof_level": "L0",
                "application_scope": True,
                "shipproof_version": "0.10.0",
            }
            path.write_text(json.dumps(record) + "\n" + json.dumps(record) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate label key"):
                finding_labels.load_label_records(Path(directory))

    def test_fp_budget_requires_repeated_false_positives_without_true_positives(self):
        matrix = {
            "SP140": {
                "true_positive": 0,
                "false_positive": 2,
                "needs_context": 0,
                "duplicate": 0,
                "reviewed": 2,
                "precision": 0.0,
            },
            "SP101": {
                "true_positive": 1,
                "false_positive": 3,
                "needs_context": 0,
                "duplicate": 0,
                "reviewed": 4,
                "precision": 0.25,
            },
            "SP061": {
                "true_positive": 0,
                "false_positive": 4,
                "needs_context": 0,
                "duplicate": 0,
                "reviewed": 4,
                "precision": 0.0,
            },
        }
        self.assertEqual(finding_labels.fp_budget_violations(matrix), ["SP061", "SP140"])
        self.assertEqual(
            finding_labels.fp_budget_violations(matrix, high_critical_rule_ids={"SP140", "SP101"}),
            ["SP140"],
        )

    def test_classifier_and_licenses_dir_satisfy_license_review(self):
        with tempfile.TemporaryDirectory() as directory:
            site = Path(directory)
            package = site / "jinja2"
            package.mkdir()
            (package / "__init__.py").write_text("value = 1\n", encoding="utf-8")
            dist = site / "jinja2-3.1.6.dist-info"
            dist.mkdir()
            (dist / "METADATA").write_text(
                "Name: Jinja2\nClassifier: License :: OSI Approved :: BSD License\n",
                encoding="utf-8",
            )
            licenses = dist / "licenses"
            licenses.mkdir()
            (licenses / "LICENSE.txt").write_text("BSD-3-Clause\n", encoding="utf-8")
            self.assertTrue(eval_clean_corpus.license_present(package))


if __name__ == "__main__":
    unittest.main()
