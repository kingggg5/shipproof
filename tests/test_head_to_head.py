from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "benchmarks" / "head_to_head.py"
SPEC = importlib.util.spec_from_file_location("head_to_head", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load head-to-head harness")
head_to_head = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = head_to_head
SPEC.loader.exec_module(head_to_head)


class FileMetricsTests(unittest.TestCase):
    def test_perfect_detection(self):
        metrics = head_to_head.compute_file_metrics(["app.js"], ["app.js"])
        self.assertEqual(metrics["true_positives"], 1)
        self.assertEqual(metrics["false_positives"], 0)
        self.assertEqual(metrics["file_precision"], 1.0)
        self.assertEqual(metrics["file_recall"], 1.0)
        self.assertEqual(metrics["file_f1"], 1.0)

    def test_partial_and_clean_corpus_scoring(self):
        metrics = head_to_head.compute_file_metrics(["app.js", "util.js"], ["app.py", "util.js"])
        self.assertEqual(metrics["true_positives"], 1)
        self.assertEqual(metrics["false_positives"], 1)
        self.assertEqual(metrics["false_negatives"], 1)
        self.assertEqual(metrics["file_precision"], 0.5)
        self.assertEqual(metrics["file_recall"], 0.5)

    def test_clean_corpus_needs_no_labels(self):
        metrics = head_to_head.compute_file_metrics([], [])
        self.assertIsNone(metrics["file_precision"])
        self.assertIsNone(metrics["file_recall"])
        self.assertEqual(metrics["false_positives"], 0)


class LabelLoadingTests(unittest.TestCase):
    def test_missing_label_file_fails_closed(self):
        with self.assertRaises(FileNotFoundError):
            head_to_head.load_labels(ROOT / "does-not-exist.json", [ROOT / "fixtures"])

    def test_default_labels_cover_the_fixture_corpora(self):
        labels = head_to_head.load_labels(
            head_to_head.DEFAULT_LABELS,
            [
                ROOT / "fixtures" / "vulnerable-node-api",
                ROOT / "fixtures" / "vulnerable-python-api",
                ROOT / "fixtures" / "secure-node-api",
            ],
        )
        self.assertEqual(labels["vulnerable-node-api"], ["app.js"])
        self.assertEqual(labels["vulnerable-python-api"], ["app.py"])
        self.assertEqual(labels["secure-node-api"], [])


class ShipProofLegTests(unittest.TestCase):
    def test_shipproof_leg_flags_the_labeled_file(self):
        corpus = ROOT / "fixtures" / "vulnerable-python-api"
        result = head_to_head.run_shipproof(corpus, repeat=1)
        self.assertEqual(result["tool"], "shipproof")
        self.assertEqual(result["files_flagged"], ["app.py"])
        self.assertGreater(result["findings"], 0)
        self.assertGreater(result["median_seconds"], 0)


class SemgrepLegTests(unittest.TestCase):
    def test_command_uses_one_corpus_argument_and_absolute_configs(self):
        corpus = ROOT / "fixtures" / "secure-node-api"
        config = ROOT / "benchmarks" / "semgrep-comparison" / "rules.yml"
        command = head_to_head.build_semgrep_command(corpus, [str(config)])
        self.assertEqual(command[-1], corpus.name)
        self.assertEqual(command.count(corpus.name), 1)
        self.assertEqual(command[-3:-1], ["--config", str(config.resolve())])


class RenderingTests(unittest.TestCase):
    def test_markdown_render_includes_every_row(self):
        markdown = head_to_head.render_markdown(
            [
                {
                    "tool": "shipproof",
                    "corpus": "demo",
                    "result": {"median_seconds": 1.5, "findings": 3, "files_flagged": ["a.py"]},
                    "metrics": head_to_head.compute_file_metrics(["a.py"], ["a.py"]),
                }
            ]
        )
        self.assertIn("| Tool | Corpus | Median seconds |", markdown)
        self.assertIn("| shipproof | demo | 1.5 | 3 | 1 |", markdown)


class MainTests(unittest.TestCase):
    def test_main_runs_shipproof_only_and_exits_zero(self):
        corpus = ROOT / "fixtures" / "secure-node-api"
        self.assertEqual(head_to_head.main([str(corpus), "--repeat", "1", "--format", "json"]), 0)

    def test_main_rejects_missing_corpus(self):
        self.assertEqual(head_to_head.main([str(ROOT / "missing-corpus")]), 2)


if __name__ == "__main__":
    unittest.main()
