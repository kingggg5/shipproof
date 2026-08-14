from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).parents[1] / "skills" / "engineer-production-systems" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from check_budget import evaluate, markdown  # noqa: E402


class BudgetTests(unittest.TestCase):
    def test_lower_is_better_within_budget(self):
        payload = evaluate(
            {"metrics": {"rss_mb": 100}},
            {"metrics": {"rss_mb": 104}},
            {"metrics": {"rss_mb": {"direction": "lower", "max_regression_percent": 5, "max": 110}}},
        )
        self.assertTrue(payload["passed"])
        self.assertIn("PASS", markdown(payload))

    def test_cpu_regression_fails(self):
        payload = evaluate(
            {"cpu_ms": 10},
            {"cpu_ms": 12},
            {"cpu_ms": {"max_regression_percent": 10}},
        )
        self.assertFalse(payload["passed"])
        self.assertEqual(payload["results"][0]["status"], "fail")

    def test_higher_is_better_throughput(self):
        payload = evaluate(
            {"throughput_rps": 100},
            {"throughput_rps": 92},
            {"throughput_rps": {"direction": "higher", "max_regression_percent": 5, "min": 90}},
        )
        self.assertFalse(payload["passed"])
        self.assertAlmostEqual(payload["results"][0]["regression_percent"], 8)

    def test_missing_metric_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            evaluate({"rss_mb": 100}, {}, {"rss_mb": {"max": 120}})

    def test_invalid_rule_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "direction"):
            evaluate({"rss_mb": 100}, {"rss_mb": 101}, {"rss_mb": {"direction": "sideways", "max": 120}})

    def test_cli_execution_with_files(self):
        import contextlib
        import io
        import json
        from check_budget import main
        from unittest.mock import patch
        payloads = [
            json.dumps({"p95_ms": 100}),
            json.dumps({"p95_ms": 103}),
            json.dumps({"p95_ms": {"max_regression_percent": 5}}),
        ]
        with patch("check_budget.Path.read_text", side_effect=payloads), contextlib.redirect_stdout(io.StringIO()):
            code = main(["--baseline", "base.json", "--current", "curr.json", "--budget", "budg.json"])
            self.assertEqual(code, 0)

    def test_multiple_stdin_inputs_fail_closed(self):
        import contextlib
        import io
        from check_budget import main
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--baseline", "-", "--current", "-", "--budget", "budget.json"]), 2)


if __name__ == "__main__":
    unittest.main()
