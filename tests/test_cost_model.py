import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from cost_model import calculate_cost, main  # noqa: E402


class CostModelTests(unittest.TestCase):
    def test_single_turn_cost_calculation(self):
        est = calculate_cost(
            model="claude-3-5-sonnet",
            context_tokens=100_000,
            output_tokens_per_iteration=1_000,
            iterations=1,
            use_prompt_caching=True,
        )
        self.assertEqual(est.iterations, 1)
        self.assertEqual(est.total_input_tokens, 100_000)
        self.assertEqual(est.total_output_tokens, 1_000)
        self.assertEqual(est.cached_input_tokens, 0)
        # 100k input * $3/M = $0.30; 1k output * $15/M = $0.015 -> $0.315
        self.assertAlmostEqual(est.estimated_cost_usd_single_run, 0.315, places=3)

    def test_prompt_caching_multi_turn_savings(self):
        est_cached = calculate_cost(
            model="claude-3-5-sonnet",
            context_tokens=50_000,
            output_tokens_per_iteration=1_000,
            iterations=5,
            use_prompt_caching=True,
        )
        est_no_cache = calculate_cost(
            model="claude-3-5-sonnet",
            context_tokens=50_000,
            output_tokens_per_iteration=1_000,
            iterations=5,
            use_prompt_caching=False,
        )
        self.assertGreater(
            est_no_cache.estimated_cost_usd_single_run, est_cached.estimated_cost_usd_single_run
        )
        self.assertGreater(est_cached.savings_from_caching_usd, 0.0)

    def test_budget_gate_pass_and_exceeded(self):
        est_pass = calculate_cost(
            model="gpt-4o-mini",
            context_tokens=10_000,
            iterations=2,
            budget_usd=1.00,
        )
        self.assertEqual(est_pass.budget_status, "PASS")

        est_fail = calculate_cost(
            model="claude-3-7-sonnet",
            context_tokens=200_000,
            iterations=5,
            budget_usd=0.01,
        )
        self.assertEqual(est_fail.budget_status, "EXCEEDED")

    def test_cli_exit_code_on_budget_exceeded(self):
        code = main(["--context-tokens", "200000", "--budget-usd", "0.0001", "--format", "json"])
        self.assertEqual(code, 1)

    def test_cli_exit_code_on_success(self):
        code = main(["--context-tokens", "1000", "--budget-usd", "50.0", "--format", "json"])
        self.assertEqual(code, 0)

    def test_new_2026_model_profiles(self):
        for model_name in [
            "claude-sonnet-5",
            "claude-3-7-sonnet",
            "gpt-4.5",
            "o1",
            "o3-mini",
            "o4-mini",
            "gemini-3-7-flash",
            "gemini-2-0-flash",
            "gemini-2-0-pro",
            "deepseek-v4-flash",
            "deepseek-v4-pro",
            "deepseek-v3",
            "deepseek-r1",
            "mistral-large",
            "codestral",
            "llama-3.3-70b",
        ]:
            est = calculate_cost(
                model=model_name,
                context_tokens=10_000,
                iterations=2,
            )
            self.assertGreater(est.estimated_cost_usd_single_run, 0.0)

    def test_rendering_and_cadence_options(self):
        from cost_model import estimate_codebase_tokens, format_markdown, format_terminal

        tokens = estimate_codebase_tokens(ROOT)
        self.assertGreater(tokens, 0)

        for cadence in ["once", "per-pr", "hourly", "daily", "weekly", "monthly"]:
            est = calculate_cost(
                model="claude-3-5-sonnet",
                context_tokens=10_000,
                iterations=2,
                cadence=cadence,
                budget_usd=10.0,
            )
            self.assertGreater(est.monthly_estimated_cost_usd, 0.0)
            table_out = format_terminal(est)
            self.assertIn("ShipProof AI Cost", table_out)
            md_out = format_markdown(est)
            self.assertIn("ShipProof AI Cost & Token Budget Report", md_out)

    def test_cli_formats(self):
        code_md = main(["--context-tokens", "1000", "--format", "markdown"])
        self.assertEqual(code_md, 0)
        code_term = main(["--context-tokens", "1000", "--format", "terminal"])
        self.assertEqual(code_term, 0)

    def test_negative_numeric_inputs_fail_closed(self):
        invalid_arguments = (
            ["--context-tokens", "-1"],
            ["--output-tokens", "-1"],
            ["--iterations", "0"],
            ["--budget-usd", "0"],
        )
        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments):
                self.assertEqual(main([*arguments, "--format", "json"]), 2)

        with self.assertRaises(ValueError):
            calculate_cost("o4-mini", context_tokens=100, output_tokens_per_iteration=-1)

    def test_missing_path_is_unavailable_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            self.assertEqual(main([str(missing), "--format", "json"]), 2)
            self.assertEqual(
                main([str(missing), "--context-tokens", "1000", "--format", "json"]),
                2,
            )


if __name__ == "__main__":
    unittest.main()
