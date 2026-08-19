import sys
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


if __name__ == "__main__":
    unittest.main()
