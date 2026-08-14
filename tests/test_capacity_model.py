from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).parents[1] / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from capacity_model import CapacityInputs, model  # noqa: E402


class CapacityModelTests(unittest.TestCase):
    def test_model_exposes_assumptions_and_design_peak(self):
        payload = model(CapacityInputs(users=10_000))
        self.assertEqual(payload["derived"]["daily_active_users"], 2_000)
        self.assertGreater(payload["derived"]["design_peak_rps"], 0)
        self.assertGreater(payload["derived"]["estimated_cpu_cores_with_headroom"], 0)
        self.assertEqual(payload["derived"]["estimated_app_memory_mb"], 512)
        self.assertIn("warning", payload)

    def test_one_million_users_requires_more_capacity(self):
        small = model(CapacityInputs(users=10_000))["derived"]
        large = model(CapacityInputs(users=1_000_000))["derived"]
        self.assertGreater(large["design_peak_rps"], small["design_peak_rps"])
        self.assertGreater(large["minimum_app_instances_with_headroom"], small["minimum_app_instances_with_headroom"])

    def test_invalid_ratio_fails_closed(self):
        with self.assertRaises(ValueError):
            model(CapacityInputs(users=10_000, dau_ratio=1.2))

    def test_load_ladder_contains_failure_modes(self):
        names = {stage["name"] for stage in model(CapacityInputs(users=10_000))["load_test_stages"]}
        self.assertEqual(names, {"smoke", "average", "peak", "stress", "spike", "soak"})


if __name__ == "__main__":
    unittest.main()
