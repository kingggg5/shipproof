from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).parents[1] / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from capacity_model import CapacityInputs, build_capacity_model  # noqa: E402


class CapacityModelTests(unittest.TestCase):
    def test_model_exposes_assumptions_and_design_peak(self):
        payload = build_capacity_model(CapacityInputs(users=10_000))
        self.assertEqual(payload["derived"]["daily_active_users"], 2_000)
        self.assertGreater(payload["derived"]["design_peak_rps"], 0)
        self.assertGreater(payload["derived"]["estimated_cpu_cores_with_headroom"], 0)
        self.assertEqual(payload["derived"]["estimated_app_memory_mb"], 512)
        self.assertIn("warning", payload)

    def test_one_million_users_requires_more_capacity(self):
        small = build_capacity_model(CapacityInputs(users=10_000))["derived"]
        large = build_capacity_model(CapacityInputs(users=1_000_000))["derived"]
        self.assertGreater(large["design_peak_rps"], small["design_peak_rps"])
        self.assertGreater(
            large["minimum_app_instances_with_headroom"],
            small["minimum_app_instances_with_headroom"],
        )

    def test_invalid_ratio_fails_closed(self):
        with self.assertRaises(ValueError):
            build_capacity_model(CapacityInputs(users=10_000, dau_ratio=1.2))

    def test_boolean_users_fail_closed(self):
        with self.assertRaises(ValueError):
            build_capacity_model(CapacityInputs(users=True))

    def test_load_ladder_contains_failure_modes(self):
        names = {
            stage["name"]
            for stage in build_capacity_model(CapacityInputs(users=10_000))["load_test_stages"]
        }
        self.assertEqual(names, {"smoke", "average", "peak", "stress", "spike", "soak"})

    def test_cli_config_file(self):
        import json
        from unittest.mock import patch

        from capacity_model import main

        with (
            patch(
                "capacity_model.Path.read_text",
                return_value=json.dumps({"users": 50000, "dau_ratio": 0.3}),
            ),
            patch("capacity_model.Path.write_text") as write_text,
        ):
            code = main(["--config", "workload.json", "--output", "report.md"])
            self.assertEqual(code, 0)
            self.assertIn("50,000", write_text.call_args.args[0])

    def test_config_values_are_not_overwritten_by_cli_defaults(self):
        import json
        from unittest.mock import patch

        from capacity_model import main

        with (
            patch(
                "capacity_model.Path.read_text",
                return_value=json.dumps({"users": 10000, "dau_ratio": 0.3}),
            ),
            patch("capacity_model.Path.write_text") as write_text,
        ):
            self.assertEqual(
                main(["--config", "workload.json", "--output", "report.md", "--format", "json"]), 0
            )
        payload = json.loads(write_text.call_args.args[0])
        self.assertEqual(payload["inputs"]["dau_ratio"], 0.3)

    def test_unknown_config_field_fails_closed(self):
        import contextlib
        import io
        import json
        from unittest.mock import patch

        from capacity_model import main

        with (
            patch(
                "capacity_model.Path.read_text",
                return_value=json.dumps({"users": 10000, "surprise": 1}),
            ),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(main(["--config", "workload.json"]), 2)


if __name__ == "__main__":
    unittest.main()
