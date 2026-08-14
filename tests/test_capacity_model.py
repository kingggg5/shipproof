from __future__ import annotations

import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).parents[1] / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from capacity_model import (  # noqa: E402
    CapacityInputs,
    build_capacity_model,
    load_config,
    render_k6_script,
    validate_k6_config,
)


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

    def test_k6_script_is_deterministic_and_uses_environment_variables(self):
        model = build_capacity_model(CapacityInputs(users=100_000))
        config = {
            "base_url_env": "SERVICE_URL",
            "auth_token_env": "LOAD_TOKEN",
            "duration": "30s",
            "routes": [
                {"name": "health", "path": "/health", "weight": 3},
                {
                    "name": "create-ticket",
                    "path": "/api/tickets",
                    "method": "POST",
                    "expected_statuses": [201, 202],
                    "body": {"subject": "capacity probe"},
                },
            ],
        }
        first = render_k6_script(model, config)
        second = render_k6_script(model, config)
        self.assertEqual(first, second)
        self.assertIn('__ENV["SERVICE_URL"]', first)
        self.assertIn('__ENV["LOAD_TOKEN"]', first)
        self.assertIn('executor: "constant-arrival-rate"', first)
        self.assertNotIn("https://", first)

    def test_k6_config_rejects_remote_targets_and_unknown_fields(self):
        with self.assertRaises(ValueError):
            validate_k6_config(
                {"routes": [{"name": "unsafe", "path": "https://example.com/", "script": "x"}]}
            )

    def test_cli_exports_k6_without_overwriting_existing_file(self):
        import contextlib
        import io
        import json
        from unittest.mock import MagicMock, patch

        from capacity_model import main, write_new_file

        config = json.dumps(
            {
                "schema_version": "1.0",
                "capacity": {
                    "inputs": {"users": 10000},
                    "k6": {"routes": [{"name": "health", "path": "/health"}]},
                },
            }
        )
        with (
            patch("capacity_model.Path.read_text", return_value=config),
            patch("capacity_model.write_new_file") as writer,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(
                main(["--config", "shipproof.json", "--export-k6", "load.js"]),
                0,
            )
        self.assertIn('executor: "constant-arrival-rate"', writer.call_args.args[1])

        existing_path = MagicMock()
        existing_path.exists.return_value = True
        with self.assertRaises(ValueError):
            write_new_file(existing_path, "content", False)

    def test_checked_in_k6_example_matches_versioned_config(self):
        root = Path(__file__).parents[1]
        inputs, k6 = load_config(root / "examples" / "capacity" / "shipproof.config.json")
        generated = render_k6_script(build_capacity_model(CapacityInputs(**inputs)), k6)
        expected = (root / "examples" / "capacity" / "generated-load-test.js").read_text(
            encoding="utf-8"
        )
        self.assertEqual(generated, expected)


if __name__ == "__main__":
    unittest.main()
