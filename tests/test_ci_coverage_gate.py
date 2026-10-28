"""The required coverage check must fail closed for either child outcome."""

from __future__ import annotations

import itertools
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path


class CoverageWorkflowTests(unittest.TestCase):
    def test_required_aggregate_rejects_non_successful_children(self):
        source = (Path(__file__).parents[1] / ".github/workflows/ci.yml").read_text(
            encoding="utf-8"
        )
        aggregate = source.split("  coverage:\n", 1)[1].split("  python-coverage:\n", 1)[0]
        self.assertIn("needs: [python-coverage, node-coverage]", aggregate)
        self.assertIn("if: always()", aggregate)
        script = re.search(r"        run: \|\n((?:          [^\n]*\n)+)", aggregate)
        self.assertIsNotNone(script)
        command = "\n".join(line[10:] for line in script[1].splitlines())
        shell = shutil.which("bash")
        if os.name == "nt":
            candidate = (
                Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Git/bin/bash.exe"
            )
            shell = str(candidate) if candidate.is_file() else None
        if shell is None:
            self.skipTest("Bash is unavailable on this host; hosted Ubuntu runs the gate")
        for python, node in itertools.product(
            ("success", "failure", "cancelled", "skipped"), repeat=2
        ):
            with self.subTest(python=python, node=node):
                result = subprocess.run(  # noqa: S603 - fixed gate with enum-only environment data
                    [shell, "-e", "-c", command],
                    env={
                        **os.environ,
                        "PYTHON_COVERAGE_RESULT": python,
                        "NODE_COVERAGE_RESULT": node,
                    },
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(
                    result.returncode == 0, python == node == "success", result.stderr[:500]
                )
