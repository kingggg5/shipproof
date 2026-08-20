from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "benchmark-scanner.py"
SPEC = importlib.util.spec_from_file_location("benchmark_scanner", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load benchmark scanner")
benchmark_scanner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = benchmark_scanner
SPEC.loader.exec_module(benchmark_scanner)


class BenchmarkScannerTests(unittest.TestCase):
    def test_peak_rss_is_available_and_positive_on_supported_ci_platforms(self):
        memory = benchmark_scanner.peak_rss_mb()
        self.assertIsNotNone(memory)
        self.assertGreater(memory, 0)


if __name__ == "__main__":
    unittest.main()
