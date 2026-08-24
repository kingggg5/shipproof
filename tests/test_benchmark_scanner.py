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

    def test_fixture_generation_is_deterministic_and_profiled(self):
        import tempfile

        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_digest, first_bytes = benchmark_scanner.write_fixture(
                Path(first), 4, "adversarial-regex", 256
            )
            second_digest, second_bytes = benchmark_scanner.write_fixture(
                Path(second), 4, "adversarial-regex", 256
            )
            self.assertEqual(first_digest, second_digest)
            self.assertEqual(first_bytes, second_bytes)
            self.assertEqual(first_bytes, 4 * 256)
            self.assertEqual(
                sorted(path.relative_to(first).as_posix() for path in Path(first).rglob("*.py")),
                sorted(path.relative_to(second).as_posix() for path in Path(second).rglob("*.py")),
            )

    def test_nearest_rank_percentile_is_deterministic(self):
        self.assertEqual(benchmark_scanner.nearest_rank_percentile([4, 1, 3, 2], 95), 4)
        self.assertEqual(benchmark_scanner.nearest_rank_percentile([4, 1, 3, 2], 50), 2)
        with self.assertRaises(ValueError):
            benchmark_scanner.nearest_rank_percentile([1], 0)


if __name__ == "__main__":
    unittest.main()
