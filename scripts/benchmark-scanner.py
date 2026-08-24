"""Generate a deterministic repository and measure ShipProof scanner cost."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import platform
import shutil
import statistics
import sys
from pathlib import Path
from time import perf_counter
from uuid import uuid4

ROOT = Path(__file__).parents[1]
SCANNER_PATH = ROOT / "skills" / "audit-production-readiness" / "scripts" / "scan_repo.py"


def load_scanner():
    # Load under the canonical module name with the scripts directory on
    # sys.path so multiprocessing workers (spawn) can import the pickled task
    # functions when --jobs > 1.
    scripts_directory = str(SCANNER_PATH.parent)
    if scripts_directory not in sys.path:
        sys.path.insert(0, scripts_directory)
    spec = importlib.util.spec_from_file_location("scan_repo", SCANNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load scanner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def peak_rss_mb() -> float | None:
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        process_api = (
            kernel32.K32GetProcessMemoryInfo
            if hasattr(kernel32, "K32GetProcessMemoryInfo")
            else ctypes.WinDLL("psapi", use_last_error=True).GetProcessMemoryInfo
        )
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        process_api.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ProcessMemoryCounters),
            wintypes.DWORD,
        ]
        process_api.restype = wintypes.BOOL
        counters = ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        process = kernel32.GetCurrentProcess()
        if not process_api(process, ctypes.byref(counters), counters.cb):
            return None
        return counters.PeakWorkingSetSize / 1_048_576
    try:
        import resource

        maximum = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return maximum / (1_048_576 if sys.platform == "darwin" else 1_024)
    except (ImportError, OSError):
        return None


def fixture_source(index: int, profile: str, bytes_per_file: int) -> str:
    if profile == "clean":
        prefix = f"def normalize_{index}(value: str) -> str:\n    return value.strip()\n"
        padding = "# bounded benchmark padding\n"
    else:
        prefix = f"def parse_{index}(value: str) -> str:\n    return value\n"
        # Exercise long near-miss regex input without embedding a vulnerable
        # sink, target, credential, or environment-specific value.
        padding = "# ((([[{{??++** aa_AA_00 :: // near-miss boundary\n"
    if len(prefix.encode("utf-8")) >= bytes_per_file:
        return prefix
    repetitions = (bytes_per_file - len(prefix.encode("utf-8"))) // len(padding.encode("utf-8")) + 1
    return (
        (prefix + padding * repetitions)
        .encode("utf-8")[:bytes_per_file]
        .decode("utf-8", errors="ignore")
    )


def write_fixture(
    root: Path, file_count: int, profile: str, bytes_per_file: int
) -> tuple[str, int]:
    digest = hashlib.sha256()
    total_bytes = 0
    for index in range(file_count):
        bucket = root / f"module-{index // 250:04d}"
        bucket.mkdir(exist_ok=True)
        path = bucket / f"service-{index:06d}.py"
        source = fixture_source(index, profile, bytes_per_file)
        path.write_text(source, encoding="utf-8")
        source_bytes = source.encode("utf-8")
        total_bytes += len(source_bytes)
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(source_bytes)
        digest.update(b"\0")
    return digest.hexdigest(), total_bytes


def nearest_rank_percentile(values: list[float], percentile: float) -> float:
    if not values:
        raise ValueError("percentile requires at least one value")
    if not 0 < percentile <= 100:
        raise ValueError("percentile must be greater than 0 and at most 100")
    ordered = sorted(values)
    rank = math.ceil(len(ordered) * percentile / 100)
    return ordered[min(rank - 1, len(ordered) - 1)]


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=1_000)
    parser.add_argument("--samples", type=int, default=3, help="Measured scan samples")
    parser.add_argument(
        "--profile",
        choices=("clean", "adversarial-regex"),
        default="clean",
        help="Generated finding-free workload shape",
    )
    parser.add_argument(
        "--bytes-per-file",
        type=int,
        default=128,
        help="Approximate generated source bytes per file",
    )
    parser.add_argument("--workdir", type=Path, default=ROOT / "benchmarks" / ".work")
    parser.add_argument("--max-seconds", type=float)
    parser.add_argument("--max-memory-mb", type=float)
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Worker processes for the measured scans (1 stays sequential)",
    )
    parser.add_argument(
        "--no-warmup",
        action="store_true",
        help="Skip the untimed warm-up pass (report cold-cache numbers only)",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    if not 1 <= arguments.files <= 100_000:
        raise ValueError("--files must be from 1 through 100000")
    if arguments.jobs < 1:
        raise ValueError("--jobs must be at least 1")
    if not 1 <= arguments.samples <= 30:
        raise ValueError("--samples must be from 1 through 30")
    if not 64 <= arguments.bytes_per_file <= 1_000_000:
        raise ValueError("--bytes-per-file must be from 64 through 1000000")
    workdir = arguments.workdir.resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    scanner = load_scanner()
    fixture = workdir / f"scanner-{uuid4().hex}"
    fixture.mkdir()
    try:
        fixture_digest, fixture_bytes = write_fixture(
            fixture,
            arguments.files,
            arguments.profile,
            arguments.bytes_per_file,
        )
        if not arguments.no_warmup:
            # The first scan of freshly written files pays OS-level first-open
            # cost (antivirus, directory metadata) that is not scanner work.
            # Warm up once, then measure the first post-warmup pass and a repeated warm pass.
            scanner.scan_repository(fixture, jobs=arguments.jobs)
        durations = []
        finding_counts = []
        file_counts = []
        findings = []
        stats = {"files_scanned": 0}
        for _ in range(arguments.samples):
            started = perf_counter()
            findings, stats = scanner.scan_repository(fixture, jobs=arguments.jobs)
            durations.append(perf_counter() - started)
            finding_counts.append(len(findings))
            file_counts.append(int(stats["files_scanned"]))
    finally:
        if fixture.parent != workdir:
            raise RuntimeError("refusing to remove a benchmark path outside the work directory")
        shutil.rmtree(fixture)
    memory = peak_rss_mb()
    median_duration = statistics.median(durations)
    p95_duration = nearest_rank_percentile(durations, 95)
    report = {
        "schema_version": "1.0",
        "tool": {"name": "ShipProof", "version": scanner.VERSION, "command": "benchmark"},
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "jobs": arguments.jobs,
        "profile": arguments.profile,
        "bytes_per_file": arguments.bytes_per_file,
        "fixture_bytes": fixture_bytes,
        "fixture_sha256": fixture_digest,
        "warmup_passes": 0 if arguments.no_warmup else 1,
        "sample_count": arguments.samples,
        "samples_seconds": [round(value, 4) for value in durations],
        "sample_finding_counts": finding_counts,
        "sample_file_counts": file_counts,
        "files": stats["files_scanned"],
        "seconds": round(durations[0], 4),
        "warm_seconds": round(durations[-1], 4),
        "median_seconds": round(median_duration, 4),
        "p95_seconds": round(p95_duration, 4),
        "files_per_second": round(arguments.files / durations[0], 1),
        "warm_files_per_second": round(arguments.files / durations[-1], 1),
        "median_files_per_second": round(arguments.files / median_duration, 1),
        "peak_rss_mb": round(memory, 2) if memory is not None else None,
        "findings": finding_counts[-1],
    }
    failures = []
    unavailable = []
    if len(set(finding_counts)) != 1:
        failures.append("nondeterministic_findings")
    if len(set(file_counts)) != 1:
        failures.append("nondeterministic_file_count")
    if file_counts[-1] != arguments.files:
        failures.append("unexpected_file_count")
    if any(finding_counts):
        failures.append("unexpected_findings")
    if arguments.max_seconds is not None and p95_duration > arguments.max_seconds:
        failures.append("duration")
    if arguments.max_memory_mb is not None:
        if memory is None:
            unavailable.append("memory")
        elif memory > arguments.max_memory_mb:
            failures.append("memory")
    report["verdict"] = "WARN" if unavailable else ("BLOCK" if failures else "PASS_WITH_EVIDENCE")
    report["failed_budgets"] = failures
    report["unavailable_budgets"] = unavailable
    print(json.dumps(report, indent=2))
    return 2 if unavailable else (1 if failures else 0)


if __name__ == "__main__":
    raise SystemExit(main())
