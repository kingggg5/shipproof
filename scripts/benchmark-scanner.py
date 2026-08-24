"""Generate a deterministic repository and measure ShipProof scanner cost."""

from __future__ import annotations

import argparse
import importlib.util
import json
import platform
import shutil
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


def write_fixture(root: Path, file_count: int) -> None:
    for index in range(file_count):
        bucket = root / f"module-{index // 250:04d}"
        bucket.mkdir(exist_ok=True)
        (bucket / f"service-{index:06d}.py").write_text(
            f"def normalize_{index}(value: str) -> str:\n    return value.strip()\n",
            encoding="utf-8",
        )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=1_000)
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
    workdir = arguments.workdir.resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    scanner = load_scanner()
    fixture = workdir / f"scanner-{uuid4().hex}"
    fixture.mkdir()
    try:
        write_fixture(fixture, arguments.files)
        if not arguments.no_warmup:
            # The first scan of freshly written files pays OS-level first-open
            # cost (antivirus, directory metadata) that is not scanner work.
            # Warm up once, then measure the first post-warmup pass and a repeated warm pass.
            scanner.scan_repository(fixture, jobs=arguments.jobs)
        started = perf_counter()
        findings, stats = scanner.scan_repository(fixture, jobs=arguments.jobs)
        duration = perf_counter() - started
        started = perf_counter()
        findings, stats = scanner.scan_repository(fixture, jobs=arguments.jobs)
        warm_duration = perf_counter() - started
    finally:
        if fixture.parent != workdir:
            raise RuntimeError("refusing to remove a benchmark path outside the work directory")
        shutil.rmtree(fixture)
    memory = peak_rss_mb()
    report = {
        "schema_version": "1.0",
        "tool": {"name": "ShipProof", "version": scanner.VERSION, "command": "benchmark"},
        "platform": platform.platform(),
        "python": platform.python_version(),
        "jobs": arguments.jobs,
        "files": stats["files_scanned"],
        "seconds": round(duration, 4),
        "warm_seconds": round(warm_duration, 4),
        "files_per_second": round(arguments.files / duration, 1),
        "warm_files_per_second": round(arguments.files / warm_duration, 1),
        "peak_rss_mb": round(memory, 2) if memory is not None else None,
        "findings": len(findings),
    }
    failures = []
    unavailable = []
    if arguments.max_seconds is not None and duration > arguments.max_seconds:
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
