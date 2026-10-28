#!/usr/bin/env python3
"""Measure graph construction on identical synthetic source, never execute it."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import runpy
import statistics
import sys
import tempfile
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine-root", type=Path, required=True)
    parser.add_argument("--profile", choices=("clean", "limits"), required=True)
    args = parser.parse_args()
    engine = args.engine_root.resolve()
    sys.path.insert(0, str(engine / "skills/audit-production-readiness/scripts"))
    import impact_graph
    import snapshot_identity

    if args.profile == "clean":
        sources = {
            f"src/file{i:04}.js": f"function normalize{i}(value) {{ return value.trim(); }}\n"
            for i in range(500)
        }
        sources = {p: (s + "// " + "x" * 512)[:511] + "\n" for p, s in sources.items()}
    else:
        source = (
            "// bounded comment padding\n" * 17000
            + "function normalize(value) { return value.trim(); }\n"
        )
        sources = {f"src/large{i:02}.js": source for i in range(16)}
    digest = hashlib.sha256()
    for name, source in sorted(sources.items()):
        digest.update(name.encode() + b"\0" + source.encode() + b"\0")
    with tempfile.TemporaryDirectory(prefix="shipproof-impact-bench-") as directory:
        root = Path(directory)
        for name, source in sources.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8", newline="\n")
        impact_graph.ImpactGraph(root).build()
        samples = []
        for _ in range(3):
            started = time.perf_counter()
            graph = impact_graph.ImpactGraph(root)
            graph.build()
            samples.append(time.perf_counter() - started)
    peak = runpy.run_path(str(engine / "scripts/benchmark-scanner.py"))["peak_rss_mb"]()
    p95 = max(samples)
    passed = p95 <= 8 and peak is not None and peak <= 256
    print(
        json.dumps(
            {
                "profile": args.profile,
                "environment": {
                    "python": platform.python_version(),
                    "platform": platform.platform(),
                },
                "runtime_digest": snapshot_identity.scanner_code_identity(),
                "fixture": {
                    "files": len(sources),
                    "bytes": sum(len(s.encode()) for s in sources.values()),
                    "sha256": digest.hexdigest(),
                },
                "warmup": 1,
                "samples_seconds": samples,
                "median_seconds": statistics.median(samples),
                "p95_seconds": p95,
                "peak_rss_mib": peak,
                "files_read": graph.files_scanned_count,
                "flows": len(graph.taint_flows),
                "completeness": getattr(graph, "completeness", {"reported": False}),
                "budget": {"p95_seconds": 8, "peak_rss_mib": 256, "pass": passed},
                "scope": "Graph construction on synthetic files only; no target execution or production throughput claim",
            },
            indent=2,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
