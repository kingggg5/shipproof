#!/usr/bin/env python3
"""Compare bounded packet preparation, not defect detection or model token use.

Run this same driver with --engine-root pointing to each trusted ShipProof tree.
Only synthetic source is read; its contents are never executed.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import platform
import runpy
import statistics
import sys
import tempfile
import time
from pathlib import Path


def fixtures(kind: str) -> tuple[dict[str, str], list[dict[str, object]]]:
    sources = {"shared/store.ts": "export function read() { return 1; }\n"}
    rows = []
    for directory in range(4):
        for index in range(12 if kind == "split" else 1):
            path = f"src{directory}/entry{index:02}.ts"
            sources[path] = (
                "import { read } from '../shared/store';\nexport const value = read();\n"
            )
            rows.append(
                {
                    "rule_id": "SP103",
                    "fingerprint": f"{len(rows):016x}",
                    "path": path,
                    "line": 2,
                    "severity": "high",
                    "proof_level": "L0",
                }
            )
            sources[f"tests/src{directory}/entry{index:02}.test.ts"] = (
                f"import '../../{path[:-3]}';\n"
            )
        if kind == "minimize":
            for index in range(6):
                sources[f"src{directory}/aaa{index}.ts"] = "export const unrelated = 1;\n"
    return {p: (s + "// " + "x" * 512)[:511] + "\n" for p, s in sources.items()}, rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine-root", type=Path, required=True)
    parser.add_argument("--workload", choices=("split", "minimize"), required=True)
    parser.add_argument("--samples", type=int, default=5)
    args = parser.parse_args()
    if not 1 <= args.samples <= 10:
        parser.error("samples must be from 1 through 10")
    engine = args.engine_root.resolve()
    sys.path.insert(0, str(engine / "skills/audit-production-readiness/scripts"))
    import review_packets

    sources, rows = fixtures(args.workload)
    digest = hashlib.sha256()
    for path, text in sorted(sources.items()):
        digest.update(path.encode() + b"\0" + text.encode() + b"\0")
    options = {}
    if "context_paths" in inspect.signature(review_packets.build_packets).parameters:
        options["context_paths"] = set(sources)
    with tempfile.TemporaryDirectory(prefix="shipproof-packet-benchmark-") as directory:
        root = Path(directory)
        for path, text in sources.items():
            absolute = root / path
            absolute.parent.mkdir(parents=True, exist_ok=True)
            absolute.write_text(text, encoding="utf-8", newline="\n")
        # One unmeasured warmup; fresh reports for every identical sample.
        review_packets.build_packets(root, rows, **options)
        samples = []
        for _ in range(args.samples):
            started = time.perf_counter()
            report = review_packets.build_packets(root, rows, **options)
            samples.append(time.perf_counter() - started)
    memory_helpers = runpy.run_path(str(engine / "scripts/benchmark-scanner.py"))
    peak = memory_helpers["peak_rss_mb"]()
    packet_rows = report["packets"]
    source_bytes = sum(p["source_bytes"] for p in packet_rows)
    p95 = sorted(samples)[min(len(samples) - 1, int(len(samples) * 0.95))]
    budget_pass = p95 <= 8 and peak is not None and peak <= 256
    print(
        json.dumps(
            {
                "schema_version": 1,
                "workload": args.workload,
                "measurement": "local source preparation; synthetic findings; no AI review or model tokens",
                "environment": {
                    "python": platform.python_version(),
                    "platform": platform.platform(),
                },
                "engine_digest": review_packets.identity.scanner_code_identity(),
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
                "counts": report["counts"],
                "source_bytes": source_bytes,
                "source_token_estimate": sum(p["token_estimate"] for p in packet_rows),
                "bounds": {
                    "max_files": max(len(p["files"]) for p in packet_rows),
                    "max_source_bytes": max(p["source_bytes"] for p in packet_rows),
                },
                "budget": {"p95_seconds": 8, "peak_rss_mib": 256, "pass": budget_pass},
            },
            indent=2,
        )
    )
    return 0 if budget_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
