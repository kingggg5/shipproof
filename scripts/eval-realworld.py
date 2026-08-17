#!/usr/bin/env python3
"""Scan well-known open-source repositories and summarize detector behaviour.

Clones (depth 1) each target into benchmarks/.work/oss-eval/ — a gitignored
scratch area — runs the ShipProof scanner, and prints a per-repo summary plus
an aggregate. Dev-side tool only: the default scan workflow stays offline.

Usage:
  python scripts/eval-realworld.py [--repos a,b,c] [--json]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from scan_repo import scan_repository  # noqa: E402

DEFAULT_REPOS = [
    # Clean, widely-deployed baselines: expect low/no high findings (FP check).
    ("https://github.com/expressjs/express", "express"),
    ("https://github.com/pallets/flask", "flask"),
    ("https://github.com/psf/requests", "requests"),
    # Famous intentionally-vulnerable apps: expect meaningful detections (recall check).
    ("https://github.com/juice-shop/juice-shop", "juice-shop"),
    ("https://github.com/digininja/DVWA", "dvwa"),
]


def run_git(*arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        ["git", *arguments],  # noqa: S607
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def prepare(url: str, name: str, workspace: Path) -> Path | None:
    target = workspace / name
    if target.exists():
        shutil.rmtree(target)
    cloned = run_git("clone", "--depth", "1", "--quiet", url, str(target))
    if cloned.returncode != 0:
        print(f"skip {name}: clone failed ({cloned.stderr.strip().splitlines()[:1]})")
        return None
    return target


def evaluate(url: str, name: str, workspace: Path) -> dict[str, object]:
    target = prepare(url, name, workspace)
    if target is None:
        return {"repo": name, "status": "skipped"}
    started = time.perf_counter()
    findings, stats = scan_repository(target)
    elapsed = round(time.perf_counter() - started, 2)
    by_rule: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for finding in findings:
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
    return {
        "repo": name,
        "status": "scanned",
        "files": stats["files_scanned"],
        "seconds": elapsed,
        "findings": len(findings),
        "by_severity": dict(sorted(by_severity.items())),
        "by_rule": dict(sorted(by_rule.items(), key=lambda item: -item[1])),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repos", help="comma-separated slugs (name or owner/name@url)")
    parser.add_argument("--json", action="store_true", help="print raw JSON")
    arguments = parser.parse_args()

    workspace = ROOT / "benchmarks" / ".work" / "oss-eval"
    workspace.mkdir(parents=True, exist_ok=True)

    targets = DEFAULT_REPOS
    if arguments.repos:
        requested = []
        for item in arguments.repos.split(","):
            item = item.strip()
            if not item:
                continue
            if "@" in item:
                url, name = item.rsplit("@", 1)
            else:
                url, name = f"https://github.com/{item}", item.split("/")[-1]
            requested.append((url, name))
        targets = requested

    results = [evaluate(url, name, workspace) for url, name in targets]
    payload = {
        "schema_version": "1.0",
        "tool": {"name": "ShipProof", "command": "eval-realworld"},
        "repos": results,
    }
    if arguments.json:
        print(json.dumps(payload, indent=2))
        return 0
    for result in results:
        if result["status"] != "scanned":
            print(f"{result['repo']:14} SKIPPED")
            continue
        print(
            f"{result['repo']:14} {result['files']:5} files {result['seconds']:6}s "
            f"findings={result['findings']:4} {result['by_severity']}"
        )
        top = list(result["by_rule"].items())[:8]
        if top:
            print(f"{'':14} top rules: {', '.join(f'{rule}x{count}' for rule, count in top)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
