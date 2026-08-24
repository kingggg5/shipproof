#!/usr/bin/env python3
"""Offline head-to-head harness comparing ShipProof with a user-supplied Semgrep run.

Fairness rules baked into the protocol:
- Both tools scan the identical local corpus on the same machine, measured
  end-to-end (process start to report) with the median of N repeats.
- ShipProof runs its own scanner exactly as shipped (no rule cherry-picking).
- Semgrep runs only with rule files the caller supplies via --semgrep-config.
  ShipProof never bundles, downloads, or copies third-party rules, and the
  harness performs no network access.
- When a label file marks vulnerable files per corpus, both tools are scored
  with the same file-level precision/recall/F1. No general superiority claim
  is made: results describe exactly these corpora, configs, and machine.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "skills" / "audit-production-readiness" / "scripts" / "scan_repo.py"
DEFAULT_LABELS = ROOT / "benchmarks" / "head-to-head-labels.json"


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="+", type=Path, help="Repository directories to scan")
    parser.add_argument(
        "--semgrep-config",
        action="append",
        default=[],
        help="Rule file for Semgrep (repeatable); without it the Semgrep leg is skipped",
    )
    parser.add_argument(
        "--labels",
        type=Path,
        default=DEFAULT_LABELS,
        help="JSON mapping corpus directory name to labeled vulnerable files",
    )
    parser.add_argument("--repeat", type=int, default=3, help="Timed runs per tool (median kept)")
    parser.add_argument("--min-file-precision", type=float)
    parser.add_argument("--min-file-recall", type=float)
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="markdown",
    )
    return parser.parse_args(argv)


def timed_run(command: list[str], cwd: Path) -> tuple[float, subprocess.CompletedProcess[str]]:
    started = time.perf_counter()
    process = subprocess.run(  # noqa: S603 - fixed argv, shell disabled by design
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        shell=False,
    )
    elapsed = time.perf_counter() - started
    return elapsed, process


def run_shipproof(corpus: Path, repeat: int) -> dict[str, object]:
    durations: list[float] = []
    file_rule_hits: set[tuple[str, str]] = set()
    for _ in range(repeat):
        elapsed, process = timed_run(
            [
                sys.executable,
                str(SCANNER),
                str(corpus),
                "--format",
                "json",
                "--fail-on",
                "none",
                # The full capability as shipped: include the interprocedural
                # taint engine so the comparison covers L2 evidence too.
                "--cross-file",
            ],
            corpus.parent,
        )
        if process.returncode not in (0, 1):
            raise RuntimeError(f"shipproof exited {process.returncode}: {process.stderr[:400]}")
        durations.append(elapsed)
        report = json.loads(process.stdout)
        prefix = f"{corpus.name}/"
        for finding in report["findings"]:
            path = finding["path"].removeprefix(prefix)
            file_rule_hits.add((path, finding["rule_id"]))
    files_flagged = sorted({path for path, _ in file_rule_hits})
    return {
        "tool": "shipproof",
        "median_seconds": round(statistics.median(durations), 3),
        "findings": len(file_rule_hits),
        "files_flagged": files_flagged,
        "rule_hits": sorted(f"{path}:{rule}" for path, rule in file_rule_hits),
    }


def build_semgrep_command(corpus: Path, configs: Sequence[str]) -> list[str]:
    command = ["semgrep", "scan", "--json", "--disable-nosem"]
    for config in configs:
        command.extend(["--config", str(Path(config).resolve())])
    command.append(corpus.name)
    return command


def run_semgrep(corpus: Path, configs: Sequence[str], repeat: int) -> dict[str, object]:
    durations: list[float] = []
    file_rule_hits: set[tuple[str, str]] = set()
    command = build_semgrep_command(corpus, configs)
    for _ in range(repeat):
        elapsed, process = timed_run(command, corpus.parent)
        if process.returncode not in (0, 1):
            raise RuntimeError(f"semgrep exited {process.returncode}: {process.stderr[:400]}")
        durations.append(elapsed)
        payload = json.loads(process.stdout)
        for result in payload.get("results", []):
            path = str(result.get("path", "")).removeprefix(f"{corpus.name}/")
            file_rule_hits.add((path, str(result.get("check_id", "semgrep"))))
    files_flagged = sorted({path for path, _ in file_rule_hits})
    return {
        "tool": "semgrep",
        "median_seconds": round(statistics.median(durations), 3),
        "findings": len(file_rule_hits),
        "files_flagged": files_flagged,
        "rule_hits": sorted(f"{path}:{rule}" for path, rule in file_rule_hits),
    }


def compute_file_metrics(
    files_flagged: Sequence[str],
    labeled_files: Sequence[str],
) -> dict[str, object]:
    """File-level scoring: identical labels for every tool, no rule mapping needed."""
    flagged = set(files_flagged)
    labeled = set(labeled_files)
    true_positives = len(flagged & labeled)
    false_positives = len(flagged - labeled)
    false_negatives = len(labeled - flagged)
    precision = true_positives / (true_positives + false_positives) if flagged else None
    recall = true_positives / (true_positives + false_negatives) if labeled else None
    if precision is not None and recall is not None and precision + recall > 0:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = None
    return {
        "files_flagged": len(flagged),
        "labeled_files": len(labeled),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "file_precision": round(precision, 3) if precision is not None else None,
        "file_recall": round(recall, 3) if recall is not None else None,
        "file_f1": round(f1, 3) if f1 is not None else None,
    }


def load_labels(labels_path: Path, corpora: Sequence[Path]) -> dict[str, list[str]]:
    if not labels_path.is_file():
        raise FileNotFoundError(f"label file does not exist: {labels_path}")
    payload = json.loads(labels_path.read_text(encoding="utf-8"))
    return {corpus.name: sorted(payload.get(corpus.name, [])) for corpus in corpora}


def render_markdown(results: Sequence[dict[str, object]]) -> str:
    lines = [
        "# ShipProof head-to-head results",
        "",
        "Same corpora, same machine, median end-to-end wall time per tool.",
        "File-level scoring uses the shared label file; it describes these",
        "corpora and configs only, not general superiority.",
        "",
        "| Tool | Corpus | Median seconds | Findings | Files flagged | Precision | Recall | F1 |",
        "| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for entry in results:
        metrics = entry["metrics"]
        lines.append(
            "| {tool} | {corpus} | {seconds} | {findings} | {flagged} | "
            "{precision} | {recall} | {f1} |".format(
                tool=entry["tool"],
                corpus=entry["corpus"],
                seconds=entry["result"]["median_seconds"],
                findings=entry["result"]["findings"],
                flagged=metrics["files_flagged"],
                precision=metrics["file_precision"]
                if metrics["file_precision"] is not None
                else "n/a",
                recall=metrics["file_recall"] if metrics["file_recall"] is not None else "n/a",
                f1=metrics["file_f1"] if metrics["file_f1"] is not None else "n/a",
            )
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    corpora = [corpus.resolve() for corpus in arguments.corpora]
    for corpus in corpora:
        if not corpus.is_dir():
            print(f"head-to-head: not a directory: {corpus}", file=sys.stderr)
            return 2
    if arguments.repeat < 1:
        print("head-to-head: --repeat must be >= 1", file=sys.stderr)
        return 2
    for name, value in (
        ("--min-file-precision", arguments.min_file_precision),
        ("--min-file-recall", arguments.min_file_recall),
    ):
        if value is not None and not 0 <= value <= 1:
            print(f"head-to-head: {name} must be from 0 through 1", file=sys.stderr)
            return 2
    configs = [str(Path(value).resolve()) for value in arguments.semgrep_config]
    for config in configs:
        if not Path(config).is_file():
            print(f"head-to-head: Semgrep config is not a file: {config}", file=sys.stderr)
            return 2
    try:
        labels = load_labels(arguments.labels.resolve(), corpora)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"head-to-head: {exc}", file=sys.stderr)
        return 2

    results: list[dict[str, object]] = []
    try:
        for corpus in corpora:
            shipproof_result = run_shipproof(corpus, arguments.repeat)
            results.append(
                {
                    "tool": "shipproof",
                    "corpus": corpus.name,
                    "result": shipproof_result,
                    "metrics": compute_file_metrics(
                        shipproof_result["files_flagged"], labels[corpus.name]
                    ),
                }
            )
            if configs:
                semgrep_result = run_semgrep(corpus, configs, arguments.repeat)
                results.append(
                    {
                        "tool": "semgrep",
                        "corpus": corpus.name,
                        "result": semgrep_result,
                        "metrics": compute_file_metrics(
                            semgrep_result["files_flagged"], labels[corpus.name]
                        ),
                    }
                )
    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"head-to-head: unavailable evidence: {exc}", file=sys.stderr)
        return 2

    threshold_failures: list[str] = []
    for entry in results:
        if entry["tool"] != "shipproof":
            continue
        metrics = entry["metrics"]
        precision = metrics["file_precision"]
        recall = metrics["file_recall"]
        if (
            arguments.min_file_precision is not None
            and precision is not None
            and precision < arguments.min_file_precision
        ):
            threshold_failures.append(f"{entry['corpus']}:precision={precision}")
        if (
            arguments.min_file_recall is not None
            and recall is not None
            and recall < arguments.min_file_recall
        ):
            threshold_failures.append(f"{entry['corpus']}:recall={recall}")

    if arguments.format == "json":
        print(
            json.dumps(
                {
                    "labels": labels,
                    "results": results,
                    "threshold_failures": threshold_failures,
                },
                indent=2,
            )
        )
    else:
        print(render_markdown(results))
    return 1 if threshold_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
