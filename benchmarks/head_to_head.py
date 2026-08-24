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
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "skills" / "audit-production-readiness" / "scripts" / "scan_repo.py"
DEFAULT_LABELS = ROOT / "benchmarks" / "head-to-head-labels.json"


def sha256_tree(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(
        (
            candidate
            for candidate in root.rglob("*")
            if candidate.is_symlink() or candidate.is_file()
        ),
        key=lambda candidate: candidate.relative_to(root).as_posix(),
    ):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"SYMLINK\0")
            digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
        else:
            digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


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
    file_rule_hits: set[tuple[str, str]] | None = None
    files_scanned: int | None = None
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
        current_files_scanned = int(report["summary"]["files_scanned"])
        if files_scanned is not None and current_files_scanned != files_scanned:
            raise RuntimeError("shipproof file count changed between repeated runs")
        files_scanned = current_files_scanned
        prefix = f"{corpus.name}/"
        current_hits: set[tuple[str, str]] = set()
        for finding in report["findings"]:
            path = finding["path"].removeprefix(prefix)
            current_hits.add((path, finding["rule_id"]))
        if file_rule_hits is not None and current_hits != file_rule_hits:
            raise RuntimeError("shipproof findings changed between repeated runs")
        file_rule_hits = current_hits
    if file_rule_hits is None:
        raise RuntimeError("shipproof benchmark did not execute")
    files_flagged = sorted({path for path, _ in file_rule_hits})
    return {
        "tool": "shipproof",
        "median_seconds": round(statistics.median(durations), 3),
        "samples_seconds": [round(value, 3) for value in durations],
        "files_scanned": files_scanned,
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
    file_rule_hits: set[tuple[str, str]] | None = None
    command = build_semgrep_command(corpus, configs)
    for _ in range(repeat):
        elapsed, process = timed_run(command, corpus.parent)
        if process.returncode not in (0, 1):
            raise RuntimeError(f"semgrep exited {process.returncode}: {process.stderr[:400]}")
        durations.append(elapsed)
        payload = json.loads(process.stdout)
        current_hits: set[tuple[str, str]] = set()
        for result in payload.get("results", []):
            path = str(result.get("path", "")).removeprefix(f"{corpus.name}/")
            current_hits.add((path, str(result.get("check_id", "semgrep"))))
        if file_rule_hits is not None and current_hits != file_rule_hits:
            raise RuntimeError("semgrep findings changed between repeated runs")
        file_rule_hits = current_hits
    if file_rule_hits is None:
        raise RuntimeError("semgrep benchmark did not execute")
    files_flagged = sorted({path for path, _ in file_rule_hits})
    return {
        "tool": "semgrep",
        "median_seconds": round(statistics.median(durations), 3),
        "samples_seconds": [round(value, 3) for value in durations],
        "findings": len(file_rule_hits),
        "files_flagged": files_flagged,
        "rule_hits": sorted(f"{path}:{rule}" for path, rule in file_rule_hits),
    }


def compute_file_metrics(
    files_flagged: Sequence[str],
    labeled_files: Sequence[str],
    total_files: int | None = None,
    context_only_files: Sequence[str] = (),
) -> dict[str, object]:
    """File-level scoring: identical labels for every tool, no rule mapping needed."""
    context_only = set(context_only_files)
    flagged = set(files_flagged) - context_only
    labeled = set(labeled_files)
    if labeled & context_only:
        raise ValueError("positive and context-only labels must be disjoint")
    true_positives = len(flagged & labeled)
    false_positives = len(flagged - labeled)
    false_negatives = len(labeled - flagged)
    observed_files = len(flagged | labeled)
    universe_size = observed_files if total_files is None else total_files - len(context_only)
    if universe_size < observed_files:
        raise ValueError("total_files is smaller than the observed label/finding universe")
    true_negatives = universe_size - true_positives - false_positives - false_negatives
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
        "true_negatives": true_negatives,
        "total_files": universe_size,
        "context_only_files": len(context_only),
        "file_precision": round(precision, 3) if precision is not None else None,
        "file_recall": round(recall, 3) if recall is not None else None,
        "file_f1": round(f1, 3) if f1 is not None else None,
    }


def load_labels(labels_path: Path, corpora: Sequence[Path]) -> dict[str, dict[str, list[str]]]:
    if not labels_path.is_file():
        raise FileNotFoundError(f"label file does not exist: {labels_path}")
    payload = json.loads(labels_path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 2 or not isinstance(payload.get("corpora"), dict):
        raise ValueError("label file must use schema_version 2 with a corpora object")
    labels: dict[str, dict[str, list[str]]] = {}
    for corpus in corpora:
        entry = payload["corpora"].get(corpus.name)
        if not isinstance(entry, dict):
            raise ValueError(f"label file is missing corpus {corpus.name}")
        positive = entry.get("positive_files")
        context_only = entry.get("context_only_files")
        if not isinstance(positive, list) or not isinstance(context_only, list):
            raise ValueError(f"{corpus.name}: labels must be arrays")
        if any(not isinstance(value, str) or not value for value in [*positive, *context_only]):
            raise ValueError(f"{corpus.name}: labels must be non-empty strings")
        if set(positive) & set(context_only):
            raise ValueError(f"{corpus.name}: positive and context-only labels overlap")
        for relative_path in [*positive, *context_only]:
            path = Path(relative_path)
            if path.is_absolute() or ".." in path.parts or not (corpus / path).is_file():
                raise ValueError(f"{corpus.name}: invalid or missing labeled file {relative_path}")
        labels[corpus.name] = {
            "positive_files": sorted(set(positive)),
            "context_only_files": sorted(set(context_only)),
        }
    return labels


def render_markdown(results: Sequence[dict[str, object]]) -> str:
    lines = [
        "# ShipProof head-to-head results",
        "",
        "Same corpora, same machine, median end-to-end wall time per tool.",
        "File-level scoring uses the shared label file; it describes these",
        "corpora and configs only, not general superiority.",
        "",
        "| Tool | Corpus | Median seconds | Findings | TP | FP | FN | TN | Precision | Recall | F1 |",
        "| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for entry in results:
        metrics = entry["metrics"]
        lines.append(
            "| {tool} | {corpus} | {seconds} | {findings} | {tp} | {fp} | {fn} | {tn} | "
            "{precision} | {recall} | {f1} |".format(
                tool=entry["tool"],
                corpus=entry["corpus"],
                seconds=entry["result"]["median_seconds"],
                findings=entry["result"]["findings"],
                tp=metrics["true_positives"],
                fp=metrics["false_positives"],
                fn=metrics["false_negatives"],
                tn=metrics["true_negatives"],
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
            total_files = int(shipproof_result["files_scanned"])
            corpus_labels = labels[corpus.name]
            results.append(
                {
                    "tool": "shipproof",
                    "corpus": corpus.name,
                    "result": shipproof_result,
                    "metrics": compute_file_metrics(
                        shipproof_result["files_flagged"],
                        corpus_labels["positive_files"],
                        total_files,
                        corpus_labels["context_only_files"],
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
                            semgrep_result["files_flagged"],
                            corpus_labels["positive_files"],
                            total_files,
                            corpus_labels["context_only_files"],
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
                    "schema_version": "1.0",
                    "tool": {"name": "ShipProof", "command": "head-to-head"},
                    "environment": {
                        "platform": platform.platform(),
                        "python": platform.python_version(),
                        "repeat": arguments.repeat,
                    },
                    "labels_sha256": hashlib.sha256(
                        arguments.labels.resolve().read_bytes()
                    ).hexdigest(),
                    "corpus_sha256": {corpus.name: sha256_tree(corpus) for corpus in corpora},
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
