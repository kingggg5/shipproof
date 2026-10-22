#!/usr/bin/env python3
"""Compare a clean-corpus evaluation report against checked-in precision thresholds.

This is an offline maintainer/CI gate. It never installs packages, never calls
the network, and never claims a public precision percentage.

Usage:
  python scripts/check-precision-trend.py
  python scripts/check-precision-trend.py --report path/to/benchmark-clean-corpus.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from paired_corpus import validate_report  # noqa: E402

DEFAULT_BASELINE = ROOT / "benchmarks" / "clean-corpus-baseline.json"
DEFAULT_THRESHOLDS = ROOT / "benchmarks" / "precision-thresholds.json"


def load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: document must be an object")
    return payload


def corpus_metrics(payload: dict[str, Any]) -> dict[str, Any]:
    if "paired" in payload or payload.get("schema_version") == "2.0":
        payload = validate_report(payload)
    summary = payload.get("summary")
    if not isinstance(summary, dict):
        raise ValueError("clean-corpus report is missing summary")
    blocked = int(summary.get("blocked_count") or 0)
    records: list[dict[str, Any]] = []
    for package in payload.get("packages") or []:
        if not isinstance(package, dict):
            continue
        findings = package.get("app_finding_records") or []
        if isinstance(findings, list):
            records.extend(item for item in findings if isinstance(item, dict))
    high_critical = [item for item in records if item.get("severity") in {"high", "critical"}]
    gate_high_medium = [
        item
        for item in records
        if item.get("tier") != "advisory" and item.get("severity") in {"critical", "high", "medium"}
    ]
    high_confidence = [item for item in records if item.get("confidence") == "high"]
    ratio = (len(high_confidence) / len(records)) if records else 0.0
    labels = payload.get("label_report") if isinstance(payload.get("label_report"), dict) else {}
    violations = labels.get("fp_budget_violations") or []
    if not isinstance(violations, list):
        raise ValueError("label_report.fp_budget_violations must be a list")
    if "label_report" not in payload:
        unreviewed_high_critical = len(high_critical)
    else:
        unreviewed_high_critical = int(labels.get("unreviewed_high_critical") or 0)
    return {
        "blocked_packages": blocked,
        "high_critical_app_findings": len(high_critical),
        "gate_high_medium_findings": len(gate_high_medium),
        "high_confidence_ratio": ratio,
        "fp_budget_violations": [str(item) for item in violations],
        "unreviewed_high_critical": unreviewed_high_critical,
        "app_findings": len(records),
    }


def check_clean_corpus(metrics: dict[str, Any], thresholds: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if metrics["blocked_packages"] > int(thresholds["max_blocked_packages"]):
        failures.append(
            f"blocked packages {metrics['blocked_packages']} exceed "
            f"{thresholds['max_blocked_packages']}"
        )
    if metrics["high_critical_app_findings"] > int(thresholds["max_high_critical_app_findings"]):
        failures.append(
            f"high/critical findings {metrics['high_critical_app_findings']} exceed "
            f"{thresholds['max_high_critical_app_findings']}"
        )
    if metrics["gate_high_medium_findings"] > int(thresholds["max_gate_high_medium_findings"]):
        failures.append(
            f"gate high+medium findings {metrics['gate_high_medium_findings']} exceed "
            f"{thresholds['max_gate_high_medium_findings']}"
        )
    if metrics["high_confidence_ratio"] > float(thresholds["max_high_confidence_ratio"]):
        failures.append(
            f"high-confidence ratio {metrics['high_confidence_ratio']:.3f} exceeds "
            f"{thresholds['max_high_confidence_ratio']}"
        )
    violations = metrics["fp_budget_violations"]
    if len(violations) > int(thresholds["max_fp_budget_violations"]):
        failures.append(f"FP budget violations {violations}")
    if metrics["unreviewed_high_critical"] > int(thresholds["max_unreviewed_high_critical"]):
        failures.append(
            f"unreviewed high/critical {metrics['unreviewed_high_critical']} exceed "
            f"{thresholds['max_unreviewed_high_critical']}"
        )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--thresholds", type=Path, default=DEFAULT_THRESHOLDS)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--require-paired", action="store_true")
    arguments = parser.parse_args()
    try:
        report = load_json(arguments.report)
        if arguments.require_paired and report.get("schema_version") != "2.0":
            raise ValueError("a paired-corpus report is required")
        thresholds_doc = load_json(arguments.thresholds)
        if thresholds_doc.get("schema_version") != 1:
            raise ValueError("precision thresholds schema_version must be 1")
        clean = thresholds_doc.get("clean_corpus")
        if not isinstance(clean, dict):
            raise ValueError("precision thresholds must include clean_corpus")
        metrics = corpus_metrics(report)
        failures = check_clean_corpus(metrics, clean)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"precision trend: {exc}", file=sys.stderr)
        return 2
    payload = {"metrics": metrics, "failures": failures}
    if arguments.json:
        print(json.dumps(payload, indent=2))
    else:
        print(
            "clean-corpus "
            f"blocked={metrics['blocked_packages']} "
            f"high_critical={metrics['high_critical_app_findings']} "
            f"gate_high_medium={metrics['gate_high_medium_findings']} "
            f"high_confidence_ratio={metrics['high_confidence_ratio']:.3f} "
            f"fp_budget={metrics['fp_budget_violations']} "
            f"unreviewed_high_critical={metrics['unreviewed_high_critical']}"
        )
        for failure in failures:
            print(f"FAIL: {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
