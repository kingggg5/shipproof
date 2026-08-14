#!/usr/bin/env python3
"""Fail CI when measured performance exceeds reviewed resource budgets."""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path


def load_json_object(path: str | Path) -> dict[str, object]:
    try:
        if str(path) == "-":
            value = json.loads(sys.stdin.read())
        else:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def extract_metric_values(payload: Mapping[str, object], label: str) -> Mapping[str, object]:
    values = payload.get("metrics", payload)
    if not isinstance(values, dict):
        raise ValueError(f"{label} metrics must be a JSON object")
    return values


def require_finite_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{label} must be a finite number")
    return float(value)


def evaluate_resource_budget(
    baseline_payload: Mapping[str, object],
    current_payload: Mapping[str, object],
    budget_payload: Mapping[str, object],
) -> dict[str, object]:
    baseline_metrics = extract_metric_values(baseline_payload, "baseline")
    current_metrics = extract_metric_values(current_payload, "current")
    budget_rules = extract_metric_values(budget_payload, "budget")
    if not budget_rules:
        raise ValueError("budget must define at least one metric")

    results: list[dict[str, object]] = []
    for metric_name, rule_config in budget_rules.items():
        if not isinstance(metric_name, str) or not isinstance(rule_config, dict):
            raise ValueError("each budget metric must map a name to an object")
        if metric_name not in baseline_metrics or metric_name not in current_metrics:
            raise ValueError(f"metric {metric_name!r} is missing from baseline or current data")

        baseline_value = require_finite_number(
            baseline_metrics[metric_name], f"baseline.{metric_name}"
        )
        current_value = require_finite_number(
            current_metrics[metric_name], f"current.{metric_name}"
        )
        direction = rule_config.get("direction", "lower")
        if direction not in ("lower", "higher"):
            raise ValueError(f"budget.{metric_name}.direction must be 'lower' or 'higher'")

        reasons: list[str] = []
        maximum_regression = rule_config.get("max_regression_percent")
        regression_percent: float | None = None
        if maximum_regression is not None:
            maximum_regression_value = require_finite_number(
                maximum_regression,
                f"budget.{metric_name}.max_regression_percent",
            )
            if maximum_regression_value < 0:
                raise ValueError(f"budget.{metric_name}.max_regression_percent cannot be negative")
            if baseline_value <= 0:
                raise ValueError(f"baseline.{metric_name} must be positive for relative comparison")
            change_percent = (current_value - baseline_value) / baseline_value * 100
            regression_percent = change_percent if direction == "lower" else -change_percent
            if regression_percent > maximum_regression_value + 1e-7:
                reasons.append(
                    f"regressed {regression_percent:.2f}% (allowed {maximum_regression_value:.2f}%)"
                )

        if "max" in rule_config:
            maximum = require_finite_number(rule_config["max"], f"budget.{metric_name}.max")
            if current_value > maximum:
                reasons.append(f"{current_value:g} exceeds maximum {maximum:g}")
        if "min" in rule_config:
            minimum = require_finite_number(rule_config["min"], f"budget.{metric_name}.min")
            if current_value < minimum:
                reasons.append(f"{current_value:g} is below minimum {minimum:g}")
        if maximum_regression is None and "max" not in rule_config and "min" not in rule_config:
            raise ValueError(f"budget.{metric_name} must define a relative or absolute limit")

        results.append(
            {
                "metric": metric_name,
                "direction": direction,
                "baseline": baseline_value,
                "current": current_value,
                "regression_percent": None
                if regression_percent is None
                else round(regression_percent, 4),
                "status": "fail" if reasons else "pass",
                "reasons": reasons,
            }
        )

    return {
        "schema_version": "1.0",
        "passed": all(item["status"] == "pass" for item in results),
        "results": results,
    }


def render_markdown_report(payload: Mapping[str, object]) -> str:
    verdict = "PASS" if payload["passed"] else "FAIL"
    lines = [
        f"# ShipProof resource budget: {verdict}",
        "",
        "| Metric | Baseline | Current | Regression | Status | Reason |",
        "| --- | ---: | ---: | ---: | --- | --- |",
    ]
    for item in payload["results"]:
        regression = (
            "n/a" if item["regression_percent"] is None else f"{item['regression_percent']:.2f}%"
        )
        reason = "; ".join(item["reasons"]) or "within budget"
        lines.append(
            f"| `{item['metric']}` | {item['baseline']:g} | {item['current']:g} | {regression} | {item['status'].upper()} | {reason} |"
        )
    lines.append("")
    return "\n".join(lines)


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline", type=str, required=True, help="Baseline JSON file path or '-' for stdin"
    )
    parser.add_argument(
        "--current", type=str, required=True, help="Current JSON file path or '-' for stdin"
    )
    parser.add_argument(
        "--budget", type=str, required=True, help="Budget JSON file path or '-' for stdin"
    )
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    arguments = parse_arguments(argv)
    if (arguments.baseline, arguments.current, arguments.budget).count("-") > 1:
        print("shipproof: stdin ('-') may be used for only one input", file=sys.stderr)
        return 2
    try:
        report_payload = evaluate_resource_budget(
            load_json_object(arguments.baseline),
            load_json_object(arguments.current),
            load_json_object(arguments.budget),
        )
    except ValueError as exc:
        print(f"shipproof: {exc}", file=sys.stderr)
        return 2
    rendered_report = (
        render_markdown_report(report_payload)
        if arguments.format == "markdown"
        else json.dumps(report_payload, indent=2)
    )
    if arguments.output:
        arguments.output.write_text(
            rendered_report + ("" if rendered_report.endswith("\n") else "\n"), encoding="utf-8"
        )
    else:
        print(rendered_report)
    return 0 if report_payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
