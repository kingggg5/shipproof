#!/usr/bin/env python3
"""Fail CI when measured performance exceeds reviewed resource budgets."""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Mapping, Sequence


def load_object(path: str | Path) -> dict[str, object]:
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


def metric_values(payload: Mapping[str, object], label: str) -> Mapping[str, object]:
    values = payload.get("metrics", payload)
    if not isinstance(values, dict):
        raise ValueError(f"{label} metrics must be a JSON object")
    return values


def number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{label} must be a finite number")
    return float(value)


def evaluate(
    baseline_payload: Mapping[str, object],
    current_payload: Mapping[str, object],
    budget_payload: Mapping[str, object],
) -> dict[str, object]:
    baseline = metric_values(baseline_payload, "baseline")
    current = metric_values(current_payload, "current")
    budgets = metric_values(budget_payload, "budget")
    if not budgets:
        raise ValueError("budget must define at least one metric")

    results: list[dict[str, object]] = []
    for name, raw_rule in budgets.items():
        if not isinstance(name, str) or not isinstance(raw_rule, dict):
            raise ValueError("each budget metric must map a name to an object")
        if name not in baseline or name not in current:
            raise ValueError(f"metric {name!r} is missing from baseline or current data")

        before = number(baseline[name], f"baseline.{name}")
        after = number(current[name], f"current.{name}")
        direction = raw_rule.get("direction", "lower")
        if direction not in ("lower", "higher"):
            raise ValueError(f"budget.{name}.direction must be 'lower' or 'higher'")

        reasons: list[str] = []
        allowed = raw_rule.get("max_regression_percent")
        delta_percent: float | None = None
        if allowed is not None:
            allowed_value = number(allowed, f"budget.{name}.max_regression_percent")
            if allowed_value < 0:
                raise ValueError(f"budget.{name}.max_regression_percent cannot be negative")
            if before <= 0:
                raise ValueError(f"baseline.{name} must be positive for relative comparison")
            change = (after - before) / before * 100
            delta_percent = change if direction == "lower" else -change
            if delta_percent > allowed_value + 1e-7:
                reasons.append(f"regressed {delta_percent:.2f}% (allowed {allowed_value:.2f}%)")

        if "max" in raw_rule:
            maximum = number(raw_rule["max"], f"budget.{name}.max")
            if after > maximum:
                reasons.append(f"{after:g} exceeds maximum {maximum:g}")
        if "min" in raw_rule:
            minimum = number(raw_rule["min"], f"budget.{name}.min")
            if after < minimum:
                reasons.append(f"{after:g} is below minimum {minimum:g}")
        if allowed is None and "max" not in raw_rule and "min" not in raw_rule:
            raise ValueError(f"budget.{name} must define a relative or absolute limit")

        results.append({
            "metric": name,
            "direction": direction,
            "baseline": before,
            "current": after,
            "regression_percent": None if delta_percent is None else round(delta_percent, 4),
            "status": "fail" if reasons else "pass",
            "reasons": reasons,
        })

    return {
        "schema_version": "1.0",
        "passed": all(item["status"] == "pass" for item in results),
        "results": results,
    }


def markdown(payload: Mapping[str, object]) -> str:
    verdict = "PASS" if payload["passed"] else "FAIL"
    lines = [f"# ShipProof resource budget: {verdict}", "", "| Metric | Baseline | Current | Regression | Status | Reason |", "| --- | ---: | ---: | ---: | --- | --- |"]
    for item in payload["results"]:
        regression = "n/a" if item["regression_percent"] is None else f"{item['regression_percent']:.2f}%"
        reason = "; ".join(item["reasons"]) or "within budget"
        lines.append(f"| `{item['metric']}` | {item['baseline']:g} | {item['current']:g} | {regression} | {item['status'].upper()} | {reason} |")
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=str, required=True, help="Baseline JSON file path or '-' for stdin")
    parser.add_argument("--current", type=str, required=True, help="Current JSON file path or '-' for stdin")
    parser.add_argument("--budget", type=str, required=True, help="Budget JSON file path or '-' for stdin")
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass
    args = parse_args(argv)
    if (args.baseline, args.current, args.budget).count("-") > 1:
        print("shipproof: stdin ('-') may be used for only one input", file=sys.stderr)
        return 2
    try:
        payload = evaluate(load_object(args.baseline), load_object(args.current), load_object(args.budget))
    except ValueError as exc:
        print(f"shipproof: {exc}", file=sys.stderr)
        return 2
    rendered = markdown(payload) if args.format == "markdown" else json.dumps(payload, indent=2)
    if args.output:
        args.output.write_text(rendered + ("" if rendered.endswith("\n") else "\n"), encoding="utf-8")
    else:
        print(rendered)
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
