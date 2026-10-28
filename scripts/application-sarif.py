"""Prepare GitHub application alerts; keep the original full SARIF untouched."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

MAX_BYTES = 16 * 1024 * 1024


def application_report(report, categories):
    categories = [value.rstrip("/") for value in categories]
    if not isinstance(report, dict) or report.get("version") != "2.1.0":
        raise ValueError("expected SARIF 2.1.0")
    runs = report.get("runs")
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
        raise ValueError("expected one native ShipProof run")
    run = runs[0]
    if run.get("tool", {}).get("driver", {}).get("name") != "ShipProof":
        raise ValueError("expected native ShipProof evidence")
    results = run.get("results")
    if not isinstance(results, list) or len(results) > 50000:
        raise ValueError("invalid or over-limit result list")
    active = []
    for result in results:
        if not isinstance(result, dict) or not isinstance(result.get("properties", {}), dict):
            raise ValueError("invalid result or scope metadata")
        if result.get("properties", {}).get("scope") != "test":
            active.append(result)
    if not 1 <= len(categories) <= 2 or len(set(categories)) != len(categories):
        raise ValueError("expected one or two distinct comparison categories")
    if any(
        not value or len(value) > 512 or any(ord(c) < 32 for c in value) for value in categories
    ):
        raise ValueError("invalid comparison category")
    return {
        **report,
        "runs": [
            {
                **run,
                "results": active,
                "automationDetails": {"id": category.rstrip("/") + "/"},
                "properties": {
                    **run.get("properties", {}),
                    "alert_scope": "application",
                    "test_results_in_full_report": len(results) - len(active),
                },
            }
            for category in categories
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--category", action="append", required=True)
    args = parser.parse_args(argv)
    try:
        if args.source.resolve() == args.output.resolve():
            raise ValueError("the full report must remain separate")
        with args.source.open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("SARIF exceeds the 16-MiB input budget")
        projected = application_report(json.loads(data.decode("utf-8")), args.category)
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(projected, stream, indent=2)
            stream.write("\n")
    except (OSError, UnicodeError, ValueError, TypeError, AttributeError, RecursionError) as exc:
        print(f"application SARIF unavailable: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
