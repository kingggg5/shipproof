#!/usr/bin/env python3
"""Validate and refresh metadata in the promoted-rules quality manifest.

tests/rule_cases_promoted.json is the authoring surface for evidence cases
(positive/negative/adversarial snippets are intentionally vulnerable code and
must live only there, never inside this script, so repository self-audits
stay clean). This tool re-derives scanner-metadata fields and primary-source
attribution, verifies full SP051-SP080 coverage, and fails on drift.

Usage: python scripts/build-promoted-quality-manifest.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from scan_repo import RULES  # noqa: E402

MANIFEST = ROOT / "tests" / "rule_cases_promoted.json"
PROMOTED_RANGE = range(51, 96)
ASVS_BASE = "https://owasp.org/www-project-application-security-verification-standard/"


def cwe_url(cwe: str) -> str:
    digits = "".join(ch for ch in cwe if ch.isdigit())
    return f"https://cwe.mitre.org/data/definitions/{digits}.html"


def main() -> int:
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    by_id = {rule.rule_id: rule for rule in RULES}
    wanted = [f"SP{n:03d}" for n in PROMOTED_RANGE]

    missing = [rid for rid in wanted if rid not in by_id]
    if missing:
        raise SystemExit(f"promoted rules absent from scanner: {missing}")

    entries = {entry["rule_id"]: entry for entry in payload["rules"]}
    problems: list[str] = []

    for rid in wanted:
        if rid not in entries:
            problems.append(f"{rid}: missing manifest entry")
            continue
        entry = entries[rid]
        rule = by_id[rid]

        # Scanner metadata is authoritative; refresh it in place.
        entry["title"] = rule.title
        entry["expected_severity"] = rule.severity
        entry["expected_confidence"] = rule.confidence
        entry["cwe"] = rule.cwe
        cwe_digits = "".join(ch for ch in rule.cwe if ch.isdigit())
        entry["sources"] = [
            {
                "url": cwe_url(rule.cwe),
                "claim": (
                    f"MITRE CWE-{cwe_digits} defines the {rule.title.lower()} weakness "
                    f"class that this detector recognizes locally."
                ),
            },
            {
                "url": ASVS_BASE,
                "claim": (
                    f"OWASP ASVS maps {rule.cwe} controls to the verification requirements "
                    f"in {rule.owasp}, which the remediation text follows."
                ),
            },
        ]

        cases = entry.get("cases", {})
        for polarity, minimum in (("positive", 2), ("negative", 4), ("adversarial", 2)):
            group = cases.get(polarity) or []
            if len(group) < minimum:
                problems.append(
                    f"{rid}: {polarity} fixtures below minimum ({len(group)}<{minimum})"
                )
            for index, case in enumerate(group):
                if polarity == "adversarial" and (
                    "expected" not in case or len(case.get("rationale", "")) < 40
                ):
                    problems.append(f"{rid}: adversarial[{index}] needs expected + rationale")

        if len(entry.get("false_positive_analysis", "")) < 120:
            problems.append(f"{rid}: false_positive_analysis too short")

    if problems:
        for problem in problems:
            print(f"manifest problem: {problem}", file=sys.stderr)
        return 1

    payload["promotion_range"] = ["SP051", "SP095"]
    payload["rules"] = [entries[rid] for rid in sorted(entries)]
    MANIFEST.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"validated + refreshed metadata for {len(entries)} promoted rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
