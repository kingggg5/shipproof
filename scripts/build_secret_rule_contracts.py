#!/usr/bin/env python3
"""Build deterministic v2 fixture references for ShipProof secret rules."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
SCANNER_SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
TESTS = ROOT / "tests"
sys.path.insert(0, str(SCANNER_SCRIPTS))
sys.path.insert(0, str(TESTS))

from scan_repo import deduplicate_and_suppress_findings, find_regex_issues  # noqa: E402
from secret_positive_fixtures import contract_source  # noqa: E402

MANIFEST = TESTS / "rule_cases_secrets.json"
POSITIVE_CASES = ("positive_a", "positive_b")
NEGATIVE_CASES = ("negative_prefix_fragment", "negative_suffix_fragment")
ADVERSARIAL_CASE = "adversarial_split_literal"


def fixture_path(rule_id: str, case_id: str) -> str:
    suffix = ".json" if rule_id == "SP005" else ".py" if rule_id == "SP004" else ".txt"
    return f"contract-secrets/{rule_id.lower()}-{case_id}{suffix}"


def findings_for(path_value: str, source: str) -> list[Any]:
    path = Path(path_value)
    findings = find_regex_issues(path, path.as_posix(), source)
    active, _ = deduplicate_and_suppress_findings(findings)
    return active


def positive_case(rule_id: str, case_id: str) -> dict[str, Any]:
    path = fixture_path(rule_id, case_id)
    source = contract_source(rule_id, case_id)
    matches = [finding for finding in findings_for(path, source) if finding.rule_id == rule_id]
    if len(matches) != 1:
        raise ValueError(f"{rule_id}:{case_id} expected one finding, got {len(matches)}")
    finding = matches[0]
    return {
        "path": path,
        "source_fixture": {"provider": "secret-runtime", "case": case_id},
        "expected_line": finding.line,
        "expected_detection": finding.detection,
        "expected_proof_level": finding.proof_level,
        "expected_fingerprint": finding.fingerprint,
    }


def silent_case(rule_id: str, case_id: str) -> dict[str, Any]:
    path = fixture_path(rule_id, case_id)
    source = contract_source(rule_id, case_id)
    if any(finding.rule_id == rule_id for finding in findings_for(path, source)):
        raise ValueError(f"{rule_id}:{case_id} unexpectedly triggers the target rule")
    return {
        "path": path,
        "source_fixture": {"provider": "secret-runtime", "case": case_id},
    }


def build_payload(current: dict[str, Any]) -> dict[str, Any]:
    payload = dict(current)
    payload["schema_version"] = 2
    payload["quality_contract_version"] = 2
    payload["coverage"] = "SP001-SP050 secrets lane (runtime synthetic v2 fixtures)"
    payload["fixture_source"] = "tests/secret_positive_fixtures.py:contract_source"
    rules = []
    for original in current["rules"]:
        entry = dict(original)
        rule_id = entry["rule_id"]
        entry["cases"] = {
            "positive": [positive_case(rule_id, case_id) for case_id in POSITIVE_CASES],
            "negative": [silent_case(rule_id, case_id) for case_id in NEGATIVE_CASES],
            "adversarial": [
                {
                    **silent_case(rule_id, ADVERSARIAL_CASE),
                    "expected": False,
                    "rationale": (
                        "The provider-shaped value is split across two source literals, so the "
                        "line-oriented detector intentionally treats it as an unverified evasion "
                        "boundary instead of claiming cross-expression reconstruction."
                    ),
                }
            ],
        }
        rules.append(entry)
    payload["rules"] = rules
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare generated content with the checked-in manifest without writing",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    current = json.loads(MANIFEST.read_text(encoding="utf-8"))
    generated = json.dumps(build_payload(current), indent=2) + "\n"
    if args.check:
        if generated != MANIFEST.read_text(encoding="utf-8"):
            print(f"{MANIFEST.relative_to(ROOT)} is stale", file=sys.stderr)
            return 1
        print(f"{MANIFEST.relative_to(ROOT)} is current")
        return 0
    MANIFEST.write_text(generated, encoding="utf-8")
    print(f"updated {MANIFEST.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
