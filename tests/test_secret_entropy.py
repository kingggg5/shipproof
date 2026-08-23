from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from scan_repo import (  # noqa: E402
    find_regex_issues,
    find_rule,
    secret_confidence,
)


def confidence_for(rule_id: str, source: str):
    """Mimic the production call site: calibration sees the RAW matched line,
    redaction happens afterwards in make_finding."""
    findings = find_regex_issues(Path("x.py"), "x.py", source)
    if not any(f.rule_id == rule_id for f in findings):
        return None
    return secret_confidence(find_rule(rule_id), source)


class SecretEntropyGateTests(unittest.TestCase):
    """Demote-only entropy gate for secret rules outside the calibrated set."""

    def test_structured_token_with_repeated_chars_demotes(self) -> None:
        # Format-valid GitHub token shape but obviously filler content.
        src = 'token = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
        self.assertEqual(confidence_for("SP006", src), "low")

    def test_high_entropy_structured_token_keeps_confidence(self) -> None:
        src = 'token = "ghp_K9mXq2vLp7wZrT3sYnB8cD4fG6hJ1kN5"'
        self.assertIsNone(confidence_for("SP006", src))

    def test_calibrated_rules_keep_two_way_behavior(self) -> None:
        # SP003 requires >=16-char values; a long zero-entropy filler demotes.
        low = confidence_for("SP003", 'api_key = "aaaaaaaaaaaaaaaaaaaa"')
        self.assertEqual(low, "low")

    def test_short_values_outside_calibration_untouched(self) -> None:
        # Values shorter than 8 chars are handled by calibrated rules only.
        src = 'token = "ghp_ab"'
        self.assertIsNone(confidence_for("SP006", src))


if __name__ == "__main__":
    unittest.main()
