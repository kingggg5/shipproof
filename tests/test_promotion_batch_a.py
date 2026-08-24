from __future__ import annotations

import json
import re
import subprocess
import sys
import unittest
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).parents[1]
SCANNER_SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCANNER_SCRIPTS))

from scan_repo import RULES  # noqa: E402


def source_for(case: dict[str, object]) -> str:
    return "".join(str(part) for part in case["source_parts"])


class PromotionBatchATests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.batch = json.loads(
            (ROOT / "research" / "promotion-batch-a.json").read_text(encoding="utf-8")
        )
        catalog = json.loads(
            (ROOT / "research" / "language-rule-candidates.json").read_text(encoding="utf-8")
        )
        cls.catalog = {item["candidate_id"]: item for item in catalog["candidates"]}
        cls.rules = {rule.rule_id: rule for rule in RULES}

    def test_batch_is_bounded_partitioned_and_not_silently_promoted(self) -> None:
        candidates = self.batch["candidates"]
        ids = [item["candidate_id"] for item in candidates]
        self.assertEqual(self.batch["schema_version"], 1)
        self.assertEqual(self.batch["candidate_count"], 25)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(
            Counter(item["ecosystem"] for item in candidates), self.batch["ecosystem_caps"]
        )
        self.assertEqual(self.batch["status_counts"], {"fixture_ready": 3, "rejected": 22})
        self.assertEqual(self.batch["promoted_ids"], [])
        self.assertTrue(set(ids).isdisjoint(self.rules))

    def test_catalog_identity_sources_and_duplicate_claims_are_exact(self) -> None:
        for item in self.batch["candidates"]:
            candidate = self.catalog[item["candidate_id"]]
            with self.subTest(candidate=item["candidate_id"]):
                self.assertEqual(item["ecosystem"], candidate["ecosystem"])
                self.assertEqual(item["source_id"], candidate["source_id"])
                self.assertEqual(item["applicability_tier"], "direct")
                self.assertEqual(item["catalog_status"], "research_only")
                self.assertGreaterEqual(len(item["decision"]), 100)
                hosts = set()
                for source in item["sources"]:
                    parsed = urlparse(source["url"])
                    self.assertEqual(parsed.scheme, "https")
                    self.assertTrue(parsed.netloc)
                    self.assertGreaterEqual(len(source["claim"]), 60)
                    hosts.add(parsed.netloc)
                self.assertGreaterEqual(len(hosts), 2)
                for rule_id in item["duplicate_rule_ids"]:
                    self.assertIn(rule_id, self.rules)

    def test_fixture_ready_prototypes_have_complete_executable_polarity(self) -> None:
        entries = [
            item for item in self.batch["candidates"] if item["batch_status"] == "fixture_ready"
        ]
        for item in entries:
            prototype = item["prototype"]
            flags = 0
            for name in prototype["flags"]:
                flags |= getattr(re, name)
            pattern = re.compile(prototype["pattern"], flags)
            cases = item["cases"]
            with self.subTest(candidate=item["candidate_id"]):
                self.assertEqual(prototype["engine"], "regex_research_only")
                self.assertGreaterEqual(len(item["false_positive_analysis"]), 200)
                self.assertGreaterEqual(len(cases["positive"]), 2)
                self.assertGreaterEqual(len(cases["negative"]), 4)
                self.assertGreaterEqual(len(cases["adversarial"]), 2)
                for polarity in ("positive", "negative", "adversarial"):
                    for case in cases[polarity]:
                        detected = bool(pattern.search(source_for(case)))
                        self.assertEqual(detected, case["expected"], source_for(case))
                        self.assertIn(Path(case["path"]).suffix, prototype["suffixes"])
                        if polarity == "adversarial":
                            self.assertGreaterEqual(len(case["rationale"]), 80)

    def test_rejections_are_final_for_this_batch_and_residuals_fail_closed(self) -> None:
        for item in self.batch["candidates"]:
            if item["batch_status"] == "rejected":
                with self.subTest(candidate=item["candidate_id"]):
                    self.assertTrue(item["rejection_class"])
                    self.assertTrue(item["recommended_route"])
                    self.assertNotIn("prototype", item)
        residuals = self.batch["residual_evidence"]
        self.assertEqual(len(residuals), 3)
        self.assertTrue(all(item["state"] != "complete" for item in residuals))

    def test_builder_is_deterministic_and_current(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/build_promotion_batch_a.py", "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
