from __future__ import annotations

import json
import re
import runpy
import unittest
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).parents[1]
CATALOG_PATH = ROOT / "research" / "language-rule-candidates.json"
BUILDER_PATH = ROOT / "scripts" / "build-language-rule-research.py"
SCANNER_PATH = ROOT / "skills" / "audit-production-readiness" / "scripts" / "scan_repo.py"
EXPECTED_ALLOCATION = {
    "csharp": 400,
    "typescript": 450,
    "php": 350,
    "react": 300,
    "go": 350,
    "cpp": 450,
    "angular": 250,
    "javascript": 450,
    "sql": 400,
    "python": 400,
    "java": 350,
    "rust": 350,
    "kotlin": 250,
    "swift": 250,
}


class LanguageRuleResearchCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = json.loads(CATALOG_PATH.read_text("utf-8"))
        cls.candidates = cls.catalog["candidates"]
        cls.builder = runpy.run_path(str(BUILDER_PATH))

    def test_catalog_has_exact_contiguous_five_thousand_candidate_range(self) -> None:
        self.assertEqual(self.catalog["status"], "research_only")
        self.assertEqual(self.catalog["candidate_count"], 5_000)
        self.assertEqual(len(self.candidates), 5_000)
        self.assertEqual(
            [item["candidate_id"] for item in self.candidates],
            [f"SP{number}" for number in range(4451, 9451)],
        )
        self.assertEqual(
            Counter(item["ecosystem"] for item in self.candidates),
            Counter(EXPECTED_ALLOCATION),
        )
        self.assertEqual(
            {key: value["count"] for key, value in self.catalog["allocations"].items()},
            EXPECTED_ALLOCATION,
        )

    def test_candidates_are_exactly_deduplicated_but_root_overlap_is_explicit(self) -> None:
        pairs = [(item["ecosystem"], item["source_id"]) for item in self.candidates]
        normalized_titles = [
            re.sub(r"[^a-z0-9]+", " ", item["title"].casefold()).strip() for item in self.candidates
        ]
        self.assertEqual(len(set(pairs)), len(pairs))
        self.assertEqual(len(set(normalized_titles)), len(normalized_titles))
        self.assertLess(self.catalog["root_overlap"]["unique_cwe_roots"], len(self.candidates))
        self.assertGreater(self.catalog["root_overlap"]["cross_ecosystem_roots"], 0)
        for item in self.candidates:
            with self.subTest(candidate=item["candidate_id"]):
                self.assertEqual(item["root_overlap_group"], item["source_id"])
                self.assertRegex(item["source_id"], r"^CWE-\d+$")

    def test_existing_rule_overlap_never_masquerades_as_a_new_gap(self) -> None:
        for item in self.candidates:
            disposition = item["dedup_disposition"]
            root_matches = item["existing_rule_ids"]
            ecosystem_matches = item["existing_ecosystem_rule_ids"]
            with self.subTest(candidate=item["candidate_id"]):
                if disposition == "extend_or_replace_existing":
                    self.assertTrue(ecosystem_matches)
                    self.assertTrue(root_matches)
                elif disposition == "distinct_ecosystem_variant":
                    self.assertFalse(ecosystem_matches)
                    self.assertTrue(root_matches)
                else:
                    self.assertEqual(disposition, "coverage_gap")
                    self.assertFalse(ecosystem_matches)
                    self.assertFalse(root_matches)

    def test_dedup_references_match_the_executable_scanner(self) -> None:
        existing, _version = self.builder["load_existing_rules"](SCANNER_PATH)
        suffixes = self.builder["SUFFIXES"]
        by_cwe: dict[str, set[str]] = {}
        for rule in existing:
            for cwe in rule.cwes:
                by_cwe.setdefault(cwe, set()).add(rule.rule_id)
        for item in self.candidates:
            expected_root = sorted(by_cwe.get(item["source_id"], set()))
            expected_ecosystem = sorted(
                rule.rule_id
                for rule in existing
                if item["source_id"] in rule.cwes
                and (not rule.suffixes or bool(rule.suffixes & suffixes[item["ecosystem"]]))
            )
            with self.subTest(candidate=item["candidate_id"]):
                self.assertEqual(item["existing_rule_ids"], expected_root)
                self.assertEqual(item["existing_ecosystem_rule_ids"], expected_ecosystem)

    def test_each_ecosystem_covers_all_production_risk_lanes(self) -> None:
        expected_lanes = {"security", "reliability", "performance", "scale"}
        for ecosystem in EXPECTED_ALLOCATION:
            cohort = [item for item in self.candidates if item["ecosystem"] == ecosystem]
            with self.subTest(ecosystem=ecosystem):
                self.assertEqual({item["risk_lane"] for item in cohort}, expected_lanes)
                if ecosystem not in {"kotlin", "swift"}:
                    self.assertIn("direct", {item["applicability_tier"] for item in cohort})
                dimensions = {lane for item in cohort for lane in item["risk_dimensions"]}
                self.assertEqual(dimensions, expected_lanes)
                self.assertGreaterEqual(
                    sum("performance" in item["risk_dimensions"] for item in cohort), 20
                )
                self.assertGreaterEqual(
                    sum("scale" in item["risk_dimensions"] for item in cohort), 25
                )

    def test_every_candidate_has_grounding_and_remains_non_executable(self) -> None:
        for item in self.candidates:
            with self.subTest(candidate=item["candidate_id"]):
                self.assertEqual(item["promotion_status"], "research_only")
                self.assertNotIn(item["cwe_status"], {"Deprecated", "Obsolete"})
                self.assertGreater(item["applicability_score"], 0)
                self.assertIn(
                    item["applicability_tier"],
                    {"direct", "language_class", "language_independent", "taxonomy_only"},
                )
                self.assertTrue(item["applicability_reasons"])
                self.assertIn(item["risk_lane"], item["risk_dimensions"])
                self.assertIn("security", item["risk_dimensions"])
                self.assertGreaterEqual(len(item["source_urls"]), 3)
                self.assertTrue(all_secure_urls(item["source_urls"]))

    def test_documented_ranges_sum_to_five_thousand(self) -> None:
        document = (ROOT / "docs" / "rule-expansion-languages-5000.md").read_text("utf-8")
        ranges = [
            (int(start), int(end), int(count.replace(",", "")))
            for start, end, count in re.findall(
                r"\| `SP(\d+)\N{EN DASH}SP(\d+)` \| [^|]+ \| ([\d,]+) \|", document
            )
        ]
        self.assertEqual(ranges[0][0], 4451)
        self.assertEqual(ranges[-1][1], 9450)
        self.assertEqual(sum(count for _start, _end, count in ranges), 5_000)
        for index, (start, end, count) in enumerate(ranges):
            self.assertEqual(end - start + 1, count)
            if index:
                self.assertEqual(start, ranges[index - 1][1] + 1)


def all_secure_urls(urls: list[str]) -> bool:
    return all(urlparse(url).scheme == "https" and urlparse(url).netloc for url in urls)


if __name__ == "__main__":
    unittest.main()
