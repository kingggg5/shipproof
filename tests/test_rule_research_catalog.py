from __future__ import annotations

import json
import re
import unittest
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).parents[1]
RESEARCH = ROOT / "research"


def load(name: str) -> dict:
    return json.loads((RESEARCH / name).read_text("utf-8"))


class RuleResearchCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.annual = load("annual-rule-candidates.json")
        cls.expert = load("expert-rule-candidates.json")
        cls.community = load("community-signals.json")

    def test_annual_catalog_has_three_hundred_candidates_per_year(self) -> None:
        candidates = self.annual["candidates"]
        self.assertEqual(self.annual["status"], "research_only")
        self.assertRegex(self.annual["cisa_kev_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            set(self.annual["nvd_api_snapshots"]), {str(year) for year in range(2021, 2027)}
        )
        for snapshots in self.annual["nvd_api_snapshots"].values():
            self.assertGreaterEqual(sum(item["sampled_results"] for item in snapshots), 300)
            self.assertTrue(
                all(re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) for item in snapshots)
            )
        self.assertEqual(len(candidates), 1_800)
        self.assertEqual(
            Counter(item["cohort_year"] for item in candidates),
            Counter({year: 300 for year in range(2021, 2027)}),
        )
        self.assertEqual(
            [item["candidate_id"] for item in candidates],
            [f"SP{number}" for number in range(1651, 3451)],
        )
        self.assertEqual(len({item["signal"] for item in candidates}), len(candidates))
        for year in range(2021, 2027):
            cohort = [item for item in candidates if item["cohort_year"] == year]
            self.assertGreaterEqual(sum(item["known_exploited"] for item in cohort), 1)
            self.assertGreaterEqual(len({cwe for item in cohort for cwe in item["cwe"]}), 40)
        for item in candidates:
            with self.subTest(candidate=item["candidate_id"]):
                self.assertRegex(item["signal"], r"^CVE-\d{4}-\d{4,}$")
                self.assertEqual(item["promotion_status"], "research_only")
                self.assertEqual(item["recommended_route"], "dependency_evidence")
                self.assertTrue(item["title"])
                self.assertTrue(item["source_urls"])
                self.assertTrue(all_secure_urls(item["source_urls"]))

    def test_expert_catalog_is_exactly_one_thousand_current_cwe_records(self) -> None:
        candidates = self.expert["candidates"]
        self.assertEqual(self.expert["status"], "research_only")
        self.assertRegex(self.expert["cwe_archive_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(len(candidates), 1_000)
        self.assertEqual(
            [item["candidate_id"] for item in candidates],
            [f"SP{number}" for number in range(3451, 4451)],
        )
        self.assertEqual(
            Counter(item["source_kind"] for item in candidates),
            Counter(
                {
                    "weakness": self.expert["weaknesses_selected"],
                    "category": self.expert["categories_selected"],
                }
            ),
        )
        self.assertEqual(len({item["source_id"] for item in candidates}), len(candidates))
        for item in candidates:
            with self.subTest(candidate=item["candidate_id"]):
                self.assertEqual(item["promotion_status"], "research_only")
                self.assertIn(item["recommended_route"], {"static_research", "taxonomy_research"})
                self.assertTrue(item["title"])
                self.assertIsInstance(item["applicable_platforms"], list)
                self.assertIsInstance(item["common_consequences"], list)
                self.assertTrue(all_secure_urls(item["source_urls"]))

    def test_all_new_candidate_ids_are_unique_and_contiguous(self) -> None:
        candidates = self.annual["candidates"] + self.expert["candidates"]
        numbers = [int(item["candidate_id"].removeprefix("SP")) for item in candidates]
        self.assertEqual(numbers, list(range(1651, 4451)))

    def test_community_signals_are_discovery_only_and_officially_confirmed(self) -> None:
        signals = self.community["signals"]
        self.assertEqual(self.community["status"], "question_discovery_only")
        self.assertRegex(self.community["researched_on"], r"^202[1-6]-\d{2}-\d{2}$")
        self.assertEqual({item["year"] for item in signals}, set(range(2021, 2027)))
        self.assertTrue(
            {"reddit", "stackoverflow", "google"}.issubset({item["platform"] for item in signals})
        )
        self.assertEqual(len({item["signal_id"] for item in signals}), len(signals))
        for item in signals:
            with self.subTest(signal=item["signal_id"]):
                self.assertEqual(item["use"], "question_discovery_only")
                self.assertGreaterEqual(len(item["theme"]), 40)
                self.assertGreaterEqual(len(item["confirmation_urls"]), 1)
                self.assertTrue(all_secure_urls([item["url"], *item["confirmation_urls"]]))

    def test_expansion_document_reserves_exact_new_ranges(self) -> None:
        document = (ROOT / "docs" / "rule-expansion-2021-2026.md").read_text("utf-8")
        ranges = [
            (int(start), int(end), int(count.replace(",", "")))
            for start, end, count in re.findall(
                r"\| `SP(\d+)\N{EN DASH}SP(\d+)` \| ([\d,]+) \|", document
            )
        ]
        self.assertEqual(ranges[0], (1651, 1950, 300))
        self.assertEqual(ranges[-1], (3451, 4450, 1_000))
        self.assertEqual(sum(count for _start, _end, count in ranges), 2_800)
        for index, (start, end, count) in enumerate(ranges):
            self.assertEqual(end - start + 1, count)
            if index:
                self.assertEqual(start, ranges[index - 1][1] + 1)


def all_secure_urls(urls: list[str]) -> bool:
    return all(urlparse(url).scheme == "https" and urlparse(url).netloc for url in urls)


if __name__ == "__main__":
    unittest.main()
