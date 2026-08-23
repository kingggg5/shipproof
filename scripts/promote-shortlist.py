#!/usr/bin/env python3
"""Rank research-catalog candidates by local implementability for promotion.

Loads every ShipProof research catalog (expert, annual, language), filters to
candidates whose platform/language intersects the scanner's supported suffixes,
excludes CWE roots already covered by executable rules, and writes a ranked
shortlist used to plan promotion batches. Dev-side tool only.

Usage:
  python scripts/promote-shortlist.py [--output research/promotion-shortlist.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from scan_repo import RULES  # noqa: E402

# Map catalog platform names to scanner suffix groups we can actually detect.
PLATFORM_LANGUAGES = {
    "JavaScript": {".js", ".mjs", ".cjs"},
    "TypeScript": {".ts", ".tsx"},
    "Python": {".py"},
    "Java": {".java", ".jsp"},
    "Kotlin": {".kt"},
    "Go": {".go"},
    "PHP": {".php"},
    "Ruby": {".rb", ".erb"},
    "C#": {".cs"},
    "C": {".c", ".h"},
    "C++": {".cpp", ".cc", ".hpp"},
    "Swift": {".swift"},
    "Rust": {".rs"},
}

CATALOGS = (
    ROOT / "research" / "expert-rule-candidates.json",
    ROOT / "research" / "annual-rule-candidates.json",
    ROOT / "research" / "language-rule-candidates.json",
)


def candidate_platforms(candidate: dict) -> set[str]:
    platforms: set[str] = set()
    for platform in candidate.get("applicable_platforms", []) or []:
        name = platform.get("name") if isinstance(platform, dict) else None
        if name:
            platforms.add(name)
    ecosystem = candidate.get("ecosystem")
    alias = {
        "javascript": "JavaScript",
        "typescript": "TypeScript",
        "python": "Python",
        "react": "TypeScript",
        "angular": "TypeScript",
        "go": "Go",
        "php": "PHP",
        "rust": "Rust",
        "kotlin": "Kotlin",
        "swift": "Swift",
        "java": "Java",
        "csharp": "C#",
        "cpp": "C++",
        "sql": "",
        "c": "C",
    }.get(str(ecosystem).lower())
    if alias:
        platforms.add(alias)
    return platforms


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "research" / "promotion-shortlist.json"
    )
    arguments = parser.parse_args(argv)

    covered_cwes = {rule.cwe for rule in RULES}
    existing_titles = {re_title(rule.title) for rule in RULES}
    supported_suffixes = set().union(*(rule.suffixes for rule in RULES if rule.suffixes))

    entries: list[dict] = []
    funnel: Counter = Counter()
    for catalog_path in CATALOGS:
        payload = json.loads(catalog_path.read_text(encoding="utf-8"))
        for candidate in payload.get("candidates", []):
            funnel["total"] += 1
            cwes = candidate.get("source_id") or ""
            cwes_list = cwes if isinstance(cwes, list) else [cwes]
            primary_cwe = next((c for c in cwes_list if str(c).startswith("CWE-")), "")
            title = str(candidate.get("title", "")).strip()
            platforms = candidate_platforms(candidate)
            languages = sorted(PLATFORM_LANGUAGES.get(platform, set()) for platform in platforms)
            suffix_hits = sorted(set().union(*languages) & supported_suffixes) if languages else []
            if not suffix_hits:
                funnel["no_supported_language"] += 1
                continue
            if primary_cwe in covered_cwes:
                funnel["cwe_already_covered"] += 1
                continue
            if re_title(title) in existing_titles:
                funnel["title_duplicate"] += 1
                continue
            funnel["implementable_pool"] += 1
            entries.append(
                {
                    "catalog": catalog_path.name.replace("-rule-candidates.json", ""),
                    "candidate_id": candidate.get("candidate_id"),
                    "cwe": primary_cwe,
                    "title": title,
                    "languages": suffix_hits,
                }
            )

    payload = {
        "schema_version": "1.0",
        "funnel": dict(sorted(funnel.items())),
        "covered_cwe_roots": len(covered_cwes),
        "candidates": entries,
    }
    arguments.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(arguments.output), **payload["funnel"]}))
    return 0


def re_title(title: str) -> str:
    return " ".join("".join(ch.lower() if ch.isalnum() else " " for ch in title).split())


if __name__ == "__main__":
    raise SystemExit(main())
