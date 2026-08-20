"""Build a deduplicated, language-specific rule-research backlog.

This maintainer tool consumes ShipProof's checked-in CWE snapshot.  It never
runs in the default scanner, CLI, GitHub Action, package install, or MCP path.
The output is intentionally a candidate catalog, not executable regex rules.
"""

from __future__ import annotations

import argparse
import json
import re
import runpy
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

FIRST_ID = 4451
ALLOCATION = {
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
DISPLAY_NAMES = {
    "csharp": "C#",
    "typescript": "TypeScript",
    "php": "PHP",
    "react": "React",
    "go": "Go",
    "cpp": "C++",
    "angular": "Angular",
    "javascript": "JavaScript",
    "sql": "SQL",
    "python": "Python",
    "java": "Java",
    "rust": "Rust",
    "kotlin": "Kotlin",
    "swift": "Swift",
}
SUFFIXES = {
    "csharp": {".cs", ".csx"},
    "typescript": {".ts", ".tsx"},
    "php": {".php", ".phtml"},
    "react": {".js", ".jsx", ".ts", ".tsx"},
    "go": {".go"},
    "cpp": {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
    "angular": {".html", ".ts"},
    "javascript": {".cjs", ".js", ".jsx", ".mjs"},
    "sql": {".sql"},
    "python": {".py", ".pyi"},
    "java": {".java"},
    "rust": {".rs"},
    "kotlin": {".kt", ".kts"},
    "swift": {".swift"},
}
LANGUAGE_ALIASES = {
    "csharp": {"C#", "ASP.NET"},
    "typescript": {"JavaScript"},
    "php": {"PHP"},
    "react": {"JavaScript"},
    "go": {"Go"},
    "cpp": {"C", "C++", "Memory-Unsafe"},
    "angular": {"JavaScript"},
    "javascript": {"JavaScript"},
    "sql": {"SQL"},
    "python": {"Python"},
    "java": {"Java"},
    "rust": {"Rust"},
    "kotlin": set(),
    "swift": set(),
}
LANGUAGE_CLASSES = {
    "csharp": {"Compiled", "Object-Oriented"},
    "typescript": {"Interpreted", "Object-Oriented"},
    "php": {"Interpreted", "Object-Oriented"},
    "react": {"Interpreted"},
    "go": {"Compiled"},
    "cpp": {"Compiled", "Memory-Unsafe", "Object-Oriented"},
    "angular": {"Interpreted", "Object-Oriented"},
    "javascript": {"Interpreted", "Object-Oriented"},
    "sql": set(),
    "python": {"Interpreted", "Object-Oriented"},
    "java": {"Compiled", "Object-Oriented"},
    "rust": {"Compiled"},
    "kotlin": {"Compiled", "Object-Oriented"},
    "swift": {"Compiled", "Object-Oriented"},
}
TECHNOLOGIES = {
    "csharp": {"Web Based", "Web Server", "Client Server"},
    "typescript": {"Web Based", "Web Server", "Client Server"},
    "php": {"Web Based", "Web Server", "Client Server"},
    "react": {"Web Based", "Client Server"},
    "go": {"Web Server", "Cloud Computing", "Client Server"},
    "cpp": {"Processor Hardware", "System on Chip", "Microcontroller Hardware"},
    "angular": {"Web Based", "Client Server"},
    "javascript": {"Web Based", "Web Server", "Client Server"},
    "sql": {"Database Server", "Client Server"},
    "python": {"Web Server", "AI/ML", "Cloud Computing"},
    "java": {"Web Server", "Mobile", "Client Server"},
    "rust": {"Web Server", "System on Chip", "Cloud Computing"},
    "kotlin": {"Mobile", "Client Server"},
    "swift": {"Mobile", "Client Server"},
}

# Official ecosystem sources constrain later detector design.  CWE remains the
# primary taxonomy source for every candidate.
OFFICIAL_SOURCES = {
    "csharp": [
        "https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/overview",
        "https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/security-warnings",
    ],
    "typescript": [
        "https://www.typescriptlang.org/docs/handbook/project-references",
        "https://www.typescriptlang.org/tsconfig/",
    ],
    "php": [
        "https://www.php.net/manual/en/security.php",
        "https://www.php.net/manual/en/security.database.php",
    ],
    "react": [
        "https://react.dev/learn/lifecycle-of-reactive-effects",
        "https://react.dev/reference/react/useSyncExternalStore",
    ],
    "go": [
        "https://go.dev/doc/security/best-practices",
        "https://go.dev/doc/security/vuln/database",
    ],
    "cpp": [
        "https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88046682",
        "https://www.sei.cmu.edu/library/sei-cert-c-and-c-coding-standards/",
    ],
    "angular": [
        "https://angular.dev/best-practices/security",
        "https://angular.dev/best-practices/runtime-performance",
    ],
    "javascript": [
        "https://nodejs.org/en/learn/getting-started/security-best-practices",
        "https://developer.mozilla.org/en-US/docs/Web/Performance",
    ],
    "sql": [
        "https://www.postgresql.org/docs/current/sql-prepare.html",
        "https://www.postgresql.org/docs/current/performance-tips.html",
    ],
    "python": [
        "https://docs.python.org/3/library/security_warnings.html",
        "https://docs.python.org/3/library/profile.html",
    ],
    "java": [
        "https://docs.oracle.com/en/java/javase/17/security/index.html",
        "https://docs.oracle.com/javase/tutorial/essential/concurrency/",
    ],
    "rust": [
        "https://doc.rust-lang.org/stable/nomicon/safe-unsafe-meaning.html",
        "https://doc.rust-lang.org/nomicon/concurrency.html",
    ],
    "kotlin": [
        "https://developer.android.com/privacy-and-security/security-tips",
        "https://developer.android.com/topic/performance/overview",
    ],
    "swift": [
        "https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Introduction.html",
        "https://developer.apple.com/documentation/foundation/nssecurecoding",
    ],
}

LANE_KEYWORDS = {
    "performance": (
        "algorithmic complexity",
        "catastrophic backtracking",
        "excessive iteration",
        "inefficient",
        "quadratic",
        "regular expression",
        "repeated expensive",
    ),
    "scale": (
        "amplification",
        "denial of service",
        "excessive allocation",
        "exhaustion",
        "flood",
        "resource consumption",
        "uncontrolled resource",
        "unrestricted resource",
    ),
    "reliability": (
        "cleanup",
        "concurren",
        "deadlock",
        "exception",
        "improper initialization",
        "incorrect calculation",
        "lifetime",
        "null pointer",
        "race condition",
        "resource leak",
        "state",
        "synchronization",
        "time-of-check",
        "use after free",
    ),
}
LANE_TARGETS = {
    "security": 0.55,
    "reliability": 0.20,
    "performance": 0.15,
    "scale": 0.10,
}
CWE_RE = re.compile(r"CWE-\d+")


@dataclass(frozen=True)
class ExistingRule:
    rule_id: str
    cwes: frozenset[str]
    suffixes: frozenset[str]


def risk_lane(record: dict[str, Any]) -> str:
    text = f"{record['title']} {record['description']}".casefold()
    for lane in ("performance", "scale", "reliability"):
        if any(keyword in text for keyword in LANE_KEYWORDS[lane]):
            return lane
    return "security"


def risk_dimensions(record: dict[str, Any]) -> list[str]:
    """Map CWE's structured consequences to non-exclusive production risks."""
    dimensions = {risk_lane(record), "security"}
    scopes = {
        scope for consequence in record["common_consequences"] for scope in consequence["scopes"]
    }
    impacts = {
        impact for consequence in record["common_consequences"] for impact in consequence["impacts"]
    }
    impact_text = " ".join(impacts).casefold()
    if "availability" in {scope.casefold() for scope in scopes}:
        dimensions.add("reliability")
    if "resource consumption" in impact_text or "denial of service" in impact_text:
        dimensions.add("scale")
    if "resource consumption (cpu)" in impact_text or "algorithmic" in impact_text:
        dimensions.add("performance")
    return sorted(dimensions)


def applicability(record: dict[str, Any], ecosystem: str) -> tuple[int, list[str], str] | None:
    platforms = record["applicable_platforms"]
    language_names = {
        item.get("name") for item in platforms if item["kind"] == "Language" and item.get("name")
    }
    language_classes = {
        item.get("class") for item in platforms if item["kind"] == "Language" and item.get("class")
    }
    technologies = {
        item.get("name") for item in platforms if item["kind"] == "Technology" and item.get("name")
    }
    exact = sorted(language_names & LANGUAGE_ALIASES[ecosystem])
    generic = "Not Language-Specific" in language_classes
    class_matches = sorted(language_names & LANGUAGE_CLASSES[ecosystem])
    technology_matches = sorted(technologies & TECHNOLOGIES[ecosystem])

    # An explicit, incompatible language list is stronger evidence than a
    # keyword in the weakness title.  Do not manufacture a cross-language rule.
    if language_names and not (exact or class_matches or generic):
        return None

    score = 0
    reasons: list[str] = []
    if exact:
        score += 1_000 + 50 * len(exact)
        reasons.append("CWE language: " + ", ".join(exact))
    if class_matches:
        score += 650 + 25 * len(class_matches)
        reasons.append("CWE language class: " + ", ".join(class_matches))
    if generic:
        score += 500
        reasons.append("CWE marks the weakness as language-independent")
    if technology_matches:
        score += 600 + 25 * len(technology_matches)
        reasons.append("CWE technology: " + ", ".join(technology_matches))
    if not platforms:
        score += 225
        reasons.append("CWE has no restrictive platform declaration")
    if record["abstraction"] == "Variant":
        score += 250
    elif record["abstraction"] == "Base":
        score += 200
    elif record["abstraction"] == "Class":
        score += 100
    reasons.append(f"CWE abstraction: {record['abstraction']}")
    if record["status"] == "Stable":
        score += 50
    if score == 0:
        score = 100
        reasons.append("taxonomy-level applicability requires maintainer validation")
    if exact or technology_matches:
        tier = "direct"
    elif class_matches:
        tier = "language_class"
    elif generic:
        tier = "language_independent"
    else:
        tier = "taxonomy_only"
    return score, reasons, tier


def load_existing_rules(scanner_path: Path) -> tuple[list[ExistingRule], str]:
    namespace = runpy.run_path(str(scanner_path))
    rules = namespace["RULES"]
    existing = [
        ExistingRule(
            rule_id=rule.rule_id,
            cwes=frozenset(CWE_RE.findall(rule.cwe)),
            suffixes=frozenset(value.casefold() for value in rule.suffixes),
        )
        for rule in rules
    ]
    return existing, str(namespace.get("VERSION", "unknown"))


def lane_targets(count: int) -> dict[str, int]:
    targets = {lane: int(count * ratio) for lane, ratio in LANE_TARGETS.items()}
    targets["security"] += count - sum(targets.values())
    return targets


def select_records(
    records: list[dict[str, Any]], ecosystem: str, count: int
) -> list[tuple[dict[str, Any], int, list[str], str]]:
    ranked_by_lane: dict[str, list[tuple[dict[str, Any], int, list[str], str]]] = defaultdict(list)
    for record in records:
        scored = applicability(record, ecosystem)
        if scored is None:
            continue
        score, reasons, tier = scored
        ranked_by_lane[risk_lane(record)].append((record, score, reasons, tier))
    for lane in ranked_by_lane:
        ranked_by_lane[lane].sort(
            key=lambda item: (-item[1], int(item[0]["source_id"].removeprefix("CWE-")))
        )

    selected: list[tuple[dict[str, Any], int, list[str], str]] = []
    selected_ids: set[str] = set()
    for lane, target in lane_targets(count).items():
        for item in ranked_by_lane[lane][:target]:
            selected.append(item)
            selected_ids.add(item[0]["source_id"])

    remaining = sorted(
        (
            item
            for lane_records in ranked_by_lane.values()
            for item in lane_records
            if item[0]["source_id"] not in selected_ids
        ),
        key=lambda item: (-item[1], int(item[0]["source_id"].removeprefix("CWE-"))),
    )
    selected.extend(remaining[: count - len(selected)])
    if len(selected) != count:
        raise RuntimeError(
            f"{ecosystem} has only {len(selected)} applicable unique CWE candidates; need {count}"
        )
    return sorted(selected, key=lambda item: (-item[1], item[0]["source_id"]))


def build_catalog(root: Path, expert_path: Path) -> dict[str, Any]:
    expert = json.loads(expert_path.read_text("utf-8"))
    records = [
        item
        for item in expert["candidates"]
        if item["source_kind"] == "weakness" and item["status"] not in {"Deprecated", "Obsolete"}
    ]
    existing, scanner_version = load_existing_rules(
        root / "skills" / "audit-production-readiness" / "scripts" / "scan_repo.py"
    )
    by_cwe: dict[str, set[str]] = defaultdict(set)
    for rule in existing:
        for cwe in rule.cwes:
            by_cwe[cwe].add(rule.rule_id)

    candidates: list[dict[str, Any]] = []
    allocations: dict[str, dict[str, Any]] = {}
    next_id = FIRST_ID
    for ecosystem, count in ALLOCATION.items():
        first = next_id
        for record, score, reasons, tier in select_records(records, ecosystem, count):
            source_id = record["source_id"]
            root_matches = sorted(by_cwe[source_id])
            ecosystem_matches = sorted(
                rule.rule_id
                for rule in existing
                if source_id in rule.cwes
                and (not rule.suffixes or bool(rule.suffixes & SUFFIXES[ecosystem]))
            )
            if ecosystem_matches:
                disposition = "extend_or_replace_existing"
            elif root_matches:
                disposition = "distinct_ecosystem_variant"
            else:
                disposition = "coverage_gap"
            lane = risk_lane(record)
            route = (
                "benchmark_or_policy_research"
                if lane in {"performance", "scale"}
                else (
                    record["recommended_route"] if tier == "direct" else "ecosystem_semantic_review"
                )
            )
            candidates.append(
                {
                    "candidate_id": f"SP{next_id}",
                    "ecosystem": ecosystem,
                    "ecosystem_name": DISPLAY_NAMES[ecosystem],
                    "source_id": source_id,
                    "title": (
                        f"[{ecosystem}/{DISPLAY_NAMES[ecosystem]}] {source_id}: {record['title']}"
                    ),
                    "description": record["description"],
                    "cwe_abstraction": record["abstraction"],
                    "cwe_status": record["status"],
                    "risk_lane": lane,
                    "risk_dimensions": risk_dimensions(record),
                    "applicability_score": score,
                    "applicability_tier": tier,
                    "applicability_reasons": reasons,
                    "applicable_platforms": record["applicable_platforms"],
                    "common_consequences": record["common_consequences"],
                    "existing_rule_ids": root_matches,
                    "existing_ecosystem_rule_ids": ecosystem_matches,
                    "dedup_disposition": disposition,
                    "root_overlap_group": source_id,
                    "recommended_route": route,
                    "promotion_status": "research_only",
                    "source_urls": list(
                        dict.fromkeys([*record["source_urls"], *OFFICIAL_SOURCES[ecosystem]])
                    ),
                }
            )
            next_id += 1
        allocations[ecosystem] = {
            "display_name": DISPLAY_NAMES[ecosystem],
            "first_id": f"SP{first}",
            "last_id": f"SP{next_id - 1}",
            "count": count,
            "official_sources": OFFICIAL_SOURCES[ecosystem],
        }

    root_counts = Counter(item["source_id"] for item in candidates)
    return {
        "schema_version": 1,
        "generated_on": date.today().isoformat(),
        "status": "research_only",
        "selection": (
            "CWE weakness variants ranked by CWE-declared language, language-class, and "
            "technology applicability; explicit incompatible language declarations are excluded"
        ),
        "promotion_boundary": (
            "No candidate is executable until it has ecosystem-specific semantics, positive, "
            "negative, and adversarial fixtures, false-positive analysis, and measured precision"
        ),
        "source_cwe_catalog_version": expert["cwe_catalog_version"],
        "source_cwe_archive_sha256": expert["cwe_archive_sha256"],
        "existing_scanner_version": scanner_version,
        "existing_rule_count": len(existing),
        "candidate_count": len(candidates),
        "allocations": allocations,
        "risk_lane_counts": dict(sorted(Counter(item["risk_lane"] for item in candidates).items())),
        "risk_dimension_counts": dict(
            sorted(Counter(lane for item in candidates for lane in item["risk_dimensions"]).items())
        ),
        "applicability_tier_counts": dict(
            sorted(Counter(item["applicability_tier"] for item in candidates).items())
        ),
        "dedup_disposition_counts": dict(
            sorted(Counter(item["dedup_disposition"] for item in candidates).items())
        ),
        "root_overlap": {
            "unique_cwe_roots": len(root_counts),
            "cross_ecosystem_roots": sum(count > 1 for count in root_counts.values()),
            "maximum_ecosystem_variants_per_root": max(root_counts.values()),
            "policy": (
                "A CWE root may repeat across ecosystems, but an (ecosystem, CWE) pair may not. "
                "Every repeat carries root_overlap_group and existing-rule references."
            ),
        },
        "candidates": candidates,
    }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", "utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expert", type=Path, default=Path("research/expert-rule-candidates.json"))
    parser.add_argument(
        "--output", type=Path, default=Path("research/language-rule-candidates.json")
    )
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    payload = build_catalog(root, args.expert)
    write_json(args.output, payload)
    print(
        json.dumps(
            {
                "candidate_count": payload["candidate_count"],
                "candidate_range": f"SP{FIRST_ID}-SP{FIRST_ID + payload['candidate_count'] - 1}",
                "ecosystems": len(payload["allocations"]),
                "risk_lane_counts": payload["risk_lane_counts"],
                "risk_dimension_counts": payload["risk_dimension_counts"],
                "applicability_tier_counts": payload["applicability_tier_counts"],
                "dedup_disposition_counts": payload["dedup_disposition_counts"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
