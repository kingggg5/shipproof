#!/usr/bin/env python3
"""Curate the entire promotion pool into explicit dispositions.

Reads research/promotion-shortlist.json (every uncovered, language-matched
research candidate), deduplicates candidates into detector targets
(CWE root x language family), and assigns every target exactly one
disposition:

  tier_a   locally observable with a deterministic line signature; queued
           into promotion waves
  tier_b   real weakness class that requires AST/dataflow evidence beyond
           the shipped engines; parked on the analyzer roadmap
  tier_c   not locally observable (design/process/hardware classes); closed
           with reason, never silently dropped

Writes research/promotion-plan.json. Dev-side tool only.

Usage: python scripts/curate-pool.py [--output research/promotion-plan.json]
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FAMILY = {
    ".js": "js_ts",
    ".mjs": "js_ts",
    ".cjs": "js_ts",
    ".ts": "js_ts",
    ".tsx": "js_ts",
    ".py": "python",
    ".java": "jvm",
    ".jsp": "jvm",
    ".kt": "jvm",
    ".go": "go",
    ".rs": "rust",
    ".php": "php",
    ".rb": "ruby",
    ".erb": "ruby",
    ".cs": "csharp",
    ".c": "clang",
    ".h": "clang",
    ".cpp": "clang",
    ".hpp": "clang",
    ".swift": "swift",
}

# Title keyword -> tier. Order encodes precedence:
#   1. FORCE_C hardware/firmware/process classes never locally observable in
#      application source, regardless of overlapping words ("On-Chip Debug"
#      contains "debug"; "Register Interface" contains "access control").
#   2. B_PATTERNS dataflow/engine-required classes beat generic injection
#      wording when both appear.
#   3. A_PATTERNS concrete API/config signatures only.
FORCE_C_PATTERNS = (
    r"on-chip|microarchitectural|register interface|volatile memory|jtag",
    r"hardware|firmware|silicon|fuse\b|one-time programmable|secure boot|boot rom",
    r"test or debug logic|debug access|debug interface",
    r"physical|tamper protection|electro",
    r"process.*organizational|policy document|training|documentation guide",
)
B_PATTERNS = (
    r"integer|numeric truncat|coercion|shift|overflow|underflow|wraparound",
    r"race condit|deadlock|double-checked|synchroniz|thread|concurr|atomic",
    r"uninitialized|uninitialised|null (?:pointer|dereference|dereference)|dereference",
    r"memory leak|resource lea|release of|double release|free(?:dom)? of|use after|lifetime|dealloca|deallocat",
    r"buffer|stack overflow|heap|out-of-bounds|out of bounds|array index|off-by-one|boundary",
    r"recursion|excessive depth|allocation|exhaust(ion|ed)|amplification",
    r"iteration|iterator|loop condition|infinite loop",
    r"serialization of sensitive|compar(?:ison|e) of object|wrong operator|incompatible types",
    r"bitwise|signed.to.unsigned|type size|cast|coerce",
    r"memoization|reachable assertion|assertion",
    r"neutralization of (?:delimiters?|input terminators?|input leaders?|quoting|escape, meta|wildcards?|whitespace|substitution|macro symbols?|variable name|record |section |line delim|parameter/argument)",
    r"output neutralization for logs|log output neutraliz",
)
A_PATTERNS = (
    r"injection|script|xss|cross-site scripting",
    r"cookie|password|secret|credential|token|api key|hard.?coded|cleartext|plaintext",
    r"tls|ssl|certificate|verify|verification disabled|https",
    r"error message|stack trace|information exposure through (?:an )?error",
    r"missing (?:authorization|authentication)|access control for user|permission|privilege (?:assignment|dropping)|forced browsing|direct request",
    r"session (?:fixation|expiration|timeout)|csrf|cross-site request|open redirect|url redir",
    r"upload|path traversal|traversal|directory|file inclusion|download of files",
    r"command injection|sql|nosql|xpath|ldap|template injection|code injection|deserializ|eval|expression language",
    r"xxe|ssrf|request forgery|prototype pollution|origin validation|postmessage",
    r"cors|same-site|samesite|httponly|secure flag|secure cookie|rate limit|brute|captcha|frequency",
    r"jwt|algorithm use|randomness|prng|iv |initialization vector|salt|cipher|ecb|encryption|hash used|md5|sha-?1",
    r"websocket|header(?:s)? (?:for|without)|crlf|mime|content-type|referrer",
    r"cache containing|web browser cache|persistent cookie|backup file|web root|wsdl file",
    r"default credentials|default variable|external variable|variable modification|extract",
    r"dependency|package|component with known|library version|outdated|mutable tag|pinning|pinned",
    r"dockerfile|container|kubernetes|terraform|iam polic|s3 bucket|bucket acl|cloudfront|rds|dynamo",
    r"url query|string query|query string|sensitive info in query|get for action",
    r"switch|break statement|default case|empty block|finalize|clone|serializable|public static field",
)


def classify(title: str) -> tuple[str, str]:
    lowered = title.lower()
    for pat in FORCE_C_PATTERNS:
        if re.search(pat, lowered):
            return "tier_c", f"not locally observable: matches hardware/class '{pat}'"
    for pat in B_PATTERNS:
        if re.search(pat, lowered):
            return "tier_b", f"dataflow/engine gap: matches '{pat}'"
    for pat in A_PATTERNS:
        if re.search(pat, lowered):
            return "tier_a", f"line-signature available: matches '{pat}'"
    return (
        "tier_c",
        "no local line signature identified (design/process/taxonomy class); closed from regex promotion scope",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--shortlist",
        type=Path,
        default=ROOT / "research" / "promotion-shortlist.json",
    )
    parser.add_argument("--output", type=Path, default=ROOT / "research" / "promotion-plan.json")
    arguments = parser.parse_args(argv)

    shortlist = json.loads(arguments.shortlist.read_text(encoding="utf-8"))
    targets: dict[tuple[str, str], dict] = defaultdict(lambda: {"candidate_ids": [], "title": ""})
    for entry in shortlist["candidates"]:
        fams = {f for f in (FAMILY.get(s) for s in entry["languages"]) if f}
        for family in fams:
            key = (entry["cwe"], family)
            slot = targets[key]
            slot["title"] = entry["title"]
            slot["candidate_ids"].append(entry["candidate_id"])

    plan_targets = []
    funnel: Counter[str] = Counter()
    waves: dict[str, list] = defaultdict(list)

    for (cwe, family), slot in sorted(targets.items()):
        # Prefer the most specific title among duplicates.
        title = min(slot["title"].split(" | "), key=len) if slot["title"] else ""
        tier, reason = classify(title)
        funnel[tier] += 1
        target_id = f"{cwe}:{family}"
        record = {
            "target_id": target_id,
            "cwe": cwe,
            "family": family,
            "title": title,
            "reason": reason,
            "candidate_ids": sorted(slot["candidate_ids"]),
        }
        plan_targets.append(record)
        if tier == "tier_a":
            wave_number = 1 if family in {"js_ts", "python", "go"} else 2
            waves[f"wave{wave_number}"].append(target_id)

    payload = {
        "schema_version": "1.0",
        "pool_size": len(shortlist["candidates"]),
        "funnel": {
            "detector_targets": len(plan_targets),
            "tier_a_promotable": funnel["tier_a"],
            "tier_b_needs_analyzer": funnel["tier_b"],
            "tier_c_closed": funnel["tier_c"],
        },
        "waves": {k: sorted(v) for k, v in sorted(waves.items())},
        "targets": plan_targets,
    }
    arguments.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(arguments.output),
                **payload["funnel"],
                "waves": {k: len(v) for k, v in payload["waves"].items()},
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
