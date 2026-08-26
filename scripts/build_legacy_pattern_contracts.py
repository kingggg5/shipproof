#!/usr/bin/env python3
"""Generate checked-in v2 contracts for legacy line-pattern scanner rules."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

try:
    from re import _constants as sre_constants
    from re import _parser as sre_parse
except ImportError:  # pragma: no cover - Python 3.10 compatibility
    import sre_constants  # type: ignore[no-redef]
    import sre_parse  # type: ignore[no-redef]

ROOT = Path(__file__).parents[1]
SCANNER_SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
OUTPUT_DIR = ROOT / "tests" / "rule-contracts"
sys.path.insert(0, str(SCANNER_SCRIPTS))

from scan_repo import (  # noqa: E402
    FILE_LEVEL_RULE_IDS,
    RULE_EXPLANATIONS,
    RULE_FRAMEWORK_HINTS,
    RULES,
    deduplicate_and_suppress_findings,
    find_regex_issues,
)

LEGACY_MIN = 101
LEGACY_MAX = 650
MANUAL_WITNESSES = {
    "SP111": "".join(("archive.", "extract", 'all("/srv/output")')),
    "SP119": "path.join(req.params.filename)",
    "SP122": "".join(("session_", "token = random.", "random()")),
    "SP124": "fetch(req.query.target)",
    "SP202": "FROM python:latest",
    "SP212": "run: printenv",
    "SP274": "process.env.API_KEY",
    "SP275": 'server.registerTool("run", { inputSchema: z.any() }, handler)',
    "SP332": "go func() { ch <- value // unbuffered\n}()",
    "SP371": "for i, item := range items {\n    go func() { use(item) }\n}",
    "SP592": "const body = (await req.json()) as any",
}


def encoded_text(source: str) -> dict[str, str]:
    """Keep scanner-positive fixture text executable without self-triggering repository scans."""

    return {"source_hex": source.encode("utf-8").hex()}


PATH_OVERRIDES = {
    "SP202": "contract-fixtures/container/sp202-positive-a/Dockerfile",
    "SP221": "contract-fixtures/supply-chain/sp221-positive-a/pyproject.toml",
    "SP269": "contract-fixtures/systemd/sp269-positive-a.service",
    "SP271": "contract-fixtures/mcp/sp271-positive-a/mcp-server.py",
    "SP272": "contract-fixtures/mcp/sp272-positive-a/mcp-server.py",
    "SP273": "contract-fixtures/mcp/sp273-positive-a/mcp-server.py",
    "SP274": "contract-fixtures/mcp/sp274-positive-a/mcp-server.py",
    "SP275": "contract-fixtures/mcp/sp275-positive-a/mcp-server.ts",
    "SP332": "contract-fixtures/go/sp332-positive-a.go",
}
SUFFIX_PRIORITY = (
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".go",
    ".php",
    ".cs",
    ".cpp",
    ".c",
    ".java",
    ".rs",
    ".sql",
    ".yaml",
    ".yml",
    ".json",
    ".tf",
    ".service",
    ".sh",
    ".txt",
)


def rule_number(rule_id: str) -> int:
    return int(rule_id.removeprefix("SP"))


def is_legacy_pattern_rule(rule: Any) -> bool:
    number = rule_number(rule.rule_id)
    return LEGACY_MIN <= number <= LEGACY_MAX and rule.rule_id not in FILE_LEVEL_RULE_IDS


def category_character(category: Any, variant: int) -> str:
    choices = {
        sre_constants.CATEGORY_DIGIT: ("7", "4"),
        sre_constants.CATEGORY_NOT_DIGIT: ("A", "q"),
        sre_constants.CATEGORY_SPACE: (" ", "\t"),
        sre_constants.CATEGORY_NOT_SPACE: ("A", "q"),
        sre_constants.CATEGORY_WORD: ("A", "q"),
        sre_constants.CATEGORY_NOT_WORD: ("-", "!"),
        sre_constants.CATEGORY_LINEBREAK: ("\n", "\r"),
        sre_constants.CATEGORY_NOT_LINEBREAK: ("A", "q"),
    }
    return choices.get(category, ("A", "q"))[variant % 2]


def character_from_class(items: Iterable[tuple[Any, Any]], variant: int) -> str:
    material = list(items)
    if any(operation is sre_constants.NEGATE for operation, _ in material):
        banned = {
            chr(argument) for operation, argument in material if operation is sre_constants.LITERAL
        }
        for candidate in ("Z", "q", "7", "_", "-", " "):
            if candidate not in banned:
                return candidate
        return "X"
    choices: list[str] = []
    for operation, argument in material:
        if operation is sre_constants.LITERAL:
            choices.append(chr(argument))
        elif operation is sre_constants.RANGE:
            choices.extend((chr(argument[0]), chr(argument[1])))
        elif operation is sre_constants.CATEGORY:
            choices.append(category_character(argument, variant))
    return choices[variant % len(choices)] if choices else "A"


def synthesize_pattern(rule: Any, variant: int = 0) -> str:
    """Return a deterministic concrete string for the supported stdlib regex subset."""

    groups: dict[int, str] = {}

    def walk(items: Iterable[tuple[Any, Any]], seed: int) -> str:
        output: list[str] = []
        for index, (operation, argument) in enumerate(items):
            local_variant = seed + index + variant
            if operation is sre_constants.LITERAL:
                output.append(chr(argument))
            elif operation is sre_constants.NOT_LITERAL:
                output.append(" " if argument != ord(" ") else "A")
            elif operation is sre_constants.ANY:
                output.append("A")
            elif operation is sre_constants.IN:
                output.append(character_from_class(argument, local_variant))
            elif operation is sre_constants.CATEGORY:
                output.append(category_character(argument, local_variant))
            elif operation is sre_constants.BRANCH:
                branches = argument[1]
                output.append(walk(branches[local_variant % len(branches)], local_variant))
            elif operation is sre_constants.SUBPATTERN:
                rendered = walk(argument[-1], local_variant)
                output.append(rendered)
                if argument[0]:
                    groups[argument[0]] = rendered
            elif operation in {
                sre_constants.MAX_REPEAT,
                sre_constants.MIN_REPEAT,
                getattr(sre_constants, "POSSESSIVE_REPEAT", object()),
            }:
                minimum, maximum, repeated = argument
                count = minimum if minimum else 1
                if variant and maximum != minimum:
                    upper = count + 1 if maximum == sre_constants.MAXREPEAT else maximum
                    count = min(max(count + 1, 2), upper)
                if count > 256:
                    raise ValueError(f"{rule.rule_id} repeat witness exceeds 256 characters")
                output.extend(walk(repeated, local_variant + offset) for offset in range(count))
            elif operation is sre_constants.GROUPREF:
                output.append(groups.get(argument, "A"))
            elif operation is sre_constants.GROUPREF_EXISTS:
                selected = argument[1] if argument[0] in groups else (argument[2] or [])
                output.append(walk(selected, local_variant))
            elif operation is sre_constants.ASSERT:
                output.append(walk(argument[1], local_variant))
            elif operation in {sre_constants.ASSERT_NOT, sre_constants.AT}:
                continue
            else:  # pragma: no cover - fail closed when a new regex opcode appears
                raise ValueError(f"unsupported regex opcode {operation!r} for {rule.rule_id}")
        return "".join(output)

    witness = walk(sre_parse.parse(rule.pattern.pattern, rule.pattern.flags), variant)
    if rule.pattern.search(witness):
        return witness
    for prefix in ("A", " ", "\n", "value = ", "const value = "):
        for suffix in ("A", " ", "\n", ";", "()"):
            candidate = prefix + witness + suffix
            if rule.pattern.search(candidate):
                return candidate
    raise ValueError(f"unable to synthesize a regex witness for {rule.rule_id}")


def ecosystem_for(rule: Any) -> str:
    frameworks = RULE_FRAMEWORK_HINTS.get(rule.rule_id, frozenset())
    for framework in ("nextjs", "react", "angular", "django", "fastapi", "express"):
        if framework in frameworks:
            return framework
    suffixes = rule.suffixes
    suffix_groups = (
        ("python", {".py", ".pyi"}),
        ("typescript", {".ts", ".tsx"}),
        ("javascript", {".js", ".jsx", ".mjs", ".cjs"}),
        ("go", {".go"}),
        ("php", {".php"}),
        ("csharp", {".cs"}),
        ("cpp", {".c", ".cpp", ".h", ".hpp"}),
        ("java", {".java", ".kt", ".kts"}),
        ("rust", {".rs"}),
        ("sql", {".sql"}),
        ("infrastructure", {".yaml", ".yml", ".json", ".tf", ".hcl", ".service"}),
    )
    if suffixes:
        for ecosystem, known_suffixes in suffix_groups:
            if suffixes <= known_suffixes or suffixes & known_suffixes == suffixes:
                return ecosystem
    title = rule.title.lower()
    for needle, ecosystem in (
        ("go ", "go"),
        ("golang", "go"),
        ("php", "php"),
        ("c#", "csharp"),
        ("asp.net", "csharp"),
        ("rust", "rust"),
        ("python", "python"),
        ("javascript", "javascript"),
        ("node", "javascript"),
        ("kubernetes", "infrastructure"),
        ("terraform", "infrastructure"),
        ("docker", "container"),
        ("systemd", "systemd"),
    ):
        if needle in title:
            return ecosystem
    return "common"


def suffix_for(rule: Any, ecosystem: str) -> str:
    for suffix in SUFFIX_PRIORITY:
        if suffix in rule.suffixes:
            return suffix
    if rule.suffixes:
        return sorted(rule.suffixes)[0]
    defaults = {
        "python": ".py",
        "typescript": ".ts",
        "javascript": ".js",
        "nextjs": ".tsx",
        "react": ".tsx",
        "angular": ".ts",
        "go": ".go",
        "php": ".php",
        "csharp": ".cs",
        "cpp": ".cpp",
        "java": ".java",
        "rust": ".rs",
        "sql": ".sql",
        "infrastructure": ".yaml",
        "systemd": ".service",
        "container": ".dockerfile",
    }
    return defaults.get(ecosystem, ".py")


def case_path(rule: Any, ecosystem: str, case_id: str) -> str:
    if rule.rule_id in PATH_OVERRIDES:
        base = PATH_OVERRIDES[rule.rule_id]
        return base.replace("positive-a", case_id)
    return f"contract-fixtures/{ecosystem}/{rule.rule_id.lower()}-{case_id}{suffix_for(rule, ecosystem)}"


def active_findings(rule: Any, path_value: str, source: str) -> list[Any]:
    path = Path(path_value)
    frameworks = RULE_FRAMEWORK_HINTS.get(rule.rule_id, frozenset())
    findings = find_regex_issues(
        path,
        path_value,
        source,
        detected_frameworks=frameworks,
    )
    active, _ = deduplicate_and_suppress_findings(findings)
    return [finding for finding in active if finding.rule_id == rule.rule_id]


def positive_source(rule: Any, variant: int) -> str:
    if rule.rule_id in MANUAL_WITNESSES:
        witness = MANUAL_WITNESSES[rule.rule_id]
    else:
        witness = synthesize_pattern(rule, variant)
    if variant == 0:
        return witness
    alternatives = (
        "\n" + witness.rstrip("\n") + "\n",
        witness.rstrip("\n") + ";\n",
        witness.rstrip("\n") + "\n\n",
    )
    return alternatives[variant % len(alternatives)]


def silent_mutations(rule: Any, path_value: str, positive: str) -> list[str]:
    match = rule.pattern.search(positive)
    if match is None:
        raise ValueError(f"{rule.rule_id} positive source does not match its regex")
    start, end = match.span()
    candidates: list[str] = []
    for position in range(start, end):
        original = positive[position]
        replacements = ("!", " ", "X") if original != "!" else ("?", " ", "X")
        for replacement in replacements:
            candidate = positive[:position] + replacement + positive[position + 1 :]
            if candidate != positive and candidate not in candidates:
                candidates.append(candidate)
        candidate = positive[:position] + positive[position + 1 :]
        if candidate and candidate not in candidates:
            candidates.append(candidate)
        candidate = positive[:position] + " /* indirect */ " + positive[position:]
        if candidate not in candidates:
            candidates.append(candidate)
    midpoint = start + max(1, (end - start) // 2)
    candidates.extend(
        (
            f"related_prefix = {positive[start:midpoint]!r}\n",
            f"related_suffix = {positive[midpoint:end]!r}\n",
            f"indirect_value = {positive[start:midpoint]!r} + {positive[midpoint:end]!r}\n",
        )
    )
    silent: list[str] = []
    for candidate in candidates:
        if candidate in silent:
            continue
        if not active_findings(rule, path_value, candidate):
            silent.append(candidate)
        if len(silent) >= 3:
            return silent
    raise ValueError(f"unable to create three silent near misses for {rule.rule_id}")


def positive_case(rule: Any, ecosystem: str, case_id: str, source: str) -> dict[str, Any]:
    path = case_path(rule, ecosystem, case_id)
    matches = active_findings(rule, path, source)
    if len(matches) != 1:
        raise ValueError(f"{rule.rule_id}:{case_id} expected one finding, got {len(matches)}")
    finding = matches[0]
    return {
        "path": path,
        **encoded_text(source),
        "expected_line": finding.line,
        "expected_confidence": finding.confidence,
        "expected_detection": finding.detection,
        "expected_proof_level": finding.proof_level,
        "expected_fingerprint": finding.fingerprint,
    }


def contract_entry(rule: Any, ecosystem: str) -> dict[str, Any]:
    positive_count = 2 if rule.severity in {"critical", "high"} else 1
    sources: list[str] = []
    for variant in range(positive_count):
        source = positive_source(rule, variant)
        path = case_path(rule, ecosystem, f"positive-{'ab'[variant]}")
        if not active_findings(rule, path, source) and variant:
            source = positive_source(rule, 0)
        sources.append(source)
    positive = [
        positive_case(rule, ecosystem, f"positive-{'ab'[index]}", source)
        for index, source in enumerate(sources)
    ]
    mutation_path = case_path(rule, ecosystem, "negative-a")
    mutations = silent_mutations(rule, mutation_path, sources[0])
    negative = [
        {
            "path": case_path(rule, ecosystem, f"negative-{'ab'[index]}"),
            **encoded_text(mutations[index]),
        }
        for index in range(2)
    ]
    adversarial = [
        {
            "path": case_path(rule, ecosystem, "adversarial-a"),
            **encoded_text(mutations[2]),
            "expected": False,
            "rationale": (
                "A one-boundary near miss preserves most of the suspicious syntax while changing "
                "the detector's required token or delimiter; it records the current evasion and "
                "false-positive boundary without claiming data-flow reconstruction."
            ),
        }
    ]
    return {
        "rule_id": rule.rule_id,
        "title": rule.title,
        "category": rule.category,
        "expected_severity": rule.severity,
        "expected_confidence": rule.confidence,
        "cwe": rule.cwe,
        "frameworks": sorted(RULE_FRAMEWORK_HINTS.get(rule.rule_id, frozenset())),
        "false_positive_analysis": RULE_EXPLANATIONS[rule.rule_id]["false_positive"],
        "cases": {"positive": positive, "negative": negative, "adversarial": adversarial},
    }


def build_payloads() -> dict[str, str]:
    grouped: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for rule in sorted(
        (rule for rule in RULES if is_legacy_pattern_rule(rule)),
        key=lambda item: rule_number(item.rule_id),
    ):
        ecosystem = ecosystem_for(rule)
        grouped[ecosystem].append(contract_entry(rule, ecosystem))
    rendered: dict[str, str] = {}
    manifest_rows = []
    for ecosystem, entries in sorted(grouped.items()):
        filename = f"pattern-{ecosystem}.v2.json"
        payload = {
            "schema_version": 2,
            "quality_contract_version": 2,
            "engine": "pattern",
            "ecosystem": ecosystem,
            "rules": entries,
        }
        content = json.dumps(payload, indent=2) + "\n"
        rendered[filename] = content
        manifest_rows.append(
            {
                "path": filename,
                "engine": "pattern",
                "ecosystem": ecosystem,
                "rule_count": len(entries),
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            }
        )
    index = {
        "schema_version": 1,
        "quality_contract_version": 2,
        "scope": "Legacy executable-rule contracts split by engine and ecosystem",
        "manifests": manifest_rows,
    }
    rendered["pattern-index.json"] = json.dumps(index, indent=2) + "\n"
    return rendered


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="check generated files without writing"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rendered = build_payloads()
    expected_paths = {OUTPUT_DIR / filename for filename in rendered}
    existing_paths = (
        {
            *OUTPUT_DIR.glob("pattern-*.v2.json"),
            *(
                path
                for path in (OUTPUT_DIR / "pattern-index.json", OUTPUT_DIR / "index.json")
                if path.is_file()
            ),
        }
        if OUTPUT_DIR.is_dir()
        else set()
    )
    stale = sorted(
        path
        for path in expected_paths
        if not path.is_file() or path.read_text(encoding="utf-8") != rendered[path.name]
    )
    unexpected = sorted(existing_paths - expected_paths)
    if args.check:
        if stale or unexpected:
            for path in stale:
                print(f"stale: {path.relative_to(ROOT)}", file=sys.stderr)
            for path in unexpected:
                print(f"unexpected: {path.relative_to(ROOT)}", file=sys.stderr)
            return 1
        print(f"{len(expected_paths)} legacy pattern contract files are current")
        return 0
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for path in unexpected:
        path.unlink()
    for filename, content in rendered.items():
        (OUTPUT_DIR / filename).write_bytes(content.encode("utf-8"))
    print(f"updated {len(expected_paths)} files in {OUTPUT_DIR.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
