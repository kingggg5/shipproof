#!/usr/bin/env python3
"""Fast, local-first production risk scanner with JSON, Markdown, and SARIF output."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Sequence

VERSION = "0.3.0"

SEVERITY = {"none": 99, "critical": 0, "high": 1, "medium": 2, "low": 3}
CONFIDENCE = {"high": 0, "medium": 1, "low": 2}
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".vscode", ".venv", "venv", "env",
    "node_modules", "vendor", "dist", "build", "coverage", ".next", ".nuxt",
    ".cache", ".pytest_cache", ".mypy_cache", ".ruff_cache", "target", "bin", "obj",
    "__pycache__",
}
TEXT_SUFFIXES = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java",
    ".kt", ".kts", ".go", ".rs", ".rb", ".php", ".cs", ".sh", ".bash",
    ".ps1", ".sql", ".graphql", ".gql", ".json", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".conf", ".properties", ".env", ".xml", ".tf", ".hcl",
}
TEXT_NAMES = {"dockerfile", "containerfile", "makefile", "procfile", ".env"}
PLACEHOLDERS = re.compile(
    r"(?i)(example|sample|placeholder|dummy|changeme|replace[_-]?me|your[_-]?|test[_-]?only|"
    r"not[_-]?a[_-]?real|fake|redacted|xxxx|<[^>]+>|\$\{|process\.env|os\.environ)"
)


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: str
    pattern: re.Pattern[str]
    message: str
    remediation: str
    cwe: str
    owasp: str
    suffixes: frozenset[str] = frozenset()
    redact: bool = False


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: str
    path: str
    line: int
    evidence: str
    message: str
    remediation: str
    cwe: str
    owasp: str
    fingerprint: str


def rx(value: str) -> re.Pattern[str]:
    return re.compile(value, re.IGNORECASE)


RULES: tuple[Rule, ...] = (
    Rule("SP001", "Private key committed", "security", "critical", "high",
         rx(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
         "A private key appears in source control.", "Revoke and rotate the key, remove it from history, and use a secret manager.",
         "CWE-798", "OWASP ASVS V14", redact=True),
    Rule("SP002", "AWS access key committed", "security", "critical", "high",
         re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
         "An AWS access key ID appears in source control.", "Disable and rotate the credential, inspect access logs, and purge it from history.",
         "CWE-798", "OWASP ASVS V14", redact=True),
    Rule("SP003", "Credential-like value committed", "security", "high", "medium",
         rx(r"\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|password)\b\s*[:=]\s*[\"'][^\"'\s]{16,}[\"']"),
         "A credential-like value is assigned directly in a file.", "Confirm it is real, then rotate it and load the replacement from an approved secret store.",
         "CWE-798", "OWASP ASVS V14", redact=True),
    Rule("SP101", "Dynamic code execution", "security", "high", "medium",
         rx(r"\b(?:eval|exec)\s*\("), "Dynamic code execution can turn untrusted input into code execution.",
         "Remove dynamic evaluation or constrain input with a safe parser and strict allowlist.", "CWE-95", "OWASP ASVS V1",
         frozenset({".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".php", ".rb"})),
    Rule("SP102", "Shell execution enabled", "security", "high", "high",
         rx(r"\bshell\s*=\s*(?:true|True)\b"), "Shell interpretation expands command-injection exposure.",
         "Pass an argument array without a shell and validate every externally controlled argument.", "CWE-78", "OWASP ASVS V1"),
    Rule("SP103", "SQL built with interpolation", "security", "high", "medium",
         rx(r"(?:execute|query|raw)\s*\(\s*(?:f[\"']|`[^`]*\$\{|[\"'][^\"']*%[s(]|[^,]+\.format\()"),
         "A database query appears to be built with string interpolation.", "Use parameterized queries or the ORM's bound parameters and add an injection regression test.",
         "CWE-89", "OWASP ASVS V1"),
    Rule("SP104", "TLS verification disabled", "security", "high", "high",
         rx(r"\b(?:verify|rejectUnauthorized)\s*[:=]\s*(?:false|False)\b"),
         "TLS peer verification is explicitly disabled.", "Restore certificate verification and configure the correct trust chain.",
         "CWE-295", "OWASP ASVS V12"),
    Rule("SP105", "JWT signature verification disabled", "security", "critical", "high",
         rx(r"(?:verify_signature[\"']?\s*[:=]\s*(?:false|False)|algorithms?\s*[:=]\s*\[[\"']none[\"']\])"),
         "JWT signature verification appears disabled.", "Require an allowlisted algorithm, issuer, audience, expiry, and a verified signature.",
         "CWE-347", "OWASP ASVS V6"),
    Rule("SP106", "Unsafe deserialization", "security", "high", "medium",
         rx(r"\b(?:pickle\.loads?|yaml\.load)\s*\("), "Unsafe deserialization can execute attacker-controlled behavior.",
         "Use a safe data format; for YAML use safe_load and constrain accepted types.", "CWE-502", "OWASP ASVS V5",
         frozenset({".py", ".pyi"})),
    Rule("SP201", "Debug mode enabled", "security", "high", "high",
         rx(r"\b(?:debug|DEBUG)\s*[:=]\s*(?:true|True|1)\b"), "Debug mode may expose internals or interactive execution in production.",
         "Make production fail closed and enable debug only in an explicit local environment.", "CWE-489", "OWASP ASVS V13"),
    Rule("SP202", "Floating container base image", "supply-chain", "medium", "high",
         rx(r"^\s*FROM\s+[^\s:@]+(?::latest)?\s*$"), "The container base image is not pinned to an immutable digest.",
         "Pin the reviewed image by digest and update it through an automated, reviewed process.", "CWE-1104", "NIST SSDF PS.3"),
    Rule("SP203", "Unpinned GitHub Action", "supply-chain", "high", "high",
         rx(r"^\s*-?\s*uses:\s*(?!\./)([^\s@]+)@(?![0-9a-f]{40}\b)[^\s#]+"),
         "A third-party GitHub Action is referenced by a mutable tag or branch.", "Pin the action to a reviewed 40-character commit SHA and retain the release tag in a comment.",
         "CWE-829", "NIST SSDF PS.3", frozenset({".yml", ".yaml"})),
    Rule("SP301", "Redis KEYS in application path", "scale", "high", "medium",
         rx(r"\b(?:redis|redis_client|r)\.keys\s*\("), "Redis KEYS can block the server while scanning the full keyspace.",
         "Use cursor-based SCAN, a purpose-built index, or a bounded key namespace.", "CWE-400", "Capacity"),
    Rule("SP302", "Unbounded SQL result", "scale", "medium", "low",
         rx(r"\bSELECT\s+\*\s+FROM\b(?![^;\n]*\bLIMIT\b)"), "A query may return an unbounded, over-wide result set.",
         "Select required columns and enforce pagination or a defensible upper bound.", "CWE-400", "Capacity", frozenset({".sql"})),
    Rule("SP303", "Blocking sleep in async code", "correctness", "high", "high",
         rx(r"\btime\.sleep\s*\("), "Blocking sleep may stall an async event loop.",
         "Use the runtime's non-blocking sleep or move blocking work to a bounded worker.", "CWE-400", "Reliability", frozenset({".py"})),
)


def is_text_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES or path.name.lower() in TEXT_NAMES


def iter_files(root: Path, max_bytes: int) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if is_text_file(path) and path.stat().st_size <= max_bytes:
            yield path


def clean_evidence(line: str, redact: bool) -> str:
    compact = line.strip().replace("\t", " ")[:240]
    return "[REDACTED: credential-like material]" if redact else compact


def is_pure_comment(line: str, path: Path) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    suffix = path.suffix.lower()
    name = path.name.lower()
    if suffix in {".py", ".pyi", ".sh", ".bash", ".ps1", ".yaml", ".yml", ".toml",
                  ".ini", ".cfg", ".conf", ".properties", ".env", ".rb", ".graphql", ".gql"} or \
            name in {"dockerfile", "containerfile", "makefile", "procfile", ".env"}:
        return stripped.startswith("#")
    if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java",
                  ".kt", ".kts", ".go", ".rs", ".cs", ".php"}:
        return stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*")
    if suffix == ".sql":
        return stripped.startswith("--") or stripped.startswith("/*") or stripped.startswith("*")
    if suffix in {".tf", ".hcl"}:
        return stripped.startswith("#") or stripped.startswith("//")
    return False


def make_finding(rule: Rule, relative: str, line: int, evidence: str) -> Finding:
    safe_evidence = clean_evidence(evidence, rule.redact)
    if rule.redact:
        content_hash = hashlib.sha256(evidence.strip().encode("utf-8", "replace")).hexdigest()[:12]
        identity = f"{rule.rule_id}:{relative}:{content_hash}"
    else:
        identity = f"{rule.rule_id}:{relative}:{safe_evidence}"
    fingerprint = hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()[:24]
    return Finding(rule.rule_id, rule.title, rule.category, rule.severity, rule.confidence,
                   relative, line, safe_evidence, rule.message,
                   rule.remediation, rule.cwe, rule.owasp, fingerprint)


def regex_findings(path: Path, relative: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    suffix = path.suffix.lower()
    lines = text.splitlines()
    for rule in RULES:
        if rule.rule_id == "SP303":
            continue
        if rule.suffixes and suffix not in rule.suffixes:
            continue
        for line_number, line in enumerate(lines, 1):
            if rule.rule_id not in {"SP001", "SP002", "SP003"} and is_pure_comment(line, path):
                continue
            if rule.pattern.search(line):
                if rule.rule_id in {"SP001", "SP002", "SP003"} and PLACEHOLDERS.search(line):
                    continue
                findings.append(make_finding(rule, relative, line_number, line))

    if suffix == ".py" and re.search(r"allow_origins\s*=\s*\[[\"']\*[\"']\]", text) \
            and re.search(r"allow_credentials\s*=\s*True", text):
        line = next((i for i, value in enumerate(lines, 1) if "allow_origins" in value), 1)
        rule = Rule("SP107", "Credentialed wildcard CORS", "security", "high", "high", rx("$^"),
                    "Wildcard origins and credentials create an unsafe cross-origin policy.",
                    "Allowlist exact trusted origins and test preflight behavior.", "CWE-942", "OWASP ASVS V3")
        findings.append(make_finding(rule, relative, line, lines[line - 1] if lines else ""))
    return findings


def dotted_name(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


class PythonVisitor(ast.NodeVisitor):
    def __init__(self, relative: str, lines: Sequence[str]) -> None:
        self.relative = relative
        self.lines = lines
        self.findings: list[Finding] = []
        self.async_depth = 0

    def add(self, rule: Rule, node: ast.AST) -> None:
        line = getattr(node, "lineno", 1)
        evidence = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        self.findings.append(make_finding(rule, self.relative, line, evidence))

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.async_depth += 1
        self.generic_visit(node)
        self.async_depth -= 1

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        previous_depth = self.async_depth
        self.async_depth = 0
        self.generic_visit(node)
        self.async_depth = previous_depth

    def visit_Call(self, node: ast.Call) -> None:
        name = dotted_name(node.func)
        if name in {"requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete", "httpx.get", "httpx.post"}:
            if not any(keyword.arg == "timeout" for keyword in node.keywords):
                rule = Rule("SP304", "Outbound request without timeout", "correctness", "high", "high", rx("$^"),
                            "An outbound request has no explicit deadline and can exhaust workers or connections.",
                            "Set connect and read deadlines, bound retries, and test dependency failure.", "CWE-400", "Reliability")
                self.add(rule, node)
        if self.async_depth and name == "time.sleep":
            rule = next(item for item in RULES if item.rule_id == "SP303")
            self.add(rule, node)
        self.generic_visit(node)


def python_ast_findings(relative: str, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    visitor = PythonVisitor(relative, text.splitlines())
    visitor.visit(tree)
    return visitor.findings


def load_baseline(path: Path | None) -> set[str]:
    if path is None:
        return set()
    payload = json.loads(path.read_text(encoding="utf-8"))
    values = payload.get("fingerprints", [])
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError("baseline must contain a string array named 'fingerprints'")
    return set(values)


def finalize_findings(findings: Iterable[Finding], baseline: set[str] | None = None) -> tuple[list[Finding], int]:
    unique: dict[tuple[str, str, int], Finding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.path, finding.line)
        if key not in unique:
            unique[key] = finding
    active: list[Finding] = []
    suppressed_count = 0
    baseline_set = baseline or set()
    for finding in unique.values():
        if finding.fingerprint in baseline_set:
            suppressed_count += 1
        else:
            active.append(finding)
    active.sort(key=lambda item: (SEVERITY[item.severity], CONFIDENCE[item.confidence], item.path, item.line))
    return active, suppressed_count


def scan(root: Path, max_bytes: int = 1_000_000, baseline: set[str] | None = None) -> tuple[list[Finding], dict[str, int]]:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")
    findings: list[Finding] = []
    files_scanned = 0
    for path in iter_files(root, max_bytes):
        files_scanned += 1
        relative = path.relative_to(root).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(regex_findings(path, relative, text))
        if path.suffix.lower() == ".py":
            findings.extend(python_ast_findings(relative, text))

    active, suppressed = finalize_findings(findings, baseline)
    return active, {"files_scanned": files_scanned, "suppressed": suppressed}


def verdict(findings: Sequence[Finding]) -> str:
    severities = {item.severity for item in findings}
    if severities & {"critical", "high"}:
        return "BLOCK"
    if severities & {"medium", "low"}:
        return "CONDITIONAL"
    return "PASS_WITH_EVIDENCE"


def json_report(root: Path, findings: Sequence[Finding], stats: dict[str, int]) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "tool": {"name": "ShipProof", "version": VERSION},
        "root": str(root.resolve()),
        "verdict": verdict(findings),
        "summary": {"findings": len(findings), **stats, "by_severity": dict(Counter(item.severity for item in findings))},
        "findings": [asdict(item) for item in findings],
        "limitations": ["Fast heuristic scan; confirm every finding.", "No runtime reachability, dependency CVE database, or git-history scan."],
    }


def markdown_report(root: Path, findings: Sequence[Finding], stats: dict[str, int]) -> str:
    counts = Counter(item.severity for item in findings)
    lines = ["# ShipProof report", "", f"**Verdict:** {verdict(findings)}", "",
             f"Scanned `{stats['files_scanned']}` files; found `{len(findings)}` active issues; suppressed `{stats['suppressed']}`.", "",
             "| Critical | High | Medium | Low |", "| ---: | ---: | ---: | ---: |",
             f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} |", ""]
    for item in findings:
        lines.extend([f"## {item.severity.upper()} · {item.rule_id} · {item.title}", "",
                      f"`{item.path}:{item.line}` · confidence: `{item.confidence}` · {item.category}", "",
                      f"> {item.evidence}", "", item.message, "", f"**Fix:** {item.remediation}", "",
                      f"Mapping: `{item.cwe}` · `{item.owasp}` · fingerprint `{item.fingerprint}`", ""])
    lines.extend(["## Limitations", "", "This is a fast heuristic scan. Confirm every finding with complete data-flow and runtime context; use dedicated SAST, secret-history, dependency, IaC, and load-testing tools for release evidence.", ""])
    return "\n".join(lines)


def sarif_report(findings: Sequence[Finding]) -> dict[str, object]:
    rules: dict[str, Finding] = {item.rule_id: item for item in findings}
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{
        "tool": {"driver": {"name": "ShipProof", "version": VERSION, "informationUri": "https://github.com/kingggg5/shipproof",
                            "rules": [{"id": item.rule_id, "name": item.title.replace(" ", "_"),
                                       "shortDescription": {"text": item.title}, "fullDescription": {"text": item.message},
                                       "help": {"text": item.remediation}, "properties": {"tags": [item.category, item.cwe, item.owasp]}}
                                      for item in rules.values()]}},
        "results": [{"ruleId": item.rule_id, "level": level[item.severity], "message": {"text": item.message},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": item.path},
                                                          "region": {"startLine": item.line}}}],
                     "partialFingerprints": {"shipproof/v1": item.fingerprint},
                     "properties": {"severity": item.severity, "confidence": item.confidence}}
                    for item in findings],
    }]}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", type=Path)
    parser.add_argument("--format", choices=("json", "markdown", "sarif"), default="markdown")
    parser.add_argument("--output", type=Path, help="Write report to a file instead of stdout")
    parser.add_argument("--baseline", type=Path, help="Suppress reviewed fingerprints from this JSON baseline")
    parser.add_argument("--baseline-out", type=Path, help="Write active fingerprints as a reviewable baseline")
    parser.add_argument("--fail-on", choices=tuple(SEVERITY), default="high")
    parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass
    args = parse_args(argv)
    try:
        if args.max_file_bytes <= 0:
            raise ValueError("max-file-bytes must be positive")
        findings, stats = scan(args.root, args.max_file_bytes, load_baseline(args.baseline))
        payload = json_report(args.root, findings, stats)
        if args.baseline_out:
            args.baseline_out.write_text(json.dumps({"version": 1, "fingerprints": [item.fingerprint for item in findings]}, indent=2) + "\n", encoding="utf-8")
        if args.format == "markdown":
            output = markdown_report(args.root, findings, stats)
        elif args.format == "sarif":
            output = json.dumps(sarif_report(findings), indent=2)
        else:
            output = json.dumps(payload, indent=2)
        if args.output:
            args.output.write_text(output + ("" if output.endswith("\n") else "\n"), encoding="utf-8")
        else:
            print(output)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"shipproof: {exc}", file=sys.stderr)
        return 2

    if args.fail_on != "none" and any(SEVERITY[item.severity] <= SEVERITY[args.fail_on] for item in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
