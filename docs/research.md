# Research synthesis

ShipProof was designed after reviewing CodeVibes, primary security standards, scanner documentation, SRE/load-testing guidance, and public engineering failure reports. Community sources supplied hypotheses; primary sources determined the implementation.

## Findings that changed the design

### Deterministic first, AI second

CodeVibes demonstrates the value of combining deterministic patterns with contextual AI review. ShipProof keeps that strength but moves deterministic work local, emits stable fingerprints, supports reviewed baselines, and treats AI conclusions as hypotheses until a complete path or test confirms them.

### No single score

A numeric score can hide one catastrophic defect behind many clean files. ShipProof instead has independent Security, Correctness, Scale, Operability, and Supply Chain gates. A blocking gate blocks the release; missing material evidence is conditional.

### Registered users are not load

Stack Overflow discussions about 1M/10M-user tests repeatedly expose an ambiguous denominator: stored accounts, DAU, active sessions, virtual users, and requests per second are different quantities. Google SRE and k6 guidance center measurable throughput, latency/error thresholds, breakpoint behavior, and recovery. The capacity model therefore exposes every conversion ratio and labels its result a hypothesis.

### Scaling failures appear between layers

The 2026 Medium account describes query slowdown, dangerous jobs, stale caches, logging cost, authentication growth,…9425 tokens truncated…city"),
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


def make_finding(rule: Rule, relative: str, line: int, evidence: str) -> Finding:
    safe_evidence = clean_evidence(evidence, rule.redact)
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
    unique = {finding.fingerprint: finding for finding in findings}
    active = [item for key, item in unique.items() if key not in (baseline or set())]
    active.sort(key=lambda item: (SEVERITY[item.severity], CONFIDENCE[item.confidence], item.path, item.line))
    return active, len(unique) - len(active)


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
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
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
        "tool": {"name": "ShipProof", "version": "0.1.0"},
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
        "tool": {"driver": {"name": "ShipProof", "version": "0.1.0", "informationUri": "https://github.com/kingggg5/shipproof",
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
