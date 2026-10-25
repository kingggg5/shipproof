"""Deterministic precision policy for per-finding confidence, gates, and context."""

from __future__ import annotations

import ast
import re
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

PROOF_RANK = {"L0": 0, "L1": 1, "L2": 2}
CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}
DOWNRANK = {"high": "medium", "medium": "low", "low": "low"}
MAX_DISPLAY_PER_RULE_FILE = 3

L0_BLOCK_ALLOWLIST = frozenset(
    {
        "SP201",  # debug/DEBUG = True in application construction or settings
        "SP665",  # Django DEBUG = True in a deployable settings module
    }
)

ADVISORY_RULE_IDS = frozenset(
    {
        "SP061",  # bare except / except Exception
        "SP591",  # Client bundling boundary, not evidence of leaked credentials.
        # These cohorts explicitly ship advisory pending representative labels.
        "SP666",
        "SP667",
        "SP668",
        "SP669",
        "SP670",
        "SP671",
        "SP672",
        "SP673",
        "SP674",
        "SP675",
        "SP676",
        "SP677",
        "SP678",
        "SP679",
        "SP680",
        "SP681",
        "SP682",
        "SP683",  # Declared version, not deployed PHP patch/attack evidence.
        "SP684",  # Declared Node patch baseline; runtime/backports are unknown.
        "SP685",  # Upstream support status, distinct from vendor support.
        "SP686",  # Local protocol selection, not a negotiated connection.
        "SP687",  # Local message cap, not demonstrated denial of service.
        "SP688",  # Image configuration, not an attacker-controlled SVG response.
        "SP689",  # Local body limit; upstream/per-request controls are unknown.
        "SP690",  # Client-selected module; deployment/asset permissions unknown.
        "SP691",  # Direct instance deletion; deployment/ownership unknown.
        "SP692",  # RSA size guard opt-out, not proof of a weak deployed key.
        "SP693",  # Ingress config, not a deployed slow-request attack.
        "SP694",  # Local noncompletion; surrounding cancellation is unknown.
        "SP695",  # Comparator contract, not a claim about all input ordering.
        "SP696",  # XML expansion settings, not proven hostile input.
        "SP697",  # Loopback configuration listener, not remote exploitability.
        "SP698",  # Synchronous API behavior; input size and CPU cost unknown.
        "SP699",  # Literal validity violation; execution/reachability unknown.
        "SP700",  # Delay coercion, not proof of a deployed timer storm.
        "SP701",  # Local pool capacity, not measured database exhaustion.
    }
)

# Filenames that usually mark an application *project root*. Nested copies such
# as Werkzeug's ``wsgi.py``, HTTPX's ``_transports/asgi.py``, or FastAPI's
# ``middleware/wsgi.py`` are library modules, not deployable entrypoints.
# ``wsgi.py`` / ``asgi.py`` are omitted on purpose: scanning a WSGI/ASGI
# library puts those names at the package root and would mis-label it as an app.
APPLICATION_ENTRY_FILES = frozenset(
    {
        "manage.py",
        "server.py",
        "server.js",
        "server.ts",
        "server.mjs",
        "next.config.js",
        "next.config.mjs",
        "next.config.ts",
    }
)
APPLICATION_DIR_SEGMENTS = frozenset(
    {
        "routes",
        "views",
        "controllers",
        "pages",
        "handlers",
    }
)
APPLICATION_SIGNAL_RULES = frozenset(
    {
        "SP108",
        "SP201",
        "SP401",
        "SP402",
        "SP407",
        "SP664",
        "SP665",
    }
)
APPLICATION_ORIENTED_RULE_IDS = frozenset(
    {
        "SP101",
        "SP106",
        "SP108",
        "SP117",
        "SP140",
        "SP201",
        "SP304",
        "SP305",
        "SP307",
        "SP310",
        "SP505",
        "SP526",
        "SP636",
        "SP664",
        "SP665",
    }
)
CODEGEN_PATH_PARTS = frozenset(
    {
        "ajv",
        "escodegen",
        "handlebars",
        "jinja2",
        "mako",
        "nunjucks",
        "pydantic",
        "werkzeug",
    }
)
DB_IMPORT_RE = re.compile(
    r"\b(?:import|from)\s+"
    r"(?:sqlalchemy|django\.db|psycopg2?|asyncpg|sqlite3|pymongo|peewee|tortoise|sqlmodel|databases)\b",
    re.IGNORECASE,
)
LLM_IMPORT_RE = re.compile(
    r"\b(?:import|from|require\(|from\s+['\"])\s*"
    r"(?:openai|anthropic|google\.generativeai|langchain|llama_index|ollama|transformers)\b",
    re.IGNORECASE,
)
PASSWORD_TOKEN_RE = re.compile(
    r"\b(?:password|passwd|secret|token|signature|digest|hmac|credential)\b",
    re.IGNORECASE,
)
USED_FOR_SECURITY_FALSE = re.compile(r"usedforsecurity\s*=\s*False")
STREAM_CONSTRUCT_RE = re.compile(
    r"\b(?:StreamingResponse|EventSourceResponse|EventSource|setHeader\s*\()\b",
    re.IGNORECASE,
)
FRAMEWORK_SSE_IMPLEMENTATION_RE = re.compile(
    r"^\s*class\s+(?:APIRouter|FastAPI)\b",
    re.MULTILINE,
)
EVAL_COMPILE_RE = re.compile(r"\b(?:eval|exec)\s*\(\s*compile\s*\(")
REPL_OR_COMPILER_RE = re.compile(
    r"\b(?:InteractiveInterpreter|InteractiveConsole|codeop|CodeType)\b"
)
DECOMPRESSION_PIPE_RE = re.compile(
    r"\b(?:createDecompressionStream|createInflate|createGunzip|createBrotli|"
    r"zlib\.|pipeline\s*\(|\.unpipe\s*\(|stream\.destroy)\b",
    re.IGNORECASE,
)
HISTORY_BOUND_RE = re.compile(
    r"\.(?:slice|pop|splice|shift|truncate|lstrip)\s*\(|"
    r"\blen\s*\(|tiktoken|token_count|max_tokens|[-:] *[0-9]+ *[:\]]",
    re.IGNORECASE,
)
SLEEP_WAIT_RE = re.compile(r"\b(?:sleep|wait|select|recv|poll|backoff)\b", re.IGNORECASE)
EXTERNAL_INPUT_RE = re.compile(
    r"\b(?:request|req\.|params|query|body|stdin|argv|input\()\b",
    re.IGNORECASE,
)


def docstring_lines(tree: ast.AST | None) -> frozenset[int]:
    """1-based line numbers of module, class, and function docstrings."""
    if tree is None:
        return frozenset()
    lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not node.body:
            continue
        first = node.body[0]
        if not isinstance(first, ast.Expr):
            continue
        value = first.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            start = getattr(value, "lineno", None)
            end = getattr(value, "end_lineno", start)
            if start is not None and end is not None:
                lines.update(range(start, end + 1))
    return frozenset(lines)


def is_codegen_library(relative_path: str, source_path: str | None = None) -> bool:
    parts = {part.lower() for part in Path(relative_path).parts}
    if source_path:
        parts.update(part.lower() for part in Path(source_path).parts)
    return bool(parts & CODEGEN_PATH_PARTS)


def detect_scan_profile(paths: Iterable[str], findings: Sequence[Any]) -> str:
    normalized = [item.replace("\\", "/").lower().removeprefix("./") for item in paths]
    names = {Path(item).name for item in normalized}
    if names & APPLICATION_ENTRY_FILES:
        return "application"
    for path in normalized:
        parts = path.split("/")
        if any(part in APPLICATION_DIR_SEGMENTS for part in parts[:-1]):
            return "application"
        if path == "app/api" or path.startswith("app/api/"):
            return "application"
    if any(getattr(item, "rule_id", None) in APPLICATION_SIGNAL_RULES for item in findings):
        return "application"
    return "library"


def is_advisory(finding: Any) -> bool:
    return getattr(finding, "tier", "gate") == "advisory" or finding.rule_id in ADVISORY_RULE_IDS


def is_secret_finding(finding: Any, secret_rule_ids: frozenset[str]) -> bool:
    return finding.rule_id in secret_rule_ids


def is_l0_allowlisted(finding: Any, secret_rule_ids: frozenset[str]) -> bool:
    if finding.rule_id in L0_BLOCK_ALLOWLIST:
        return True
    if not is_secret_finding(finding, secret_rule_ids):
        return False
    match = getattr(finding, "match_confidence", None) or finding.confidence
    return match == "high"


def is_gate_finding(
    finding: Any,
    *,
    block_min_proof: str,
    secret_rule_ids: frozenset[str],
) -> bool:
    if is_advisory(finding):
        return False
    proof = getattr(finding, "proof_level", "L0")
    if PROOF_RANK.get(proof, 0) >= PROOF_RANK.get(block_min_proof, 1):
        return True
    return proof == "L0" and is_l0_allowlisted(finding, secret_rule_ids)


def context_allows(finding: Any, source_text: str, relative_path: str) -> bool:
    """Return whether a finding still has enough context to report."""
    rule_id = finding.rule_id
    line = (
        source_text.splitlines()[finding.line - 1]
        if 0 < finding.line <= source_text.count("\n") + 1
        else ""
    )
    if rule_id == "SP140":
        nearby = nearby_text(source_text, finding.line, 4)
        if USED_FOR_SECURITY_FALSE.search(nearby):
            return False
        if not PASSWORD_TOKEN_RE.search(nearby):
            return False
    if (
        rule_id == "SP307"
        and not DB_IMPORT_RE.search(source_text)
        and not re.search(
            r"\b(?:db|session|cursor|orm|conn)\.(?:query|execute|filter_by|find_one)\b",
            line,
        )
    ):
        return False
    if rule_id == "SP310":
        block = function_block(source_text, finding.line)
        if SLEEP_WAIT_RE.search(block) or re.search(r"\bbreak\b", block):
            return False
    if rule_id == "SP636":
        if FRAMEWORK_SSE_IMPLEMENTATION_RE.search(source_text):
            return False
        if not STREAM_CONSTRUCT_RE.search(nearby_text(source_text, finding.line, 8)):
            return False
    if rule_id == "SP367":
        block = function_block(source_text, finding.line)
        if DECOMPRESSION_PIPE_RE.search(block) or DECOMPRESSION_PIPE_RE.search(
            nearby_text(source_text, finding.line, 8)
        ):
            return False
    if rule_id == "SP147" and re.search(
        r"(?:^|/)debug/(?:shared/)?debugger\.(?:js|ts)$",
        relative_path.replace("\\", "/"),
        re.IGNORECASE,
    ):
        return False
    if rule_id == "SP505" and not LLM_IMPORT_RE.search(source_text):
        return False
    if rule_id == "SP526":
        block = function_block(source_text, finding.line)
        name_match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*append\b", line)
        if name_match and HISTORY_BOUND_RE.search(block):
            variable = name_match.group(1)
            if re.search(rf"\b{re.escape(variable)}\b", block) and HISTORY_BOUND_RE.search(block):
                return False
    if rule_id in {"SP101", "SP117"} and is_codegen_library(relative_path):
        return False
    if (
        rule_id in {"SP101", "SP117"}
        and finding.proof_level == "L0"
        and not EXTERNAL_INPUT_RE.search(nearby_text(source_text, finding.line, 8))
    ):
        return False
    if rule_id == "SP101":
        if EVAL_COMPILE_RE.search(line) or EVAL_COMPILE_RE.search(
            nearby_text(source_text, finding.line, 2)
        ):
            return False
        if REPL_OR_COMPILER_RE.search(source_text) and not EXTERNAL_INPUT_RE.search(
            nearby_text(source_text, finding.line, 8)
        ):
            return False
        if re.search(
            r"(?:^|/)debug/console\.py$",
            relative_path.replace("\\", "/"),
            re.IGNORECASE,
        ):
            return False
        if re.search(r"\bcompile\s*\(", function_block(source_text, finding.line)) and not (
            EXTERNAL_INPUT_RE.search(nearby_text(source_text, finding.line, 8))
        ):
            return False
    if (
        rule_id == "SP106"
        and re.search(r"\b(?:bccache|cache|__pycache__|bytecache)\b", finding.path, re.IGNORECASE)
        and not EXTERNAL_INPUT_RE.search(nearby_text(source_text, finding.line, 6))
    ):
        return False
    return not (
        rule_id == "SP106"
        and re.search(r"\b(?:cache|bccache|tmp|temp)\b", line, re.IGNORECASE)
        and not EXTERNAL_INPUT_RE.search(nearby_text(source_text, finding.line, 6))
    )


def nearby_text(source_text: str, line_number: int, radius: int) -> str:
    lines = source_text.splitlines()
    start = max(0, line_number - 1 - radius)
    end = min(len(lines), line_number + radius)
    return "\n".join(lines[start:end])


def function_block(source_text: str, line_number: int) -> str:
    lines = source_text.splitlines()
    index = max(0, line_number - 1)
    start = index
    while start > 0 and not re.match(
        r"^\s*(?:def |async def |function |const \w+ = |export )", lines[start]
    ):
        start -= 1
    indent = len(lines[index]) - len(lines[index].lstrip()) if lines else 0
    end = index + 1
    while end < len(lines):
        stripped = lines[end]
        if (
            stripped.strip()
            and (len(stripped) - len(stripped.lstrip())) <= indent
            and end > index
            and not stripped.strip().startswith(("#", "*", "//"))
        ):
            break
        end += 1
    return "\n".join(lines[start:end])


def has_corroboration(finding: Any, source_text: str) -> bool:
    if finding.rule_id == "SP140":
        return bool(PASSWORD_TOKEN_RE.search(nearby_text(source_text, finding.line, 4)))
    if finding.rule_id in {"SP101", "SP117"}:
        return bool(EXTERNAL_INPUT_RE.search(nearby_text(source_text, finding.line, 8)))
    return finding.rule_id in L0_BLOCK_ALLOWLIST


def has_contradiction(finding: Any, source_text: str, relative_path: str) -> bool:
    if finding.rule_id == "SP140" and USED_FOR_SECURITY_FALSE.search(
        nearby_text(source_text, finding.line, 2)
    ):
        return True
    return finding.rule_id in {"SP101", "SP117"} and is_codegen_library(relative_path)


def apply_file_precision(
    findings: Sequence[Any],
    *,
    relative_path: str,
    source_text: str,
    secret_rule_ids: frozenset[str],
    source_path: str | None = None,
) -> list[Any]:
    refined: list[Any] = []
    for finding in findings:
        if not context_allows(finding, source_text, source_path or relative_path):
            continue
        match_confidence = getattr(finding, "match_confidence", None) or finding.confidence
        risk = finding.confidence
        if finding.rule_id in ADVISORY_RULE_IDS:
            finding = replace(
                finding,
                confidence="low",
                tier="advisory",
                match_confidence=match_confidence,
            )
            refined.append(finding)
            continue
        if not is_secret_finding(finding, secret_rule_ids) and finding.proof_level == "L0":
            if finding.rule_id in L0_BLOCK_ALLOWLIST:
                risk = finding.confidence
            else:
                risk = "medium"
                if has_contradiction(finding, source_text, relative_path):
                    risk = "low"
                elif has_corroboration(finding, source_text):
                    risk = "high"
        finding = replace(
            finding,
            confidence=risk,
            match_confidence=match_confidence,
            tier=getattr(finding, "tier", "gate"),
        )
        refined.append(finding)
    return refined


def apply_library_mode(
    findings: Sequence[Any], profile: str, secret_rule_ids: frozenset[str]
) -> list[Any]:
    if profile != "library":
        return [
            replace(item, scan_profile=profile) if hasattr(item, "scan_profile") else item
            for item in findings
        ]
    updated: list[Any] = []
    for finding in findings:
        if is_secret_finding(finding, secret_rule_ids):
            updated.append(replace(finding, scan_profile=profile))
            continue
        if finding.rule_id in APPLICATION_ORIENTED_RULE_IDS:
            updated.append(
                replace(
                    finding,
                    severity=DOWNRANK.get(finding.severity, finding.severity),
                    scan_profile=profile,
                )
            )
            continue
        updated.append(replace(finding, scan_profile=profile))
    return updated


def collapse_for_display(findings: Sequence[Any]) -> tuple[list[Any], list[str]]:
    grouped: dict[tuple[str, str], list[Any]] = defaultdict(list)
    for finding in findings:
        grouped[(finding.rule_id, finding.path)].append(finding)
    visible: list[Any] = []
    notes: list[str] = []
    for (rule_id, path), items in grouped.items():
        visible.extend(items[:MAX_DISPLAY_PER_RULE_FILE])
        extra = len(items) - MAX_DISPLAY_PER_RULE_FILE
        if extra > 0:
            notes.append(
                f"{extra} additional {rule_id} finding(s) in {path} omitted from this view; JSON and SARIF keep all"
            )
    return visible, notes
