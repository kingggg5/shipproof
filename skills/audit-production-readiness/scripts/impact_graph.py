#!/usr/bin/env python3
"""AST-based Change Impact Graph Analyzer for ShipProof.

Constructs static call graphs, maps callers, identifies touched state/database entities,
and discovers relevant regression test suites for modified or audited symbols.
Operates strictly offline and dependency-free using Python's standard library.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

VERSION = "0.8.0"

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".venv",
    ".work",
    "venv",
    "env",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    ".cache",
    ".npm-cache",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "target",
    "__pycache__",
}

PYTHON_SUFFIXES = {".py", ".pyi"}
JS_TS_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

KNOWN_SANITIZERS = frozenset(
    {
        "int",
        "float",
        "bool",
        "abs",
        "len",
        "round",
        "escape",
        "html.escape",
        "markupsafe.escape",
        "bleach.clean",
        "shlex.quote",
        "quote",
        "quote_plus",
        "re.escape",
        "uuid.uuid4",
        "uuid.uuid",
        "uuid.UUID",
        "is_uuid",
        "sanitize",
        "dompurify.sanitize",
        "validator.escape",
    }
)

# Simple-call sink table shared by the JS/TS lexical analyzer. Keys are the
# lowercased final call segment; values map onto the same rule IDs the Python
# engine reports so downstream policy and explanations stay consistent.
JS_SINK_CALLS: dict[str, tuple[str, str]] = {
    "execute": ("sql_injection", "SP103"),
    "query": ("sql_injection", "SP103"),
    "raw": ("sql_injection", "SP103"),
    "exec": ("command_injection", "SP102"),
    "execsync": ("command_injection", "SP102"),
    # Filesystem sinks: a tainted path reaching these calls is the classic
    # traversal pattern; containment guards and basename() clear it upstream.
    "readfile": ("path_traversal", "SP110"),
    "readfilesync": ("path_traversal", "SP110"),
    "writefile": ("path_traversal", "SP110"),
    "writefilesync": ("path_traversal", "SP110"),
    "appendfile": ("path_traversal", "SP110"),
    "createreadstream": ("path_traversal", "SP110"),
    "createwritestream": ("path_traversal", "SP110"),
}
JS_CODE_EXEC_SINK_CALLS: dict[str, tuple[str, str]] = {
    "eval": ("code_execution", "SP101"),
}
# Outbound HTTP sinks matched by receiver so route registrations such as
# router.get(...) are never mistaken for requests: bare fetch(...) and
# axios.<method>(...) only. Both map to SP124 (user-controlled request URL).
JS_HTTP_SINK_BARE_NAMES = frozenset({"fetch"})
JS_SANITIZER_SIMPLE_NAMES = frozenset({"number", "parseint", "parsefloat"})
JS_AUTH_HINTS = ("auth", "admin", "permission", "policy", "role", "scope", "jwt", "passport")
JS_BUILTIN_CALLEE_NAMES = frozenset(
    {
        "array",
        "boolean",
        "catch",
        "console",
        "date",
        "decodeuricomponent",
        "encodeuricomponent",
        "error",
        "exports",
        "for",
        "if",
        "import",
        "isnan",
        "isfinite",
        "json",
        "map",
        "math",
        "number",
        "object",
        "parseint",
        "parsefloat",
        "promise",
        "rangeerror",
        "regexp",
        "require",
        "return",
        "string",
        "symbol",
        "switch",
        "typeerror",
        "weakmap",
        "while",
    }
)


@dataclass
class TaintSinkOccurrence:
    sink_type: str  # "sql_injection", "command_injection", "code_execution", "ssrf", "xss"
    rule_id: str  # "SP103", "SP102", "SP101", etc.
    line: int
    param_name: str
    call_snippet: str


@dataclass
class CalleeCallSite:
    callee_name: str
    param_name: str
    arg_index: int
    line: int


@dataclass
class FunctionSummary:
    name: str
    file: str
    params: list[str]
    is_entrypoint: bool
    entrypoint_taint_params: list[str]
    param_to_sinks: list[TaintSinkOccurrence]
    callee_calls: list[CalleeCallSite]
    sanitized_params: set[str]


@dataclass
class CrossFileTaintFlow:
    source_file: str
    source_entrypoint: str
    source_param: str
    sink_file: str
    sink_function: str
    sink_rule_id: str
    sink_type: str
    sink_line: int
    call_chain: list[str]
    is_sanitized: bool
    sanitizer: str | None = None


@dataclass
class SymbolDef:
    name: str
    kind: str
    file: str
    line_start: int
    line_end: int
    callers: list[str]
    calls: list[str]
    tables_touched: list[str]
    relevant_tests: list[str]
    is_entrypoint: bool = False
    is_reachable: bool = False


@dataclass
class ImpactReport:
    target_file: str
    target_line: int | None
    target_symbols: list[str]
    direct_callers: list[str]
    transitive_callers: list[str]
    tables_touched: list[str]
    relevant_tests: list[str]
    total_files_analyzed: int
    blast_radius_score: str
    reachability_status: str
    cross_file_taint_flows: list[CrossFileTaintFlow]


class PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, rel_path: str):
        self.rel_path = rel_path
        self.symbols: dict[str, SymbolDef] = {}
        self.summaries: dict[str, FunctionSummary] = {}
        self.current_class: str | None = None
        self.current_func: str | None = None
        self.calls_in_func: set[str] = set()
        self.tables_in_func: set[str] = set()
        self.func_params: list[str] = []
        self.func_sanitized: set[str] = set()
        self.func_aliases: dict[str, str] = {}
        self.func_sinks: list[TaintSinkOccurrence] = []
        self.func_callee_calls: list[CalleeCallSite] = []
        self.is_entrypoint_func: bool = False
        self.entrypoint_taint_params: list[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        prev_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = prev_class

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._handle_func(node, is_async=False)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._handle_func(node, is_async=True)

    def _handle_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef, is_async: bool) -> None:
        full_name = f"{self.current_class}.{node.name}" if self.current_class else node.name
        prev_func = self.current_func
        prev_calls = self.calls_in_func
        prev_tables = self.tables_in_func
        prev_params = self.func_params
        prev_sanitized = self.func_sanitized
        prev_aliases = self.func_aliases
        prev_sinks = self.func_sinks
        prev_callee_calls = self.func_callee_calls
        prev_is_entry = self.is_entrypoint_func
        prev_taint_params = self.entrypoint_taint_params

        self.current_func = full_name
        self.calls_in_func = set()
        self.tables_in_func = set()
        self.func_params = [a.arg for a in node.args.args if a.arg not in ("self", "cls")]
        self.func_sanitized = set()
        self.func_aliases = {}
        self.func_sinks = []
        self.func_callee_calls = []

        is_route = any(
            isinstance(d, ast.Call)
            and isinstance(d.func, ast.Attribute)
            and d.func.attr in {"get", "post", "put", "delete", "patch", "route"}
            for d in node.decorator_list
        )
        self.is_entrypoint_func = is_route or node.name in {"main", "handler", "lambda_handler"}
        if self.is_entrypoint_func:
            self.entrypoint_taint_params = list(self.func_params)
        else:
            self.entrypoint_taint_params = []

        self.generic_visit(node)

        end_line = getattr(node, "end_lineno", node.lineno)
        self.symbols[full_name] = SymbolDef(
            name=full_name,
            kind="route" if is_route else ("async_function" if is_async else "function"),
            file=self.rel_path,
            line_start=node.lineno,
            line_end=end_line,
            callers=[],
            calls=sorted(self.calls_in_func),
            tables_touched=sorted(self.tables_in_func),
            relevant_tests=[],
            is_entrypoint=self.is_entrypoint_func,
        )

        self.summaries[full_name] = FunctionSummary(
            name=full_name,
            file=self.rel_path,
            params=self.func_params,
            is_entrypoint=self.is_entrypoint_func,
            entrypoint_taint_params=self.entrypoint_taint_params,
            param_to_sinks=self.func_sinks,
            callee_calls=self.func_callee_calls,
            sanitized_params=self.func_sanitized,
        )

        self.current_func = prev_func
        self.calls_in_func = prev_calls
        self.tables_in_func = prev_tables
        self.func_params = prev_params
        self.func_sanitized = prev_sanitized
        self.func_aliases = prev_aliases
        self.func_sinks = prev_sinks
        self.func_callee_calls = prev_callee_calls
        self.is_entrypoint_func = prev_is_entry
        self.entrypoint_taint_params = prev_taint_params

    def visit_Assign(self, node: ast.Assign) -> None:
        if self.current_func and isinstance(node.value, ast.Call):
            func_name = self._extract_call_name(node.value.func)
            if func_name and any(san in func_name.lower() for san in KNOWN_SANITIZERS):
                for arg in node.value.args:
                    if isinstance(arg, ast.Name) and arg.id in self.func_params:
                        self.func_sanitized.add(arg.id)
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                self.func_sanitized.add(target.id)
        # Alias tracking: a single target assigned from exactly one live
        # parameter (possibly through other aliases) carries that parameter's
        # taint into later statements (q = "SELECT" + uid; execute(q)).
        if self.current_func and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            names = {c.id for c in ast.walk(node.value) if isinstance(c, ast.Name)}
            roots = {self._resolve_alias(name) for name in names}
            roots = {
                root
                for root in roots
                if root in self.func_params and root not in self.func_sanitized
            }
            target_name = node.targets[0].id
            if len(roots) == 1 and target_name not in self.func_sanitized:
                root = next(iter(roots))
                if target_name != root:
                    self.func_aliases[target_name] = root
        self.generic_visit(node)

    def _resolve_alias(self, name: str) -> str:
        current = name
        seen: set[str] = set()
        while current in self.func_aliases and current not in seen and len(seen) < 6:
            seen.add(current)
            current = self.func_aliases[current]
        return current

    def _resolve_carrier(self, name: str) -> str | None:
        """Map a local name to the live parameter whose taint it carries, or
        None when the name is not a parameter, not an alias, or sanitized."""
        if name in self.func_params:
            return None if name in self.func_sanitized else name
        root = self._resolve_alias(name)
        if root in self.func_params and root not in self.func_sanitized:
            return root
        return None

    def visit_Call(self, node: ast.Call) -> None:
        if self.current_func:
            call_name = self._extract_call_name(node.func)
            if call_name:
                self.calls_in_func.add(call_name)
                simple_call = call_name.split(".")[-1].lower()

                # 1. Track Callee Call Sites for inter-procedural propagation
                for idx, arg in enumerate(node.args):
                    param_name = self._extract_var_name(arg)
                    if param_name:
                        resolved = self._resolve_carrier(param_name)
                        if resolved is None:
                            continue
                        # Check if arg is wrapped in a sanitizer at call site
                        if self._is_node_sanitized(arg):
                            self.func_sanitized.add(param_name)
                            if param_name in self.func_aliases:
                                del self.func_aliases[param_name]
                        else:
                            self.func_callee_calls.append(
                                CalleeCallSite(
                                    callee_name=call_name,
                                    param_name=resolved,
                                    arg_index=idx,
                                    line=node.lineno,
                                )
                            )

                # 2. Track Dangerous Sinks
                if simple_call in {"execute", "executemany", "raw"}:
                    # Only the first argument carries the SQL statement; the
                    # remaining arguments are bound parameters (cursor.execute
                    # (sql, (a, b))) and are safe by construction.
                    for arg in node.args[:1]:
                        p_name = self._extract_tainted_param_in_expr(arg)
                        if p_name is None and isinstance(arg, ast.Name):
                            p_name = self._resolve_carrier(arg.id)
                            if p_name is not None:
                                self.func_aliases.pop(arg.id, None)
                        if p_name and p_name not in self.func_sanitized:
                            self.func_sinks.append(
                                TaintSinkOccurrence(
                                    sink_type="sql_injection",
                                    rule_id="SP103",
                                    line=node.lineno,
                                    param_name=p_name,
                                    call_snippet=ast.unparse(node)
                                    if hasattr(ast, "unparse")
                                    else call_name,
                                )
                            )
                elif simple_call in {"system", "popen", "check_output", "check_call"}:
                    for arg in node.args:
                        p_name = self._extract_tainted_param_in_expr(arg)
                        if p_name is None and isinstance(arg, ast.Name):
                            p_name = self._resolve_carrier(arg.id)
                            if p_name is not None:
                                self.func_aliases.pop(arg.id, None)
                        if p_name and p_name not in self.func_sanitized:
                            self.func_sinks.append(
                                TaintSinkOccurrence(
                                    sink_type="command_injection",
                                    rule_id="SP102",
                                    line=node.lineno,
                                    param_name=p_name,
                                    call_snippet=ast.unparse(node)
                                    if hasattr(ast, "unparse")
                                    else call_name,
                                )
                            )
                elif simple_call in {"eval", "exec", "compile"}:
                    for arg in node.args:
                        p_name = self._extract_tainted_param_in_expr(arg)
                        if p_name is None and isinstance(arg, ast.Name):
                            p_name = self._resolve_carrier(arg.id)
                            if p_name is not None:
                                self.func_aliases.pop(arg.id, None)
                        if p_name and p_name not in self.func_sanitized:
                            self.func_sinks.append(
                                TaintSinkOccurrence(
                                    sink_type="code_execution",
                                    rule_id="SP101",
                                    line=node.lineno,
                                    param_name=p_name,
                                    call_snippet=ast.unparse(node)
                                    if hasattr(ast, "unparse")
                                    else call_name,
                                )
                            )

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if self.current_func and isinstance(node.value, str):
            self._extract_tables_from_str(node.value)
        self.generic_visit(node)

    def _extract_var_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        return None

    def _is_node_sanitized(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Call):
            func_name = self._extract_call_name(node.func)
            if func_name and any(san in func_name.lower() for san in KNOWN_SANITIZERS):
                return True
        return False

    def _extract_tainted_param_in_expr(self, node: ast.AST) -> str | None:
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Name)
                and child.id in self.func_params
                and child.id not in self.func_sanitized
            ):
                return child.id
        return None

    def _extract_call_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            val = self._extract_call_name(node.value)
            return f"{val}.{node.attr}" if val else node.attr
        return None

    def _extract_tables_from_str(self, text: str) -> None:
        match = re.search(
            r"\b(?:FROM|INTO|UPDATE|JOIN|TABLE)\s+([a-zA-Z0-9_]+)", text, re.IGNORECASE
        )
        if match:
            table = match.group(1).lower()
            if table not in {"select", "where", "set", "values", "dual"}:
                self.tables_in_func.add(table)


def extract_js_ts_symbols(rel_path: str, content: str) -> dict[str, SymbolDef]:
    symbols: dict[str, SymbolDef] = {}
    lines = content.splitlines()

    func_pattern = re.compile(r"^(?:export\s+)?(?:async\s+)?function\s+([a-zA-Z0-9_$]+)\s*\(")
    arrow_pattern = re.compile(
        r"^(?:export\s+)?(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>"
    )
    method_pattern = re.compile(r"^\s*(?:async\s+)?([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*\{")

    for i, line in enumerate(lines, 1):
        name = None
        kind = "function"
        m = func_pattern.search(line.strip()) or arrow_pattern.search(line.strip())
        if m:
            name = m.group(1)
        elif "class " not in line and "if (" not in line and "for (" not in line:
            m_meth = method_pattern.search(line)
            if m_meth and m_meth.group(1) not in {
                "constructor",
                "if",
                "for",
                "while",
                "switch",
                "catch",
            }:
                name = m_meth.group(1)

        if name:
            sample_chunk = "\n".join(lines[i - 1 : min(len(lines), i + 35)])
            calls = set(re.findall(r"\b([a-zA-Z0-9_$]+)\s*\(", sample_chunk))
            calls.discard(name)
            calls.discard("if")
            calls.discard("for")
            calls.discard("catch")
            calls.discard("require")

            tables = set()
            for t_match in re.finditer(
                r"\b(?:FROM|INTO|UPDATE|JOIN|TABLE)\s+([a-zA-Z0-9_]+)",
                sample_chunk,
                re.IGNORECASE,
            ):
                tbl = t_match.group(1).lower()
                if tbl not in {"select", "where", "set", "values"}:
                    tables.add(tbl)

            symbols[name] = SymbolDef(
                name=name,
                kind=kind,
                file=rel_path,
                line_start=i,
                line_end=min(len(lines), i + 35),
                callers=[],
                calls=sorted(calls),
                tables_touched=sorted(tables),
                relevant_tests=[],
            )

    return symbols


JS_EXCLUDED_CALLEES = frozenset(
    name.lower()
    for name in JS_BUILTIN_CALLEE_NAMES | set(JS_SINK_CALLS) | set(JS_CODE_EXEC_SINK_CALLS)
)


@dataclass
class _JsFunctionSpan:
    name: str
    params_text: str
    decl_start: int  # char offset where the function header match starts
    body_start: int  # char offset just after the opening '{'
    body_end: int  # char offset of the matching '}'
    line_start: int


class JsTsAnalyzer:
    """Bounded lexical taint analysis for JavaScript and TypeScript files.

    Produces the same FunctionSummary contract as the Python AST visitor so
    interprocedural taint propagation covers Node.js routes without adding a
    parser dependency. Extraction is deliberately conservative: dynamic
    dispatch, cross-scope reassignment, and unusual syntax may be missed, and
    every emitted flow stays review-first evidence rather than proof.
    """

    MAX_FILE_CHARS = 400_000
    MAX_FUNCTIONS_PER_FILE = 400
    MAX_BODY_CHARS = 60_000
    MAX_ARG_CHARS = 2_000
    MAX_PARAMS = 12
    MAX_SINKS_PER_FUNCTION = 32
    MAX_CALLEES_PER_FUNCTION = 64

    FUNC_DECL = re.compile(
        r"(?:^|\n)[ \t]*(?:export\s+)?(?:default\s+)?(?:async\s+)?function[ \t]+"
        r"(?P<name>[A-Za-z_$][\w$]*)[ \t]*\((?P<params>[^)]*)\)[ \t]*\{"
    )
    ARROW_DECL = re.compile(
        r"(?:^|\n)[ \t]*(?:export\s+)?(?:const|let|var)[ \t]+(?P<name>[A-Za-z_$][\w$]*)"
        r"[ \t]*(?::[^=\n]+)?=[ \t]*(?:async[ \t]+)?\((?P<params>[^)]*)\)[ \t]*"
        r"(?::[^=\n]+)?=>[ \t]*\{"
    )
    ARROW_SINGLE_PARAM = re.compile(
        r"(?:^|\n)[ \t]*(?:export\s+)?(?:const|let|var)[ \t]+(?P<name>[A-Za-z_$][\w$]*)"
        r"[ \t]*(?::[^=\n]+)?=[ \t]*(?:async[ \t]+)?(?P<param>[A-Za-z_$][\w$]*)[ \t]*=>[ \t]*\{"
    )
    ROUTE_REGISTRATION = re.compile(
        r"\.\s*(?P<method>get|post|put|patch|delete|all|head|options)[ \t]*\("
    )
    REQUEST_SOURCE_ACCESS = re.compile(
        r"\breq(?:uest)?\s*\.\s*(?:params|query|body|headers|cookies|files|session)\b"
        r"|\blocation\s*\.\s*(?:search|hash|href)\b"
        r"|\bdocument\s*\.\s*cookie\b"
        r"|\bwindow\s*\.\s*name\b"
    )
    DECLARATION_LINE = re.compile(
        r"(?:const|let|var)\s+(?P<target>[^=\n]{1,120}?)\s*(?::[^=\n]+)?=(?!=)(?P<rhs>.*)"
    )
    PLAIN_ASSIGNMENT = re.compile(
        r"(?:this\.)?(?P<name>[A-Za-z_$][\w$]*)\s*(?::[^=\n]+)?=(?!=)(?P<rhs>.*)"
    )
    SINK_CALL = re.compile(
        r"\.\s*(?P<method>execute|executemany|query|raw|execSync|exec"
        r"|readFile|readFileSync|writeFile|writeFileSync|appendFile"
        r"|createReadStream|createWriteStream)\s*\("
        r"|(?<![\w$.])(?P<bare>eval|fetch)\s*\("
        r"|axios\s*\.\s*(?P<http_method>get|post|put|delete|patch|request)\s*\("
        r"|res(?:ponse)?\s*\.\s*(?P<res_sink>send|write)\s*\(",
        re.IGNORECASE,
    )
    CALLEE_CALL = re.compile(r"(?<![\w$.])(?P<callee>[A-Za-z_$][\w$]{0,63})\s*\(")
    DOM_SINK_ASSIGNMENT = re.compile(
        r"\.\s*(?:innerHTML|outerHTML)\s*=(?!=)|insertAdjacentHTML\s*\("
    )
    DOCUMENT_WRITE_CALL = re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\(")
    SANITIZER_WRAP = re.compile(
        r"(?:\bnumber\b|\bparseint\b|\bparsefloat\b|\bpath\s*\.\s*basename\b"
        r"|[A-Za-z_$][\w$]*sanitiz[\w$]*|[A-Za-z_$][\w$]*escape[\w$]*"
        r"|\bdompurify\b[\w$]*)\s*\([^()]*\)",
        re.IGNORECASE,
    )
    IDENTIFIER_TOKEN = re.compile(r"[A-Za-z_$][\w$]*")
    CONTAINMENT_GUARD = re.compile(r"\b(?P<name>[A-Za-z_$][\w$]*)\s*\.\s*startsWith\s*\(")
    ENTRYPOINT_FALLBACK_NAMES = frozenset({"main", "handler"})
    RESPONSE_SIDE_NAMES = frozenset({"res", "response", "next"})
    RESERVED_WORDS = frozenset(
        {"true", "false", "null", "undefined", "this", "new", "typeof", "await"}
    )

    def analyze(self, rel_path: str, content: str) -> list[FunctionSummary]:
        """Return function summaries with entrypoint/taint evidence for one file."""
        if len(content) > self.MAX_FILE_CHARS:
            content = content[: self.MAX_FILE_CHARS]
        spans = self._collect_named_spans(content)
        route_handlers, inline_spans = self._collect_registrations(content)
        spans.extend(inline_spans)
        spans.sort(key=lambda item: (item.decl_start, item.name))
        if len(spans) > self.MAX_FUNCTIONS_PER_FILE:
            spans = spans[: self.MAX_FUNCTIONS_PER_FILE]

        summaries: list[FunctionSummary] = []
        for span in spans:
            is_entrypoint = (
                span.name in route_handlers
                or span.name.startswith("inline:")
                or span.name in self.ENTRYPOINT_FALLBACK_NAMES
            )
            summaries.append(self._summarize(rel_path, content, span, is_entrypoint, spans))
        return summaries

    # ------------------------------------------------------------------
    # Span extraction
    # ------------------------------------------------------------------

    def _collect_named_spans(self, content: str) -> list[_JsFunctionSpan]:
        found: dict[int, _JsFunctionSpan] = {}
        for pattern in (self.FUNC_DECL, self.ARROW_DECL, self.ARROW_SINGLE_PARAM):
            for match in pattern.finditer(content):
                if match.start() in found:
                    continue
                brace_index = match.end() - 1
                body_end = self._match_delim(content, brace_index, "{", "}")
                if body_end is None:
                    continue
                groups = match.groupdict()
                params_text = groups.get("params") or groups.get("param") or ""
                found[match.start()] = _JsFunctionSpan(
                    name=groups["name"],
                    params_text=params_text,
                    decl_start=match.start(),
                    body_start=brace_index + 1,
                    body_end=body_end,
                    line_start=content.count("\n", 0, match.start()) + 1,
                )
        return sorted(found.values(), key=lambda item: (item.decl_start, item.name))

    def _collect_registrations(self, content: str) -> tuple[set[str], list[_JsFunctionSpan]]:
        """Parse Express-style route registrations.

        Returns the names of declared handlers referenced by a registration
        plus anonymous handler spans declared inline inside the call.
        """
        route_handlers: set[str] = set()
        inline_spans: list[_JsFunctionSpan] = []
        limit = len(content)

        for match in self.ROUTE_REGISTRATION.finditer(content):
            open_paren = match.end() - 1
            close_paren = self._match_delim(
                content,
                open_paren,
                "(",
                ")",
                bound=min(limit, open_paren + self.MAX_ARG_CHARS * 8),
            )
            if close_paren is None:
                continue
            tokens = [
                (text, open_paren + 1 + offset)
                for text, offset in self._split_top_level(content[open_paren + 1 : close_paren])
            ]
            # A registration looks like <obj>.method("<path>", ..., <handler>);
            # require the quoted path and at least one further argument so HTTP
            # clients such as axios.get(url, config) are not mistaken for routes.
            if len(tokens) < 2 or tokens[0][0][:1] not in {"'", '"', "`"}:
                continue
            handler_text, handler_offset = tokens[-1]
            stripped = handler_text.strip().rstrip(";").strip()
            while stripped.startswith("[") and stripped.endswith("]"):
                inner_tokens = self._split_top_level(stripped[1:-1])
                if not inner_tokens:
                    break
                last_text, last_offset = inner_tokens[-1]
                handler_offset = handler_offset + 1 + last_offset
                stripped = last_text.strip().rstrip(";").strip()
            if not stripped:
                continue
            inline_marker = "=>" in stripped
            keyword_marker = re.match(r"(?:async\s+)?function\b", stripped) is not None
            if inline_marker or keyword_marker:
                span = self._inline_span(content, handler_offset, stripped)
                if span is not None:
                    inline_spans.append(span)
                continue
            if self.IDENTIFIER_TOKEN.fullmatch(stripped):
                route_handlers.add(stripped.rsplit(".", 1)[-1])
        return route_handlers, inline_spans

    def _inline_span(
        self, content: str, token_offset: int, token_text: str
    ) -> _JsFunctionSpan | None:
        header = token_text.split("=>", 1)[0]
        paren_match = re.search(r"\(([^)]*)\)", header)
        if paren_match:
            params_text = paren_match.group(1)
        else:
            bare = re.match(r"(?:async\s+)?([A-Za-z_$][\w$]*)", header.strip())
            params_text = bare.group(1) if bare else ""
        brace_relative = token_text.find("{")
        if brace_relative < 0:
            return None
        brace_absolute = token_offset + brace_relative
        body_end = self._match_delim(content, brace_absolute, "{", "}")
        if body_end is None:
            return None
        return _JsFunctionSpan(
            name=f"inline:{content.count(chr(10), 0, token_offset) + 1}",
            params_text=params_text,
            decl_start=token_offset,
            body_start=brace_absolute + 1,
            body_end=body_end,
            line_start=content.count("\n", 0, token_offset) + 1,
        )

    # ------------------------------------------------------------------
    # Per-function analysis
    # ------------------------------------------------------------------

    def _summarize(
        self,
        rel_path: str,
        content: str,
        span: _JsFunctionSpan,
        is_entrypoint: bool,
        all_spans: Sequence[_JsFunctionSpan],
    ) -> FunctionSummary:
        raw_body = content[
            span.body_start : min(span.body_end, span.body_start + self.MAX_BODY_CHARS)
        ]
        body = self._blank_nested_bodies(raw_body, span, all_spans)
        params = self._parse_params(span.params_text)

        # Comments may quote request sources in examples; only executable
        # lines count as evidence.
        code_lines = [line for line in body.splitlines() if not line.lstrip().startswith("//")]
        code_only_body = "\n".join(code_lines)

        tainted: set[str] = set(params)
        sanitized: set[str] = set()
        has_source_access = self.REQUEST_SOURCE_ACCESS.search(code_only_body) is not None
        if is_entrypoint and has_source_access:
            tainted.update({"req", "request"})
        elif not is_entrypoint and has_source_access:
            # Global request-derived reads (location.hash, document.cookie,
            # req.headers inside middleware) make this function a taint root
            # even without a route registration.
            is_entrypoint = True
            tainted.update({"req", "request"})
        aliases = self._track_assignments(body, tainted, sanitized)

        # Carriers exclude response-side objects (never attacker-controlled).
        # Sanitizer-cleared locals drop out through _track_assignments, so a
        # fully sanitized chain produces no flow instead of a safe-marked one.
        carriers = sorted(tainted - sanitized - self.RESPONSE_SIDE_NAMES)
        sinks = self._collect_sinks(content, span.body_start, body, carriers, aliases)
        if has_source_access:
            # DOM sinks are assignments rather than calls; scan them on the
            # same carrier set so client-side XSS chains reach the engine.
            sinks.extend(self._collect_dom_sinks(content, span.body_start, body, carriers, aliases))
        callees = self._collect_callees(content, span.body_start, body, carriers, aliases)

        entrypoint_taint_params: list[str] = []
        if is_entrypoint:
            candidates = set(carriers)
            if not candidates:
                candidates = {name for name in params if name not in self.RESPONSE_SIDE_NAMES}
            entrypoint_taint_params = sorted(candidates)[: self.MAX_PARAMS]

        return FunctionSummary(
            name=span.name,
            file=rel_path,
            params=params,
            is_entrypoint=is_entrypoint,
            entrypoint_taint_params=entrypoint_taint_params,
            param_to_sinks=sinks,
            callee_calls=callees,
            sanitized_params=sanitized,
        )

    def _blank_nested_bodies(
        self,
        raw_body: str,
        span: _JsFunctionSpan,
        all_spans: Sequence[_JsFunctionSpan],
    ) -> str:
        """Replace nested function declarations with blanks so their statements
        are attributed to the innermost function only (mirrors the Python AST
        visitor's current-function attribution)."""
        chars = list(raw_body)
        for other in all_spans:
            if other is span:
                continue
            if other.decl_start < span.body_start or other.body_end > span.body_end:
                continue
            start = max(other.decl_start - span.body_start, 0)
            end = min(other.body_end + 1 - span.body_start, len(chars))
            for index in range(start, end):
                if chars[index] != "\n":
                    chars[index] = " "
        return "".join(chars)

    def _track_assignments(
        self, body: str, tainted: set[str], sanitized: set[str]
    ) -> dict[str, str]:
        """Propagate request-derived taint through local aliases and record
        sanitizer-wrapped assignments (mirrors the Python visitor's behavior
        of clearing both source and target names).

        Returns a target->source alias map so a sink that consumes a derived
        variable can be attributed back to the parameter carrying the taint."""
        aliases: dict[str, str] = {}
        for line in body.splitlines():
            if "=>" in line:
                # Arrow expressions are function boundaries, not value aliases.
                continue
            if line.lstrip().startswith("//"):
                continue
            declaration = self.DECLARATION_LINE.search(line)
            plain = None if declaration else self.PLAIN_ASSIGNMENT.match(line.strip())
            if declaration is not None:
                targets = self._binding_names(declaration.group("target"))
                rhs = declaration.group("rhs")
            elif plain is not None:
                targets = [plain.group("name").rsplit(".", 1)[-1]]
                rhs = plain.group("rhs")
            else:
                continue
            targets = [name for name in targets if name.lower() not in self.RESERVED_WORDS][:8]
            if not targets:
                continue
            cleaned_rhs = self.SANITIZER_WRAP.sub(" ", rhs)
            had_wrap = bool(self.SANITIZER_WRAP.search(rhs))
            req_derived = bool(self.REQUEST_SOURCE_ACCESS.search(rhs))
            flowing = any(
                self._contains_word(cleaned_rhs, name) for name in sorted(tainted - sanitized)
            )
            if req_derived:
                if had_wrap and not flowing and not self.REQUEST_SOURCE_ACCESS.search(cleaned_rhs):
                    sanitized.update(targets)
                else:
                    tainted.update(targets)
            elif flowing:
                sources = [
                    name
                    for name in sorted(tainted - sanitized)
                    if self._contains_word(cleaned_rhs, name)
                ]
                tainted.update(targets)
                # Single-source aliasing lets sinks reached through the copy
                # report under the parameter that carries the taint.
                if len(sources) == 1 and len(targets) == 1:
                    aliases[targets[0]] = sources[0]
            elif had_wrap:
                wrapped_sources = [
                    name for name in sorted(tainted - sanitized) if self._contains_word(rhs, name)
                ]
                if wrapped_sources:
                    sanitized.update(wrapped_sources)
                    sanitized.update(targets)
        # Containment guards: a value explicitly checked against a prefix
        # (reportPath.startsWith(BASE_DIR)) was reviewed for traversal, so its
        # flow is treated as sanitized downstream.
        for guard_match in self.CONTAINMENT_GUARD.finditer(body):
            sanitized.add(guard_match.group("name"))
        return aliases

    def _collect_sinks(
        self,
        content: str,
        base_offset: int,
        body: str,
        carriers: Sequence[str],
        aliases: dict[str, str] | None = None,
    ) -> list[TaintSinkOccurrence]:
        occurrences: list[TaintSinkOccurrence] = []
        if not carriers:
            return occurrences
        limit = len(body)
        carrier_list = list(carriers)
        alias_map = aliases or {}
        for match in self.SINK_CALL.finditer(body):
            method = (match.group("method") or "").lower()
            bare = (match.group("bare") or "").lower()
            http_method = (match.group("http_method") or "").lower()
            res_sink = (match.group("res_sink") or "").lower()
            if http_method:
                sink_info: tuple[str, str] | None = ("ssrf", "SP124")
            elif res_sink:
                sink_info = ("xss", "SP080")
            elif method:
                sink_info = JS_SINK_CALLS.get(method) or JS_CODE_EXEC_SINK_CALLS.get(method)
            elif bare == "eval":
                sink_info = JS_CODE_EXEC_SINK_CALLS.get("eval")
            elif bare == "fetch":
                sink_info = ("ssrf", "SP124")
            else:
                sink_info = None
            if sink_info is None:
                continue
            open_paren = match.end() - 1
            close_paren = self._match_delim(
                body,
                open_paren,
                "(",
                ")",
                bound=min(limit, open_paren + 2 + self.MAX_ARG_CHARS),
            )
            if close_paren is None:
                continue
            cleaned_args = self.SANITIZER_WRAP.sub(" ", body[open_paren + 1 : close_paren])
            # Parameterized style passes values inside a placeholder array
            # (db.query(sql, [x])); the driver binds them safely, so drop
            # flat bracketed segments before searching for raw carriers.
            cleaned_args = re.sub(r"\[[^[\]]*\]", " ", cleaned_args)
            hit = next(
                (name for name in carrier_list if self._contains_word(cleaned_args, name)),
                None,
            )
            if hit is None:
                continue
            # A response sink is only an XSS sink when HTML markup is being
            # assembled; tainted JSON/plain payloads are safe by design.
            if (
                sink_info[0] == "xss"
                and sink_info[1] == "SP080"
                and not re.search(r"<[a-zA-Z]", cleaned_args)
            ):
                continue
            # Resolve the derived variable back to the carrier that entered the
            # function (const reportPath = path.join(dir, ".." + rawName) ->
            # rawName) so interprocedural propagation can match its parameter.
            root = hit
            for _ in range(6):
                if root in alias_map:
                    root = alias_map[root]
                else:
                    break
            occurrences.append(
                TaintSinkOccurrence(
                    sink_type=sink_info[0],
                    rule_id=sink_info[1],
                    line=content.count("\n", 0, base_offset + match.start()) + 1,
                    param_name=root,
                    call_snippet=body[match.start() : close_paren + 1][:160],
                )
            )
            if len(occurrences) >= self.MAX_SINKS_PER_FUNCTION:
                break
        occurrences.sort(key=lambda item: (item.line, item.param_name))
        return occurrences

    def _collect_dom_sinks(
        self,
        content: str,
        base_offset: int,
        body: str,
        carriers: Sequence[str],
        aliases: dict[str, str] | None = None,
    ) -> list[TaintSinkOccurrence]:
        """DOM XSS sinks expressed as assignments (innerHTML/outerHTML/
        insertAdjacentHTML) and document.write calls. These never appear as
        ordinary call expressions, so they need their own bounded scan."""
        occurrences: list[TaintSinkOccurrence] = []
        if not carriers:
            return occurrences
        carrier_list = list(carriers)
        alias_map = aliases or {}
        limit = len(body)

        def resolve_root(name: str) -> str:
            current = name
            for _ in range(6):
                if current in alias_map:
                    current = alias_map[current]
                else:
                    return current
            return current

        patterns = (
            (self.DOM_SINK_ASSIGNMENT, "xss", "SP147"),
            (self.DOCUMENT_WRITE_CALL, "xss", "SP146"),
        )
        for pattern, sink_type, rule_id in patterns:
            for match in pattern.finditer(body):
                line_end = body.find("\n", match.end())
                if line_end == -1:
                    line_end = min(limit, match.end() + self.MAX_ARG_CHARS)
                rhs_text = body[match.end() : min(limit, line_end)]
                cleaned_rhs = self.SANITIZER_WRAP.sub(" ", rhs_text)
                hit = next(
                    (name for name in carrier_list if self._contains_word(cleaned_rhs, name)),
                    None,
                )
                if hit is None:
                    continue
                occurrences.append(
                    TaintSinkOccurrence(
                        sink_type=sink_type,
                        rule_id=rule_id,
                        line=content.count("\n", 0, base_offset + match.start()) + 1,
                        param_name=resolve_root(hit),
                        call_snippet=body[match.start() : line_end][:160],
                    )
                )
                if len(occurrences) >= self.MAX_SINKS_PER_FUNCTION:
                    occurrences.sort(key=lambda item: (item.line, item.param_name))
                    return occurrences
        occurrences.sort(key=lambda item: (item.line, item.param_name))
        return occurrences

    def _collect_callees(
        self,
        content: str,
        base_offset: int,
        body: str,
        carriers: Sequence[str],
        aliases: dict[str, str] | None = None,
    ) -> list[CalleeCallSite]:
        call_sites: list[CalleeCallSite] = []
        if not carriers:
            return call_sites
        limit = len(body)
        carrier_list = list(carriers)
        alias_map = aliases or {}
        for match in self.CALLEE_CALL.finditer(body):
            callee = match.group("callee")
            if callee.lower() in JS_EXCLUDED_CALLEES:
                continue
            open_paren = match.end() - 1
            close_paren = self._match_delim(
                body,
                open_paren,
                "(",
                ")",
                bound=min(limit, open_paren + 2 + self.MAX_ARG_CHARS),
            )
            if close_paren is None:
                continue
            arguments = self._split_top_level(body[open_paren + 1 : close_paren])[:8]
            for position, (argument, _offset) in enumerate(arguments):
                cleaned_argument = self.SANITIZER_WRAP.sub(" ", argument)
                hit = next(
                    (name for name in carrier_list if self._contains_word(cleaned_argument, name)),
                    None,
                )
                if hit is None:
                    continue
                root = hit
                for _ in range(6):
                    if root in alias_map:
                        root = alias_map[root]
                    else:
                        break
                call_sites.append(
                    CalleeCallSite(
                        callee_name=callee,
                        param_name=root,
                        arg_index=position,
                        line=content.count("\n", 0, base_offset + match.start()) + 1,
                    )
                )
                break
            if len(call_sites) >= self.MAX_CALLEES_PER_FUNCTION:
                break
        call_sites.sort(key=lambda item: (item.line, item.callee_name, item.arg_index))
        return call_sites

    # ------------------------------------------------------------------
    # Lexical helpers (string/comment aware, bounded)
    # ------------------------------------------------------------------

    def _match_delim(
        self,
        text: str,
        open_index: int,
        open_char: str,
        close_char: str,
        bound: int | None = None,
    ) -> int | None:
        limit = min(len(text), bound) if bound is not None else len(text)
        depth = 0
        index = open_index
        while index < limit:
            char = text[index]
            if char == "/" and index + 1 < limit and text[index + 1] == "/":
                newline = text.find("\n", index, limit)
                index = newline if newline != -1 else limit
                continue
            if char == "/" and index + 1 < limit and text[index + 1] == "*":
                closing = text.find("*/", index + 2, limit)
                index = closing + 2 if closing != -1 else limit
                continue
            if char in {"'", '"', "`"}:
                index = self._scan_past_string(text, index, limit)
                continue
            if char == open_char:
                depth += 1
            elif char == close_char:
                depth -= 1
                if depth == 0:
                    return index
            index += 1
        return None

    def _scan_past_string(self, text: str, quote_index: int, limit: int) -> int:
        quote = text[quote_index]
        index = quote_index + 1
        while index < limit:
            char = text[index]
            if char == "\\":
                index += 2
                continue
            if quote == "`" and char == "$" and index + 1 < limit and text[index + 1] == "{":
                close_brace = self._match_delim(text, index + 1, "{", "}", bound=limit)
                if close_brace is None:
                    return limit
                index = close_brace + 1
                continue
            if char == quote:
                return index + 1
            index += 1
        return limit

    def _split_top_level(self, text: str) -> list[tuple[str, int]]:
        parts: list[tuple[str, int]] = []
        depth = 0
        segment_start = 0
        index = 0
        limit = len(text)
        while index < limit:
            char = text[index]
            if char in {"'", '"', "`"}:
                index = self._scan_past_string(text, index, limit)
                continue
            if char in "{([":
                depth += 1
            elif char in "})]":
                depth -= 1
            elif char == "," and depth <= 0:
                parts.append((text[segment_start:index], segment_start))
                segment_start = index + 1
            index += 1
        tail = text[segment_start:]
        if tail.strip():
            parts.append((tail, segment_start))
        cleaned: list[tuple[str, int]] = []
        for text_part, offset in parts:
            leading = len(text_part) - len(text_part.lstrip())
            stripped = text_part.strip()
            if stripped:
                cleaned.append((stripped, offset + leading))
        return cleaned

    def _parse_params(self, params_text: str) -> list[str]:
        if not params_text or not params_text.strip():
            return []
        names: list[str] = []
        for text_part, _offset in self._split_top_level(params_text[:400]):
            part = text_part.rstrip(",")
            if not part:
                continue
            if part[0] in "{[":
                for name in self.IDENTIFIER_TOKEN.findall(part):
                    if name.lower() not in self.RESERVED_WORDS and name not in names:
                        names.append(name)
            else:
                match = re.match(r"\.{0,3}([A-Za-z_$][\w$]*)", part.strip())
                if match:
                    name = match.group(1)
                    if name.lower() not in self.RESERVED_WORDS and name not in names:
                        names.append(name)
            if len(names) >= self.MAX_PARAMS:
                break
        return names[: self.MAX_PARAMS]

    def _binding_names(self, target_text: str) -> list[str]:
        names: list[str] = []
        for name in self.IDENTIFIER_TOKEN.findall(target_text[:200]):
            if name.lower() not in self.RESERVED_WORDS and name not in names:
                names.append(name)
        return names[:8]

    @staticmethod
    def _contains_word(text: str, word: str) -> bool:
        if not word:
            return False
        escaped = re.escape(word)
        return re.search(rf"(?<![\w$]){escaped}(?![\w$])", text) is not None


class ImpactGraph:
    def __init__(self, root: Path):
        self.root = root.resolve()
        if not self.root.exists():
            raise ValueError(f"path does not exist: {self.root}")
        if not self.root.is_dir():
            raise ValueError(f"not a directory: {self.root}")
        self.symbols: dict[str, list[SymbolDef]] = defaultdict(list)
        self.file_to_symbols: dict[str, list[SymbolDef]] = defaultdict(list)
        self.summaries: dict[str, list[FunctionSummary]] = defaultdict(list)
        self.file_to_summaries: dict[str, list[FunctionSummary]] = defaultdict(list)
        self.caller_graph: dict[str, set[str]] = defaultdict(set)
        self.test_files: list[tuple[str, str]] = []
        self.files_scanned_count = 0
        self.taint_flows: list[CrossFileTaintFlow] = []
        self.reachable_symbols: set[str] = set()

    def build(self) -> None:
        """Scan repository and build AST-based symbol, caller, and data-flow graphs."""
        for directory, subdirs, filenames in os.walk(
            self.root, topdown=True, onerror=lambda _: None
        ):
            subdirs[:] = [d for d in subdirs if d not in SKIP_DIRS]
            for filename in filenames:
                path = Path(directory, filename)
                if path.is_symlink():
                    continue

                suffix = path.suffix.lower()
                if suffix not in PYTHON_SUFFIXES and suffix not in JS_TS_SUFFIXES:
                    continue

                try:
                    rel_path = path.relative_to(self.root).as_posix()
                    content = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                self.files_scanned_count += 1
                is_test = (
                    "/test" in rel_path.lower()
                    or rel_path.lower().startswith("test")
                    or "_test." in rel_path.lower()
                    or ".test." in rel_path.lower()
                    or ".spec." in rel_path.lower()
                )

                if is_test:
                    self.test_files.append((rel_path, content))

                if suffix in PYTHON_SUFFIXES:
                    try:
                        tree = ast.parse(content, filename=rel_path)
                        visitor = PythonASTVisitor(rel_path)
                        visitor.visit(tree)
                        for sym in visitor.symbols.values():
                            self.symbols[sym.name].append(sym)
                            self.file_to_symbols[rel_path].append(sym)
                        for summary in visitor.summaries.values():
                            self.summaries[summary.name].append(summary)
                            self.file_to_summaries[rel_path].append(summary)
                    except SyntaxError:
                        pass
                elif suffix in JS_TS_SUFFIXES:
                    js_symbols = extract_js_ts_symbols(rel_path, content)
                    try:
                        js_summaries = JsTsAnalyzer().analyze(rel_path, content)
                    except (ValueError, IndexError, RecursionError):
                        # Lexical analysis must never break a scan; fall back to
                        # symbol extraction only for this file.
                        js_summaries = []
                    entrypoint_names = {
                        summary.name for summary in js_summaries if summary.is_entrypoint
                    }
                    for sym in js_symbols.values():
                        if sym.name in entrypoint_names:
                            sym.is_entrypoint = True
                        self.symbols[sym.name].append(sym)
                        self.file_to_symbols[rel_path].append(sym)
                    for summary in js_summaries:
                        self.summaries[summary.name].append(summary)
                        self.file_to_summaries[rel_path].append(summary)

        # Build caller graph
        for sym_list in self.symbols.values():
            for sym in sym_list:
                for callee in sym.calls:
                    callee_simple = callee.split(".")[-1]
                    caller_id = f"{sym.file}:{sym.name}"
                    self.caller_graph[callee].add(caller_id)
                    self.caller_graph[callee_simple].add(caller_id)

        # Compute reachability and propagate inter-procedural taint
        self.compute_reachability()
        self.taint_flows = self.propagate_interprocedural_taint()

    def compute_reachability(self) -> None:
        """Compute reachability from public route entrypoints."""
        entrypoints: set[str] = set()
        for sym_list in self.symbols.values():
            for sym in sym_list:
                if sym.is_entrypoint:
                    sym.is_reachable = True
                    entrypoints.add(f"{sym.file}:{sym.name}")

        self.reachable_symbols = set(entrypoints)
        queue = list(entrypoints)
        visited = set(entrypoints)

        while queue:
            curr_caller_id = queue.pop(0)
            curr_file, curr_name = curr_caller_id.split(":", 1)
            matching_syms = [
                s for s in self.file_to_symbols.get(curr_file, []) if s.name == curr_name
            ]
            for sym in matching_syms:
                for callee in sym.calls:
                    callee_simple = callee.split(".")[-1]
                    callee_syms = self.symbols.get(callee, []) or self.symbols.get(
                        callee_simple, []
                    )
                    for c_sym in callee_syms:
                        c_id = f"{c_sym.file}:{c_sym.name}"
                        c_sym.is_reachable = True
                        self.reachable_symbols.add(c_id)
                        if c_id not in visited:
                            visited.add(c_id)
                            queue.append(c_id)

    def propagate_interprocedural_taint(self) -> list[CrossFileTaintFlow]:
        """Trace data-flow taint from entrypoints across functions and files."""
        flows: list[CrossFileTaintFlow] = []
        all_summaries: list[FunctionSummary] = []
        for sum_list in self.summaries.values():
            all_summaries.extend(sum_list)

        entrypoints = [s for s in all_summaries if s.is_entrypoint and s.entrypoint_taint_params]

        for ep in entrypoints:
            for source_param in ep.entrypoint_taint_params:
                queue: list[tuple[FunctionSummary, str, list[str], bool]] = [
                    (
                        ep,
                        source_param,
                        [f"{ep.file}:{ep.name}"],
                        source_param in ep.sanitized_params,
                    )
                ]
                visited_states: set[tuple[str, str]] = set()

                while queue:
                    curr_sum, curr_param, path, is_sanitized = queue.pop(0)
                    state_key = (f"{curr_sum.file}:{curr_sum.name}", curr_param)
                    if state_key in visited_states:
                        continue
                    visited_states.add(state_key)

                    if curr_param in curr_sum.sanitized_params:
                        is_sanitized = True

                    # Check if curr_param reaches any dangerous sink in curr_sum
                    for sink in curr_sum.param_to_sinks:
                        if sink.param_name == curr_param:
                            flows.append(
                                CrossFileTaintFlow(
                                    source_file=ep.file,
                                    source_entrypoint=ep.name,
                                    source_param=source_param,
                                    sink_file=curr_sum.file,
                                    sink_function=curr_sum.name,
                                    sink_rule_id=sink.rule_id,
                                    sink_type=sink.sink_type,
                                    sink_line=sink.line,
                                    call_chain=path,
                                    is_sanitized=is_sanitized,
                                    sanitizer="cleared_by_sanitizer" if is_sanitized else None,
                                )
                            )

                    # Propagate to downstream callees
                    for call_site in curr_sum.callee_calls:
                        if call_site.param_name == curr_param:
                            callee_sums = self.summaries.get(
                                call_site.callee_name, []
                            ) or self.summaries.get(call_site.callee_name.split(".")[-1], [])
                            for c_sum in callee_sums:
                                if call_site.arg_index < len(c_sum.params):
                                    c_param = c_sum.params[call_site.arg_index]
                                    next_path = [*path, f"{c_sum.file}:{c_sum.name}"]
                                    if len(next_path) <= 6:
                                        queue.append((c_sum, c_param, next_path, is_sanitized))

        return flows

    def analyze_impact(self, target_file: str, target_line: int | None = None) -> ImpactReport:
        candidate = Path(target_file)
        candidate = (
            candidate.resolve() if candidate.is_absolute() else (self.root / candidate).resolve()
        )
        try:
            norm_file = candidate.relative_to(self.root).as_posix()
        except ValueError as exc:
            raise ValueError(f"target file escapes repository root: {target_file}") from exc
        if not candidate.is_file():
            raise ValueError(f"target file does not exist: {candidate}")
        if candidate.suffix.lower() not in PYTHON_SUFFIXES | JS_TS_SUFFIXES:
            raise ValueError(f"unsupported target file type: {candidate.suffix or '<none>'}")
        if target_line is not None and target_line < 1:
            raise ValueError("target line must be positive")
        target_symbols: list[SymbolDef] = []

        file_syms = self.file_to_symbols.get(norm_file, [])
        if target_line is not None:
            for sym in file_syms:
                if sym.line_start <= target_line <= sym.line_end:
                    target_symbols.append(sym)
        if not target_symbols and file_syms:
            target_symbols = file_syms

        target_names = [s.name for s in target_symbols]
        direct_callers: set[str] = set()
        tables_touched: set[str] = set()

        for sym in target_symbols:
            tables_touched.update(sym.tables_touched)
            simple_name = sym.name.split(".")[-1]
            for caller in self.caller_graph.get(sym.name, set()):
                if not caller.startswith(f"{norm_file}:"):
                    direct_callers.add(caller)
            for caller in self.caller_graph.get(simple_name, set()):
                if not caller.startswith(f"{norm_file}:"):
                    direct_callers.add(caller)

        transitive_callers: set[str] = set(direct_callers)
        for caller in list(direct_callers):
            caller_sym_name = caller.split(":")[-1]
            for grand_caller in self.caller_graph.get(caller_sym_name, set()):
                transitive_callers.add(grand_caller)

        relevant_tests: set[str] = set()
        search_terms = set(target_names)
        for name in target_names:
            search_terms.add(name.split(".")[-1])
        base_name = Path(norm_file).stem
        search_terms.add(base_name)

        for test_path, content in self.test_files:
            if test_path == norm_file:
                continue
            for term in search_terms:
                if term and len(term) > 2 and term in content:
                    relevant_tests.add(test_path)
                    break

        # Calculate Reachability
        is_any_reachable = any(
            sym.is_entrypoint or f"{norm_file}:{sym.name}" in self.reachable_symbols
            for sym in target_symbols
        )
        reachability_status = (
            "REACHABLE (Hot Path from API Entrypoint)"
            if is_any_reachable
            else "UNREACHABLE / STANDALONE (0 Inbound Entrypoints)"
        )

        # Match relevant Cross-file taint flows
        file_taint_flows = [
            f
            for f in self.taint_flows
            if f.source_file == norm_file
            or f.sink_file == norm_file
            or any(norm_file in step for step in f.call_chain)
        ]

        caller_count = len(transitive_callers)
        test_count = len(relevant_tests)
        table_count = len(tables_touched)

        if caller_count >= 8 or table_count >= 3:
            blast_score = "CRITICAL"
        elif caller_count >= 4 or table_count >= 1:
            blast_score = "HIGH"
        elif caller_count >= 1 or test_count >= 1:
            blast_score = "MEDIUM"
        else:
            blast_score = "LOW"

        return ImpactReport(
            target_file=norm_file,
            target_line=target_line,
            target_symbols=target_names,
            direct_callers=sorted(direct_callers),
            transitive_callers=sorted(transitive_callers),
            tables_touched=sorted(tables_touched),
            relevant_tests=sorted(relevant_tests),
            total_files_analyzed=self.files_scanned_count,
            blast_radius_score=blast_score,
            reachability_status=reachability_status,
            cross_file_taint_flows=file_taint_flows,
        )


def render_impact_markdown(report: ImpactReport) -> str:
    lines = [
        f"# ShipProof Change Impact Analysis: `{report.target_file}`",
        "",
        f"**Blast Radius Score:** `{report.blast_radius_score}` · **Reachability:** `{report.reachability_status}`",
        f"Analyzed `{report.total_files_analyzed}` repository files",
        "",
    ]

    if report.target_symbols:
        lines.append(f"### Target Symbols (`{len(report.target_symbols)}`)")
        for sym in report.target_symbols:
            lines.append(f"- `{sym}`")
        lines.append("")

    lines.append(f"### Callers & Inbound Dependencies (`{len(report.transitive_callers)}`)")
    if report.transitive_callers:
        for caller in report.transitive_callers:
            marker = " (Direct)" if caller in report.direct_callers else " (Transitive)"
            lines.append(f"- `{caller}`{marker}")
    else:
        lines.append("- _No external callers identified (isolated or root endpoint)._")
    lines.append("")

    if report.cross_file_taint_flows:
        lines.append(
            f"### Cross-File Data-Flow Taint Traces (`{len(report.cross_file_taint_flows)}`)"
        )
        for flow in report.cross_file_taint_flows:
            chain_str = " -> ".join(flow.call_chain)
            status = " [SANITIZED / SAFE]" if flow.is_sanitized else " [ACTIVE TAINT SINK]"
            lines.append(f"- `{flow.sink_rule_id}` ({flow.sink_type}){status}:")
            lines.append(
                f"  - Source: `{flow.source_file}:{flow.source_entrypoint}` (`{flow.source_param}`)"
            )
            lines.append(
                f"  - Sink: `{flow.sink_file}:{flow.sink_function}` (Line {flow.sink_line})"
            )
            lines.append(f"  - Call Path: `{chain_str}`")
        lines.append("")

    if report.tables_touched:
        lines.append(f"### State & Data Entities Touched (`{len(report.tables_touched)}`)")
        for tbl in report.tables_touched:
            lines.append(f"- Table / Entity: `{tbl}`")
        lines.append("")

    lines.append(f"### Impact-Selected Regression Tests (`{len(report.relevant_tests)}`)")
    if report.relevant_tests:
        for test_file in report.relevant_tests:
            lines.append(f"- [x] `{test_file}`")
        lines.append("")
    else:
        lines.append("- _No existing tests directly reference these symbols._")
        lines.append("")

    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="Target file (and optional :line) to analyze impact for")
    parser.add_argument("--root", default=".", type=Path, help="Repository root directory")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args(argv)

    target_str = args.target
    target_line = None
    if ":" in target_str and not Path(target_str).exists():
        parts = target_str.rsplit(":", 1)
        if parts[1].isdigit():
            target_str = parts[0]
            target_line = int(parts[1])

    try:
        graph = ImpactGraph(args.root)
        graph.build()
        report = graph.analyze_impact(target_str, target_line)
    except (OSError, ValueError) as exc:
        print(f"shipproof: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        payload = {
            "schema_version": "1.0",
            "tool": {"name": "ShipProof", "version": VERSION, "command": "impact"},
            "verdict": "CONDITIONAL",
            "root": str(args.root.resolve()),
            **asdict(report),
            "limitations": [
                "Impact is inferred from static symbols and references; dynamic dispatch may be absent.",
                "Selected tests are candidates, not proof that all affected behavior is covered.",
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(render_impact_markdown(report))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
