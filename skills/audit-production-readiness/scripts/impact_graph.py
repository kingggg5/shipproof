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
        prev_sinks = self.func_sinks
        prev_callee_calls = self.func_callee_calls
        prev_is_entry = self.is_entrypoint_func
        prev_taint_params = self.entrypoint_taint_params

        self.current_func = full_name
        self.calls_in_func = set()
        self.tables_in_func = set()
        self.func_params = [a.arg for a in node.args.args if a.arg not in ("self", "cls")]
        self.func_sanitized = set()
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
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self.current_func:
            call_name = self._extract_call_name(node.func)
            if call_name:
                self.calls_in_func.add(call_name)
                simple_call = call_name.split(".")[-1].lower()

                # 1. Track Callee Call Sites for inter-procedural propagation
                for idx, arg in enumerate(node.args):
                    param_name = self._extract_var_name(arg)
                    if param_name and param_name in self.func_params:
                        # Check if arg is wrapped in a sanitizer at call site
                        if self._is_node_sanitized(arg):
                            self.func_sanitized.add(param_name)
                        else:
                            self.func_callee_calls.append(
                                CalleeCallSite(
                                    callee_name=call_name,
                                    param_name=param_name,
                                    arg_index=idx,
                                    line=node.lineno,
                                )
                            )

                # 2. Track Dangerous Sinks
                if simple_call in {"execute", "executemany", "raw"}:
                    for arg in node.args:
                        p_name = self._extract_tainted_param_in_expr(arg)
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
                    for sym in js_symbols.values():
                        self.symbols[sym.name].append(sym)
                        self.file_to_symbols[rel_path].append(sym)

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
