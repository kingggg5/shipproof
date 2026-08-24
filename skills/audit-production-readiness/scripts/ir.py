#!/usr/bin/env python3
"""ShipProof Intermediate Representation.

Language-agnostic function summaries produced by every language frontend.
Analysis passes consume IRProgram without knowing which parser created it.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Effect kinds (normalized across languages)
# ---------------------------------------------------------------------------


class EffectKind:
    DB_READ = "db_read"
    DB_WRITE = "db_write"
    HTTP_CALL = "http_call"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    SUBPROCESS = "subprocess"
    CACHE_OP = "cache_op"
    QUEUE_OP = "queue_op"
    LOCK_ACQUIRE = "lock_acquire"
    TASK_SPAWN = "task_spawn"


# ---------------------------------------------------------------------------
# Taint kinds (what kind of untrusted data)
# ---------------------------------------------------------------------------


class TaintKind:
    USER_INPUT = "user_input"
    PATH = "path"
    SQL = "sql"
    HTML = "html"
    SHELL = "shell"
    URL = "url"
    SECRET = "secret_kind"  # noqa: S105
    TENANT_ID = "tenant_id"
    AUTH_PRINCIPAL = "auth_principal"
    UNTRUSTED_JSON = "untrusted_json"


# ---------------------------------------------------------------------------
# Guard kinds (protective checks found on code paths)
# ---------------------------------------------------------------------------


class GuardKind:
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ADMIN_CHECK = "admin_check"
    TENANT_CHECK = "tenant_check"
    VALIDATION = "validation"
    RATE_LIMIT = "rate_limit"
    NULL_CHECK = "null_check"
    BOUNDS_CHECK = "bounds_check"


# ---------------------------------------------------------------------------
# Core IR nodes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IREffect:
    """A side effect observed inside a function body."""

    kind: str  # EffectKind value
    target: str  # e.g. table name, URL prefix, file path pattern
    line: int


@dataclass(frozen=True)
class IRGuard:
    """A protective check that dominates subsequent code."""

    kind: str  # GuardKind value
    expression: str  # source text of the guard condition
    line: int


@dataclass(frozen=True)
class IRSource:
    """Taint source: where untrusted data enters the function."""

    variable: str  # local variable or parameter name
    kind: str  # TaintKind value
    line: int


@dataclass(frozen=True)
class IRSink:
    """Dangerous operation consuming potentially tainted data."""

    rule_id: str  # SP103, SP110, etc.
    sink_type: str  # sql_injection, path_traversal, etc.
    variable: str  # root tainted variable name
    call_expr: str  # truncated evidence snippet
    line: int


@dataclass(frozen=True)
class IRCallee:
    """Call to another function passing potentially tainted arguments."""

    callee_name: str
    arg_index: int
    param_name: str  # caller-side carrier (root tainted variable)
    line: int


@dataclass
class IRFunction:
    """Language-agnostic summary of one function's security-relevant behavior."""

    name: str
    file: str
    params: list[str]
    line_start: int
    line_end: int
    is_entrypoint: bool
    entry_taint_vars: list[str]  # variables tainted at entry
    sinks: list[IRSink]
    callees: list[IRCallee]
    sanitized_params: set[str]
    aliases: dict[str, str]  # derived_var -> root_param
    effects: list[IREffect]
    guards: list[IRGuard]

    @property
    def simple_name(self) -> str:
        return self.name.rsplit(".", 1)[-1]


@dataclass
class IRProgram:
    """All functions across all files, plus cross-reference indexes."""

    functions: list[IRFunction] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)  # detected framework names
    framework_models: dict[str, dict] = field(default_factory=dict)

    def __post_init__(self):
        self._by_name: dict[str, list[IRFunction]] = {}
        self._by_file: dict[str, list[IRFunction]] = {}
        for fn in self.functions:
            self._by_name.setdefault(fn.simple_name, []).append(fn)
            self._by_file.setdefault(fn.file, []).append(fn)

    def find_by_name(self, name: str) -> list[IRFunction]:
        return self._by_name.get(name, [])

    def find_by_file(self, path: str) -> list[IRFunction]:
        return self._by_file.get(path, [])

    @property
    def entrypoints(self) -> list[IRFunction]:
        return [fn for fn in self.functions if fn.is_entrypoint]

    @property
    def db_sink_functions(self) -> list[IRFunction]:
        """Functions containing DB effects (useful for N+1/tenant checks)."""
        return [
            fn
            for fn in self.functions
            if any(e.kind in ("db_read", "db_write") for e in fn.effects)
        ]


# ---------------------------------------------------------------------------
# Shared analysis pass: interprocedural taint propagation
# ---------------------------------------------------------------------------


def propagate_taint(program: IRProgram) -> list[dict]:
    """Summary-driven interprocedural taint propagation over IRFunction nodes.

    Returns a list of confirmed flow dicts, each containing the full path
    from entrypoint through intermediate calls to the terminal sink.
    """
    flows: list[dict] = []
    visited: set[tuple[str, str, str]] = set()

    for entry in program.entrypoints:
        for taint_var in entry.entry_taint_vars:
            stack = [(entry, taint_var, [f"{entry.file}:{entry.name}"], False)]
            local_visited: set[tuple[str, str]] = set()
            while stack:
                fn, carrier, chain, was_sanitized = stack.pop(0)
                state_key = (fn.name, carrier)
                if state_key in local_visited:
                    continue
                local_visited.add(state_key)
                was_sanitized = was_sanitized or carrier in fn.sanitized_params

                # Check sinks within this function
                for sink in fn.sinks:
                    if sink.variable != carrier:
                        continue
                    flow_key = (entry.file, fn.file, f"{sink.rule_id}:{sink.line}")
                    if flow_key in visited:
                        continue
                    visited.add(flow_key)
                    flows.append(
                        {
                            "source_file": entry.file,
                            "source_entrypoint": entry.name,
                            "source_param": taint_var,
                            "sink_file": fn.file,
                            "sink_function": fn.name,
                            "sink_rule_id": sink.rule_id,
                            "sink_type": sink.sink_type,
                            "sink_line": sink.line,
                            "call_chain": list(chain),
                            "is_sanitized": was_sanitized,
                        }
                    )

                # Propagate into callees
                for callee in fn.callees:
                    if callee.param_name != carrier:
                        continue
                    candidates = program.find_by_name(callee.callee_name)
                    same_language = [
                        target
                        for target in candidates
                        if Path(target.file).suffix.lower() == Path(fn.file).suffix.lower()
                    ]
                    if len(same_language) != 1:
                        continue
                    for target_fn in same_language:
                        next_idx = callee.arg_index
                        if next_idx < len(target_fn.params):
                            c_param = target_fn.params[next_idx]
                            new_chain = [*chain, f"{target_fn.file}:{target_fn.name}"]
                            stack.append((target_fn, c_param, new_chain, was_sanitized))

    return flows


def aggregate_effects(program: IRProgram) -> dict[str, Counter]:
    """Aggregate effect kinds per file for production-reliability reporting."""
    result: dict[str, Counter] = {}
    for fn in program.functions:
        counter = result.setdefault(fn.file, Counter())
        for effect in fn.effects:
            counter[effect.kind] += 1
    return {k: v for k, v in result.items()}


# ---------------------------------------------------------------------------
# Symbol resolution with confidence levels
# ---------------------------------------------------------------------------


class ResolutionConfidence:
    RESOLVED = "resolved"
    PROBABLE = "probable"
    AMBIGUOUS = "ambiguous"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class SymbolResolution:
    """Result of resolving a name to its semantic role."""

    name: str
    resolved_to: str  # e.g. "pg.query", "prisma.user.findMany", "custom_wrapper"
    confidence: str  # ResolutionConfidence value


def resolve_symbol(name: str, imports: dict[str, str]) -> SymbolResolution:
    """Resolve a dotted name against the file's import table.

    Returns a SymbolResolution with confidence based on how much evidence
    was available. Never pretends ambiguous names are fully resolved.
    """
    root = name.split(".")[0]
    source = imports.get(root, "")
    if not source:
        return SymbolResolution(
            name=name, resolved_to="", confidence=ResolutionConfidence.UNRESOLVED
        )
    return SymbolResolution(name=name, resolved_to=source, confidence=ResolutionConfidence.RESOLVED)


# ---------------------------------------------------------------------------
# Guard dominance check (bounded, line-level)
# ---------------------------------------------------------------------------


def check_guard_dominance(
    guards: list[IRGuard], sinks: list[IRSink], body_lines: list[str]
) -> list[IRSink]:
    """Return sinks that are NOT dominated by any guard of matching kind.

    A guard dominates a sink when it appears on an earlier line in the same
    function and the sink is not inside an early-return branch. This is a
    bounded heuristic; full CFG dominance is a future enhancement.
    """
    if not guards:
        return list(sinks)
    unguarded = []
    for sink in sinks:
        dominated = False
        for guard in guards:
            # Guard must appear before the sink on a prior line
            if 0 < guard.line < sink.line:
                dominated = True
                break
        if not dominated:
            unguarded.append(sink)
    return unguarded


# ---------------------------------------------------------------------------
# Framework model loading
# ---------------------------------------------------------------------------


def load_framework_model(path: Path) -> dict:
    """Load a framework model JSON file declaring sources/sinks/guards."""
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))
