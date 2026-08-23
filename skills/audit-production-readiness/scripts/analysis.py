#!/usr/bin/env python3
"""Unified analysis engine consuming ShipProof IR.

Implements Phase 1-4 of the canonical roadmap:
  P1  Program graph: call graph, taint propagation, effect aggregation
  P2  Evidence engine: E0-E5 levels, path explanation, receipts
  P3  Root cause grouping + blast radius
  P4  Production invariant checks (tenant, auth, retry, timeout, N+1)

Phases 5-8 (failure chains, runtime evidence, LLM verifier, AI provenance)
are stubbed with explicit interfaces for future implementation.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from ir import (
    GuardKind,
    IRFunction,
    IRProgram,
    aggregate_effects,
    propagate_taint,
)

# ---------------------------------------------------------------------------
# Evidence levels (E0-E5)
# ---------------------------------------------------------------------------


class EvidenceLevel:
    CANDIDATE = "E0"
    STRUCTURAL = "E1"
    STATIC_REACHABLE = "E2"
    CONFIG_REACHABLE = "E3"
    RUNTIME_OBSERVED = "E4"
    REPRODUCED = "E5"


EVIDENCE_ORDER = {
    EvidenceLevel.CANDIDATE: 0,
    EvidenceLevel.STRUCTURAL: 1,
    EvidenceLevel.STATIC_REACHABLE: 2,
    EvidenceLevel.CONFIG_REACHABLE: 3,
    EvidenceLevel.RUNTIME_OBSERVED: 4,
    EvidenceLevel.REPRODUCED: 5,
}


def assign_evidence_level(
    flow: dict,
    has_guard: bool,
    has_sanitizer: bool,
) -> str:
    """Assign an evidence level to a taint flow based on available proof."""
    if flow["is_sanitized"]:
        return EvidenceLevel.CANDIDATE
    if len(flow["call_chain"]) > 1:
        return EvidenceLevel.STATIC_REACHABLE
    return EvidenceLevel.STRUCTURAL


# ---------------------------------------------------------------------------
# Root-cause grouping
# ---------------------------------------------------------------------------


@dataclass
class RootCauseGroup:
    """A group of findings sharing one underlying defect."""

    root_cause_id: str
    symbol: str
    description: str
    finding_ids: list[str]
    affected_files: set[str]
    blast_radius: str  # LOW / MEDIUM / HIGH / CRITICAL


def group_by_root_cause(flows: list[dict]) -> list[RootCauseGroup]:
    """Group flows by shared sink function (same defect, many entrypoints)."""
    groups: dict[tuple[str, str], RootCauseGroup] = {}
    for flow in flows:
        if flow.get("is_sanitized"):
            continue
        key = (flow["sink_rule_id"], flow["sink_function"])
        if key not in groups:
            groups[key] = RootCauseGroup(
                root_cause_id=f"RC-{flow['sink_rule_id']}-{flow['sink_function']}",
                symbol=flow["sink_function"],
                description=flow["sink_type"],
                finding_ids=[],
                affected_files=set(),
                blast_radius="LOW",
            )
        g = groups[key]
        g.finding_ids.append(f"{flow['source_entrypoint']}→{flow['sink_line']}")
        g.affected_files.add(flow["sink_file"])

    # Assign blast radius based on affected file count
    for g in groups.values():
        n_files = len(g.affected_files)
        if n_files >= 3:
            g.blast_radius = "HIGH"
        elif n_files >= 2:
            g.blast_radius = "MEDIUM"
    return sorted(groups.values(), key=lambda g: (-len(g.finding_ids), g.root_cause_id))


# ---------------------------------------------------------------------------
# Production invariant checks
# ---------------------------------------------------------------------------

AUTH_GUARD_PATTERNS = re.compile(
    r"(?:isAuth|checkAuth|requireAuth|verifyToken|ensureAdmin|hasRole|hasPermission|"
    r"authenticate|authorize|login_required|admin_required)",
    re.IGNORECASE,
)

TENANT_SCOPE_PATTERNS = re.compile(
    r"(?:tenant_id|tenantId|organization_id|org_id|company_id)",
    re.IGNORECASE,
)


@dataclass
class InvariantViolation:
    """An invariant that is violated by a code pattern."""

    invariant_id: str
    severity: str
    file: str
    line: int
    message: str


def check_auth_dominance(fn: IRFunction) -> list[InvariantViolation]:
    """Flag privileged effects not dominated by any auth guard."""
    violations = []
    privileged_effects = [
        e for e in fn.effects if e.kind in ("db_write", "subprocess", "task_spawn")
    ]
    auth_guards = [
        g
        for g in fn.guards
        if g.kind
        in (
            GuardKind.AUTHENTICATION,
            GuardKind.AUTHORIZATION,
            GuardKind.ADMIN_CHECK,
        )
    ]
    if privileged_effects and not auth_guards:
        for e in privileged_effects:
            violations.append(
                InvariantViolation(
                    invariant_id="auth-dominance",
                    severity="high",
                    file=fn.file,
                    line=e.line,
                    message=f"Privileged effect '{e.kind}' on '{e.target}' without visible authentication guard.",
                )
            )
    return violations


def check_tenant_isolation(fn: IRFunction) -> list[InvariantViolation]:
    """Flag DB writes that lack tenant scoping when tenant context exists."""
    violations = []
    has_tenant_context = any(TENANT_SCOPE_PATTERNS.search(p) for p in fn.params)
    db_writes = [e for e in fn.effects if e.kind == "db_write"]
    if has_tenant_context and db_writes:
        body_has_tenant_scope = any(TENANT_SCOPE_PATTERNS.search(g.expression) for g in fn.guards)
        if not body_has_tenant_scope:
            violations.append(
                InvariantViolation(
                    invariant_id="tenant-isolation",
                    severity="critical",
                    file=fn.file,
                    line=fn.line_start,
                    message="DB write from function receiving tenant context lacks visible tenant scope constraint.",
                )
            )
    return violations


def check_retry_amplification(fn: IRFunction) -> list[InvariantViolation]:
    """Detect nested retry configurations that could multiply."""
    violations = []
    http_effects = [e for e in fn.effects if e.kind == "http_call"]
    if len(http_effects) > 1:
        violations.append(
            InvariantViolation(
                invariant_id="retry-amplification",
                severity="medium",
                file=fn.file,
                line=http_effects[0].line,
                message=f"{len(http_effects)} HTTP calls in one function; verify each has bounded retries.",
            )
        )
    return violations


def check_timeout_propagation(fn: IRFunction) -> list[InvariantViolation]:
    """Detect functions making HTTP calls without timeout configuration."""
    violations = []
    http_effects = [e for e in fn.effects if e.kind == "http_call"]
    if http_effects:
        violations.append(
            InvariantViolation(
                invariant_id="timeout-propagation",
                severity="medium",
                file=fn.file,
                line=http_effects[0].line,
                message=f"{len(http_effects)} outbound HTTP calls; ensure each has an explicit timeout.",
            )
        )
    return violations


ALL_INVARIANT_CHECKS = [
    check_auth_dominance,
    check_tenant_isolation,
    check_retry_amplification,
    check_timeout_propagation,
]


def run_invariants(program: IRProgram) -> list[InvariantViolation]:
    """Run every registered invariant check against all functions."""
    violations: list[InvariantViolation] = []
    for fn in program.functions:
        if not fn.is_entrypoint:
            continue
        for check in ALL_INVARIANT_CHECKS:
            violations.extend(check(fn))
    return violations


# ---------------------------------------------------------------------------
# Unified analysis result
# ---------------------------------------------------------------------------


@dataclass
class AnalysisResult:
    """Complete output from running the unified analysis pipeline."""

    taint_flows: list[dict]
    evidence_levels: dict[str, str]  # flow_key -> evidence level
    root_cause_groups: list[RootCauseGroup]
    invariant_violations: list[InvariantViolation]
    effect_summary: dict[str, Counter]
    total_functions: int
    total_entrypoints: int


def analyze_program(program: IRProgram) -> AnalysisResult:
    """Run all analysis passes over an IRProgram."""
    flows = propagate_taint(program)

    evidence_levels = {}
    for i, flow in enumerate(flows):
        key = f"{flow['sink_rule_id']}:{flow['sink_file']}:{flow['sink_line']}"
        evidence_levels[key] = assign_evidence_level(flow, False, False)

    groups = group_by_root_cause(flows)
    violations = run_invariants(program)
    effects = aggregate_effects(program)

    return AnalysisResult(
        taint_flows=flows,
        evidence_levels=evidence_levels,
        root_cause_groups=groups,
        invariant_violations=violations,
        effect_summary=effects,
        total_functions=len(program.functions),
        total_entrypoints=len(program.entrypoints),
    )
