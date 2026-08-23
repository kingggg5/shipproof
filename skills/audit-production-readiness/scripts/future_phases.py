#!/usr/bin/env python3
"""Phase 5-8 skeleton modules for ShipProof roadmap.

These modules define clear interfaces for future implementation.
Each phase has explicit inputs, outputs, and dependencies so future
contributors can implement them without redesigning the architecture.

Status markers:
  STUB     — interface defined, implementation not started
  PARTIAL  — some functionality exists, needs completion
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Phase 5 — Failure Graph
# ---------------------------------------------------------------------------


@dataclass
class FailureChain:
    """A connected chain of failure modes across system boundaries."""

    chain_id: str
    trigger: str  # e.g. "dependency latency"
    propagation: list[str]  # e.g. ["timeout", "retry", "pool exhaustion"]
    amplification: int | None  # worst-case multiplier if computable
    affected_effects: list[str]


class FailureGraphAnalyzer(ABC):
    """STUB — Connect individually valid patterns into failure chains.

    Requires: IRProgram with effects populated per function.
    Consumes effect graph to detect:
      latency → timeout → retry → pool exhaustion → retry storm
    """

    @abstractmethod
    def build_failure_chains(self, program) -> list[FailureChain]:
        """Identify chains where one failure mode triggers downstream failures."""
        raise NotImplementedError("Phase 5: Failure graph analysis not yet implemented")


# ---------------------------------------------------------------------------
# Phase 6 — LLM Adversarial Verifier
# ---------------------------------------------------------------------------


@dataclass
class VerifierResult:
    """Result of an adversarial falsification attempt."""

    verdict: str  # LIKELY_TRUE / LIKELY_FALSE / NEEDS_EVIDENCE
    counterexamples: list[str]  # evidence that disproves or weakens the finding
    confidence_note: str


class LLMVerifier(ABC):
    """STUB — LLM adversarial falsifier for taint flow candidates.

    Actively searches for sanitizer, guard, framework guarantee,
    unreachable branch, database constraint that would disprove the finding.
    Never produces BLOCK alone; only annotates with LIKELY_TRUE/FALSE/NEEDS_EVIDENCE.
    """

    @abstractmethod
    def verify(self, finding_context: dict) -> VerifierResult:
        """Send focused evidence context pack to LLM; return adversarial verdict."""
        raise NotImplementedError("Phase 6: LLM verifier not yet implemented")

    @abstractmethod
    def build_evidence_context_pack(self, finding: dict, program) -> dict:
        """Build a curated context slice (never whole repo)."""
        raise NotImplementedError("Phase 6: Evidence context pack not yet implemented")


# ---------------------------------------------------------------------------
# Phase 7 — Runtime Evidence Correlation
# ---------------------------------------------------------------------------


@dataclass
class RuntimeSpan:
    """A single runtime observation correlated with a static construct."""

    span_name: str  # e.g. "POST /checkout", "db.query"
    p50_ms: float | None
    p99_ms: float | None
    call_count: int | None
    error_count: int | None


class RuntimeEvidenceCorrelator(ABC):
    """STUB — Correlate static findings with OpenTelemetry spans.

    Maps static constructs to runtime observations to upgrade
    E2 (static reachable) → E4 (runtime observed).

    Important: lack of runtime observation does NOT mean safe.
    """

    @abstractmethod
    def correlate(self, static_finding: dict, telemetry_spans: list[RuntimeSpan]) -> str:
        """Return upgraded evidence level if runtime confirms the path."""
        raise NotImplementedError("Phase 7: Runtime correlation not yet implemented")


# ---------------------------------------------------------------------------
# Phase 8 — AI Change Provenance
# ---------------------------------------------------------------------------


@dataclass
class ChangeProvenance:
    """Metadata about how a change was authored."""

    author_type: str  # human / ai_assisted / ai_generated
    tools_used: list[str]
    files_changed: list[str]
    trust_boundaries_touched: list[str]  # auth, tenant, payments, CI/CD
    tests_added: bool
    human_approved: bool


class ChangeProvenanceAnalyzer(ABC):
    """STUB — Assess risk of AI-authored changes based on trust boundaries touched.

    AI-authored changes are not automatically unsafe, but changes touching
    auth, payments, tenant isolation, or CI/CD require elevated verification
    regardless of authorship.
    """

    @abstractmethod
    def assess_change_risk(self, provenance: ChangeProvenance) -> str:
        """Return elevated / normal / low verification requirement."""
        raise NotImplementedError("Phase 8: AI change provenance not yet implemented")


__all__ = [
    "ChangeProvenance",
    "ChangeProvenanceAnalyzer",
    "FailureChain",
    "FailureGraphAnalyzer",
    "LLMVerifier",
    "RuntimeEvidenceCorrelator",
    "RuntimeSpan",
    "VerifierResult",
]
