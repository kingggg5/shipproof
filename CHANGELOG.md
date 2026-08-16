# Changelog

## 0.5.0 - 2026-08-16

- Expand framework-aware detection across 30+ ecosystems spanning JS/TS, Python, Go, Rust, PHP, Ruby, JVM, and Containers.
- Add deep-dive production defense rules: `SP113` (PHP unserialize), `SP114` (ReDoS nested quantifiers), `SP314` (Committed SQLite file), `SP315` (Go HTTP request body close leak), `SP316` (Outbound HTTP inside database transaction), `SP317` (Blocking calls inside async def).
- Add full Detection Rules Reference table with zero emoji formatting.
- Add GitHub Packages registry publishing support for `@kingggg5/shipproof`.
- Update all GitHub Action workflows with verified immutable commit SHAs.

## 0.4.0 - 2026-08-14

- Prepare version 0.4.0 with versioned config/evidence schemas and aligned scan, budget, and capacity envelopes.
- Add a repository-safe composite GitHub Action and a fast pre-commit scanner hook.
- Add deterministic capacity-to-k6 generation with environment-only targets, weighted routes, thresholds, provenance, and overwrite protection.
- Add an optional official-SDK MCP stdio adapter with three read-only, bounded tools.
- Add allowlisted TypeScript, Go, and Rust evidence adapters with offline dependency policy and explicit Rust build-script consent.
- Add an owner-authored production engineering playbook that unifies eight control planes without unsafe universal thresholds.
- Convert research into a question-and-decision notebook and concentrate external source links outside the README and skill execution guides.
- Include repository documentation in the npm package so README links remain usable after installation.
- Add a bounded Engineering Loop prompt/reference and define AWE TraceGate as the orchestrator over ShipProof's reusable evidence contracts.
- Add a phased ecosystem roadmap for pre-commit, GitHub Actions, generated k6 tests, MCP, and polyglot evidence adapters.
- Add a five-finding before/after API demo, contract fixtures, and CLI workflow E2E coverage.
- Add `.shipproof.yml` plus `shipproof check` for one bounded repository policy across scan, performance, and capacity gates.
- Add Python and Node coverage gates, a scanner self-benchmark, a terminal visual, and a tag-validated GitHub Release workflow.

## 0.3.1 - 2026-08-14

- Replace ambiguous internal identifiers with domain-specific function and variable names.
- Prune ignored directory trees during scanning to reduce traversal time and peak memory on large repositories.
- Scan `bin` sources and documentation/configuration files for credential patterns without applying code-only rules to prose.
- Enforce Python 3.10+ detection and reject extra prompt arguments in the npm CLI.
- Add ecosystem-specific EditorConfig rules, pinned Ruff development checks, and a dedicated CI quality job.
- Remove the duplicate Python installer, misleading npm-ready badge, and repository-specific vulnerability-claim discussion from the public README.

## 0.3.0 - 2026-08-14

- Add a zero-dependency npm front door with `doctor`, project/user skill installation, prompt catalog, scanner, resource-budget, and capacity commands.
- Add progressive guidance for architecture, databases, AI/RAG/MCP, software supply chains, operations, and authorized defensive reverse engineering.
- Align Codex installation with current `.agents/skills` discovery while retaining Claude Code compatibility.
- Add Node 20/24 CI, npm package-content verification, expanded CodeQL coverage, and dependency update configuration.
- Refresh research against 2025–2026 OWASP, NIST, CISA, MCP, SLSA, npm, OpenTelemetry, PostgreSQL, and Codex security guidance.
- Remove prior third-party product positioning and keep ShipProof's design and implementation independent.

## 0.2.0 - 2026-08-14

- Add `engineer-production-systems` for proactive secure, efficient implementation.
- Add kernel, browser-engine, parser, IPC, and network-protocol guidance.
- Add deterministic CPU/RAM/latency/throughput regression budgets.
- Add Claude Code plugin metadata and dual-host installation.
- Expand capacity estimates with explicit CPU and memory assumptions.

## 0.1.0 - 2026-08-13

- Initial Codex plugin with production-readiness audit, scanner, SARIF, baselines, and capacity model.
