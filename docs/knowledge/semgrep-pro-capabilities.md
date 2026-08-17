# What paid scanners actually do: Semgrep Pro capability analysis

> Research note (2026-08) informing ShipProof's build-vs-route decisions.
> Sources are linked inline; claims are Semgrep's own unless marked otherwise.

## What the paid tiers buy

Semgrep's free Community Edition (CE) ships the OSS engine plus community rules:
single-file, intraprocedural matching. Everything that separates the paid
product is listed below ([pricing](https://semgrep.dev/pricing/),
[Pro Engine](https://semgrep.dev/products/pro-engine/),
[CE comparison](https://semgrep.dev/products/semgrep-vs-ce/)).

| Capability | Method used | Tier |
| --- | --- | --- |
| Interfile / cross-function taint analysis | Dataflow: sources→sanitizers→sinks tracked across files and functions | Pro Engine (paid) |
| Proprietary rules (20,000+) | Vendor-maintained, license-restricted (`--config pro`) | Paid |
| Precision claim (5x more precise, 2x coverage) | Cross-file analysis eliminates single-file false assumptions | Paid (marketing benchmark) |
| WebGoat benchmark 72% vs 48% detection | Pro taint rules vs CE rules on the same suite | [Semgrep's own 2025 study](https://semgrep.dev/blog/2025/security-research-comparing-semgrep-community-edition-and-semgrep-code-for-static-analysis/) |
| Secrets detection with validation | Semantic parsing + entropy + live credential verification | Paid |
| Supply chain (SCA) with reachability | Dependency resolution + call-graph reachability to the vulnerable symbol; malicious-package detection; MCP server exposing signals to AI tools | Paid |
| AI triage / remediation | LLM-assisted finding explanation and autofix suggestions in platform | Paid |
| Dashboard, policy, SSO, managed CI | Platform services | Team (~$30/contributor/mo) / Enterprise (quote; reported $25k–$135k/yr) |

Community-reported caveat: even Pro struggles through heavy abstraction layers
(Reddit r/devsecops threads), and cross-file coverage is deep for ~8–9
languages, cross-function for ~8 more, experimental beyond that (Konvu
comparison).

## How this maps to ShipProof's build-vs-route line

ShipProof's contract is offline, dependency-free, deterministic evidence at
L0 (pattern) and L1 (structural/AST). Each paid capability falls into one of
three buckets:

1. **Route, don't rebuild.** Reachability-based SCA, live secret validation,
   and dashboards are already served by OSV-Scanner, Trivy, Gitleaks, and the
   user's platform. ShipProof's `evidence` adapters and README routing already
   point there; adding them as core features would add dependencies and break
   the offline contract.
2. **Build gradually as engines mature.** Cross-file taint is the single
   biggest detection-quality lever paid tools have (the 72%-vs-48% gap is
   mostly this). ShipProof's roadmap already stages this: Python AST today
   (L1), data-flow (L2) and cross-file (L3) later — the failure catalog marks
   every item with the engine class that would catch it, so L2+ items are the
   backlog for that work.
3. **Differentiate where they don't go.** Semgrep sells findings; ShipProof's
   identity is production evidence they do not ship: measured CPU/RAM/latency
   budgets, capacity models with k6 generation, AI-cost rules (SP501), and
   honest proof levels that never claim data-flow evidence an engine did not
   perform.

## Tactical takeaways for the rule factory

- The paid gap is concentrated in **interfile taint**, not rule count. Our
  adversarial fixtures already record exactly which evasions need data-flow
  (indirect URL assignment, IV moved to constants, aliased imports); each is
  a named L2 work item with a test waiting.
- Semgrep's precision pitch validates our decision to ship few, high-precision
  rules with negative fixtures instead of volume.
- Their MCP server for supply-chain signals confirms the direction of our MCP
  adapter; a future `shipproof_scan --with-evidence` could fan out to local
  analyzers the same way, keeping everything read-only and local.
