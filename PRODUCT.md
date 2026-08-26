# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Primary users are engineers and technical leads shipping AI-assisted changes. They need a fast, reviewable answer to “is this change safe to merge?” across local development, pull requests, and release preparation.

## Product Purpose

ShipProof is a local-first production evidence gate for AI-assisted software. It scans a repository for security, correctness, scale, performance, and release risks, then emits deterministic findings and machine-readable evidence. Success means a team can inspect, reproduce, and automate the gate without uploading source code or adding a runtime dependency.

## Positioning

ShipProof combines a dependency-free static scanner, resource-budget checks, capacity modelling, and distribution adapters behind one explicit exit-code contract. It is an evidence-producing gate, not an AI code generator and not a claim of formal verification.

## Operating Context

The product is used from a terminal, a GitHub Action, a pre-commit hook, or an MCP client. Teams compare findings in pull requests and retain JSON/SARIF output as release evidence. The default path is offline, read-only, and dependency-free.

## Capabilities and Constraints

- The CLI scans repository scope and supports terminal, JSON, and SARIF output.
- The GitHub Action and pre-commit adapters reuse the same scanner contract.
- The MCP server is an optional integration surface; it is not required for local scanning.
- Exit codes are contractual: `0` pass, `1` gate failure, `2` invalid or unavailable evidence.
- The default workflow must not add telemetry, network calls, install scripts, or dependency downloads.
- The product must not be described as a certification, penetration test, or formal proof of absence.

## Brand Commitments

The name is ShipProof. Existing assets live under `docs/assets/`, including the logo, workflow diagram, and terminal demo. The public voice is direct, technical, calm, and evidence-led. The website should look credible to open-source and platform-engineering teams without inventing customers, benchmarks, or compliance claims.

## Evidence on Hand

- Product contract and current capabilities: `README.md` and `CONTRIBUTING.md`.
- Workflow illustration: `docs/assets/shipproof-workflow.png`.
- Terminal illustration: `docs/assets/terminal-demo.svg`.
- Brand mark: `docs/assets/shipproof-logo.svg`.
- Public source and release history: `https://github.com/kingggg5/shipproof`.

No customer testimonials, independently measured benchmarks, or external certification evidence are currently recorded. The website must label illustrative output as sample data.

## Product Principles

1. Evidence beats confidence: every gate result should be inspectable and reproducible.
2. Local-first is a product promise, not a deployment option.
3. One scanner contract should work across human and automation workflows.
4. Helpful findings include remediation context and false-positive boundaries.
5. Claims stay inside the evidence the product can actually produce.

## Accessibility & Inclusion

The public website must remain keyboard usable, provide visible focus states, preserve semantic heading order, respect reduced-motion preferences, and maintain readable contrast on small screens.

## Open Decisions

The bilingual public site is hosted at `https://shipproof-site.sjet2744.chatgpt.site/shipproof/` and mirrors the dependency-free source under `website/`. Analytics, a custom domain, and any future GPT companion remain undecided; no tracking or OpenAI API integration is included in this surface.
