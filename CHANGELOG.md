# Changelog

## 0.6.0 - 2026-08-19

- Expand rule catalog to **150+ rules** across Multi-Language ecosystems with detectors `SP591` – `SP650`.
- Add AI Agent Token & Financial Cost Budget Engine (`shipproof cost`): computes context footprint, prompt caching discount calculations across frontier AI models (Claude 3.7/3.5, GPT-4o, Gemini 2.0/1.5, DeepSeek-V3/R1), and multi-iteration financial budget gates (`--budget-usd`).
- Add Git Worktree Isolation Sandbox (`shipproof worktree`): enables AI coding agents to create, test, and merge isolated workspace sandboxes safely without touching working branches.
- Add Production Readiness Status Badge (`shipproof badge`): outputs shields.io Markdown or JSON status badges for `README.md`.
- Add Next.js 15 App Router & TypeScript Enterprise Gate (`SP591` – `SP600`): Server-only ORM leakage in `"use client"` bundles, unawaited route segment params, mutating actions missing revalidation, and IDOR protection.
- Add Multi-Language Enterprise Production Gate (`SP601` – `SP625`): OWASP Top 10 for LLMs, Kubernetes container hardening, GraphQL/gRPC resilience, OAuth2/PKCE security, PostgreSQL table lock protection, and language failure modes in Rust, Go, Java, Python, C#.
- Add Cloud & Infrastructure-as-Code detectors (`SP626` – `SP630`): AWS S3 public access, unencrypted EBS/RDS storage, open security group SSH/RDP ports, IAM wildcard policies, CloudFront HTTPS enforcement.
- Add Edge Runtimes & Serverless Isolation rules (`SP631` – `SP634`): Cloudflare Workers / Deno / Vercel Edge Node.js module check, unbounded KV loops, unbuffered response accumulation, authenticated CDN cache leaks.
- Add Real-Time & Streaming Concurrency rules (`SP635` – `SP638`): WebSocket missing heartbeat keepalive, Server-Sent Events missing disconnect listeners, WebSocket unauthenticated handshake, BroadcastChannel unmount leaks.
- Add Cryptographic Primitives & Key Management rules (`SP639` – `SP643`): Insecure symmetric ciphers, weak RSA key length, static/hardcoded IV reuse, legacy MD5/SHA1 hashing, timing-unsafe HMAC comparisons.
- Add Modern Framework & Multitenancy Security rules (`SP644` – `SP650`): Svelte unescaped `{@html}`, Android WebView file access, iOS URLSession SSL trust bypass, Frontend API proxy SSRF, React useEffect WebSocket teardown, multitenant query tenant scoping, recursive JSON stack overflow bounds.
- Expand full test suite to 284 unit tests passing 100% with 0 scanner findings.

## Unreleased

- Publish the failure catalog (`docs/knowledge/failure-catalog.md`): 463 researched failure modes across 21 sections (web security, auth, crypto, SQL, APIs, performance, frontend, Python, concurrency, reliability, infrastructure, CI/CD, data integrity, AI/LLM), each with impact, fix direction, detection feasibility, and references. The catalog feeds detector selection for future rules.
- Speed up the regex engine 3.3x (1,000-file benchmark: 7.16s → 2.19s, 139.7 → 456.5 files/s) by precomputing per-line comment/ignore flags once per file instead of per rule, and caching the applicable rule set per file class; findings and fingerprints are unchanged, enforced by the golden contract.
- Add eleven CWE-driven detectors with positive, negative, and adversarial tests each: `SP115` (XXE via unhardened lxml), `SP116` (`dangerouslySetInnerHTML` XSS), `SP117` (`new Function` eval), `SP118` (timer-string eval), `SP119` (path traversal via `path.join`), `SP120` (`node-serialize` RCE), `SP121` (open redirect), `SP122` (insecure randomness for security values), `SP123` (hardcoded cipher IV), `SP124` (JS SSRF), and `SP318` (retry policies without a stop condition). Adversarial cases document the evasions the current engine cannot see, seeding the Red Team corpus.
- Add evidence proof levels: every finding now reports `detection` (`pattern`, `ast`, `structural`, `artifact`) and `proof_level` (`L0`/`L1`) in JSON and SARIF, with documentation that higher levels requiring data-flow or runtime evidence are deliberately not claimed.
- Add the launch article draft (`docs/launch/ai-code-failure-modes.md`) mapping the shipped rule catalog to the failure modes of AI-written code.
- Add diff-aware scanning: `shipproof scan . --changed-since <git-ref>` limits the scan to files changed relative to a git ref (added, copied, modified, renamed, plus untracked files), fails closed outside a git repository or on unsafe/unresolvable refs, and records the ref under `changed_since` in JSON output. The GitHub Action exposes it as a `changed-since` input for pull-request runs.
- Make the bare `shipproof` invocation equivalent to `shipproof scan` so the core workflow is a single word.
- Add `AGENTS.md` and `llms.txt` so coding agents and LLM clients can discover and use ShipProof correctly.
- Fix `shipproof hook install` crashing on a missing `writeFileSync` import; the command now writes a marked, idempotent pre-commit hook, refuses to overwrite foreign hooks, and `hook remove` deletes only shipproof-managed hooks.
- Implement detector rules `SP402` (authentication-sensitive Express route without rate limiting), `SP407` (cookie-session routes without CSRF protection), and `SP408` (Next.js/Nuxt config without a `Content-Security-Policy` header), each with positive and negative tests; `shipproof explain` now resolves all three.
- Add the golden compatibility contract: `fixtures/golden-contract` must produce identical findings and fingerprints through direct Python, the Node CLI, and the SARIF builder, with SARIF result content (level, location, fingerprint) now asserted.
- Add a k6 generation determinism gate: identical inputs must produce byte-identical scripts that pass a syntax check and contain no embedded host or credential.
- Add a packed-artifact smoke test (`npm run test:package`) that installs the real npm tarball into a clean consumer project and runs version, scan, explain, and skill checks from the installed tree; CI runs it on Node 24 and the release workflow runs it before publishing.
- Maintain a moving major tag (`v0`) on every release with an annotation that it is an alias, not a stability contract, and document the tag discipline.
- Expand the Node coverage gate to `lib/cli.mjs` (85%) and `lib/evidence.mjs` (71%), with new MCP bridge tests covering evidence envelopes and cancelled tool calls.
- Sync the README rule tables with scanner severities (including `SP302` and seven Thai-table drifts) and add a structure test that fails when either README drifts from the code rules again.
- Fix the zero-config quickstart: `npx @kingggg5/shipproof` cannot run anonymously because GitHub Packages requires authentication for public packages; the documented one-liner is now `npx github:kingggg5/shipproof check`.
- Document reserved rule IDs (`SP111`, `SP308`–`SP312`) in both READMEs and correct the roadmap MCP tool count from three to five.

## 0.5.1 - 2026-08-16

- Release `kingggg5/shipproof@v0.5.1` GitHub Action with immutable runner references.
- Configure official `@kingggg5/shipproof` npm package distribution on GitHub Packages.

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
