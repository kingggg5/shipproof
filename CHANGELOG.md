# Changelog

## Unreleased

## 0.10.0 - 2026-08-24

- Complete machine-readable assurance contracts for all 620 executable rules: positive, negative, adversarial, CWE/control, remediation, and false-positive boundaries now fail closed through a derived inventory.
- Triage the first 25-candidate polyglot promotion batch without inflating the executable catalog: three research-only prototypes reached `fixture_ready`, 22 were rejected as duplicates or unsupported semantic claims, and none were promoted without shadow evidence.
- Harden optional TypeScript, Go, and Rust evidence adapters with repository-contained executable resolution, tool-specific version probes, explicit project-code consent, bounded/redacted diagnostics, and distinct unavailable, timeout, output-limit, crash, and finding states.
- Make performance evidence reproducible with multi-sample median/p95 reports, deterministic workload digests, clean/adversarial/large-file profiles, explicit memory and time budgets, and weekly CI coverage.
- Correct controlled-corpus labels to distinguish reportable sinks from context-only source/helper files; head-to-head reports now include TP, FP, FN, TN, digests, environment identity, and repeat timings.
- Add an opt-in, fail-closed real-world evaluator backed by a license-reviewed manifest of six public repositories pinned to full commit revisions. Findings remain explicitly unreviewed until maintainers label them.
- Add a tested 1.0 migration gate that removes every hidden legacy alias when the package major reaches 1 while retaining warning-only compatibility in 0.x.
- Close evaluator empty-selection and cross-repository license-permalink gaps, refresh every versioned command contract, and publish the 0.10.0 release boundary.

## 0.9.0 - 2026-08-24

- Prepare the evidence-contract and analyzer-correctness fixes for the `0.9.0` release; see [docs/releases/v0.9.0.md](docs/releases/v0.9.0.md).

- Add `scan --history`: scan git history for secrets that were added in past commits and may still exist in history even after removal from HEAD. Uses only stdlib subprocess + git commands; bounded to 500 commits by default; findings anchored to the introducing commit with redacted evidence.
- Extend secrets detection quality: a demote-only Shannon entropy gate now covers all non-calibrated secret rules (45+ provider token patterns), dropping format-valid but obviously filler test tokens to low confidence while leaving structured high-entropy keys untouched.
- Add four supply-chain detectors: `SP092` npm wildcard/latest ranges, `SP093` Maven SNAPSHOT versions, `SP094` Dockerfile ADD over remote URLs, `SP095` package lifecycle scripts fetching from network.
- Enforce promoted-quality contract for SP051-SP095: every catalog-promoted rule ships with executed positive/negative/adversarial fixtures, documented false-positive boundaries, dual primary sources, and complete explanations via `tests/rule_cases_promoted.json`.
- Add secrets-lane quality manifest for SP001-SP050: all 50 secret-detection rules documented with false-positive boundaries, dual primary sources, negative/adversarial evidence, and enforcement tests.

## 0.8.1 - 2026-08-23

- Ship a JavaScript/TypeScript interprocedural taint engine: inline and named route handlers become entrypoints, request-derived values flow through local aliases into SQL, command-execution, path-traversal, SSRF (`fetch`/`axios`), DOM XSS (`innerHTML`, `document.write`), and reflected-HTML sinks, with sanitizer awareness (`Number`, `path.basename`, containment guards) and parameterized-query suppression. The Python engine gains the same alias tracking (a query built from a parameter now reaches `execute()` through its variable), and `execute(sql, params)` tuples are no longer treated as injectable SQL text.
- Extend `SP108` to Express: admin/internal routes fire without route-level auth middleware only when the file registers no global auth use and carries no broad authorization signal; comment prose can no longer grant or revoke coverage.
- Promote 30 researched candidates into executable detectors (`SP051`–`SP080`): prototype pollution via request merges, hardcoded JWT signing secrets, DES/3DES/RC4 ciphers, shell interpolation on both Python and Node, session cookies missing HttpOnly/SameSite, credentials in URL query strings, Mongo operator injection, PHP dynamic includes / `preg_replace` `/e` / `extract()` / superglobal shell calls, Java EL evaluation, `if`-assignments, `Runtime.exec` concatenation, default-AES transforms, Spring mappings without method constraints, Go 0777 modes / clock-seeded `math/rand` / allow-all WebSocket origins, Ruby `eval(params)` / `VERIFY_NONE`, Flask and Express file responses from request data, stack traces returned to clients, bare `except`, and reflected HTML responses. The catalog reaches 605 executable rules.
- Precision hardening grounded in real-world OSS triage (express, flask, requests, juice-shop, DVWA, NodeGoat): SSRF loopback URLs require request-call context, `.open(` method look-alikes no longer match path traversal, sync-I/O findings require loop context, code-shaped matches inside string literals are suppressed while OAuth URL content rules stay exempt, minified/hashed bundles downgrade confidence, Next.js-only rules downgrade outside Next manifests, and comment lines cannot grant Express authorization coverage.
- Enrich SARIF 2.1.0 output for GitHub code-scanning: a deterministic `security-severity` ranking property per rule, STRIDE threat-model tags across every covered CWE root, `versionControlProvenance` plus `automationDetails` bound to local git metadata (read-only; omitted outside git repositories), and review-required mechanical fix scaffolds surfaced as JSON `fix_scaffold` fields and SARIF `fixes` for curated flag-flip rules. Redacted secret rules never produce scaffolds, so before/after text can never leak credential material.
- Expand the benchmark story: multi-file cross-file-taint corpora with secure counterparts, an adversarial precision-trap suite (comment/string-literal look-alikes must stay silent while two-hop aliasing, destructured params, cookie-to-DOM chains, and three-file taint chains must all fire), head-to-head runs over all fixtures with the full engine enabled, a promotion-shortlist pipeline that ranks the 7,800-slot research backlog by local implementability (4,270-candidate pool), and a weekly CI benchmark workflow with opt-in open-source evaluation.
- Cut real-world false positives by 38% (1,461 → 908 findings across the five bundled OSS corpora: dvwa, express, flask, juice-shop, requests) with curated-suite precision and recall unchanged at 100%: SP304 requires proven HTTP-client bindings (Flask's dict-like `session.get` and test clients no longer count), SP367 only matches Node stream destinations (RxJS operator chains excluded), SP213 stops flagging the safe `--ignore-scripts` flag, SP140 no longer matches helper names like `_lazy_sha1`, and SP527 requires agent-loop context instead of any `while True:`.
- Benchmark-driven tuning carried forward: the scanner benchmark warms the OS file cache with an untimed pass, reports cold and warm scans separately, supports `--jobs N`, loads under its canonical module name for worker unpickling, skips the literal-gate probe on files of four lines or fewer, and falls back to sequential scanning with a stderr note when process pools are unavailable.

## 0.8.0 - 2026-08-22

- Promote four evidence-gated framework detectors through the full rule process (positive/negative/adversarial fixtures, two-source primary grounding, false-positive analysis, both README tables, and quality manifest): `SP662` Django `CORS_ALLOW_ALL_ORIGINS` wildcard CORS, `SP663` Django `SESSION_COOKIE_SECURE = False`, `SP664` FastAPI routes without visible rate limiting, and `SP665` Django `DEBUG` in deployable settings. All are medium severity, non-blocking pilots; the demo "after" fixture now demonstrates SP664 remediation with a real token-bucket limiter.
- Add framework-aware confidence: structural framework rules keep their default confidence only when repository manifests declare that framework; present-but-undeclared frameworks downgrade confidence one level (never suppress). Repositories without any manifest keep full confidence because framework state is unknown.
- Add deterministic parallel scanning: `shipproof scan . --jobs N` scans files in worker processes while producing byte-identical output (enforced by a jobs=1 vs jobs=4 parity test); falls back to sequential scanning with a stderr note if process pools are unavailable.
- Add an offline head-to-head benchmark harness (`benchmarks/head_to_head.py`): identical local corpora, median end-to-end wall time over N repeats, and file-level precision/recall/F1 against a shared label file for any tool. Semgrep (or any scanner) runs only with caller-supplied rule files — ShipProof never bundles, downloads, or copies third-party rules, and the harness performs no network access; results are corpus-scoped and never a general superiority claim.
- Make literal gate construction lazy so `--explain`, `--snippet`, and MCP startup skip the ~100 ms prefilter build; extend cross-file stats with `cross_file_flows_unsanitized`.
- Harden the Node layer further: zod schemas use the two-argument `z.record` (compatible with zod 3 and 4), MCP snippets are byte-limited to match the Python scanner (non-ASCII snippets now fail fast instead of exiting 2 later), `scan.max_file_bytes` enforces the same 1024-byte floor as the Action and MCP, an opt-in TTL result cache (`SHIPPROOF_MCP_CACHE_MS`, default off) serves repeated IDE scan calls, and evidence reports classify diagnostics into `severity_counts` (error/warning/other).
- Document Code Scanning upload: the Action README example now shows `github/codeql-action/upload-sarif` with the required `security-events: write` permission.
- Fix the exit-code contract end to end: an unexpected scanner crash (including `RecursionError` on pathologically nested Python, and raw Windows NTSTATUS statuses) now exits `2` (invalid evidence) instead of masquerading as a gate block; `shipproof check` gate timeouts and output-buffer overflows report actionable errors naming the gate and the `SHIPPROOF_GATE_TIMEOUT_MS` / `SHIPPROOF_MAX_BUFFER_BYTES` overrides.
- Close an inline-suppression bypass: `shipproof-ignore` markers are honored only inside comments (or at the start of a documentation line), never inside string literals, and a single marker can now suppress multiple rule IDs (`# shipproof-ignore SP101 SP102`). The Python AST engine now honors these markers too.
- Treat every credential rule that redacts evidence as a secret rule: `SP026`–`SP050` and eight other redacting rules gain placeholder filtering, comment scanning, and document (`.md`/`.rst`/`.txt`) scanning, closing false negatives for provider tokens leaked into READMEs.
- Speed up full-repository scans by roughly 48% (10.4s → 5.4s on this repo) by bounding the quadratic `SP577`/`SP579` multiline windows to their reporting span, and add a sound literal-gate prefilter (validated over 370 million rule/line checks with zero false skips) that skips rules whose required literals are absent from a file; single-file linting, stat calls, and rule lookups were also de-duplicated.
- Improve detection precision: the same rule firing on the same line from two engines now keeps the higher proof level (AST/taint evidence is no longer shadowed by the cruder regex hit); Python docstring examples no longer trigger non-secret rules while secrets inside docstrings are still reported; placeholder filtering now targets the credential value, which un-breaks `SP004` for the `os.environ.get(...)` form; and entropy confidence calibration extends to `SP004` and `SP019`–`SP021`.
- Detect assembled credentials the regex engine cannot see: string-concatenation assignments (`api_key = "..." + "..."`) are flagged by the AST engine as `SP003`, and base64-encoded credential literals decoded into credential-named variables are flagged at low confidence.
- Add exact SARIF regions and richer GitHub annotations: findings now carry `column`, `end_line`, and `end_column`; SARIF reports include `startColumn`/`endLine`/`endColumn`, and `github` annotations emit `col` with sanitized messages.
- Add opt-in cross-file taint analysis: `shipproof scan . --cross-file` (also exposed on the MCP `shipproof_scan` tool with new `exclude`, `min_confidence` inputs) promotes unsanitized interprocedural flows from route entrypoints to dangerous sinks into `L2` findings with call-chain evidence, using the existing offline impact-graph analyzer.
- Harden the Node layer: Python runtime detection is shared and cached across the CLI, MCP server, and GitHub Action (one probe per process instead of up to twelve spawns per `check`); the MCP tool timeout is configurable via `SHIPPROOF_MCP_TIMEOUT_MS`; GitHub Action step summaries escape table cells and cap rendered rows; the policy parser rejects mapping-shaped sequence items, explains leading-zero numbers, and gives JSON syntax errors context; and evidence availability probing no longer treats a repo file named `go`/`cargo` as the real toolchain.


## 0.7.0 - 2026-08-20
- Rework both public READMEs around an explicit trust model, verified `0.7.0`/571-rule status, evidence levels, executable-versus-research boundaries, ecosystem scope, and immutable Action guidance. Remove stale version/coverage badges and unsupported external statistics; add project governance, citation metadata, expanded contribution/conduct/security policies, and ship those documents in the allowlisted package artifact.
- Add opt-in, content-free scanner decision traces and progressive `summary`/`overview`/`full` context for rule explanations and AI fix prompts. The implementation adapts only the high-value context-disclosure and observability ideas identified in the OpenViking review; it adds no server, vector database, embeddings, telemetry, network path, or runtime dependency, and preserves `full` as the compatibility default.
- Promote six high-signal cloud and CI/CD candidates as non-blocking executable rules `SP656`–`SP661`: Kubernetes RBAC wildcard grants, `cluster-admin` bindings, masked scanner exits, security steps that continue on error, broad reusable-workflow secret inheritance, and Kubernetes `AlwaysAllow` authorization. Each rule ships with official-source grounding, CWE mapping, false-positive analysis, and positive/negative/adversarial fixtures.
- Publish an ordered P0–P5 development plan covering contract integrity, executable-rule fixture assurance, evidence-gated candidate promotion, polyglot analyzers, scale/performance proof, real-world evaluation, measurable acceptance gates, and CLI 1.0 cleanup.
- Add 5,000 deduplicated language-specific research candidates (`SP4451–SP9450`) across C#, TypeScript, PHP, React, Go, C++, Angular, JavaScript, SQL, Python, Java, Rust, Kotlin, and Swift. Rank variants from CWE-declared applicability, retain structured security/reliability/performance/scale consequences, cross-check executable CWE/suffix overlap, ground each ecosystem in owning documentation, and keep every record non-executable until its precision fixtures pass.
- Add 2,800 traceable rule-research candidates without bulk-enabling detectors: 300 critical NVD samples for each year from 2021 through 2026 (`SP1651–SP3450`), plus 1,000 current CWE-grounded expert candidates (`SP3451–SP4450`). Add CISA KEV/vendor provenance, a 2021–2026 Reddit/Stack Overflow/Google discovery ledger with official confirmation links, an allowlisted offline snapshot builder, and tests enforcing counts, contiguous IDs, source URLs, CWE diversity, and research-only status.
- Fail closed across evidence and release paths: reject missing analysis targets and non-positive cost inputs with exit `2`; probe Go with `go version`; require explicit approval before executing repository-local TypeScript or Rust tooling; distinguish analyzer crashes from findings; discard stale GitHub Action reports and derive summaries from the real gate exit; upload SARIF after blocking findings; and restrict releases to exact tags without automated registry publication or failure-masking fallbacks.
- Harden scanner correctness and precision: route previously unreachable language and manifest suffixes, bound multiline structural matches, preserve Unicode/subdirectory Git changes, prevent credential rehydration in terminal and fix-prompt context, verify autofix results before returning success, and scope Dockerfile-only rules to Dockerfiles. Add the evidence-gated 1,000-candidate expansion program plus non-blocking pilot rules `SP651`–`SP661` and an enforceable positive/negative/adversarial quality manifest for every future rule.
- Simplify the public CLI around `check`, `scan`, and `explain`; group deterministic primitives under `gate`, move heuristic analyzers under `labs`, add `config validate`, merge global skill setup into `init --scope global`, hide legacy aliases with migration warnings, and retire the static `badge` command because it could not attest repository status. `init` now emits a policy that round-trips through `check`, and missing-policy fallback no longer swallows wrong-type or unsafe policy errors.
- Publish the failure catalog (`docs/knowledge/failure-catalog.md`): 527 researched failure modes across 27 sections, each with impact, fix direction, detection feasibility, and references. The catalog feeds detector selection for future rules.
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

## 0.6.0 - 2026-08-19

- Expand the executable rule catalog to **560 rules** across multiple language ecosystems, including detectors `SP591`–`SP650`.
- Add AI Agent Token & Financial Cost Budget Engine (`shipproof cost`): computes context footprint, prompt caching discount calculations across frontier models (Claude 3.7/3.5, GPT-4o, Gemini 2.0/1.5, DeepSeek-V3/R1), and multi-iteration financial budget gates (`--budget-usd`).
- Add Git Worktree Isolation Sandbox (`shipproof worktree`): enables AI coding agents to create, test, and merge isolated workspace sandboxes safely without touching working branches.
- Add Production Readiness Status Badge (`shipproof badge`): outputs shields.io Markdown or JSON status badges for `README.md`.
- Add Next.js 15 App Router & TypeScript Enterprise Gate (`SP591`–`SP600`): server-only DB/ORM leakage in `"use client"` bundles, unawaited route-segment parameters, mutating actions missing revalidation, and IDOR protection.
- Add Multi-Language Enterprise Production Gate (`SP601`–`SP625`): OWASP Top 10 for LLMs, Kubernetes container hardening, GraphQL/gRPC resilience, OAuth2/PKCE security, PostgreSQL table-lock protection, and language failure modes in Rust, Go, Java, Python, and C#.
- Add Cloud & Infrastructure-as-Code detectors (`SP626`–`SP630`): AWS S3 public access, unencrypted EBS/RDS storage, open security-group SSH/RDP ports, IAM wildcard policies, and CloudFront HTTPS enforcement.
- Add Edge Runtimes & Serverless Isolation rules (`SP631`–`SP634`): Cloudflare Workers, Deno, and Vercel Edge Node.js module checks, unbounded KV loops, unbuffered response accumulation, and authenticated CDN cache leaks.
- Add Real-Time & Streaming Concurrency rules (`SP635`–`SP638`): WebSocket heartbeat keepalive, Server-Sent Events disconnect listeners, WebSocket handshake authentication, and BroadcastChannel unmount leaks.
- Add Cryptographic Primitives & Key Management rules (`SP639`–`SP643`): insecure symmetric ciphers, weak RSA key length, static IV reuse, legacy MD5/SHA1 hashing, and timing-unsafe HMAC comparisons.
- Add Modern Framework & Multitenancy Security rules (`SP644`–`SP650`): Svelte raw HTML, Android WebView file access, iOS URLSession trust bypass, frontend API proxy SSRF, React WebSocket teardown, multitenant query scoping, and recursive JSON nesting bounds.
- Expand the full test suite to 284 unit tests with zero high-gate self-scan findings.

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
