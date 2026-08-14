# 2025–2026 research synthesis

Last reviewed: 2026-08-14.

ShipProof uses community reports to discover questions and primary standards, specifications, vendor documentation, and executable evidence to make decisions. It does not copy another project's source or prompts. The implementation is deliberately local-first, dependency-light, and conservative about claims.

## Findings that changed the design

### Secure design must precede scanning

The [OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/) puts broken access control first and elevates software supply-chain failures while retaining insecure design and adding mishandling of exceptional conditions. OWASP explicitly says the Top 10 is an awareness document and discourages tools from claiming full coverage. [ASVS 5.0.0](https://owasp.org/www-project-application-security-verification-standard/) is the stable verifiable requirements baseline released in May 2025.

Design consequence: ShipProof begins with business and authorization invariants, keeps gates independent, includes failure semantics, and never markets its regex/AST scanner as OWASP coverage or certification.

### Security ownership belongs with the producer

[CISA's 2025 product security bad-practices guidance](https://www.cisa.gov/news-events/alerts/2025/01/17/cisa-and-fbi-release-updated-guidance-product-security-bad-practices) calls out preventable classes such as default credentials, injection, and memory-unsafety and reinforces secure defaults. Its buffer-overflow guidance recommends memory-safe languages for new exposed code where feasible, compiler protections, sanitizers, fuzzing, manual review, root-cause analysis, and a memory-safety roadmap.

Design consequence: the engineering skill asks for class-level prevention before detection, routes new systems work toward memory-safe components when appropriate, and preserves a layered evidence ladder for legacy kernel, browser, parser, and protocol code.

### A secure lifecycle includes provenance and response

The [NIST Secure Software Development Framework](https://csrc.nist.gov/projects/ssdf) covers preparation, protected development environments, well-secured production, provenance, and vulnerability response. It also links the SP 800-218A profile for generative AI and dual-use foundation models. [SLSA 1.2](https://slsa.dev/spec/v1.2/build-track-basics) separates build integrity guarantees and requires signed hosted-build provenance for Build L2.

Design consequence: ShipProof reviews the full source-to-artifact path, dependency resolution, CI identities, SBOM/provenance, protected release, rollback, and response—not merely source lines.

### Agentic systems add an authorization boundary

The [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) records goal hijacking, tool misuse, identity/privilege abuse, agentic supply-chain compromise, unexpected code execution, and memory/context poisoning. The [MCP security guidance](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices) requires narrow consent, secure state, sandboxing, scope minimization, and defenses against confused deputies; the current authorization specification requires audience-bound tokens and prohibits token passthrough.

OpenAI's 2026 [Codex Security workflow](https://openai.com/index/codex-security-now-in-research-preview/) emphasizes repository-specific threat modeling, identification, isolated validation, remediation, and human-reviewed patches. OpenAI's [Codex operating controls](https://openai.com/index/running-codex-safely/) emphasize technical boundaries, explicit approval for risky actions, and agent-native telemetry.

Design consequence: retrieved content, memory, tool metadata, and model output are untrusted data; every tool call is re-authorized at execution; writes are split from reads; scopes, arguments, output, cost, and time are bounded; audit events and kill switches are required.

### Database scale is evidence, not user count

Current [PostgreSQL documentation](https://www.postgresql.org/docs/current/using-explain.html) continues to make query plans the basis for understanding execution. Google SRE guidance on [cascading failures](https://sre.google/sre-book/addressing-cascading-failures/) and k6 guidance on [thresholds](https://grafana.com/docs/k6/latest/using-k6/thresholds/) reinforce overload control, measurable SLOs, and staged load evidence.

Community posts on Medium, Reddit, and Stack Overflow repeatedly expose the same modeling error: registered accounts, DAU, peak sessions, virtual users, and RPS are not interchangeable. They also surface practical hypotheses—pool exhaustion, locks, production-shaped data, retry storms, hot keys, logging cost, and recovery—but do not establish a universal architecture.

Design consequence: the capacity tool exposes every ratio, CPU/memory assumption, and headroom value. The data guide requires query-plan, pool, lock, migration, restore, and RPO/RTO evidence before recommending replicas, partitioning, sharding, services, or orchestration.

### Observability must remain interoperable and bounded

[OpenTelemetry semantic conventions](https://opentelemetry.io/docs/concepts/semantic-conventions/) define common names across traces, metrics, logs, profiles, and resources.

Design consequence: ShipProof asks for correlated telemetry and audit evidence using standard naming when available, but explicitly limits high-cardinality labels and sensitive fields so observability does not become a memory, cost, privacy, or credential leak.

### npm publication is a supply-chain event

The npm CLI supports package `bin`, `files`, `engines`, and lifecycle controls. Current npm guidance recommends [trusted publishing](https://docs.npmjs.com/trusted-publishers/) with short-lived OIDC credentials instead of long-lived tokens and automatically attaches provenance for eligible public packages. npm also warns that [provenance](https://docs.npmjs.com/generating-provenance-statements/) links source and build but does not prove a package contains no malicious code.

Design consequence: the CLI has no runtime npm dependencies or install lifecycle script, package contents are allowlisted, `npm pack --dry-run` is a CI gate, registry publication is human-gated, and the README distinguishes GitHub npm installation from an unpublished registry release.

### A large open-source project needs a memorable front door

[Loop Engineering](https://github.com/cobusgreyling/loop-engineering) demonstrates a useful open-source product pattern: one memorable CLI routes to focused capabilities, `doctor` creates a day-two health habit, and automation advances from report-only to assisted operation with human gates. Its repository is MIT-licensed.

Design consequence: ShipProof independently implements a much smaller `shipproof` front door around its existing gates, keeps each skill focused, and defines Observe/Assist/Operate authority levels. It does not import Loop Engineering source or prompts and does not implement unattended external actions.

## Why the implementation stays small

- One shared skill tree prevents Codex and Claude guidance from drifting.
- Progressive references keep the initial agent context small and load only the relevant discipline.
- The npm CLI routes to existing Python gates instead of duplicating security and capacity logic in JavaScript.
- `spawnSync` receives an executable plus argument array with shell interpretation disabled.
- Project and personal skill installation skips existing directories unless `--force`; replacement verifies each target remains below the fixed skills root.
- The CLI never executes commands found in repository configuration.
- Fixed prompt names map to packaged files rather than arbitrary paths.
- No network, telemetry, package installation, exploit, DAST, fuzz, or load activity occurs by default.

## Deliberate limitations

- The scanner is heuristic and cannot prove reachability, exploitability, runtime configuration, dependency safety, or absence of vulnerabilities.
- AI review can miss defects or invent paths. Confirm findings and retain human release authority.
- Capacity arithmetic cannot predict nonlinear overload. Only production-shaped testing can establish a breakpoint and recovery behavior.
- Reverse-engineering guidance is restricted to authorized defensive investigation and remediation.
- ShipProof does not replace product/domain experts, privacy counsel, independent security review, incident response, or platform-specific testing.
- npm support is prepared and installable from GitHub; registry availability depends on the owner completing trusted-publisher setup.

## Primary source index

- [OpenAI: Build skills](https://learn.chatgpt.com/docs/build-skills)
- [OpenAI: Build plugins](https://learn.chatgpt.com/docs/build-plugins)
- [OpenAI: Codex Security](https://openai.com/index/codex-security-now-in-research-preview/)
- [OpenAI: Running Codex safely](https://openai.com/index/running-codex-safely/)
- [Claude Code: Skills](https://code.claude.com/docs/en/skills)
- [Claude Code: Plugins reference](https://code.claude.com/docs/en/plugins-reference)
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/)
- [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Agentic Top 10](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
- [NIST SSDF](https://csrc.nist.gov/projects/ssdf)
- [CISA Product Security Bad Practices](https://www.cisa.gov/news-events/alerts/2025/01/17/cisa-and-fbi-release-updated-guidance-product-security-bad-practices)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [SLSA 1.2 Build Track](https://slsa.dev/spec/v1.2/build-track-basics)
- [npm Trusted Publishing](https://docs.npmjs.com/trusted-publishers/)
- [npm Provenance](https://docs.npmjs.com/generating-provenance-statements/)
- [OpenTelemetry Semantic Conventions](https://opentelemetry.io/docs/concepts/semantic-conventions/)
- [PostgreSQL EXPLAIN](https://www.postgresql.org/docs/current/using-explain.html)
- [Google SRE: Cascading Failures](https://sre.google/sre-book/addressing-cascading-failures/)
- [Grafana k6 Thresholds](https://grafana.com/docs/k6/latest/using-k6/thresholds/)
- [LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html)
- [Linux Kernel Concurrency Sanitizer](https://docs.kernel.org/dev-tools/kcsan.html)
- [syzkaller](https://github.com/google/syzkaller)
- [OSS-Fuzz](https://github.com/google/oss-fuzz)
