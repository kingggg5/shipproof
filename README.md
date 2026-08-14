# ShipProof

**Secure-by-design engineering skills and evidence gates for AI coding agents.**

[![CI](https://github.com/kingggg5/shipproof/actions/workflows/ci.yml/badge.svg)](https://github.com/kingggg5/shipproof/actions/workflows/ci.yml)
[![Security](https://github.com/kingggg5/shipproof/actions/workflows/security.yml/badge.svg)](https://github.com/kingggg5/shipproof/actions/workflows/security.yml)
[![npm-ready](https://img.shields.io/badge/npm-ready-CB3837?logo=npm)](package.json)
[![Codex](https://img.shields.io/badge/Codex-skill%20%2B%20plugin-111827)](https://learn.chatgpt.com/docs/build-skills)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-skill%20%2B%20plugin-D97757)](https://code.claude.com/docs/en/skills)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

ShipProof teaches Codex and Claude Code how to design, implement, investigate, and audit production software across application code, APIs, databases, AI agents, supply chains, kernels, browser engines, parsers, and network protocols. Its zero-dependency npm front door and local Python gates turn assumptions into repeatable CI evidence.

It does **not** promise “perfect,” “unhackable,” “maximum performance,” or “one million users” from a static scan. It makes assumptions visible, verifies what can be verified, and preserves human authority for consequential actions and releases.

## Start in one minute

```bash
npm install --global github:kingggg5/shipproof
shipproof doctor .
shipproof init . --target both
```

`init` adds repository-scoped skills to `.agents/skills` for Codex and `.claude/skills` for Claude Code. It skips existing skill directories unless you explicitly pass `--force`.

Node.js 20+ runs the front-door CLI. Python 3.10+ is needed only for `scan`, `budget`, and `capacity`. There are no runtime npm or Python package dependencies.

## Two modes, one workflow

| Skill | Use it for | Outcome |
| --- | --- | --- |
| `engineer-production-systems` | Design, implementation, refactoring, hardening, performance, data, AI/MCP, and authorized defensive systems work | Small, bounded, testable production code with explicit assumptions |
| `audit-production-readiness` | Deep review, vulnerability triage, incidents, release gates, and 10k-to-1M-user planning | Independent Security, Correctness, Data & Privacy, Scale, Operability, and Supply Chain gates |

```mermaid
flowchart LR
    A["Requirements + workload"] --> B["Engineering contract"]
    B --> C["AI implements bounded code"]
    C --> D["Tests + scanners + benchmarks"]
    D --> E["CPU/RAM/latency budget gate"]
    E --> F["Production readiness audit"]
    F --> G{"Human release decision"}
    G -->|"blocking evidence"| H["Fix + regression test"]
    G -->|"missing evidence"| I["Targeted experiment"]
    G -->|"verified"| J["Release"]
```

## What it tells the AI to do

- Read the real architecture and trace the affected path before changing code.
- Define authorization, tenancy, correctness, workload, latency, CPU, memory, and recovery constraints.
- Bound input, output, recursion, concurrency, fan-out, queues, caches, retries, timeouts, logs, and retained state.
- Prefer simple composition and narrow interfaces over speculative abstractions or premature microservices.
- Measure before and after with the same workload; report variance and tail behavior, not one fast run.
- Treat static and AI findings as leads until a path, reproducer, sanitizer failure, or focused test confirms them.
- Keep dangerous actions human-approved and never upload private code or run active tests without authorization.

Progressive references cover production architecture, full-stack boundaries, database invariants and migrations, AI/RAG/MCP security, software supply chains, operability and incident response, performance, low-level systems, and authorized defensive reverse engineering. The agent loads only the relevant discipline instead of carrying one giant prompt.

## Systems coverage

ShipProof routes high-risk code to a stricter evidence ladder:

| Target | Review focus | Recommended evidence when authorized |
| --- | --- | --- |
| Kernel and drivers | User/kernel boundaries, lifetime/refcounts, copy-to/from-user, ioctl/netlink, locks/RCU, teardown races | KASAN, KMSAN, KCSAN, UBSAN, syzkaller, minimized reproducers |
| Browser engines | GC/refcount boundaries, parsers/codecs, JIT, IPC, sandbox/origin identity, re-entrancy | ASan, UBSan, MSan, coverage-guided fuzzing, regression corpora |
| Network protocols | Framing, integer/length checks, explicit state machines, negotiation, replay, fragmentation, amplification | Structure-aware fuzzing, protocol corpora/dictionaries, fault and sequence tests |
| Services and apps | Authn/authz, tenancy, transactions, retries, idempotency, timeouts, queues, dependency budgets | Unit/integration tests, SAST/SCA, load/soak tests, traces and resource profiles |

The bundled scanner stays deliberately conservative. Deep memory-safety and protocol findings need compiler instrumentation, sanitizers, fuzzers, and target-specific reasoning—not misleading regex matches.

## Codex and Claude compatibility

Both hosts use the open `SKILL.md` structure, so ShipProof keeps one source of truth.

| Host | Skill metadata | Plugin manifest | Personal skill path |
| --- | --- | --- | --- |
| Codex | `skills/*/SKILL.md` + optional `agents/openai.yaml` | `.codex-plugin/plugin.json` | `~/.agents/skills` or `<repo>/.agents/skills` |
| Claude Code | `skills/*/SKILL.md` | `.claude-plugin/plugin.json` | `~/.claude/skills` |

## One front door

```text
shipproof doctor [path] [--json]
shipproof init [path] [--target codex|claude|both] [--force]
shipproof install [--target codex|claude|both] [--force]
shipproof prompt <build|audit|threat-model|database|performance|systems|incident|ai-agent>
shipproof scan [path] [--format markdown|json|sarif] [--fail-on high]
shipproof budget --baseline baseline.json --current current.json --budget budget.json
shipproof capacity --users 1000000 [workload assumptions]
```

- `doctor` is read-only and checks runtimes, source control, CI, lockfiles, security policy, and skill integration.
- `init` installs project skills; `install` installs personal skills.
- `prompt` prints a focused versioned prompt without network calls.
- `scan`, `budget`, and `capacity` safely route to one Python implementation with shell interpretation disabled.

See [the command reference](docs/commands.md) for options and exit codes.

## Install alternatives

Install from a clone:

```bash
git clone https://github.com/kingggg5/shipproof.git
cd shipproof
npm install --global .
```

Python-only fallback:

```bash
python install.py --target both
```

Then invoke the skill while building:

```text
Use $engineer-production-systems to implement this feature with explicit security,
CPU, RAM, latency, and failure budgets.
```

Before release:

```text
Use $audit-production-readiness to audit this repository for production.
```

Claude Code can also load the repository directly as a plugin during development:

```bash
claude --plugin-dir .
```

Plugin-installed Claude skills use the namespaced commands `/shipproof:engineer-production-systems` and `/shipproof:audit-production-readiness`.

## Reproducible resource budgets

Benchmarks remain owned by your project. ShipProof only evaluates their numeric outputs, which keeps CI local, fast, and provider-independent.

`perf-baseline.json`:

```json
{"metrics":{"p95_latency_ms":120,"cpu_ms":8.5,"rss_mb":180,"throughput_rps":850}}
```

`perf-current.json` has the same keys. Define reviewed limits in `perf-budget.json`:

```json
{
  "metrics": {
    "p95_latency_ms": {"direction":"lower","max_regression_percent":10,"max":160},
    "cpu_ms": {"direction":"lower","max_regression_percent":8},
    "rss_mb": {"direction":"lower","max_regression_percent":5,"max":220},
    "throughput_rps": {"direction":"higher","max_regression_percent":5,"min":750}
  }
}
```

Run the gate:

```bash
python skills/engineer-production-systems/scripts/check_budget.py \
  --baseline perf-baseline.json --current perf-current.json \
  --budget perf-budget.json --format markdown
```

Runnable sample files live in [`examples/performance`](examples/performance).

Exit codes are `0` for pass, `1` for a measured budget failure, and `2` for missing or invalid evidence.

## Audit and capacity tools

Fast local scan with Markdown, JSON, or SARIF 2.1.0 output:

```bash
python skills/audit-production-readiness/scripts/scan_repo.py . \
  --format sarif --output shipproof.sarif --fail-on high
```

Create a reviewed fingerprint baseline for accepted debt:

```bash
python skills/audit-production-readiness/scripts/scan_repo.py . \
  --format json --baseline-out .shipproof-baseline.json --fail-on none
```

Turn one million registered users into a transparent workload hypothesis, including CPU and memory assumptions:

```bash
python skills/audit-production-readiness/scripts/capacity_model.py \
  --users 1000000 --dau-ratio 0.25 --peak-hour-ratio 0.20 \
  --actions-per-session 12 --requests-per-action 2 --instance-rps 250 \
  --cpu-ms-per-request 5 --memory-mb-per-instance 512 --format markdown
```

Replace every sample value with analytics and a production-shaped benchmark. Registered users are not concurrent users, and capacity arithmetic is not a load test.

## Layer with mature tools

ShipProof routes the agent to tools already present in the environment and never silently installs them:

- [CodeQL](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli) or [Semgrep](https://semgrep.dev/docs/) for source and data-flow analysis.
- [OSV-Scanner](https://google.github.io/osv-scanner/) or [Trivy](https://trivy.dev/docs/latest/) for dependencies, containers, IaC, secrets, licenses, and SBOM evidence.
- [Gitleaks](https://github.com/gitleaks/gitleaks) for current and historical secrets.
- [SkillSpector](https://github.com/NVIDIA/SkillSpector) for trust checks before installing third-party agent skills.
- [OpenSSF Scorecard](https://scorecard.dev/) for repository and supply-chain posture.
- [LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html), [OSS-Fuzz](https://github.com/google/oss-fuzz), or [syzkaller](https://github.com/google/syzkaller) for authorized target-specific fuzzing.
- [Grafana k6](https://grafana.com/docs/k6/latest/) or the project's existing harness for SLO-driven load testing.

## Research and independent design

ShipProof is independently implemented. Its 2025–2026 design is grounded in primary guidance from OWASP ASVS and the Web/Agentic Top 10, NIST SSDF, CISA Secure by Design, MCP security specifications, SLSA, npm trusted publishing/provenance, OpenTelemetry, PostgreSQL, and mature sanitizing/fuzzing projects. Community projects and engineering reports are used to discover questions, never as proof.

- See [docs/research.md](docs/research.md) for the source-by-source synthesis, design consequences, and limitations.
- See [docs/web-applications-playbook.md](docs/web-applications-playbook.md) for modern Web Application, API, RSC, database concurrency, and event loop resilience playbooks.
- See [docs/systems-and-scale-playbook.md](docs/systems-and-scale-playbook.md) for the comprehensive systems vulnerability catalog (kernels, browser engines, protocols) and 10k-to-1M workload scaling formulas.
- See [docs/2025-2026-engineering-standards.md](docs/2025-2026-engineering-standards.md) for 2025–2026 standards including Python 3.13 No-GIL concurrency, Post-Quantum FIPS 203 ML-KEM, WASI 0.3, and MCP Agentic Security.

ShipProof deliberately avoids a single readiness score because one critical defect must not be averaged away by many clean files.

## About large vulnerability claims

The cited counts—107 Critical, 990 High, 1,286 Medium, and 53 Low—sum to 2,436. We could not locate a primary public report that ties this exact distribution to the Linux kernel, WebKit, FreeBSD, or a 40-year-old bug, so ShipProof does not repeat it as a verified benchmark.

Verified primary material does show the broader lesson: modern AI-assisted research has found serious flaws in mature operating systems and browsers, while projects such as OSS-Fuzz report thousands of vulnerabilities over years of continuous fuzzing. The engineering response is layered verification and retained regression evidence, not trusting a headline or one model pass.

## Development

```bash
npm ci --ignore-scripts
npm run test:node
python -m unittest discover -s tests -v
python -m compileall -q skills tests install.py
python skills/audit-production-readiness/scripts/scan_repo.py . --fail-on high
npm pack --dry-run
```

The runtimes use only Node and the Python standard library. CI tests Node 20/24 and Python 3.10/3.12, verifies package contents, and runs CodeQL for Python and JavaScript/TypeScript. Read [CONTRIBUTING.md](CONTRIBUTING.md) before adding a detector: each rule needs positive and negative tests, a mapping, remediation, and false-positive analysis.

The scoped npm manifest is ready for a future registry release. Until the owner configures npm trusted publishing, use the GitHub npm install shown above; this project does not claim an unpublished registry release. See [docs/releasing.md](docs/releasing.md).

## License and security

[MIT](LICENSE). Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).
