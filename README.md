# ShipProof

**Make AI-written code prove it is ready to ship.**

Security · Correctness · Scale · Performance · Production readiness

Works with **Codex**, **Claude Code**, local terminals, pre-commit, and GitHub Actions.

[![CI](https://github.com/kingggg5/shipproof/actions/workflows/ci.yml/badge.svg)](https://github.com/kingggg5/shipproof/actions/workflows/ci.yml)
[![Security](https://github.com/kingggg5/shipproof/actions/workflows/security.yml/badge.svg)](https://github.com/kingggg5/shipproof/actions/workflows/security.yml)
[![Public beta](https://img.shields.io/badge/public_beta-v0.4.0-2563eb)](CHANGELOG.md)
[![Coverage gates](https://img.shields.io/badge/coverage-Python_80%25_%7C_Node_core_70%25-0f766e)](.github/workflows/ci.yml)
[![Codex](https://img.shields.io/badge/Codex-skill%20%2B%20plugin-111827)](https://learn.chatgpt.com/docs/build-skills)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-skill%20%2B%20plugin-D97757)](https://code.claude.com/docs/en/skills)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

ShipProof is a small production gate for AI-assisted repositories. It scans code without executing it, checks measured CPU/RAM/latency budgets, models reviewed capacity assumptions, and gives coding agents focused engineering instructions. Results are available as terminal output, JSON, SARIF, pre-commit, GitHub Actions, or an optional read-only MCP adapter.

It does **not** promise “perfect,” “unhackable,” “maximum performance,” or “one million users” from a static scan. It makes assumptions visible, verifies what can be verified, and preserves human authority for consequential actions and releases.

![ShipProof terminal demo](docs/assets/terminal-demo.svg)

## Understand it in 30 seconds

The checked-in [demo API](examples/demo-api/README.md) contains five real, intentionally vulnerable code paths: missing admin authorization, interpolated SQL, unbounded pagination, a missing outbound timeout, and production debug mode.

```bash
shipproof scan examples/demo-api/fixtures/before --fail-on high
# BLOCK · 5 findings

python -m unittest discover -s examples/demo-api/fixtures/after/tests -v
shipproof scan examples/demo-api/fixtures/after --fail-on high
# PASS_WITH_EVIDENCE · 0 findings
```

The test suite verifies the exact before/after contract. Additional [Node.js, Python, secure, and performance fixtures](fixtures/README.md) guard against missed findings and obvious false positives.

## Start in one minute

```bash
npm install --global github:kingggg5/shipproof
shipproof doctor .
shipproof init . --target both
shipproof check .
```

`init` adds repository-scoped skills to `.agents/skills` for Codex and `.claude/skills` for Claude Code. It skips existing skill directories unless you explicitly pass `--force`.

Node.js 20+ runs the front-door CLI. Python 3.10+ is needed for `scan`, `check`, `budget`, `capacity`, and the MCP tools. The core has no runtime npm or Python package dependencies.

## Add the GitHub Action

```yaml
name: ShipProof
on: [pull_request]
permissions:
  contents: read
jobs:
  production-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: kingggg5/shipproof@v0.4.0
        with:
          fail-on: high
```

`v0.4.0` is the public-beta contract. Pin ShipProof to the release commit SHA when immutable supply-chain references are required. The project will not publish a misleading `@v1` alias until the stable CLI compatibility guarantee exists.

For Google Apps Script repositories, use a reviewed post-`v0.4.0` commit and set `include-gas: true` (or `scan.include_gas: true` in policy). This opt-in scans `.gs` server code and inline `<script>` blocks in `.html` templates; it does not execute Apps Script template directives or replace `clasp`/runtime UAT. The action also accepts newline-separated repository-relative `exclude` patterns for non-runtime tooling directories.
## One policy, one command

Commit a bounded [`.shipproof.yml`](.shipproof.yml), then run every declared repository gate:

```yaml
version: 1
scan:
  path: .
  exclude:
    - vendor/**
security:
  fail_on: high
performance:
  baseline: perf/baseline.json
  current: perf/current.json
  budget: perf/budget.json
capacity:
  config: capacity.json
```

```bash
shipproof check .
```

The dependency-free YAML subset rejects executable tags, anchors, duplicate keys, unknown fields, path traversal, and arbitrary commands. Set `scan.include_gas: true` only for repositories that intentionally contain Google Apps Script `.gs`/HTML-template source; the default remains `false`. The full shape is documented by the [policy schema](schemas/shipproof-policy.schema.json).

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

The [ShipProof production engineering playbook](docs/production-playbook.md) is the owner-authored map across those disciplines: eight control planes, one decision doctrine, and a compact release record. It keeps ShipProof's reasoning in the foreground while the focused references provide execution detail.

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
shipproof prompt <build|audit|threat-model|database|performance|systems|incident|ai-agent|loop>
shipproof scan [path] [--format markdown|json|sarif] [--fail-on high]
shipproof check [path] [--config .shipproof.yml] [--format markdown|json]
shipproof budget --baseline baseline.json --current current.json --budget budget.json
shipproof capacity --users 1000000 [workload assumptions]
shipproof capacity --config shipproof.config.json --export-k6 load-test.js
shipproof evidence . --list --format json
shipproof mcp
```

- `doctor` is read-only and checks runtimes, source control, CI, lockfiles, security policy, and skill integration.
- `init` installs project skills; `install` installs personal skills.
- `prompt` prints a focused versioned prompt without network calls.
- `scan`, `check`, `budget`, and `capacity` safely route to fixed Python implementations with shell interpretation disabled.
- `evidence` runs only fixed TypeScript, Go, or Rust analyzer commands; Rust requires explicit project-code approval because Cargo build scripts can execute.
- `mcp` exposes only read-only scan, budget, and capacity tools over local stdio.

See [the command reference](docs/commands.md) for options and exit codes.

## Install from a clone

Install from a clone:

```bash
git clone https://github.com/kingggg5/shipproof.git
cd shipproof
npm install --global .
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

Generate a deterministic k6 starting point from the reviewed config:

```bash
shipproof capacity --config examples/capacity/shipproof.config.json \
  --export-k6 load-test.js --format json
BASE_URL=https://staging.example.test LOAD_TEST_TOKEN=replace-me k6 run load-test.js
```

The generated file contains no hostname or credential. Running it is a separate, authorized action; review the rate, routes, target environment, and thresholds first.

## Pull-request and pre-commit gates

Use the composite action from the checked-out repository while developing this release:

```yaml
permissions:
  contents: read
steps:
  - uses: actions/checkout@v4
  - uses: ./
    with:
      path: .
      format: sarif
      output: shipproof.sarif
      fail-on: high
```

The action writes a report but does not upload it or request `security-events: write`; the caller owns that permission and upload step. External users should pin a published full commit SHA or reviewed major tag, not a moving branch.

For local commits, add this repository to `.pre-commit-config.yaml` and select the `shipproof-scan` hook. Pin `rev` to a reviewed commit SHA.

## Local MCP and language evidence

Install the optional MCP peers beside ShipProof, then point an MCP client at `shipproof mcp`:

```bash
npm install --save-dev github:kingggg5/shipproof @modelcontextprotocol/sdk@1.29.0 zod@3.25.76
npx shipproof mcp
```

Set `SHIPPROOF_MCP_ROOT` to the repository root when the client does not launch the server there. Paths are canonicalized, symlink escapes are denied, execution is bounded to 30 seconds and 2 MB, and no raw shell or file-reading tool is exposed.

Inspect available language-native evidence adapters before running one:

```bash
shipproof evidence . --list --format json
shipproof evidence . --adapter typescript --format json
shipproof evidence . --adapter go --format json
shipproof evidence . --adapter rust --allow-project-code --format json
```

Dependency downloads are disabled for Go and Rust adapters. TypeScript must exist in the repository. The Rust opt-in is deliberate because `cargo clippy` can execute project-controlled `build.rs` code.

## Layer with mature tools

ShipProof routes the agent to tools already present in the environment and never silently installs them:

- CodeQL or Semgrep for source and data-flow analysis.
- OSV-Scanner or Trivy for dependencies, containers, IaC, secrets, licenses, and SBOM evidence.
- Gitleaks for current and historical secrets.
- SkillSpector for trust checks before installing third-party agent skills.
- OpenSSF Scorecard for repository and supply-chain posture.
- LLVM libFuzzer, OSS-Fuzz, or syzkaller for authorized target-specific fuzzing.
- Grafana k6 or the project's existing harness for SLO-driven load testing.

## ShipProof design and research trail

ShipProof is independently implemented. Its public guidance is written as ShipProof decisions—each tied to an invariant, evidence, and a limitation—not as a collage of external checklists.

- Read the [production playbook](docs/production-playbook.md) for the first-party operating model.
- Read the [research notebook](docs/research.md) only when you need to trace which primary pages were opened, what question they answered, what ShipProof retained, and what it deliberately did not claim.

External links are concentrated in the notebook so the README and skill instructions remain ShipProof's own concise guidance. Community posts and repositories may suggest questions, but they are not accepted as proof and their code or prompts are not imported.

ShipProof deliberately avoids a single readiness score because one critical defect must not be averaged away by many clean files.

## AWE TraceGate engineering loop and roadmap

AWE TraceGate should orchestrate the loop; ShipProof should remain the reusable evidence engine. This keeps loop state, budgets, approvals, and user experience in AWE TraceGate while one ShipProof contract serves local CLI, pre-commit, GitHub Actions, generated k6 tests, and MCP clients.

```text
Observe -> Contract -> Change -> Verify -> Audit -> Decide -> Learn
   ^                                                        |
   +--------------------- bounded next iteration -----------+
```

Run `shipproof prompt loop` to load the bounded workflow. See the [delivery roadmap](docs/roadmap.md) for what shipped in 0.4.0 and which acceptance evidence still belongs before a stable 1.0 release.

## Development

```bash
npm ci --ignore-scripts
python -m pip install -r requirements-dev.txt
npm run lint
npm run test
python -m compileall -q skills tests
python skills/audit-production-readiness/scripts/scan_repo.py . --fail-on high
npm pack --dry-run
```

The core runtime uses only Node and the Python standard library; Ruff is development-only. The optional MCP adapter uses the official MCP SDK and Zod as explicitly installed peers. CI tests Node 20/24 and Python 3.10/3.12, verifies package contents, and runs CodeQL for Python and JavaScript/TypeScript. Read [CONTRIBUTING.md](CONTRIBUTING.md) before adding a detector: each rule needs positive and negative tests, a mapping, remediation, and false-positive analysis.

The scoped npm manifest is ready for a future registry release. Until the owner configures npm trusted publishing, use the GitHub npm install shown above; this project does not claim an unpublished registry release. See [docs/releasing.md](docs/releasing.md).

## License and security

[MIT](LICENSE). Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).
