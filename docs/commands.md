# Command reference

ShipProof's core npm CLI uses only Node built-ins. It never turns repository configuration into an arbitrary command. Python gates and evidence adapters are launched from fixed allowlists with argument arrays and shell interpretation disabled.

## Install

```bash
npm install --global github:kingggg5/shipproof
shipproof help
```

Use `SHIPPROOF_PYTHON` only when Python is not discoverable as `py -3`, `python3`, or `python`. Set it to an executable path or command name, not a command string with arguments. The detected runtime is probed once per process and shared by every gate.

Policy gates launched by `shipproof check` buffer scanner JSON with a 60 second timeout and a 16 MB output cap. Override with `SHIPPROOF_GATE_TIMEOUT_MS` (minimum 1000) and `SHIPPROOF_MAX_BUFFER_BYTES` (minimum 65536); a timeout, an output overflow, or a scanner crash is always reported as exit `2` (invalid or unavailable evidence), never as a gate block.

## JSON evidence contracts

Machine-readable outputs use the common [evidence envelope](../schemas/evidence-envelope.schema.json) and command-specific Draft 2020-12 schemas for [scan](../schemas/scan-report.schema.json), [check](../schemas/check-report.schema.json), [budget](../schemas/budget-report.schema.json), [capacity](../schemas/capacity-report.schema.json), [cost](../schemas/cost-report.schema.json), [impact](../schemas/impact-report.schema.json), [invariants](../schemas/invariants-report.schema.json), and optional [analyzer evidence](../schemas/evidence-report.schema.json). CI validates real command output against these schemas. Additive or breaking field changes require a deliberate schema and compatibility-fixture update.

## `doctor`

```bash
shipproof doctor .
shipproof doctor . --json
```

Checks Node, the optional Python gate runtime, source control, CI, security policy, Codex/Claude skills, and dependency lockfiles. It does not modify files or access the network.

Exit `0` means all checks passed. Exit `1` means recommendations remain. Exit `2` means invalid input or an execution error.

## `init`

```bash
shipproof init . --target both
shipproof init services/api --target codex
shipproof init . --target claude --force
shipproof init --scope global --target both
```

Project scope is the default. It copies skills to project-scoped discovery paths and creates a validated `.shipproof.yml` when one does not exist:

- Codex: `<project>/.agents/skills`
- Claude Code: `<project>/.claude/skills`

Existing skill directories are skipped. `--force` replaces only the two fixed ShipProof skill directories after verifying each destination remains inside the selected skills root.

Global scope copies skills to user discovery paths:

- Codex: `~/.agents/skills`
- Claude Code: `~/.claude/skills`

For managed or test environments, override the final skills directories with `SHIPPROOF_CODEX_SKILLS_DIR` and `SHIPPROOF_CLAUDE_SKILLS_DIR`.

## `config validate`

```bash
shipproof config validate .
shipproof config validate services/api --config policy.yml --format json
```

Parses and validates a repository policy without running its gates. Missing files, wrong path types, unsafe paths, unsupported YAML, and invalid policy fields return exit `2`.

## `scan`

Running `shipproof` with no command at all is equivalent to `shipproof scan`.

```bash
shipproof scan . --format markdown --fail-on high
shipproof scan . --format sarif --output shipproof.sarif --fail-on high
shipproof scan . --format json --baseline-out .shipproof-baseline.json --fail-on none
shipproof scan . --changed-since origin/main
shipproof scan . --format json --trace --fail-on high
shipproof scan . --fix-prompt --context-level overview
```

The arguments after `scan` match `scan_repo.py`. `--fail-on` accepts `critical`, `high`, `medium`, `low`, or `none`. `--changed-since GIT_REF` limits the scan to files changed relative to a git ref (added, copied, modified, renamed, plus untracked files) and fails closed with exit `2` outside a git repository or on an unresolvable ref; the ref is recorded under `changed_since` in JSON output. Repeat `--exclude` with repository-relative glob patterns to skip generated or vendored paths. Parent traversal and absolute patterns are rejected. `--cross-file` opts into interprocedural taint analysis: unsanitized flows from route entrypoints through helpers into dangerous sinks (SQL, command execution, eval) across files are promoted to `L2` taint findings on the sink line, and the flow count is recorded under `cross_file_flows` in JSON output. Cross-file analysis is slower and remains deterministic and offline. `--jobs N` scans files with N worker processes for large repositories; output is byte-identical to the sequential scan (`--jobs 1` stays sequential), and the scanner falls back to sequential execution with a stderr note when process pools are unavailable.

`--trace` adds a deterministic decision trace to JSON, Markdown, or terminal repository-scan output. It reports bounded counts for rule selection, file selection, filters, baseline suppression, and gate evaluation. It deliberately excludes source text, evidence text, finding paths, secret values, timestamps, timings, user identifiers, and network telemetry. The option is rejected for SARIF, GitHub annotations, snippets, explanations, fix prompts, and autofix modes instead of silently doing less than requested.

`--context-level summary|overview|full` progressively discloses `--fix-prompt` content. `summary` is the compact remediation contract, `overview` adds local context and implicit requirements, and `full` adds engineering dimensions and failure scenarios. The default is `full`, preserving existing output. Exit `0` means no finding met the threshold, `1` means the threshold failed, and `2` means evidence or input was invalid.

## `explain`

```bash
shipproof explain SP108 --context-level summary
shipproof explain SP108 --context-level overview --format json
shipproof explain SP108 --context-level full
```

The same progressive levels apply to rule explanations: `summary` returns the detection and remediation, `overview` adds mappings, rationale, false-positive guidance, and a regression test, and `full` adds attack and engineering context. `full` remains the default.

## `check`

```bash
shipproof check .
shipproof check . --config .shipproof.yml --format json
```

Loads a version-1 repository policy and executes its fixed scan, performance-budget, and capacity gates. The configuration is a strict, dependency-free YAML subset: mappings use two-space indentation, `scan.exclude` is a scalar list, and anchors, tags, block scalars, executable values, duplicate keys, unknown fields, path traversal, and arbitrary commands are rejected.

Exit `0` means every declared evidence gate passed, exit `1` means a declared scan or performance gate blocked, and exit `2` means the policy or required evidence was invalid or unavailable. Capacity remains explicitly `CONDITIONAL` evidence and does not block merely because the model requires production-shaped validation.

## `labs impact`

```bash
shipproof labs impact src/user.py
shipproof labs impact src/user.py:42 --format json
```

Performs experimental AST-based change-impact analysis. It estimates blast radius, callers, touched entities, selected tests, and cross-file data-flow chains. Labs output is a review aid and is never treated as production proof.

## `labs invariants`

```bash
shipproof labs invariants .
shipproof labs invariants . --format json
```

Analyzes foundational architectural and security invariants using Python and JS AST parsing:
- `INV-AUTH-01`: Administrative routes must declare visible authentication guards.
- `INV-TENANT-01`: Multi-tenant repository queries must explicitly filter on `tenant_id` or `org_id`.
- `INV-TX-01`: Database transactions must not execute slow outbound HTTP calls or unbounded sleeps.

## Maintainer benchmark

```bash
npm run benchmark
```

This developer-only script executes the bundled synthetic benchmark. It is not part of the public evidence contract and must not be presented as real-world precision or recall.

## `gate budget`

```bash
shipproof gate budget --baseline baseline.json --current current.json \
  --budget budget.json --format markdown
```

The gate accepts finite numeric metrics and explicit `lower`/`higher` directions. Define a relative regression limit, an absolute min/max, or both. Exit `1` is a measured failure; exit `2` is missing or invalid evidence.

## `labs capacity`

```bash
shipproof labs capacity --users 1000000 --dau-ratio 0.25 \
  --peak-hour-ratio 0.20 --actions-per-session 12 \
  --requests-per-action 2 --burst-multiplier 2 --instance-rps 250

# Reusable workload assumptions; explicit CLI values override this JSON
shipproof labs capacity --config workload.json --format json
```

Legacy config may contain input keys directly or inside an `inputs` object. The canonical versioned shape is:

```json
{
  "$schema": "./schemas/shipproof-config.schema.json",
  "schema_version": "1.0",
  "capacity": {
    "inputs": {"users": 100000},
    "k6": {
      "base_url_env": "BASE_URL",
      "duration": "1m",
      "routes": [{"name": "health", "path": "/health"}]
    }
  }
}
```

Unknown keys and invalid types fail closed. The result estimates design RPS, read/write and database work, in-flight work, instance/CPU/memory hypotheses, and a load-test ladder. It cannot prove capacity.

Generate a k6 file without embedding a target or authorization token. Sensitive request-body fields must use an environment placeholder such as `{"$env":"LOAD_TEST_PASSWORD"}`:

```bash
shipproof labs capacity --config shipproof.config.json --export-k6 load-test.js
shipproof labs capacity --config shipproof.config.json --export-k6 load-test.js --force
```

Existing files are not replaced without `--force`. One k6 iteration makes one request, so the constant-arrival-rate scenario maps the rounded design peak RPS to iterations per second. Reviewed request bodies are copied into the generated file; ShipProof rejects literal values for common sensitive keys, but you must still review every body and run only against an authorized environment.

## `labs cost`

Model AI agent token consumption, prompt caching savings, and dollar costs across modern 2026 foundation models:

```bash
shipproof labs cost . --model claude-3-5-sonnet --iterations 3
shipproof labs cost . --model gpt-4o --cadence per-pr --budget-usd 0.50
shipproof labs cost --context-tokens 50000 --model deepseek-r1 --format markdown
```

Supported models: `claude-sonnet-5`, `claude-3-7-sonnet`, `claude-3-5-sonnet`, `claude-3-5-haiku`, `claude-3-opus`, `gpt-4.5`, `gpt-4o`, `gpt-4o-mini`, `o1`, `o3-mini`, `o4-mini`, `gemini-3-7-flash`, `gemini-2-0-flash`, `gemini-2-0-flash-lite`, `gemini-2-0-pro`, `gemini-1-5-pro`, `gemini-1-5-flash`, `deepseek-v4-flash`, `deepseek-v4-pro`, `deepseek-v3`, `deepseek-r1`, `mistral-large`, `codestral`, `llama-3.3-70b`.
Exit `0` is under budget, `1` is budget exceeded, and `2` is invalid input.

## Retired and legacy commands

`badge` is retired and returns exit `2`: static CLI output cannot attest the current repository state. Use a CI workflow-status badge instead.

The old top-level `impact`, `invariants`, `cost`, `capacity`, `budget`, and `evidence` forms remain as temporary aliases and print a migration warning. `install`, `prompt`, `hook`, `worktree`, and `benchmark` are hidden legacy aliases scheduled for removal in 1.0.0. Prefer `init --scope global`, shipped skills, a reviewed pre-commit configuration, standard `git worktree`, and `npm run benchmark` respectively.

## `gate evidence`

```bash
shipproof gate evidence . --list --format json
shipproof gate evidence . --adapter typescript --allow-project-code --format json
shipproof gate evidence . --adapter go --format json
shipproof gate evidence . --adapter rust --allow-project-code --format json
```

Adapters are fixed: repository-local TypeScript `tsc --noEmit`, `go vet ./...` with module downloads disabled, and offline `cargo clippy`. TypeScript and Rust require `--allow-project-code`: the local `tsc` is repository-controlled and Cargo may execute `build.rs`. There is no pass-through for commands or analyzer arguments. Exit `0` is pass, `1` is analyzer findings, and `2` is invalid or unavailable evidence.

## `mcp`

Install the optional peers in the same npm project, then start the local stdio server:

```bash
npm install --save-dev @modelcontextprotocol/sdk@1.29.0 zod@3.25.76
shipproof mcp
```

The server registers five tools: `shipproof_scan`, `shipproof_budget`, `shipproof_capacity`, `shipproof_explain`, and `shipproof_lint_snippet`. `shipproof_explain` accepts `context_level` with the same `summary`, `overview`, and `full` contract as the CLI. `SHIPPROOF_MCP_ROOT` selects the only accessible repository root. The adapter canonicalizes existing paths, rejects traversal and symlink escape, and bounds scanner subprocesses.

## Pre-commit and composite action

The repository exposes the `shipproof-scan` pre-commit hook. Pin the repository `rev` to a reviewed commit SHA.

The root composite `action.yml` accepts `path`, `format`, `output`, `fail-on`, `baseline`, and `max-file-bytes`. Paths must remain inside `GITHUB_WORKSPACE`; output directories must already exist. It does not upload SARIF or request write permissions. The caller owns upload policy and should normally keep `contents: read` as the only default permission.
