# Command reference

ShipProof's core npm CLI uses only Node built-ins. It never turns repository configuration into an arbitrary command. Python gates and evidence adapters are launched from fixed allowlists with argument arrays and shell interpretation disabled.

## Install

```bash
npm install --global github:kingggg5/shipproof
shipproof help
```

Use `SHIPPROOF_PYTHON` only when Python is not discoverable as `py -3`, `python3`, or `python`. Set it to an executable path or command name, not a command string with arguments. The detected runtime is probed once per process and shared by every gate.

Policy gates launched by `shipproof check` buffer scanner JSON with a 120 second timeout and a 16 MB output cap. Override with `SHIPPROOF_GATE_TIMEOUT_MS` (minimum 1000) and `SHIPPROOF_MAX_BUFFER_BYTES` (minimum 65536); a timeout, an output overflow, or a scanner crash is always reported as exit `2` (invalid or unavailable evidence), never as a gate block.

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

The arguments after `scan` match `scan_repo.py`. `--fail-on` accepts `critical`, `high`, `medium`, `low`, or `none`. `--block-min-proof` accepts `L0`, `L1`, or `L2` and defaults to `L1`: findings below that proof level still appear, but they produce `REVIEW` instead of `BLOCK` unless they are allowlisted high-confidence secrets or application debug flags. `--scan-profile` accepts `auto`, `application`, or `library`; `auto` treats repositories without application entrypoints as libraries and downranks application-oriented rules. `--changed-since GIT_REF` selects changed files (added, copied, modified, renamed, plus untracked files) and returns exit `2` outside a git repository or for an unresolvable ref. The ref is recorded as `summary.changed_since`. Repeat `--exclude` with repository-relative globs; absolute and parent-traversal patterns are rejected.

The Node launcher resolves Python from absolute host `PATH` entries and rejects repository-local shadow binaries. For `scan <path>`, the selected path is also the runtime trust boundary, while the original launcher directory remains the working directory so relative scanner arguments keep their documented meaning. Missing or unsupported runtimes return exit `2` rather than running a repository-provided interpreter.

`--cross-file` opts into offline interprocedural taint analysis across selected, successfully read files; unsanitized flows into supported dangerous sinks become `L2` findings. `--jobs N` uses worker processes for large repositories with byte-identical output to `--jobs 1`. If the pool fails, the scanner resets partial results and counters before retrying sequentially, with a stderr note.

`--inspect-archives` opts into bounded in-memory inspection of ZIP-based containers (`.zip`, Office Open XML, JAR/WAR/wheel). Members are never extracted to disk or executed. Paths are reported as `archive.zip!/inner.js`. Nested archives, path escape, encryption, member/byte/ratio bombs, and non-ZIP containers such as `.tar` / `.7z` stay incomplete. Default scans still omit container members.

`--trace` adds a deterministic decision trace to JSON, Markdown, or terminal repository-scan output. It reports bounded counts for rule selection, file selection, filters, baseline suppression, and gate evaluation. It deliberately excludes source text, evidence text, finding paths, secret values, timestamps, timings, user identifiers, and network telemetry. The option is rejected for SARIF, GitHub annotations, snippets, explanations, fix prompts, and autofix modes instead of silently doing less than requested.

`--context-level summary|overview|full` progressively discloses `--fix-prompt` content. `summary` is the compact remediation contract, `overview` adds local context and implicit requirements, and `full` adds engineering dimensions and failure scenarios. The default is `full`, preserving existing output. Exit `0` means the configured gates passed, `1` means a severity or explicitly enabled completeness gate failed, and `2` means evidence or input was invalid.

### Coverage and baseline contracts

`summary.completeness` accounts for the selected source scope, not all repository content or runtime behavior. Unreadable files/directories, parser-limit failures, source files above `--max-file-bytes`, overlong source lines (over 8,192 characters), symlinks/reparse points, unknown binaries, and containers such as ZIP with uninspected members set `is_complete: false`. A would-be pass becomes `CONDITIONAL`; high/critical findings still produce `BLOCK`. The policy-check report also retains `CONDITIONAL` when its gates pass but scan coverage is incomplete. Repository `scan`, the GitHub Action, and MCP default to fail-closed incomplete coverage; the production `check` command additionally enforces a full-root scan, a high security floor, a bounded 10 MB source limit, and ignores repository policy attempts to weaken those controls.

| Entry point | Completeness gate |
| --- | --- |
| Python / Node `scan` | Enabled by default; `--fail-on-incomplete` remains accepted for explicit command intent; `--allow-incomplete` is an explicit exploratory override |
| `check` repository policy | Always fail-closed for incomplete scan evidence |
| GitHub Action | `fail-on-incomplete: "true"` (default) |
| MCP `shipproof_scan` | `fail_on_incomplete: true` (default) |

Repository scan, Action, and MCP defaults are strict. `scan --allow-incomplete`, or an Action/MCP boolean set to `false` (translated to that flag), is an explicit exploratory override that must not be used for release evidence. `check` ignores repository attempts to weaken the high security floor or fail-closed coverage. The gate remains effective with `--fail-on none` and autofix/dry-run. MCP returns evidence rather than process exit codes; strict mode adds `decision_trace.gate.failed`. JSON and SARIF Action summaries flag incomplete coverage; SARIF also records `runs[0].properties.completeness` and an unsuccessful invocation with a warning notification.

Changed-only scope, explicit excludes, and baseline-file exclusions are applied before omission counts. Recognized assets (including generated `.sarif` reports) and database artifacts are deliberately outside source inspection; unknown binaries and symlinks/reparse points are counted as incomplete evidence. Dependency/build trees are pruned for bounded performance, but repository scans consult the Git index (and explicit changed-file selections) and inspect tracked files inside those trees, so a committed payload cannot hide behind a conventional directory name. Untracked members of pruned trees are not enumerated; unreadable counts may include a directory error rather than a known file count. Database artifacts are identified from a bounded header, not by analyzing their contents. `files_scanned` counts successful source/artifact inspections, not failed reads. Source and framework-manifest reads are byte-bounded; unsupported UTF-8 source is reported as unreadable. Scan a quiescent checkout: this is not a filesystem snapshot or a guarantee that every language construct, hidden payload, or runtime dependency was analyzed.

`--show-suppressed` lists baseline-suppressed findings in JSON, Markdown, or terminal. SARIF retains these findings as external suppressions even without that flag and also accepts the flag. It is rejected with GitHub annotations, snippet/stdin, explanation, fix-prompt, and autofix modes instead of silently ignoring the request.

Baseline format version 2 accepts legacy string fingerprints, reasoned fingerprint objects, and human-authored glob rules. Every supplied matcher in a rule (`id`, `path`, `evidence`) must match; at least one matcher and a non-empty `reason` are required. Unknown fields and duplicate JSON keys are rejected to prevent accidental scope widening. Matcher/metadata strings are limited to 512 printable characters, fingerprints to 10,000 entries, rules to 256, and input/output to 2,000,000 bytes. Missing files, invalid values, or exceeded limits return exit `2`.

`--baseline-out` writes active fingerprints and preserves glob rules. Supply `--baseline-reason TEXT` after reviewing the debt; without it the reason is `Generated baseline; review required`. Review the generated file before loading it with `--baseline`; generation is not approval. Keep secrets out of reason and matcher text. Version-1 string baselines remain readable. Fingerprints use the existing finding identity, not whole-file/content digests; `scanner_version` is informational with a major-version warning, not cryptographic provenance or a stale-suppression check.

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

Loads a version-1 repository policy and executes its fixed scan, performance-budget, and capacity gates. The configuration is a strict, dependency-free YAML subset: mappings use two-space indentation, `scan.exclude` is a scalar list, and anchors, tags, block scalars, executable values, duplicate keys, unknown fields, path traversal, and arbitrary commands are rejected. Policy is repository-authored input, so `check` ignores policy attempts to narrow the scan or lower the security floor and always fails closed when scan evidence is incomplete.

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
shipproof gate evidence --import fixtures/external-evidence/valid-envelope.json --format json
```

Adapters are fixed: repository-local TypeScript `tsc --noEmit`, `go vet ./...` with module downloads disabled, and offline `cargo clippy`. TypeScript and Rust require `--allow-project-code`: the local `tsc` is repository-controlled and Cargo may execute `build.rs`. Even the repository-local TypeScript version probe is not executed during discovery without that consent; `--list` reports `approval required` instead. There is no pass-through for commands or analyzer arguments. Every ready adapter must pass its own version probe; JSON evidence records that bounded version string. Diagnostics are redacted, capped at 200 lines and 4,096 characters per line, and the child process has a fixed 2 MB output cap and 120-second timeout. Timeout, output overflow, crash, or unavailable tools return exit `2`; analyzer findings return `1`; a usable clean analyzer run returns `0`.

`--import FILE` is a separate opt-in path for a versioned external evidence envelope. The file must declare a non-ShipProof tool identity, semantic version, config/target digests, timestamp, and limitations. Imported findings keep `original_rule_id` and `proof_level: external`; they are never rewritten as native ShipProof proof. Malformed, oversized, or identity-spoofed envelopes return exit `2`. The importer does not download, execute, or refresh the originating tool.

## `mcp`

Install the optional peers in the same npm project, then start the local stdio server:

```bash
npm install --save-dev @modelcontextprotocol/sdk@1.32.1 zod@3.25.76
shipproof mcp
```

The Zod peer range is `^3.25.76 || ^4.6.7`, supporting Zod 3 and 4. To use Zod 4, install the optional peers with:

```bash
npm install --save-dev @modelcontextprotocol/sdk@1.32.1 zod@4.6.7
```

Both peer versions use the same five-tool contract. Capacity `users` must be a
positive safe integer (at most `9007199254740991`) with either Zod major.
Maintainers can explicitly run `npm run test:mcp:peers -- 3.25.76` or
`npm run test:mcp:peers -- 4.6.7` to install peers in a fresh packed consumer and
exercise all five tools. These opt-in tests access npm; ordinary CLI use and the
default package smoke test do not install MCP peers. CI also tests both pinned
peer versions against Node 20/22/24, with missing peers treated as a test failure.

The server registers five tools: `shipproof_scan`, `shipproof_budget`, `shipproof_capacity`, `shipproof_explain`, and `shipproof_lint_snippet`. `shipproof_explain` accepts `context_level` with the same `summary`, `overview`, and `full` contract as the CLI. `SHIPPROOF_MCP_ROOT` selects the only accessible repository root. The adapter canonicalizes existing paths, rejects traversal and symlink escape, and bounds scanner subprocesses.

Every `shipproof_scan` call reads current source files. `SHIPPROOF_MCP_CACHE_MS` is deprecated: values from `0` through `3600000` remain accepted and validated for configuration compatibility, but no scan verdict is cached. A nonzero value produces a startup warning on stderr. Python runtime discovery is still cached; repository findings are not.

## Pre-commit and composite action

The repository exposes the `shipproof-scan` pre-commit hook. Pin the repository `rev` to a reviewed commit SHA.

The root composite `action.yml` accepts `path`, `format`, `output`, `fail-on`, `baseline`, and `max-file-bytes`. Paths must remain inside `GITHUB_WORKSPACE`; output directories must already exist. It does not upload SARIF or request write permissions. The caller owns upload policy and should normally keep `contents: read` as the only default permission.
