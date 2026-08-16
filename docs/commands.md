# Command reference

ShipProof's core npm CLI uses only Node built-ins. It never turns repository configuration into an arbitrary command. Python gates and evidence adapters are launched from fixed allowlists with argument arrays and shell interpretation disabled.

## Install

```bash
npm install --global github:kingggg5/shipproof
shipproof help
```

Use `SHIPPROOF_PYTHON` only when Python is not discoverable as `py -3`, `python3`, or `python`. Set it to an executable path or command name, not a command string with arguments.

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
```

Copies skills to project-scoped discovery paths:

- Codex: `<project>/.agents/skills`
- Claude Code: `<project>/.claude/skills`

Existing skill directories are skipped. `--force` replaces only the two fixed ShipProof skill directories after verifying each destination remains inside the selected skills root.

## `install`

```bash
shipproof install --target both
```

Copies skills to user discovery paths:

- Codex: `~/.agents/skills`
- Claude Code: `~/.claude/skills`

For managed or test environments, override the final skills directories with `SHIPPROOF_CODEX_SKILLS_DIR` and `SHIPPROOF_CLAUDE_SKILLS_DIR`.

## `prompt`

```bash
shipproof prompt list
shipproof prompt database
shipproof prompt ai-agent
shipproof prompt loop
```

Prints a versioned prompt from an allowlisted catalog. Names are `build`, `audit`, `threat-model`, `database`, `performance`, `systems`, `incident`, `ai-agent`, and `loop`. The loop prompt adds explicit iteration, evidence, approval, no-progress, and budget stop conditions.

## `scan`

Running `shipproof` with no command at all is equivalent to `shipproof scan`.

```bash
shipproof scan . --format markdown --fail-on high
shipproof scan . --format sarif --output shipproof.sarif --fail-on high
shipproof scan . --format json --baseline-out .shipproof-baseline.json --fail-on none
shipproof scan . --changed-since origin/main
```

The arguments after `scan` match `scan_repo.py`. `--fail-on` accepts `critical`, `high`, `medium`, `low`, or `none`. `--changed-since GIT_REF` limits the scan to files changed relative to a git ref (added, copied, modified, renamed, plus untracked files) and fails closed with exit `2` outside a git repository or on an unresolvable ref; the ref is recorded under `changed_since` in JSON output. Repeat `--exclude` with repository-relative glob patterns to skip generated or vendored paths. Parent traversal and absolute patterns are rejected. Exit `0` means no finding met the threshold, `1` means the threshold failed, and `2` means evidence or input was invalid.

## `check`

```bash
shipproof check .
shipproof check . --config .shipproof.yml --format json
```

Loads a version-1 repository policy and executes its fixed scan, performance-budget, and capacity gates. The configuration is a strict, dependency-free YAML subset: mappings use two-space indentation, `scan.exclude` is a scalar list, and anchors, tags, block scalars, executable values, duplicate keys, unknown fields, path traversal, and arbitrary commands are rejected.

Exit `0` means every declared evidence gate passed, exit `1` means a declared scan or performance gate blocked, and exit `2` means the policy or required evidence was invalid or unavailable. Capacity remains explicitly `CONDITIONAL` evidence and does not block merely because the model requires production-shaped validation.

## `budget`

```bash
shipproof budget --baseline baseline.json --current current.json \
  --budget budget.json --format markdown
```

The gate accepts finite numeric metrics and explicit `lower`/`higher` directions. Define a relative regression limit, an absolute min/max, or both. Exit `1` is a measured failure; exit `2` is missing or invalid evidence.

## `capacity`

```bash
shipproof capacity --users 1000000 --dau-ratio 0.25 \
  --peak-hour-ratio 0.20 --actions-per-session 12 \
  --requests-per-action 2 --burst-multiplier 2 --instance-rps 250

# Reusable workload assumptions; explicit CLI values override this JSON
shipproof capacity --config workload.json --format json
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

Generate a k6 file without embedding a target or token:

```bash
shipproof capacity --config shipproof.config.json --export-k6 load-test.js
shipproof capacity --config shipproof.config.json --export-k6 load-test.js --force
```

Existing files are not replaced without `--force`. One k6 iteration makes one request, so the constant-arrival-rate scenario maps the rounded design peak RPS to iterations per second. Review the generated concurrency allocation and run only against an authorized environment.

## `evidence`

```bash
shipproof evidence . --list --format json
shipproof evidence . --adapter typescript --format json
shipproof evidence . --adapter go --format json
shipproof evidence . --adapter rust --allow-project-code --format json
```

Adapters are fixed: repository-local TypeScript `tsc --noEmit`, `go vet ./...` with module downloads disabled, and offline `cargo clippy`. Rust requires `--allow-project-code` because Cargo may execute `build.rs`. There is no pass-through for commands or analyzer arguments. Exit `0` is pass, `1` is analyzer findings, and `2` is invalid or unavailable evidence.

## `mcp`

Install the optional peers in the same npm project, then start the local stdio server:

```bash
npm install --save-dev @modelcontextprotocol/sdk@1.29.0 zod@3.25.76
shipproof mcp
```

The server registers `shipproof_scan`, `shipproof_budget`, and `shipproof_capacity`. All are annotated read-only and call the same bounded implementations as the CLI. `SHIPPROOF_MCP_ROOT` selects the only accessible repository root. The adapter canonicalizes existing paths, rejects traversal and symlink escape, propagates cancellation, and caps each process at 30 seconds and 2 MB.

## Pre-commit and composite action

The repository exposes the `shipproof-scan` pre-commit hook. Pin the repository `rev` to a reviewed commit SHA.

The root composite `action.yml` accepts `path`, `format`, `output`, `fail-on`, `baseline`, and `max-file-bytes`. Paths must remain inside `GITHUB_WORKSPACE`; output directories must already exist. It does not upload SARIF or request write permissions. The caller owns upload policy and should normally keep `contents: read` as the only default permission.
