# Command reference

ShipProof's npm CLI is a zero-dependency front door. It never reads repository configuration and executes an arbitrary command. Python gates are launched with a fixed script path, an argument array, and shell interpretation disabled.

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
```

Prints a versioned prompt from an allowlisted catalog. Names are `build`, `audit`, `threat-model`, `database`, `performance`, `systems`, `incident`, and `ai-agent`.

## `scan`

```bash
shipproof scan . --format markdown --fail-on high
shipproof scan . --format sarif --output shipproof.sarif --fail-on high
shipproof scan . --format json --baseline-out .shipproof-baseline.json --fail-on none
```

The arguments after `scan` match `scan_repo.py`. `--fail-on` accepts `critical`, `high`, `medium`, `low`, or `none`. Exit `0` means no finding met the threshold, `1` means the threshold failed, and `2` means evidence or input was invalid.

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

The config may contain the input keys directly or inside an `inputs` object. Unknown keys and invalid types fail closed. The result estimates design RPS, read/write and database work, in-flight work, instance/CPU/memory hypotheses, and a load-test ladder. It cannot prove capacity; replace assumptions and run authorized production-shaped tests.
