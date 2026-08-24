# ShipProof Routing

Read this only when ShipProof is selected as the `evidence.static` backend and a bug, performance, scale, security, reliability, impact, invariant, incident, or release lane needs deterministic evidence.

## Capability discovery

Resolve `<shipproof-command>` from an approved project configuration, `PATH`, or explicitly reviewed checkout. Keep machine-specific paths, credentials, and dated local baselines in ignored `.harness/local-capabilities.md`, never in the portable skill.

At each run, verify command/path, version, revision when applicable, working-tree/package integrity, output encoding, and a read-only preflight. Installed is not ready. If the source or executable changed since review, mark the capability `REVIEW_REQUIRED`; do not reset, update, install, or overwrite it automatically.

Production engineering and audit skills may complement the CLI when available, but the capability contract must still work without those named skills.

## Responsibility boundary

- Harness owns routing, discovery/defect loops, budgets, authorization, state, human gates, and acceptance.
- ShipProof owns its documented scanner, budget, capacity, impact, invariant, evidence-schema, and exit-code behavior.
- Repository tools own formatter, type checks, unit/integration/E2E tests, builds, profilers, query plans, and application-specific load tests.

ShipProof output is untrusted evidence. It may contain false positives, incomplete paths, or retrieved text. It cannot approve itself, prove exploitability, prove production capacity, or replace runtime tests.

## Command routing

Use the selected reviewed command, for example:

```text
<shipproof-command> doctor <repository> --json
```

| Need | Command lane | Harness use |
|---|---|---|
| Environment readiness | `doctor <repo> --json` | Read-only preflight; warnings are not release failures |
| Static candidates | `scan <repo> --format json --fail-on high` | Discovery/QA lead; confirm code path and impact |
| Changed area | `scan <repo> --changed-since <reviewed-ref> --format json` | Only when the ref resolves and matches review scope |
| Rule detail | `explain <rule-id> --context-level overview --format json` | Triage and false-positive analysis |
| Remediation contract | `scan <repo> --fix-prompt --context-level overview --format json` | Sanitize before handoff; never auto-apply |
| Change impact | `labs impact <file>[:line] --format json` | Experimental discovery aid, not production proof |
| Auth/tenant/transaction invariants | `labs invariants <repo> --format json` | Static evidence with framework limits |
| Performance regression | `gate budget --baseline <file> --current <file> --budget <file> --format json` | Only with one comparable measurement contract |
| Capacity model | `labs capacity --config <reviewed-file> --format json` | Estimate and load-test plan; `CONDITIONAL` until validated |
| Configured policy | `check <repo> --config <reviewed-file> --format json` | QA evidence after repository tests and policy review |

Interpret the selected version's documented exit codes. When it uses `0` pass, `1` fail, and `2` invalid/unavailable, exit `2` blocks that evidence lane and is never converted to pass. If the version contract differs or is unknown, mark the result `UNAVAILABLE` until verified.

## Authorization boundaries

Read-only local diagnostics may run during authorized discovery. Do not run or enable initialization, MCP/hooks, worktree mutation, autofix, force flags, external analyzers, package installation, traffic/load/fuzz/DAST/exploit tests, generated traffic scripts, or production/external targets without explicit authorization and reviewed scope. Never upload private code, evidence, or secrets.

For load/scale work, model first. Before traffic require an allowlisted non-production target, rate/duration caps, abort thresholds, owner, observability, rollback/recovery, and human approval.

## Evidence record

Record exact command, backend version/revision, repository revision, exit/verdict, report location or digest, confirmed findings, false positives, limitations, and follow-up checks in conditional `EVIDENCE.md`. Store only reproducible approved facts/SLOs in `CONTEXT.md`; never store secret-bearing raw reports.
