# Harness Configuration

- Schema version: 2
- Project ID:

## Routing defaults

- Default operation: start
- Default scale: auto
- Explicit full may be downgraded: no
- Auto-resume validated unfinished run: when no new task or a clear continuation
- Discovery no-progress limit: 2
- Same-blocker attempt limit: 3

## Gates

- Quick: decision when material; acceptance summary for delivery
- Standard: concise plan checkpoint when material; conditional design/decision; acceptance for delivery
- Full: plan; conditional design; decision when material; acceptance for delivery
- Review: findings handoff; no delivery Acceptance Gate
- Design trigger: changed visual direction, flow/information architecture, design system, motion contract, or third-party assets

## Memory

- Authoritative project store: `.harness/MEMORY.json`
- Recall ceiling: 20 records and 12000 UTF-8 bytes
- Global store: `$HARNESS_HOME/MEMORY.json` or `~/.harness/MEMORY.json`
- Derived views: `CONTEXT.md`, `PREFERENCES.md`, `DECISIONS.md`
- Semantic adapter: none
- Semantic cache root: `.harness/.cache/memory`
- Semantic cache is canonical: no

## Capability bindings

Leave backend blank until preflight proves it ready. Do not treat installation as readiness.

| Capability ID | Preferred backend | Fallback | State |
|---|---|---|---|
| agents.parallel | | sequential role passes | UNAVAILABLE |
| agents.isolated | | labeled self-review | UNAVAILABLE |
| docs.versioned | | official docs/repo/local source | UNAVAILABLE |
| repository.remote | | local Git/official web/user evidence | UNAVAILABLE |
| browser.interactive | | E2E/manual evidence/Not verified | UNAVAILABLE |
| image.search | | official design sources/Not used | UNAVAILABLE |
| memory.semantic | | exact authoritative-store scan | UNAVAILABLE |
| evidence.static | | project checks/manual review | UNAVAILABLE |
| evidence.runtime | | focused local checks/Not verified | UNAVAILABLE |

## Local-only capability notes

Keep machine paths, credentials, account names, and private endpoints in ignored `.harness/local-capabilities.md`; never commit them to portable policy.
