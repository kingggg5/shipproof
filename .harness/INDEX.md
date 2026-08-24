# Harness Index

- Schema version: 2
- Project ID: project-25bc2383-ce85-49b1-b32b-49387e479288
- Memory store: `MEMORY.json`
- Active run ID: RUN-ff934524c3ec446b9b01047596b5d8d1
- Active state: WAITING_ACCEPTANCE
- Active workflow: `WORKFLOW.md`
- State authority: `STATE.json`
- Last verified: 2026-08-24T09:17:12Z

## Load order

1. Applicable platform, user, and repository instructions.
2. This index, `CONFIG.md`, `IDENTITY.json`, and `STATE.json`.
3. Active `WORKFLOW.md` and its current-turn overrides.
4. Query-selected, verified records from authoritative `MEMORY.json`, then an authorized global `MEMORY.json`.
5. Only optional annexes activated below.

`CONTEXT.md`, `PREFERENCES.md`, and `DECISIONS.md` are readable projections. Never use a stale projection instead of `MEMORY.json`, and never edit generated record rows directly.

## Files

| File | Purpose | Authority/load condition |
|---|---|---|
| `IDENTITY.json` | Stable Project ID and sanitized repository fingerprint | Identity authority; always |
| `CONFIG.md` | Portable routing, gate and memory defaults | Always at intake/resume/recall |
| `MEMORY.json` | Durable facts, preferences, decisions, commands and tombstones | Durable-memory authority; query-selected |
| `STATE.json` | Run state and exactly one next action | Run-state authority; always |
| `WORKFLOW.md` | Current request, overrides, gates, role/evidence summaries | Active run |
| `CONTEXT.md` | Generated fact/command/contract/risk view | Human inspection only |
| `PREFERENCES.md` | Generated project-preference view | Human inspection only |
| `DECISIONS.md` | Generated decision view | Human inspection only |
| `DESIGN.md` | Approved UI/design contract | UI lane only |
| `EVIDENCE.md` | Detailed bug/performance/security/UI/audit evidence | Activated lane only |
| `EVALUATION.md` | Harness/model benchmark evidence | Benchmark only |

## Active optional annexes

- `EVIDENCE.md` — release-readiness, rule-contract, and performance evidence for the active run.

## Archives

- Last archived workflow:
- Last compacted:
