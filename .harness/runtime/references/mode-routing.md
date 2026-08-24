# Adaptive Mode Routing

Scale and operation are independent. Record `operation`, `requested_scale`, `selected_scale`, and `selection_reason` in `STATE.json`.

## Operations

| Operation | Meaning |
|---|---|
| `start` | Start a new delivery run. This is the default. |
| `resume` | Validate project identity and state, then continue the one recorded next action. |
| `review` | Keep implementation roles read-only and return severity-ordered findings. |
| `init` | Create missing canonical files and approved provider adapters without overwriting existing content. |
| memory command | Run the lightweight memory protocol without the delivery graph. |

An explicit operation wins. An unfinished run means `run_id` is non-empty and state is not `DONE`. With no explicit operation: a request containing a clearly new task uses `start`; no new task plus a validated unfinished run uses `resume`; a request that clearly continues the active objective also uses `resume`. If the new request and active run overlap ambiguously, ask whether to resume or start rather than replacing state silently. A freshly initialized blank state is not unfinished. `review` may combine with any scale. Resume retains its selected scale unless new evidence requires escalation or the human explicitly changes it.

## Deterministic scale selection

1. An explicit `full`, `standard`, or `quick` selects that scale. Never downgrade explicit `full`. If explicit `quick` is unsafe, pause and recommend escalation before material work.
2. With `auto`, select `full` when any full trigger applies.
3. Otherwise select `quick` only when every quick condition applies.
4. Otherwise select `standard`.

Full triggers: security, privacy, authentication/authorization, schema or data migration, concurrency correctness, production/external mutation, irreversible work, multi-service architecture, incident/release readiness, material dependency or supply-chain risk, performance/scale claims, or uncertainty that can change architecture or authorization.

Quick requires all of these: one bounded domain, unambiguous acceptance, low risk, no material external effect, no durable architecture/schema choice, and a deterministic focused verification path. A typo, isolated style correction, or proven one-file regression often qualifies.

Standard covers normal multi-file bugs and features, cross-component work, and product changes without a full trigger.

Escalate only upward when evidence changes the classification. Record the trigger and continue from the current state; do not discard valid completed work.

## Roles and gates

| Scale | Typical active roles | Human checkpoints |
|---|---|---|
| quick | PM, one applicable implementer, deterministic QA pass; Researcher/Designer only on trigger | Decision when material; Acceptance summary for delivery |
| standard | PM, Planner, applicable specialists, QA; Researcher/Designer conditional | Concise plan checkpoint for material scope; conditional Design/Decision; Acceptance for delivery |
| full | PM, Planner, Researcher, every applicable specialist, isolated QA when available | Bounded discovery, Plan, conditional Design, Decision as needed, Acceptance for delivery |

Do not activate a role or gate merely because its row exists. The Design Gate triggers only for a new or changed visual direction, flow/information architecture, design system, motion contract, or third-party asset choice.

## Review semantics

- `review quick`: one bounded artifact or diff and focused checks.
- `review standard`: ordinary repository/diff review with applicable domains.
- `review full`: release, incident, security/privacy, architecture, performance/scale, or explicitly deep audit.

Review never authorizes implementation, external mutation, hidden cleanup, or durable-memory mutation. It ends with a findings handoff rather than an Acceptance Gate unless the user explicitly starts a remediation run. A same-agent review is labeled `self-review`; only isolated context and ownership may be labeled `independent QA`.
