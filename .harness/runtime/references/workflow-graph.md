# Workflow Graph

This is the only canonical delivery graph and transition policy. `STATE.json` is the machine-readable state authority. `WORKFLOW.md` records the human-readable run contract and checkpoint evidence without copying this graph.

## Canonical graph

```mermaid
flowchart TD
	H[Human] <--> PM[Project Manager]
	PM --> R{Route and capability preflight}
	R -->|discovery trigger| D[Bounded discovery]
	R -->|plan needed| P[Planner / Architect]
	R -->|quick implementation-ready| C{Applicable work}
	R -->|read-only review-ready| QA[Tester / Reviewer / QA]
	D -->|material question| H
	D -->|plan-ready| P
	P --> PG{Plan checkpoint or gate}
	PG -->|revise| PM
	PG -->|approved or not required| C{Applicable work}
	C --> DS[Product Designer]
	C --> FE[Frontend Engineer]
	C --> BE[Backend Engineer]
	DS --> DG{Design gate when triggered}
	DG -->|revise| DS
	DG -->|approved| FE
	FE --> I[Integration]
	BE --> I
	DS --> I
	I --> QA
	QA -->|fail| T[Classify and route defect]
	T --> PM
	QA -->|delivery pass| A{Human acceptance}
	QA -->|review findings ready| RH[Review handoff]
	A -->|changes| PM
	A -->|accepted| M[Consolidate memory and finish]
	RH --> RD[Finish review without memory mutation]
```

Researcher supports discovery, planning, design, and verification as a read-only evidence role. Inactive roles are `N/A`; do not create work merely to exercise all seven roles.

## States and legal transitions

Allowed states are `INTAKE`, `DISCOVERY`, `PLAN`, `WAITING_PLAN`, `DESIGN`, `WAITING_DESIGN`, `BUILD`, `INTEGRATE`, `VERIFY`, `REWORK`, `WAITING_DECISION`, `WAITING_ACCEPTANCE`, `DONE`, and `BLOCKED`.

| From | Allowed next states |
|---|---|
| INTAKE | DISCOVERY, PLAN, BUILD, VERIFY, WAITING_DECISION, BLOCKED |
| DISCOVERY | DISCOVERY, PLAN, WAITING_DECISION, BLOCKED |
| PLAN | WAITING_PLAN, DESIGN, BUILD, VERIFY, WAITING_DECISION |
| WAITING_PLAN | PLAN, DESIGN, BUILD, BLOCKED |
| DESIGN | WAITING_DESIGN, BUILD, WAITING_DECISION |
| WAITING_DESIGN | DESIGN, BUILD, BLOCKED |
| BUILD | INTEGRATE, VERIFY, REWORK, WAITING_DECISION, BLOCKED |
| INTEGRATE | VERIFY, REWORK, BLOCKED |
| VERIFY | REWORK, WAITING_ACCEPTANCE, DONE (read-only review only), BLOCKED |
| REWORK | DISCOVERY, PLAN, DESIGN, BUILD, INTEGRATE, VERIFY, WAITING_DECISION, BLOCKED |
| WAITING_DECISION | DISCOVERY, PLAN, DESIGN, BUILD, VERIFY, BLOCKED |
| WAITING_ACCEPTANCE | REWORK, DONE, BLOCKED |
| BLOCKED | DISCOVERY, PLAN, DESIGN, BUILD, VERIFY, WAITING_DECISION |
| DONE | INTAKE |

Reject any other transition. A resume must restore exactly one `next_action`; if more than one action appears active, normalize at a human checkpoint.

`VERIFY -> DONE` is legal only for an explicit read-only review after its findings handoff. It performs no Acceptance Gate, implementation, stateful external action, or durable-memory consolidation. Delivery runs must use `VERIFY -> WAITING_ACCEPTANCE -> DONE`.

## Role contracts

| Role | Responsibility | Default boundary |
|---|---|---|
| Project Manager | Scope, routing, state, ownership, gates, integration, memory, handoff | Sole shared-state writer |
| Planner / Architect | System map, contracts, tasks, dependencies, rollout, measurable DoD | Read-only until approval |
| Researcher | Repository and external evidence, provenance, injection screening, unknowns | Read-only |
| Product Designer | User outcome, flows, hierarchy, states, tokens, accessibility, motion and reference contract | Approved design scope |
| Frontend Engineer | Client behavior, accessibility, responsive UI, data integration, frontend tests and budgets | Assigned client files |
| Backend Engineer | APIs, domain logic, data, validation, authorization, concurrency, observability and tests | Assigned server/data files |
| Tester / Reviewer / QA | Acceptance matrix, negative/boundary cases, final diff, regression and risk verification | Read-only; isolated when claimed independent |

Roles are contracts, not processes. Map them to isolated agents, sequential isolated sessions, or labeled same-agent passes using [capability-contract.md](capability-contract.md). A same-context pass can verify work but is never called independent.

## Role packet and ownership

Create a packet from `assets/templates/ROLE-PACKET.md` for each active parallel/material role. A quick same-agent pass may keep the same required fields as one inline workflow-ledger row instead of creating a separate file. Every packet includes objective, exclusions, verified memory IDs, inputs, owned files or read-only scope, capability/permission limits, required evidence, checks, stop condition, and expected next state. Give semantic-memory results only after canonical ID/source verification; never forward raw retrieval dumps.

The Project Manager serializes overlapping file ownership. Frontend and backend may run in parallel only after their interface contract is stable. Designer may support implementation but does not silently rewrite an approved direction. QA does not repair production code during its verification pass.

## Failure routing

Classify before retrying: requirement, discovery, plan/contract, design contract, implementation, test expectation, environment/capability, performance budget, or scale evidence. Preserve the same workload and threshold when repairing performance failures. Never weaken a valid assertion or label unavailable evidence as a pass.

Discovery stops after two consecutive cycles add no material evidence. The same blocker surviving three evidence-based attempts becomes `BLOCKED` or `WAITING_DECISION`; record attempted fixes and ask the human rather than retrying blindly.

## Checkpoint writes

The Project Manager updates `STATE.json` and the current workflow only at intake, plan/gate, integration, verification, blocker, and completion. Use optimistic memory revisions from [memory-loop.md](memory-loop.md). Role agents return structured packets and do not concurrently edit `.harness/`.
