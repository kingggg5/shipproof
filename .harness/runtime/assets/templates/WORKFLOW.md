# Harness Workflow

- Schema version: 4
- Project ID:
- Run ID:
- State authority: `STATE.json`
- Memory revision at load: 0

## Request and route

- User request:
- Operation:
- Requested scale:
- Selected scale/reason:
- Client/provider/model/effort when known:
- Capability profile ID or summary:
- Explicit exclusions:

## Current-turn overrides

These expire with this run and do not mutate durable memory.

| Key | Override | Conflicting record ID | Reason | Future action |
|---|---|---|---|---|

## Acceptance criteria

| ID | Criterion | Verification | Status |
|---|---|---|---|

## Checkpoints and gates

| Checkpoint/gate | Required decision or evidence | Status | Human/date |
|---|---|---|---|
| Intake | Route, scope, risk, capabilities | Pending | |
| Plan | Scope, exclusions, task graph, contracts | Pending or N/A | |
| Design | Triggered design contract only | Pending or N/A | |
| Decision | Durable/risky choices | Pending or N/A | |
| Integration | Stable contracts and ownership | Pending or N/A | |
| Verification | Acceptance matrix and evidence | Pending | |
| Acceptance | Delivery only; review uses findings handoff | Pending or N/A | |

## Capability bindings

| Capability ID | Backend/version | Permission/isolation | State | Fallback/limitation |
|---|---|---|---|---|

## Role packets

| Packet ID | Role/pass | Isolation label | Objective | Scope/owned files | State | Return evidence |
|---|---|---|---|---|---|---|

## Task graph

| Task | Owner/pass | Depends on | Deliverable | State |
|---|---|---|---|---|

## Memory recall manifest

| ID | Scope | Load state | Verification state | Used? | Reason |
|---|---|---|---|---|---|

## Memory transactions

`MEMORY.json` is authoritative. This table is an audit projection and may be rebuilt from its last committed transaction.

| Tx ID | Operation | Record ID | Before revision | After revision | Result/adapter state |
|---|---|---|---|---|---|

## Verification summary

Put detailed bug, performance, scale, security, research, UI, or ShipProof evidence in conditional `EVIDENCE.md`.

| Check | Command/method | Result | Evidence location | Date |
|---|---|---|---|---|

## Defect loop

| Blocker ID | Attempt | Classification | Evidence | Routed to | Result |
|---|---|---|---|---|---|

## Handoff snapshot

- Outcome:
- Material changes or findings:
- Passed checks:
- Not verified:
- Residual risks:
- Human decisions:
- Memory/adapter changes:
- Reusable next command:
