# Bounded engineering loop

Use this loop when the user asks for autonomous iteration, continuous improvement, or repeated build-and-verify work. Drive toward a defined acceptance condition; never loop merely to appear active.

## Establish the loop contract

Record before the first change:

- Objective and explicitly excluded scope.
- Current baseline and the evidence command that reproduces it.
- Functional, security, resource, and operational acceptance gates.
- Maximum iterations, elapsed time, compute/cost, and external calls.
- Actions that require human approval.
- Rollback point and evidence location.

Unknown acceptance criteria require a short discovery pass, not an unbounded implementation loop.

## Run one hypothesis per iteration

1. **Observe:** read current code and evidence; identify the highest-value failing gate.
2. **Contract:** state one root-cause hypothesis, expected effect, files in scope, and verification command.
3. **Change:** make the smallest coherent reversible edit.
4. **Verify:** run focused tests first, then relevant full gates. Compare against the same baseline.
5. **Audit:** check authorization, failure behavior, resource bounds, operability, and regression risk.
6. **Decide:** accept the iteration, revert it, or escalate the unknown. Never keep an unverified partial improvement.
7. **Learn:** preserve the result, update the next hypothesis, and stop when a terminal condition is reached.

## Preserve integrity

- Do not weaken a test, threshold, scanner, authorization rule, or acceptance criterion merely to make a gate pass.
- Do not combine unrelated fixes in one iteration. A changed outcome must remain attributable.
- Do not repeat an unchanged command without new evidence or a changed hypothesis.
- Keep deterministic evidence separate from AI interpretation.
- Keep user files and unrelated worktree changes outside the loop.
- Require approval for destructive actions, releases, permission changes, production mutations, and expanded scope.

## Stop conditions

Stop with exactly one result:

- **PASS WITH EVIDENCE:** every required gate passes and the objective is met.
- **CONDITIONAL:** the change works, but a material unknown or medium risk has an owner and next experiment.
- **BLOCKED:** a required invariant fails or safe progress needs new authority, credentials, data, or an external state change.
- **BUDGET EXHAUSTED:** the iteration/time/cost limit is reached. Report the best confirmed state; do not label it complete.
- **NO PROGRESS:** two consecutive iterations do not improve evidence. Stop, revisit the model, and request review rather than thrashing.

## AWE TraceGate integration boundary

Keep responsibilities explicit:

- **AWE TraceGate** owns orchestration, loop state, budgets, approvals, policy, and user experience.
- **ShipProof** owns deterministic commands, focused engineering guidance, evidence formats, and release gates.
- **Adapters** expose the same ShipProof contracts through CLI, pre-commit, GitHub Actions, generated k6 tests, and MCP without duplicating core rules.

Persist a compact iteration record with run ID, iteration number, source revision, hypothesis, changed scope, commands, input/output digests, gate results, decision, and next reason. Redact secrets and personal data.

The orchestrator may recommend the next step. It must not silently relax gates, approve its own consequential action, or declare release authority.
