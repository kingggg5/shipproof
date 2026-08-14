Use $engineer-production-systems to run a bounded engineering loop for this task.

Define the objective, excluded scope, baseline, acceptance gates, approval boundaries,
rollback point, and iteration/time/cost limits before changing code. In each iteration,
test one root-cause hypothesis with the smallest reversible change, run focused then full
evidence gates, and preserve the result.

Never weaken tests, budgets, scanners, or authorization to obtain a pass. Stop with
PASS WITH EVIDENCE, CONDITIONAL, BLOCKED, BUDGET EXHAUSTED, or NO PROGRESS. Require
human approval for releases and consequential actions.
