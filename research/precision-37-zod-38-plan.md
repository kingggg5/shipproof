# Precision #37 and Zod #38 implementation contract

Baseline: `fde6ef8a251745e359e6e2cebcc89e9f7f47d570` (22 October 2026).

## Invariants

- Keep the offline/read-only scanner, stable rule IDs, schemas and exit semantics.
- Do not change precision thresholds, FP budgets, proof floors, severities or finding
  scopes to hide findings. Do not remove packages, rewrite upstream source hashes,
  blanket-label unknowns false positive, or suppress results to pass the gate.
- Preserve the original 30-package corpus and its raw results. Its baseline has
  146 findings, 136 unreviewed, including 66 high/critical. A mutable Action reference
  is a real control gap, not a false positive because it occurs in a popular package.
- The user explicitly approved paired original/remediated evaluation. Preserve
  every original package/source digest and require its reviewed positives to be
  detected; apply the unchanged quiet thresholds to genuinely remediated copies.
  Record exact reviewed transformations and both legs, never rename true positives
  as false positives. Reject missing sources, unverified changes or missing positives.
- Retain optional Zod 3 compatibility while adding Zod 4. Align the capacity user
  count with the safe-integer bound across both schema versions and document it.
  Keep zero core runtime
  dependencies, bounded MCP execution, path confinement, fresh evidence and no
  non-protocol stdout. SDK stays pinned to 1.32.1.

## Implementation slices

1. Zod peer range `^3.25.76 || ^4.6.7`, pinned dev peer 4.6.7; source and genuine
   installed-tarball MCP contracts on pinned 3.25.76/4.6.7, Node 20/22/24 in CI.
   Test all five tools, invalid values, traversal, byte limits, fresh rescans,
   schemas, defaults and missing-peer behavior. Keep network installs opt-in in
   maintainer tests, never in the default consumer/CLI path.
2. Triage source-backed findings by detector root cause. Start with SP621's missing
   HTTP-handler context and SP061's over-broad treatment of rethrowing handlers.
   Preserve genuine SP203 detections. Add failing positive/negative/adversarial
   real-walker regressions before implementing bounded corrections.
3. Run the original full corpus, unchanged precision gate, assurance generators,
   full local checks, high self-scan, coverage, package boundary and benchmark jobs.
   Record actual results and source digests, including any remaining true positives.

## Delivery and bounds

Use reviewable commits, existing PR #38 and a focused precision PR as appropriate;
merge only verified heads. Do not publish a release, move tags or publish npm.
Do not run external active scanning, paid model calls or unbounded fuzz/load work.
Use focused regressions per hypothesis; after two non-improving iterations, stop
that approach and reassess the evidence. Maintain concise progress checkpoints.
QA is primary self-review plus explicitly scoped mechanical assistance, not an
independent security certification.
