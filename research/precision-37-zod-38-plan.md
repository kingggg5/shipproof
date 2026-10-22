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

## Implementation result: local evidence, 22 October 2026

Zod compatibility is merged in [PR #38](https://github.com/kingggg5/shipproof/pull/38).
Its source and installed-tarball MCP peer matrix passed all six Node 20/22/24
and Zod 3.25.76/4.6.7 combinations. Precision delivery remains subject to the
focused PR's exact-head CI and live Benchmarks run.

| Measured leg | Packages / files | Application findings | High/critical | Gate high+medium |
| --- | --- | ---: | ---: | ---: |
| Untouched original sources, corrected detectors | 30 / 867 | 130 | 54 | 74 |
| Reviewed remediated source copies | 30 / 867 | 72 | 0 | 16 |

The original leg intentionally still fails the zero-high quiet gate. The paired
gate first requires all 54 reviewed original high-signature locations, then
checks the remediated leg against the unchanged ceilings. These positive sites
establish rule predicates, not 54 confirmed exploitable application bugs.

The [reviewed recipes](../benchmarks/clean-corpus-remediations.json) change nine
files: pin 51 Action references at their original refs' verified commits, disable
shell interpretation in one reference profile, bound the example HTTP server's
header reads, and retain its shutdown CancelFunc. The shell-free reference
intentionally changes compound-string command semantics; it is not a vendor
patch or a drop-in compatibility claim. Upstream package versions and existing
source pins, ten label records, severities, scopes, proof floors, and precision
thresholds are not relaxed. Newly structural predicates carry L1 local evidence;
this strengthens evidence rather than hiding findings below a gate.

Confirmed detector corrections cover string versus path joins, tuple arity
versus error identity, workflow run commands versus metadata, uppercase Django
settings, effective Go timeout fallback/cancellation ownership, and real local
Rust route context. The real-walker cohort contains 78 cases, supplemented by
root-directory invariance, lexical bounds, shadowing and output-redaction tests.
The cache-parent suppression bug is corrected: identical package bytes no longer
lose deserialization findings merely because the installation lives in `.cache`.

The paired validator rejects missing packages, changed source/recipe hashes,
lost positives, changed profiles/scopes, source omissions, truncated finding
records, inconsistent summaries and mismatched receipts. Failed remediation
retains the original raw report for triage. The plan additionally pins the 15
previously unpinned source sets, with two explicit unmodified MarkupSafe wheel
variants; it does not rewrite the original source manifest. Binary metadata
remains visible in completeness ledgers. Neither leg certifies whole-application
coverage, API compatibility, runtime behavior or a universal precision rate.

SP061's 56 low/advisory observations and other context-dependent results remain
visible and unreviewed; they are not silently labeled false positives to reduce
noise. Further expansion needs representative field evidence rather than a
larger rules count.

Primary boundary references: [Go Server deadlines](https://pkg.go.dev/net/http#Server),
[Go cancellation](https://pkg.go.dev/context#WithTimeout),
[Go strings.Cut return types](https://pkg.go.dev/strings#Cut),
[Go blank identifier](https://go.dev/ref/spec#Blank_identifier),
[Django host validation](https://docs.djangoproject.com/en/5.2/ref/settings/#allowed-hosts),
[Actix route macro](https://docs.rs/actix-web/latest/actix_web/attr.get.html),
[Axum routing source](https://github.com/tokio-rs/axum/blob/main/axum/src/routing/method_routing.rs),
and [Trio process arguments](https://trio.readthedocs.io/en/stable/reference-io.html#quoting-more-than-you-wanted-to-know).
Context7's monthly quota was unavailable, so upstream documentation and pinned
package source supplied the fallback evidence. No external detector rules were
copied. See also the separate [Node.js security research](nodejs-security-2026-10.md).
