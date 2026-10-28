# Bounded host-agent review orchestration

Design recorded 2026-10-28 before implementation. Baseline: `2debd79`.

## Objective and decisions

Improve optional local review packets without changing native findings, rule IDs,
fingerprints, gate decisions, or default scan work. Implement original behavior
inspired by OpenCodeReview, not its source, prompts, or rule packs. The reviewed
upstream revision is `375f64cd6f67a48a135da83cfcf59c52669a09cb`.

1. Split one directory over multiple packets; primary review files precede optional
   context. Keep 10 files, 128 KiB source bytes, and 20 packets as hard ceilings.
2. Resolve bounded, literal local imports against an explicit eligible-file scope;
   include relevant test files where the relationship is directly observable.
   Unsupported/ambiguous imports remain unknown. Context is not dataflow proof.
3. Add `scan --packet-discover --packet-out DIR`: schedule selected source files
   even when no rule fired. Reuse the scanner's exclusions and changed-file scope.
   Discovery items are not SP findings, reviewed evidence, or blocking proof.
4. Include deduplicated rule summaries for native findings, and expose source-byte
   estimates honestly. No model, credential, network call, provider, new command,
   automatic suppression, or repository code execution is introduced.

The additive packet format becomes `review-packet/1.1`; existing findings and
fingerprint-based response accounting remain available. Old 1.0 artifacts are not
rewritten. A response must belong to its scheduled packet and input digest.

Full historical CHANGELOG stays in the source repository; npm keeps user-facing
documentation and links to the online history. This frees actual payload bytes
for runtime functionality. Existing packed/unpacked size ceilings do not change.

## Acceptance contract

- Reproduce the baseline: 12 same-directory files schedule 10 and defer 2; no
  existing findings produce no packet; sibling selection misses an imported file.
- Schedule all 12 in two packets when budgets permit; oversized or unavailable
  sources do not starve smaller review targets. No selected item silently vanishes.
- Partial context, unresolved imports, exhausted budgets, failed identity, and
  missing agent responses never imply complete review or application safety.
- Respect excluded files, baseline artifact exclusions, changed scope, symlink
  boundaries, literal opacity, source mutations, and resource caps. No project
  settings, package scripts, tsconfig, or executable rules are evaluated.
- Separate discovery targets, native findings, context roles, rule guidance, and
  agent assessments. Keep redaction, source hashing, and no automatic gate override.
- Direct Python, Node, packed CLI and installed skill agree. Plain scans retain
  their output and 0/1/2 behavior. New flags fail clearly when used without output.
- Focused regressions, full `npm run check`, high self-scan, assurance, and package
  smoke pass with unchanged thresholds. Measure identical before/after packet
  workloads, including scope, bytes, accounting, wall time and peak RSS.

## Bounded loop and limitations

Three implementation/verification passes; checkpoint after 90 minutes or two
passes with no improvement. Baseline and logs live in the ignored
`.cache/packet-orchestration-20261028/` directory. Rollback is the baseline commit;
do not reset unrelated user work. No release or tag is part of this task.

The initial resolver is not a compiler, complete call graph, type checker, or
framework-specific authorization analyzer. No live model evaluation is authorized
or claimed. Token, precision, recall, or defect-finding improvements require a
separate controlled evaluation with a fixed model and held-out human labels.

## Source references

- [Bounded grouping and omitted-file recovery](https://github.com/alibaba/open-code-review/blob/375f64cd6f67a48a135da83cfcf59c52669a09cb/internal/agent/grouping.go)
- [Rule grouping with provenance](https://github.com/alibaba/open-code-review/blob/375f64cd6f67a48a135da83cfcf59c52669a09cb/internal/delegate/rulegroup.go)
- [Host-agent delegation](https://github.com/alibaba/open-code-review/blob/375f64cd6f67a48a135da83cfcf59c52669a09cb/pages/src/content/docs/en/integrations/delegate.md)

## Implemented boundary

`review_packets.py` now splits a directory across bounded packets, prioritizes
primary sources, separates discovery from native findings, and includes compact
deduplicated rule guidance and language review questions. Native coordinates,
scope, tier and verification state remain visible without becoming permissions.
`.test.` and `.spec.` names are classified as test context. Role labels never
suppress native evidence.

`review_context.py` resolves literal local Python, JS/TS, Dart and Lua/Luau import
hints against the scanner's eligible-file set. It can add a conventionally named
test only when that file directly imports the target. Package aliases, C#/.NET
namespace binding, dynamic paths and ambiguous resolutions remain unknown. Source
strings and comments are data; nothing in the target is imported or executed.
At most 5,000 context files are eligible, import parsing reads at most 4 MiB, and
each packet has at most 256 review items. Native rule guidance has a 16 KiB cap.

The CLI collects opt-in scope using the existing walker, exclusions and changed
selection. Unchanged dependency context may be included without widening the
gate. Invalid packet identity returns exit 2; exhausted preparation budgets retain
explicit deferred rows. Successful preparation never changes native JSON/SARIF
or gate decisions. The installed audit skill explains how a host agent consumes
only the ledger's listed packets and returns bounded decisions.

Tracking fingerprints legitimately repeat at different lines in Umami's pinned
source. They are preserved. A separate per-occurrence `item_id` keeps every row
in the ledger; a fingerprint-only response is accepted only when unambiguous.
New responses echo the digest binding source, policy, rules and review targets.
Malformed, stale and cross-packet decisions cannot complete an item. Legacy
unique-fingerprint responses remain readable; ambiguous legacy rows stay pending.
This is input identity, not signed authorship or proof of a correct assessment.

## Repeatable experiments

Run the same source-only driver against a frozen `git archive 2debd79` tree and
the candidate, with no other local validation workers active:

```text
python benchmarks/benchmark-review-packets.py --engine-root BASELINE --workload split
python benchmarks/benchmark-review-packets.py --engine-root CANDIDATE --workload split
python benchmarks/benchmark-review-packets.py --engine-root BASELINE --workload minimize
python benchmarks/benchmark-review-packets.py --engine-root CANDIDATE --workload minimize
```

Each arm uses one warmup and five samples of identical 512-byte synthetic source
files. Findings are synthetic scheduling inputs, not detector results. The split
fixture selects 48 targets in four components; the minimization fixture selects
four targets with relevant import/test context and unrelated siblings. Input tree
hashes, source bytes, every sample, p95 and process peak RSS are retained in the
companion observations JSON. The predeclared ceilings are 8 seconds and 256 MiB;
these workloads do not demonstrate production throughput or model token cost.

## Pinned public-source replay

The existing exports and revision/license manifests were reused; no dependency,
application, test suite or game from these repositories was executed. The full
export roots, including their context metadata, were scanned on both sides.

| Projection | Native files scanned | App/test observations | Exit before/after | Review items scheduled/deferred |
| --- | ---: | ---: | --- | ---: |
| Umami | 1,405 | 61 / 68 | 1 / 1 | 89 / 1,206 |
| TodoApp | 44 | 1 / 0 | 1 / 1 | 40 / 0 |
| LocalSend | 406 | 1 / 0 | 1 / 1 | 39 / 331 |
| ProfileStore | 6 | 0 / 0 | 0 / 0 | 2 / 0 |

Native reports compare equal. The first three export roots retain an unrecognized
binary and therefore incomplete coverage; their exit 1 is preserved, not waived.
They are not clean-corpus labels. ProfileStore's native source scan is complete,
but its optional import context is partial. All four reviews remain uncompleted:
no agent responses were supplied. Directory grouping, 20-packet limits and
unresolved imports deliberately leave review work outstanding. Use changed scope
for a bounded PR review; whole-root discovery is not a claim to review every file
within one budget. Source roles do not establish safety or runtime reachability.

## Verification record

The frozen tree passes `npm run check`: 1,008 Python tests (three Windows
symlink-privilege skips), two demo tests, the Node/SDK suites and packed smoke.
Fresh Python branch coverage is 87% against the unchanged 80% floor. The packed
CLI, Action and separately installed Codex/Claude audit skills execute locally;
their native reports and installed packet ledgers agree. Skill validation passes.
There are still 673 executable rules and 673 complete rule contracts.

The npm artifact contains 112 files, 471,514 packed / 1,846,277 unpacked bytes,
within the original 500,000 / 1,870,000 caps. Full release history is source-only;
README links preserve access to the online changelog. Version remains 0.12.0
with an Unreleased entry; this task creates no tag or release.

| Workload | Before | After |
| --- | --- | --- |
| Split: targets prepared | 40 / 48 | 48 / 48 |
| Split: source bytes / packets | 20,480 / 4 | 30,720 / 8 |
| Split: median / p95 seconds | 0.0919 / 0.0967 | 0.1817 / 0.1929 |
| Split: peak RSS MiB | 25.14 | 25.82 |
| Minimize: targets prepared | 4 / 4 | 4 / 4 |
| Minimize: source bytes | 10,240 | 6,144 |
| Minimize: median / p95 seconds | 0.0321 / 0.0327 | 0.0245 / 0.0260 |
| Minimize: peak RSS MiB | 24.82 | 24.90 |

Both arms pass their predeclared resource ceilings. The split workload prepares
more targets and useful context at additional cost; it is not a speedup. The
minimization workload removes 40% of source bytes while selecting the same four
targets. Neither result measures actual model tokens or defect precision. Exact
fixtures, all samples, runtime digests and public-source replay results are in
[the observations](packet-orchestration-observations-2026-10.json).

The baseline 55 identity/anchor/packet/triage tests and new targeted tests cover
actual accounting, code/data boundaries, stale evidence and source mutations,
native JSON/SARIF parity, discovery, resource caps, repeated fingerprints and
untrusted model responses. Test thresholds, executable rule counts, realistic
negative debt and the paired-corpus definitions are unchanged.

Validation is primary-agent self-review plus automated tests and source replay.
The documentation helper performed mechanical edits, not independent QA. Actual
precision, recall and end-to-end model tokens remain unmeasured; reduced source
bytes alone must not be reported as improved defect detection or token savings.
