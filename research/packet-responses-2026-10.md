# Validated host-agent response handoff

Design recorded 2026-10-28 before changes. Baseline: `ed1baea6f95be0660477297c73413a12e3137c1f`.

## Contract

Complete the optional local agent-review handoff on the existing `scan` command.
Keep native findings, fingerprints, rule count, policies, JSON/SARIF and native
0/1 gate results unchanged for successful response handoffs. No model/provider, network,
target execution, telemetry, new command, automatic suppression or release.

First fix three reproduced defects: computed JS `import(...)` can be omitted
from unresolved context; oversized failed reads consume no 4-MiB import budget;
and an altered packet body can accept a response echoing its unchanged cached
digest. Track unknown context, reserve failed-read bytes conservatively, and
recompute packet identity before accepting any response. Keep legacy 1.0 unique
fingerprint bookkeeping readable but never promote it into verified completion.

Add `scan --packet-responses FILE --packet-out DIR`. The input is a bounded JSON
array of packet responses. The CLI regenerates packets from the current target
with the same scan/discovery options; it does not trust an old ledger. Response
paths/content do not enter request identity, so adding the response flag cannot
invalidate an otherwise unchanged request. No audit source is implicitly excluded.

Reject duplicate JSON keys, nonfinite constants, invalid encoding, excessive
size/nesting, unknown fields, unsupported versions, stale source/config/rules,
wrong packet/item identities and invalid decision values. Preserve native evidence.
Use existing 2,000,000-byte guarded input reads, 1,000-response and 256-decision
ceilings. Notes remain bounded/redacted. Structured validation counters, rather
than parsing human error text, drive CLI errors. Missing replies and partial
context stay explicitly incomplete. Invalid/unavailable response evidence exits 2;
model assessments never cause a native gate failure or make a blocked gate pass.

## Acceptance and loop

- Reproduce all three failures before changing their implementations.
- Test real reads exceeding a small reserved budget, stable cache notes, computed
  versus literal imports, opaque examples and unsupported script/member calls.
- Test stale, modified and version-downgraded packets, repeated fingerprints,
  wrong-packet decisions, valid retries after malformed decisions, duplicates,
  invalid JSON and source/policy changes between prepare and response ingestion.
- Test direct Python and Node JSON/SARIF/0/1/2 parity; run packed CLI and installed
  Codex/Claude skill handoffs with valid and stale replies.
- Replay the existing four pinned public source exports; preserve native reports,
  high-gate exits and incomplete coverage without executing their applications.
- Run full checks, fresh coverage, high self-scan, assurance and package smoke.
  Keep all thresholds, 673 rules, corpus labels and 500,000/1,870,000 byte caps.
- Measure the same packet workloads on a frozen baseline and candidate with no
  competing workers. Also measure the failed-read budget directly. No actual
  model token, precision, recall or finding-quality improvement is asserted.

Three bounded implementation passes; checkpoint after 90 minutes or two passes
without progress. Logs and baseline archive go under the ignored
`.cache/packet-responses-20261028/`. Roll back only this cohort's edits if needed;
preserve user changes. Commit/push after verification; no merge, tag or release.

## Implemented and verified

The three baseline failures are reproduced and covered by regressions. Context
parsing handles literal/computed imports before declaration syntax, rejects
unsupported member/script paths, and retains unknown cache notes. Every guarded
context read reserves its possible `limit+1` bytes; successful reads refund only
unused bytes. Failed reads cannot leave their full budget available for reuse.

The response reader checks JSON depth before decoding, rejects duplicate keys,
nonfinite/numeric values (the protocol contains no numeric fields), invalid UTF-8
and oversized files, and accepts UTF-8 BOMs. Response packets are generated from
current source rather than loaded from an old ledger. The canonical digest is
recomputed over every packet body before bookkeeping. Version mismatches,
malformed identifiers and conflicting decisions stay invalid. An invalid verdict
does not consume an item's later valid decision; identical replies are idempotent.
Legacy bookkeeping never establishes `review_complete`.

Native findings and input packets remain unchanged while response validation and
completion counts live in the ledger. Missing/deferred work and partial context
remain incomplete. Error/timeout replies are not success evidence. Hashes establish
input consistency, not signed authorship, honest agent work or finding correctness.

## Local verification

- `npm run check`: 1,024 Python tests, three Windows symlink-privilege skips, two
  demo tests, Node/MCP suites, exact package manifest and packed smoke all pass.
- Fresh Python branch coverage: 87%, retaining the 80% floor. High self-scan:
  0 app findings, 32 existing test findings, complete supported scan coverage.
- All 673 rule contracts remain complete. No rule, corpus, proof or precision
  thresholds changed. The preinstalled Draft 2020-12 validator accepts the new
  schema and its valid/invalid reference examples; core has no such dependency.
- Packed CLI and independently installed Codex/Claude copies accept current
  replies, preserve native reports and input packets, and reject stale replies.
- Artifact: 113 files, 473,990 packed / 1,856,829 unpacked bytes. The original
  500,000 / 1,870,000 caps and version 0.12.0 are unchanged.

## Public-source and resource measurements

The same pinned Umami, TodoApp, LocalSend and ProfileStore exports were replayed
against baseline and candidate using the strict high gate. Native JSON and exit
codes match before preparation, after preparation, and after applying **simulated**
responses. Three exports retain incomplete binary coverage and exit 1. No source
application, public test suite, game, or model was executed. Counts are bookkeeping,
not independently labelled vulnerabilities or a real agent-review benchmark.

| Projection | Simulated completed items | Deferred items | Rejected replies |
| --- | ---: | ---: | ---: |
| Umami | 89 | 1,206 | 0 |
| TodoApp | 40 | 0 | 0 |
| LocalSend | 39 | 331 | 0 |
| ProfileStore | 2 | 0 | 0 |

Every projection retains `review_complete=false` because of deferred work and/or
partial context. Applying statuses does not repair missing import/type information.

Identical fixture measurements use Windows, Python 3.12.10, one warmup and five
samples, with no other validation workers active. Both arms retain 8-second p95
and 256-MiB RSS ceilings. Source trees are frozen with explicit runtime digests.

| Workload | Median before/after seconds | p95 before/after seconds | RSS before/after MiB |
| --- | ---: | ---: | ---: |
| Prepare 48 targets | 0.1777 / 0.1869 | 0.2273 / 0.2039 | 28.00 / 26.19 |
| Prepare 4 targets | 0.0252 / 0.0256 | 0.0305 / 0.0274 | 24.93 / 24.88 |
| Prepare + reconcile 4 targets | 0.0285 / 0.0279 | 0.0316 / 0.0360 | 24.89 / 24.82 |

These small measurements do not establish a speedup. The response case measures
the in-memory API, not model latency or file loading. On the separate failed-read
fixture (eight 200-byte files, 64-byte context allowance), baseline makes eight
guarded reads consuming 520 bytes and leaves its allowance untouched. Candidate
makes one 64-byte read, exhausts the allowance, and records the remaining sources
as unknown. This verifies the I/O bound directly rather than enlarging it.

Exact samples, revisions, source projections, counters, bounds and limitations
are stored in [the observations](packet-responses-observations-2026-10.json).
Validation was primary-agent self-review plus automated gates; the helper made
mechanical documentation edits. Actual model tokens, precision, recall, semantic
finding quality and production-scale behavior remain unmeasured.
