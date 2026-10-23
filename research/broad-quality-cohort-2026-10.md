# Broad correctness / security / resource cohort — 23 October 2026

## Engineering contract (before implementation)

- Baseline: clean `5d48e8755f8f2bb5dc2fd0f49814bb50a8fb1edc`, 661 executable
  rules; previous full check 930 Python tests, 86% coverage, all CI green.
- Objective: select bounded checks for correctness, security and resource use;
  repair vendor-confirmed false-positive semantics in existing rules. Candidate
  IDs SP693–SP698: explicit Node ingress deadline removal, empty async races,
  boolean native-array comparators, C# XML entity-limit removal and an unverified
  Python logging-configuration listener, and directly awaited synchronous Node
  compression. Promotion is evidence-gated, not a quota.
- Existing-rule work: awaited asyncio tasks, bounded ThreadPoolExecutor defaults,
  Go idle/open connection meanings, and an import-aware synchronous-compression
  performance variant. Preserve rule IDs where the invariant is the same; retire
  a rule only when its claimed unsafe default is contradicted by owning docs.
- Foundation: move the explanation dictionary to a pure-data runtime module,
  preserving the `scan_repo.RULE_EXPLANATIONS` API and serialized metadata exactly.
  Main source is 998,712 bytes, too close to its unchanged 1 MB scan ceiling.
- Default remains offline/read-only/dependency-free; no downloaded project code
  execution, live services, active load/exploit tests, private-code uploads,
  dependency/tool installation, permission changes, merge or release.
- Acceptance: each new rule has >=3 positive, >=5 negative and >=2 adversarial
  cases, primary references, duplicate analysis, real walker/adapters and
  normalized evidence. Verify authored/native probes, pinned public-source replay,
  existing paired corpus, full check, coverage, MCP and high self-scan. Existing
  severity/proof/coverage/precision budgets and corpus labels are not relaxed.
- Resources: 50,000-token lexical limits remain; use bounded local signatures.
  Compare identical 1,000-file/512-byte profiles with one warm-up and 3 samples,
  jobs=1; preserve 8 s / 256 MiB and 500,000/1,870,000 byte package ceilings.
- Three implementation/review passes; 90-minute checkpoint, no paid calls, <=24
  primary documentation requests, reuse existing pinned field corpora. Stop on
  two no-progress passes or a material safety/authority blocker. Rollback reference
  is the baseline commit, without resetting unrelated changes.
- Evidence: `.cache/broad-quality-20261023/`; commit concise provenance/results,
  authored fixtures and code only. Commit/push continue the authorized workflow;
  PR #49 stays open and version stays 0.12.0.

Context7 resolution was attempted for Python and Node; quota was exhausted.
Use direct owning documentation/source as fallback, not unverifiable claims.

## Accepted changes and source boundaries

| ID | Category | Admitted local evidence |
| --- | --- | --- |
| SP693 | Scale | Imported Node HTTP(S) server with both receive deadlines explicitly zero |
| SP694 | Correctness | Direct await of literal-empty native Promise.race or explicitly imported Dart Future.any |
| SP695 | Correctness | Native literal array (at least two entries), simple two-parameter boolean comparator |
| SP696 | Security | Inline XmlReader settings consumed by Create: DTD Parse, entity limit zero, no finite document cap |
| SP697 | Security | Imported logging.config.listen with literal valid port, explicit verify=None and immediate start |
| SP698 | Performance | Direct await of an imported synchronous Node zlib operation |

All six additions are structural advisories at every severity/proof floor.
Names, type assertions or keywords alone do not establish API identity. Unknown
overrides, custom/shadowed APIs, complex syntax and unsupported wrappers stay
unresolved. SP694 does not flag standalone pending sentinels or chained timeout
wrappers. SP695 does not treat function-property indexing as a sort invocation.
SP696 declines other reader modes/settings; a null resolver prevents external
resolution but does not itself bound internal entities. SP697 concerns a
**loopback** listener, not an internet-exposed remote-code-execution claim.
SP698 does not establish buffer size, production latency or worker placement.

Existing-rule precision corrections:

- **SP346** now uses import-bound AST evidence for a discarded expression call.
  Await, return, assignment, task-set ownership, custom imports, visible factory
  overrides and invalid literal arguments stay silent. Severity and eligibility
  are retained. Its authored cases moved to the legacy structural partition, not
  into a new rule ID; fingerprints/proof can change intentionally with this repair.
- **SP375** no longer conflates zero idle retention with unlimited open connections.
  The open-cap signature retains its legacy name-only receiver boundary; this is
  not a claim of complete Go type or later-reconfiguration analysis.
- **SP348 retired**, ID reserved: supported Python executor defaults already bound
  workers. This says nothing about queue backpressure or per-request pool creation;
  those distinct risks were not disabled. Known-invalid assumptions were corrected,
  not kept as synthetic positives to increase the rule count.

The registry is **666 executable rules**: 661 + six additions − one retirement.
Shared CWE roots are not treated as semantic duplicates. SP693 addresses receive
time rather than body/message size; SP694 is not Promise.all/Future.wait; SP696
addresses internal expansion separately from SP670 external resolution; SP698 is
not the password-hashing or filesystem rules. The generated candidate dedup index
was refreshed without promoting research entries merely because their CWE matches.

## Primary references and native checks

Owning references reviewed on 23 October 2026:

- [Node HTTP receive deadlines](https://nodejs.org/api/http.html#serverrequesttimeout)
  and [zlib synchronous APIs](https://nodejs.org/api/zlib.html).
- [Promise.race](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/race),
  [array comparator contract](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/sort#sorting_with_non-well-formed_comparator),
  [Dart Future.any](https://api.dart.dev/dart-async/Future/any.html).
- [XML entity-character limit](https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlreadersettings.maxcharactersfromentities).
- [Python task ownership](https://docs.python.org/3/library/asyncio-task.html#asyncio.create_task),
  [bounded executor defaults](https://docs.python.org/3/library/concurrent.futures.html#concurrent.futures.ThreadPoolExecutor),
  [logging listener verification](https://docs.python.org/3/library/logging.config.html#logging.config.listen).
- [Go idle/open pool semantics](https://pkg.go.dev/database/sql#DB.SetMaxIdleConns).

Authored bounded probes used installed runtimes only; no downloaded application
was executed, no listener opened and no external connection established:

- Node **24.22.1**: defaults 300,000/60,000 ms versus explicit zero deadlines;
  empty race remained pending through bounded microtasks, nonempty completed;
  boolean sort reproduced incorrect order; synchronous compression returned a
  Buffer before await. No CPU-load or exploitability claim from these probes.
- Python **3.12.10**: default executor had 16 workers on this host; an awaited
  created task completed; an unstarted logging listener had a null verifier.
  The probe does not claim deterministic garbage collection of discarded tasks.
- Dart **3.12.2**: an empty race remained pending until a 20 ms test timeout;
  a nonempty race completed. The scanner does not report the bounded wrapper.
- Go **1.26.5** `database/sql`: setting idle retention to zero preserved an open cap of five;
  setting the open cap to zero removed it. No database connection was opened.
- .NET **8.0.29 / 10.0.12**: a tiny four-character internal entity exceeded a
  limit of two, but passed at zero with a null external resolver. The installed
  default was 10,000,000 despite the reference page's generic default description;
  the detector requires explicit zero and never infers an unsafe omitted default.

## Verification and compatibility

- **123 authored cohort cases**: 28 positive, 70 negative/unresolved, 25 adversarial.
  Real walker, suppression, normalized evidence, stable movement fingerprints,
  Python/Node JSON/SARIF parity, retirement and explicit analysis-budget tests.
- Python suite: **939 tests**, three Windows symlink-privilege skips; two demo
  tests. Full branch coverage **86%**, unchanged 80% floor. Node suites exercise
  all five MCP tools with new cohort snippets and precision counterparts.
- Final `npm run check` passed end to end. Source MCP used installed SDK 1.32.1 /
  Zod 4.6.7 on Node 24.22.1; cross-version source/packed peers are verified in CI.
  High self-scan is complete: zero application findings and 32 pre-existing
  intentional test findings, no suppressed findings or parser-limit omissions.
- Assurance: **666/666 complete**, 117 realistic-negative contracts. Existing
  near-miss-only debt remains 549; high/critical realistic-negative debt shrank
  from 419 to 416 through the retirement and two repaired contracts. The baseline
  was updated with the shrink-only command; no threshold or corpus label relaxed.
- Eight pinned field snapshots, **2,615 source files**: the six earlier projects
  retained all 201 rule/fingerprint observations; two small Luau libraries retained
  zero. Source/context/license hashes were verified around each replay. Existing
  unreviewed observations were not relabelled as false positives.
- Existing paired corpus: 30 packages / 867 files per leg; original 130 application
  observations and all 54 high/critical signatures retained. Quiet leg: 72
  observations, zero high/critical, 16 gate-medium, no blocked packages or FP-budget
  violations. This is not an independent whole-product precision/recall estimate.
- Source identities and raw-report hashes are in
  [metadata-only observations](broad-quality-observations-2026-10.json). Existing
  replay commands/manifests are reused; no new third-party source vendored.

## Resource and packaging evidence

The explanation extraction preserved all 661 original records exactly before
semantic edits: normalized dictionary SHA-256
`c1c27a1a66f818e4325aec5027521430a4ca62e9371a7b7f08c3d8914947c6cf`.
The public import is still the same object, and a regression test enforces the
new module is pure data. Final main source is **640,494 bytes** (baseline 998,712),
and explanations 364,879 bytes, both under the unchanged 1 MB scan ceiling.
The benchmark maintainer README stays in source control but is explicitly omitted
from npm; runtime benchmark drivers remain. No package budget increase.
Final package: **110 files, 477,779 packed / 1,862,938 unpacked bytes**, under the
unchanged 500,000 / 1,870,000 byte limits.

A full self-check caught an intermediate defect: the new API parent-map builder
charged its 50,000-node budget to the scanner's unrelated 53,407-node AST. It now
checks for relevant direct imports **before** allocating/traversing that map.
Relevant over-budget inputs still report incomplete evidence; tests cover both
paths. The bound was not raised or silently bypassed for relevant source.

Same Windows 11 / Python 3.12.10 workload: 1,000 files, 512 bytes/file, one warm-up,
three sequential samples, jobs=1. Fixture digests are identical before/after.

| Profile | Median before / after | p95 before / after | Peak RSS before / after |
| --- | ---: | ---: | ---: |
| Clean Python | 2.1435 / 2.1307 s | 2.2843 / 2.1341 s | 29.45 / 29.41 MiB |
| TypeScript configuration | 2.2392 / 2.2693 s | 2.2543 / 2.2831 s | 29.09 / 28.84 MiB |

Both produced zero findings and passed the unchanged 8 s / 256 MiB ceilings.
The TS profile became slightly slower; no general speed-up or production-scale
claim. Smaller source files improve maintainability, not proof of lower latency.

## Review outcome

Semantic decisions and integration were primary-agent review, not an independent
audit. Mechanical extraction and documentation work were delegated. The engineering
skill enforced a fixed scope/budget, primary-source checks and measured acceptance.
Remaining unknowns include deployment, caller-controlled input, workload size,
cross-file monkeypatching, full language/type graphs and native Roblox execution.
No merge, release or version change is part of this cohort.
