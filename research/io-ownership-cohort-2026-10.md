# I/O ownership and client-selected persistence — 26 October 2026

## Engineering contract

- Baseline: clean `6a218b4a258be03cf687e984b6c67e5ee15ccd42`, 667 executable
  rules, 961 Python tests, 87% coverage; exact-head CI16/16, Security and
  Benchmarks passed. Version remains 0.12.0, current branch/PR49 are reused.
- Objective: review the remaining 35 withdrawn React missing-array observations;
  repair SP336 to require import-bound inline native stream construction and
  source-error ownership evidence; retire duplicate spelling-only SP367 after
  counterexamples/retention review. Do not infer missing handlers from adjacency.
- Extend SP703 to directly awaited fs.readFile/writeFile callback overloads;
  extend SP705 to concurrent DROP/REINDEX operations in explicit transactions.
  One new advisory candidate, SP707, requires a native local Roblox remote with
  a flat callback directly passing its client-selected key/value to the native
  DataStore API. Aliases, guards, unknown bindings and runtime exposure remain
  unresolved. No rule-count target overrides proof/precision requirements.
- No exit/schema changes, dependency additions, telemetry, source upload,
  scanned-project execution, live Roblox calls, active exploitation, permission
  changes, merge or release. Native Node probes use authored disposable files
  and bounded children; PostgreSQL probes use a new isolated single-user cluster
  without network listeners. Existing user data/services are untouched.
- Each new/promoted signature needs at least 3 positive/5 negative/2 adversarial
  original cases, primary-source/CWE/remediation/FP boundaries, real walker,
  anchors/ignore/scope/privacy, every advisory floor and CLI/JSON/SARIF/MCP parity.
- Preserve existing source pins/labels/thresholds and all 54 required original
  high/critical signatures. Reuse the eleven projections (ten repositories),
  retain the FastAPI/Python3.14 incompleteness. No new public source fetch is
  necessary for this cohort; the Luau library sample is not game/recall evidence.
- Unchanged 1MB file and 50k-token limits; unchanged package ceilings 500,000 /
  1,870,000 bytes. Compare identical 1,000-file/512-byte workloads, 1 warm-up /
  3 samples, jobs=1, 8s/256MiB. Do not claim broader performance from a guard.
- Three bounded implementation/review passes; 90-minute checkpoint, stop after
  two no-progress passes. Evidence under `.cache/continuation-20261026/`, rollback
  baseline above. Gates: focused contracts, full npm check, coverage, high
  self-scan, assurance, paired corpus and exact-head CI after authorized push.

Context7 was attempted first and returned a monthly-quota error; primary Node,
Roblox and PostgreSQL documentation/source is the fallback. Fast-agent work is
mechanical source/context extraction only; semantic review remains primary and
is not represented as an independent security audit.

## Promotion and duplicate decisions

SP703 variants share the callback-completion contract and ID; SP705 variants share
PostgreSQL's explicit-transaction restriction. SP336 keeps its source-error
ownership family but replaces the old receiver-name regex; it remains advisory
pending representative labels. SP367 does not become a second pipe detector.
SP707 describes client-selected persistence, distinct from module execution and
instance removal. Remaining research records are not automatically executable.

## Accepted boundaries and sources

| Rule | Primary source | Observable condition and limits |
| --- | --- | --- |
| SP336 repair | [Node pipe](https://nodejs.org/api/stream.html#readablepipedestination-options) | Import-bound native fs.createReadStream(path).pipe(createWriteStream(path)), one argument each. The source is not retained and has no pre-attached handler. Named/custom streams, options, visible prototype changes and pre-attached listeners stay unresolved. A destination error listener is not a source listener. This is L1 advisory even though severity remains high; runtime failure/external controls are unknown. |
| SP703 extension | [Node callback readFile](https://nodejs.org/api/fs.html#fsreadfilepath-options-callback) | Direct await of callback readFile/writeFile with supported arity and inline function callback, including ordinary/single-parameter/async arrows. Callback APIs do not return completion promises. The existing stream pipeline variant remains. Promises imports, wrappers, shadows and escapes stay silent. |
| SP705 extension | [DROP INDEX](https://www.postgresql.org/docs/18/sql-dropindex.html), [REINDEX](https://www.postgresql.org/docs/18/sql-reindex.html) | Concurrent DROP INDEX and simple REINDEX INDEX/TABLE join CREATE INDEX under the same explicit-transaction restriction. Other options, runner/cross-file state and compatible dialects are not resolved. |
| SP707 | [Roblox trust boundary](https://create.roblox.com/docs/scripting/security/client-server-boundary), [DataStores](https://create.roblox.com/docs/cloud-services/data-stores) | Local native remote, three distinct simple callback parameters, direct game:GetService('DataStoreService'):GetDataStore(fixedName):SetAsync(clientKey,clientValue). Short ASCII store names up to 32 characters are the signature budget, not a claim about the platform's maximum. Server-selected keys, guards, aliases, complex types and wrappers stay unresolved. Pcall handles errors and does not authorize writes; it is silent here only because nested callbacks are outside this direct signature. |

All changed signatures are explicitly advisory at every severity/proof floor.
Native game exposure, successful storage writes, value types and intentionally
shared-store policy are not inferred. No live Roblox game/DataStore is accessed.
SP707 describes client-selected persistence, rather than claiming demonstrated
corruption. No general callback/pipe keyword detector or model inference is added.

The per-file visible-prototype check is computed once and reused; it is not
repeated for every literal array comparator. Native stream guards also reject
ordinary quoted prototype-property spellings and known-invalid primitive paths.
Dynamic monkeypatching and full type/control-flow resolution remain unsupported.

## Source review and precision decisions

The [review inventory](io-ownership-review-2026-10.json) completes the previously
unreviewed 35 SP423 sites. All **40** historical missing-array claims have an
explicit dependency array: 37 exact calls pass bounded paired-token extraction;
three template-containing calls were inspected directly while retaining the
lexer's unresolved status. The claim being disproved is absence of an array,
not whether a component can have some other render-cycle bug. Five sites were
already reviewed in the previous cohort; only 35 are newly reviewed here.

SP367 is retired and its ID reserved. Its receiver spelling did not establish
Node stream identity or handler ownership, and it overlapped SP336. One pinned
Umami site, `src/lib/analytics-schema.ts:35`, imports Zod and composes schemas
with `.pipe(schema)`; it is a confirmed nonstream false positive. A bounded
installed-Zod probe validates the separate API, without executing project code.

The other three withdrawals are HTTP download sites in build-geo,
download-country-names and download-language-names. Their request/destination
handlers do not establish complete response-source error ownership. They remain
review leads in the inventory; they are **not** labeled safe or confirmed false
positives. A future HTTP-specific detector needs import-bound response callbacks,
escape/alias/handler analysis and realistic counterparts. The narrow SP336
repair does not claim to cover every streamed download.

One historical precision-plan negative retains identical source bytes and now
maps from retired SP367 to canonical SP336. The hardening positive now supplies
native imports and constructors, and also asserts that an unknown named pipe
receiver is insufficient proof. The realistic-negative requirement is retained
for SP336. Original/remediated benchmark labels, source pins, recipes, positive
retention assertions and thresholds are unchanged.

## Executed tests

- **89** original cohort cases: 25 positive, 48 negative/unresolved and 16
  adversarial, through the real offline walker. SP336 migrates into the legacy
  structural JavaScript partition; SP703/SP705 variants augment their existing
  canonical v2 rows. Generators verify their current outputs together.
- Integration covers all eight JS/TS suffixes, Lua/Luau suffixes, import aliases,
  shadows, escapes, invalid paths, prototype changes, scope/ignores, line movement,
  fingerprints, minimal evidence/fix prompts and Python/CLI/JSON/SARIF parity.
  Official-SDK MCP exercises repaired FS streams, callback reads/writes, concurrent
  DROP/REINDEX and client-selected persistence; peer matrices run in CI.
- Native **Node24.22.1** authored files: awaited callback readFile/writeFile both
  return undefined before completion; promises readFile yields the bytes. A
  bounded child with an unhandled source ENOENT exits 1; promises.pipeline handles
  the same error. No external endpoints or untrusted source are executed. The
  installed **Zod4.6.7** schema pipe parses the authored value as 7.
- Native **PostgreSQL16.14**, a new isolated single-user database, no listener:
  concurrent DROP INDEX and REINDEX INDEX/TABLE fail inside BEGIN with SQLSTATE
  **25001**, and the authored outside-transaction operations succeed. Additional
  temporary-relation attempts also hit the transaction restriction. These are
  harmless authored objects, not a real application schema or a load test.

## Pinned-source and paired-corpus results

[Observation receipts](io-ownership-observations-2026-10.json) compare identical
pins and source-tree hashes across ten repositories / eleven projections:
**3,543 selected / 3,542 scanned** files. Ten projections are complete. The
FastAPI template's Python3.14 syntax still creates one explicit omission under
local Python3.12.10; its report remains INCOMPLETE/exit2. No source or selection
was rewritten to pass, and CI success is not a full replay of that template.

Observations **548 → 544**, zero added sites, four withdrawn SP367 sites with the
disposition above. Repeated fingerprints remain separate path/line/column sites.
The two Luau libraries are a small compatibility sample, not deployed-game or
recall evidence. Zero new sites do not establish recall or zero false positives.
No scanned project is built or executed; no third-party source is copied into
tracked test fixtures. Historical reports are preserved.

The original/remediated 30-package corpus retains **867 files per leg** and all
**54** required original high/critical signatures. Original: 130 app observations,
chi deliberately blocked. Remediated: 72 app observations, zero high/critical,
zero blocked packages and 16 gate-eligible medium observations. The existing
precision trend and FP budgets pass; neither leg is relabeled to hide risk.

## Local verification and resource cost

| Check | Result |
| --- | --- |
| npm run check | Pass: 970 Python tests (3 Windows privilege skips), 2 demo tests, Node suites, package manifest and isolated CLI/Action/two-skill smoke |
| Python branch-aware coverage | 87%, existing 80% floor retained |
| High self-scan | Complete, 0 app / 32 existing test findings, no suppression/parser/size omissions |
| Assurance | 667/667 complete, 125 realistic negatives, 542 near-miss-only, 409 high/critical realistic-negative debt |
| Package | 111 files; original 500,000 packed / 1,870,000 unpacked ceilings pass |
| Contract freshness, paired trend, whitespace | Pass |

The first full suite exposed two old test assumptions referencing SP367; these
were replaced by the native-positive/unknown-receiver checks and canonical
realistic-negative requirement described above. The subsequent full suite passes.
Coverage retains the initial full traversal and appends corrected hardening,
assurance, precision-plan and demo suites. Exact-head CI performs a fresh matrix;
its outcome is recorded on PR49, not inferred from the local result.

Comparable Windows11/Python3.12.10, jobs1, 1,000 files/512,000 bytes, one warm-up
and three samples, identical fixture hashes before/after, before test/replay
workers started:

| Workload | Baseline samples, median / p95 s | Candidate samples, median / p95 s | Peak RSS MiB before / after |
| --- | --- | --- | --- |
| io-ownership | [1.4349,1.4077,1.3893], 1.4077 / 1.4349 | [1.4716,1.4595,1.4245], 1.4595 / 1.4716 | 28.37 / 27.95 |
| typescript-config | [2.0826,2.0752,2.0439], 2.0752 / 2.0826 | [2.0830,2.0929,2.0636], 2.0830 / 2.0929 | 28.01 / 28.60 |

Both have zero findings and pass the unchanged 8s/256MiB budgets. The I/O median
is slightly slower; TS is effectively unchanged at this sample size. No general
speed or memory improvement is claimed. Earlier pre-review measurements remain
separate. Only the fixture driver was copied to the frozen baseline; its runtime
bytes remain intact. Candidate runtime-source digest:
`2794acc4017f69e77a2a95daa64dff15cb0381cade8fd55480e920066696f5fd`.

At the checkpoint all selected code changes and source reviews are implemented;
remaining work is publication of the commit and exact-head CI, with no added
feature scope. QA is same-agent semantic review with executed checks. The fast
agent performed mechanical extraction, generator wiring and documentation only;
it is not an independent security audit. No merge or release is included.
