# Node / React / Luau / PostgreSQL cohort — 26 October 2026

## Engineering contract

- Baseline: clean `7ca0477498e2bc8144f004201feb7b184e8df1a7`, 667 executable
  rules. Earlier selected SP690–SP701 are already implemented. The 7,800 catalog
  entries are research-only; a catalog allocation is not a ready detector.
- Objective: promote five bounded, source-reviewed checks: SP702 imported React
  async effect setup, SP703 awaited callback-style Node pipeline, SP704 pg
  connection-string overrides of an explicit TLS object, SP705 concurrent index
  creation inside an explicit PostgreSQL transaction, SP706 explicitly temp-first
  SECURITY DEFINER lookup. Extend SP691 with the same direct client-selected
  removal boundary for Player.Kick. SP104 already has a broad TLS-property variant;
  a pg-only addition would duplicate it. Binding-sensitive TLS repair needs its
  own cross-API contract and is deferred rather than adding a duplicate.
- Review SP334/SP359/SP363/SP423 default/missing-config assumptions against owning
  documentation. Retire unsupported claims; do not recycle IDs or change gates.
  Walker verification also reproduced SP325 on a harmless BEGIN even with a local
  timeout: its negative lookahead can backtrack and cannot establish absence of
  session/role configuration. Retire this invalid absence claim as well; a timeout
  policy needs resolved database settings and workload evidence.
- Defaults remain read-only, offline and dependency-free. No code from scanned
  projects is executed, no source is uploaded, no new dependencies are installed.
  Native probes may execute only authored in-memory Node/React examples or a new
  isolated PostgreSQL single-user database, without opening network listeners.
- Each new ID needs >=3 positive / >=5 negative / >=2 adversarial original cases,
  source/CWE/remediation, duplicate review, real walker, scope/ignore/anchor/privacy
  checks, advisory gate behavior and CLI/JSON/SARIF/MCP parity. Unknown imports,
  overrides, syntax and dialect remain unresolved, not safe.
- SQL lexer: bounded input and tokens; nested comments, dollar bodies and quoted
  data stay opaque. Unsupported psql metacommands, procedural unquoted bodies and
  malformed input must not masquerade as SQL proof.
- Validate on unchanged pinned TypeScript/React, Luau and Python snapshots plus
  an explicit SQL projection from pinned public source. Preserve all observations,
  digests, completeness failures and labels. At most two new source projections,
  <=2,500 files / 25 MB each; no application-wide safety/FPR claim.
- Gates: focused contracts then full npm check, coverage (existing 80% floor),
  high self-scan, assurance, original/remediated corpus and exact-head remote CI.
  Preserve package ceilings 500,000 packed / 1,870,000 unpacked bytes and scanner
  limits. Compare identical 1,000-file/512-byte workloads, 1 warm-up/3 samples,
  one worker, 8 s / 256 MiB. Do not claim improved speed without measurements.
- Three implementation/review passes, checkpoint at 90 minutes; stop after two
  passes without evidence improvement. Rollback is the baseline commit; evidence
  is retained under `.cache/web-database-20261026/`. Commit/push is authorized;
  version stays 0.12.0, no merge, release or permission changes in this cohort.

Context7 resolution was attempted first and returned a monthly-quota error.
Primary vendor documentation is the fallback. Mechanical candidate inventory was
delegated; detector decisions and final QA remain same-agent review, not an
independent security audit.

## Candidate disposition

The existing Luau/TypeScript, broad-quality and value cohorts' selected rules are
already active. Generic CWE/language catalog records remain research-only. The
next-step suggestion for a cross-library SQL injection detector still needs
argument provenance, bindings and sanitizer evidence; a method named Unsafe is
not sufficient. Missing settings, generic `any` and empty effect dependency
arrays are not promoted merely to increase the count.

## Implemented signatures and primary evidence

| ID | Primary source | Boundary and duplicate decision |
| --- | --- | --- |
| SP702 | [React effect lifecycle](https://react.dev/reference/react/useEffect), [React's commit implementation](https://github.com/react/react/blob/main/packages/react-reconciler/src/ReactFiberCommitEffects.js) | Runtime React import plus inline async setup for useEffect/useLayoutEffect/useInsertionEffect. Inner async work in synchronous setup is valid. This is a return/lifecycle contract, distinct from the retired missing-array claim. No React renderer was installed or mounted. |
| SP703 | [Node pipeline API](https://nodejs.org/api/stream.html#streampipelinesource-transforms-destination-callback) | Direct await of callback pipeline, with at least source/destination/inline callback. Promises imports, callback-only ownership and wrappers stay silent. Existing pipe-error rules concern another API/condition; this check does not infer an unhandled error. A deliberately thenable custom destination can change await semantics and needs review. |
| SP704 | [pg TLS configuration](https://node-postgres.com/features/ssl), [configuration precedence implementation](https://github.com/brianc/node-postgres/blob/master/packages/pg/lib/connection-parameters.js), [custom Pool clients](https://github.com/brianc/node-postgres/blob/master/packages/pg-pool/index.js) | Direct imported pg Client/Pool, literal PostgreSQL URL with a recognized SSL parameter, and a separate flat SSL object containing ca. Reports lost configuration, not a TLS bypass. Dynamic/duplicate URL keys, spreads, custom Client/connection/stream options and ambiguous bindings stay unresolved. No duplicate SP104 property warning was added. |
| SP705 | [PostgreSQL concurrent indexes](https://www.postgresql.org/docs/18/sql-createindex.html) | Explicit supported transaction in one SQL file, before completion. Comments/strings/dollar bodies do not begin transactions; COMMIT AND CHAIN and ROLLBACK TO are distinguished. Transactions managed by a runner or another file are unknown. |
| SP706 | [PostgreSQL definer functions](https://www.postgresql.org/docs/18/sql-createfunction.html#SQL-CREATEFUNCTION-SECURITY), [name lookup](https://www.postgresql.org/docs/18/runtime-config-client.html#GUC-SEARCH-PATH) | Single SQL SELECT body, explicit pg_temp-first path and unqualified FROM relation. Qualified/CTE/function relations, nested expression FROM, procedural bodies and ALTER/DROP FUNCTION lifecycle files stay unresolved. Does not prove TEMP/EXECUTE privileges or escalation. |
| SP691 extension | [Roblox client/server boundary](https://create.roblox.com/docs/scripting/security/client-server-boundary), [Player.Kick](https://create.roblox.com/docs/reference/engine/classes/Player#Kick) | Direct Kick() on the client-selected argument shares Destroy's target-authorization boundary and ID. Requires a locally constructed native remote, unescaped single handler and one direct statement. Guarded/server-selected targets stay silent. Runtime target type is unknown; no live game was invoked. |

The five new IDs are medium, L1 structural, explicitly advisory at every
severity/proof floor. They are not promoted to blocking on the strength of this
small source sample. This is a bounded signature layer, not a TypeScript compiler,
React linter, SQL grammar/dialect resolver or deployed database audit.

The SQL lexer caps 50,000 tokens and 128 nested comments; malformed or unsupported
lexical evidence records a parser omission. Unquoted BEGIN ATOMIC bodies are
unresolved. PostgreSQL-compatible engines can differ; the rule names/messages
state PostgreSQL semantics and do not establish every file's deployed dialect.

## Precision repairs

- **SP325 retired:** BEGIN alone cannot establish missing effective timeout
  policy. Its old lookahead could also match a transaction containing a timeout.
  [PostgreSQL session settings](https://www.postgresql.org/docs/18/runtime-config-client.html#GUC-STATEMENT-TIMEOUT)
  and the native probe show an inherited finite timeout without SET LOCAL.
- **SP334 retired:** [Node's process contract](https://nodejs.org/docs/latest-v24.x/api/process.html#event-uncaughtexception)
  has default fatal-error behavior. Requiring a listener next to listen() neither
  proves recovery nor checks listener behavior; adding a handler can override it.
- **SP359 retired:** [Express 5 error handling](https://expressjs.com/en/guide/error-handling/)
  forwards rejected handler promises. The old spelling/absence pattern did not
  resolve Express identity/version or installed wrappers. A future Express 4
  check needs those boundaries; this does not declare Express 4 handlers safe.
- **SP363 retired:** [pg Pool](https://node-postgres.com/apis/pool) defaults to a
  maximum of ten clients. Omission does not prove unlimited capacity. Aggregate
  pool sizing across replicas remains a runtime/capacity question.
- **SP423 retired:** [React](https://react.dev/reference/react/useEffect) permits
  effects after every commit. An infinite cycle additionally needs state changes
  that cause repetition; the old pattern also misread calls with explicit arrays.

All five IDs remain reserved. Severity/proof floors, paired-corpus labels,
positive-retention assertions and package/resource ceilings are unchanged. The
registry remains **667**: five additions and five retirements. Research catalog
overlap references were regenerated; CWE overlap is a triage hint, not proof of
semantic duplication or a new executable rule.

## Executed contracts and native probes

- New cohort: **104 original cases** — 27 positive, 57 negative/unresolved and
  20 adversarial (including must-detect transformations), through the real walker.
  Luau's existing contract gains ten Kick cases. Scope, ignores, line movement,
  fingerprints, minimal evidence, fix prompts and Python/Node/JSON/SARIF parity
  are checked. MCP exercises all five IDs and Kick through the official SDK.
- Node **24.22.1**: a bounded in-memory callback pipeline returns its destination
  before completion; the promises API completes before await resumes. Express
  **5.2.1** forwards an authored async rejection through an in-memory router.
  No listener/socket or scanned application was started.
- PostgreSQL **16.14**, a new isolated single-user database, no network listener:
  concurrent creation inside BEGIN is rejected with SQLSTATE **25001**; the same
  creation outside the transaction succeeds. A temp-first authored function reads
  `temporary`; temp-last and schema-qualified counterparts read `protected`.
  An inherited statement timeout remains 5s inside a transaction without local
  reconfiguration. Only harmless authored schemas/tables are used.
- The initial initdb attempt failed on the Windows account's non-ASCII default
  role name; the successful probe uses a new cluster and explicit ASCII probe
  role. No existing database/service was modified. React and pg are unavailable
  locally for native package probes; documentation/source and authored static
  counterparts are the limit of those claims.

## Pinned public-source comparison

The [metadata-only observations](web-database-observations-2026-10.json) retain
source-tree/runtime/report hashes, file coverage and exact limitations. Eleven
projections cover **ten repositories**, 3,543 selected / **3,542 scanned** files.
Ten projections are complete; the FastAPI template still requires Python 3.14
syntax and has one parser omission under local Python 3.12.10. Its replay remains
INCOMPLETE/exit 2; no source/scope was rewritten to make it pass.

The previous TS/.NET/Dart, Luau and Python pins are unchanged. Added SQL scope is
all 28 regular `.sql` files under Umami's `db/postgresql/` and
`prisma/migrations/`, commit `559e3c607c23d2c72d9bd4f6481bda428255323c`, MIT,
34,741 bytes. [Manifest](../benchmarks/web-database-cohort-repositories.json).
Git blob bytes, provider context and license hashes were verified. ClickHouse is
outside the declared PostgreSQL scope; the TS and SQL Umami projections are not
independent projects. No third-party application was built or executed.

Observations: **588 → 548**, with **zero added sites** and 40 withdrawn SP423
sites (38 Umami, 2 Shlink). Five full calls were reviewed and have explicit arrays:
Umami UpdateNotice, BoardProvider, BoardComponentSelect; Shlink Home and its
TestModalWrapper. These disprove those five missing-array claims, not all other
component behavior. The other 35 withdrawals remain unreviewed. Other findings
are retained without relabeling. The two small Luau libraries remain a limited
library-only sample. This is not an independent precision/recall measurement;
zero new observations cannot establish recall or zero false positives.

The original/remediated 30-package corpus retains both legs, 867 source files per
leg and all 54 required high/critical signatures. Original: 130 app observations,
chi remains deliberately blocked. Remediated: 72 app observations, zero
high/critical and zero blocked packages, 16 gate-eligible medium observations;
precision-trend and existing FP budgets pass without label/threshold changes.

## Local verification and cost

| Check | Result |
| --- | --- |
| `npm run check` | Pass: lint, Node suites, 961 Python tests (3 Windows privilege skips), 2 demo tests, pack allowlist and isolated CLI/Action/two-skill smoke |
| Python branch-aware coverage | 87%, existing 80% floor; SQL helper 97% |
| High self-scan | Complete, 512 files, 0 app / 32 pre-existing test findings, 0 suppression or parser/size omissions |
| Assurance | 667/667 complete; 124 realistic negatives, 543 near-miss-only, 410 high/critical realistic-negative debt |
| Package | 111 files, 474,356 packed / 1,834,281 unpacked bytes; original ceilings retained |
| Paired corpus / contract freshness / whitespace | Pass |

The first full run found stale generated overlap references and four too-short
adversarial rationales. Those data were corrected and focused quality/catalog
tests rerun; the subsequent full check passes. Coverage preserves the initial
full run and appends corrected contract/catalog/demo runs. Exact-head CI runs a
fresh matrix; its status is recorded on PR #49, not inferred from local results.

Final review rejects pg's supported custom Client/connection injection rather
than assuming standard URL parsing, with two additional silent counterparts.
JS preflight now uses pipeline/connectionString markers instead of incidental
`pg`/`stream` substrings; an image-only `.jpg` import is verified not to enter
unrelated API signature parsing. These changes were followed by a fresh full
check and pinned-source replay. No broader speed-up is inferred from the guard.

Comparable Windows 11 / Python 3.12.10, jobs=1, 1,000 files / 512,000 bytes,
one warm-up and three samples, identical fixture hashes before/after:

| Workload | Baseline samples, median / p95 s | Candidate samples, median / p95 s | Peak RSS MiB before / after |
| --- | --- | --- | --- |
| web-database | [1.6339, 1.4523, 1.4457], 1.4523 / 1.6339 | [1.5257, 1.5132, 1.5531], 1.5257 / 1.5531 | 28.96 / 28.95 |
| typescript-config | [2.3050, 2.3634, 2.4046], 2.3634 / 2.4046 | [2.2345, 2.3105, 2.2936], 2.2936 / 2.3105 | 28.96 / 28.66 |

Both workloads have zero findings and pass 8s / 256 MiB. The mixed median is
slower; the small TS difference is not a general improvement claim. These are single-host
measurements, not a speed-up or memory-improvement claim. Only the workload
driver is copied into the frozen baseline tree; baseline runtime bytes are intact.
The table uses the final verified runs after local scan/test workers completed.
Earlier measurements, including runs before the final guard and runs overlapping
source replay, are retained separately in the cache and are not substituted for
the selected final series. Sites in observation comparisons include path/line/
column/fingerprint; repeated fingerprints alone are not collapsed into one site.

At the review checkpoint, all five planned additions and precision repairs are
implemented; remaining work is commit/push and exact-head CI, with no new feature
scope. The runtime-source digest is
`e92f7fbfa3b215f7a657398467250b1e69d6802b9482399d2b797a0248fda4d1`.

QA is same-agent review with executed checks; the fast agent performed mechanical
inventory, verbatim Git projection and documentation updates, not an independent
security review. Remaining catalog items still need source, binding, realistic
negative and field evidence before promotion. Version stays 0.12.0; no merge or
release is included in this cohort.
