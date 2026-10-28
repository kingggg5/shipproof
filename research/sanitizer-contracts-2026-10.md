# Context-specific sanitizer closeout

Design recorded 2026-10-28 before implementation. Baseline:
`c5fef9f8568fa726bd667f7a00b200fcdb862977` (all hosted checks green).

## Confirmed reproductions

Native Python loses a direct request-to-SQL trace after `html.escape` or an
identity function named `cleanIdentity`. Cross-file Python also drops an identity
function named `hint` because the substring `int` is trusted. Raw input is traced;
the same input after those wrappers is not. Scalar conversions must remain safe
for appropriate injection contexts, while validation predicates, mere names,
HTML encoding and path handling must not clear unrelated sink risks.

## Completion contract

- Implement original shared transform contracts for Python native and Python/JS
  cross-file checks. Preserve taint provenance separately from protection kinds.
  Numeric/UUID, shell-argument quoting, HTML text and path checks have distinct
  meanings. Unknown protector functions remain unresolved advisory leads, not
  trusted sanitizers or confirmed vulnerabilities.
- Bind recognized builtins/imports conservatively; shadowing/rebinding cannot
  create protection. Support straightforward import aliases and transparent
  one-argument identity wrappers. Do not build a compiler or guess dynamic APIs.
- Protection applies to a value/use, never to the original parameter globally.
  Carry bounded transfer information through helper calls. Preserve raw aliases,
  safe overwrites and sink-before-transform behavior. Safe SQL bind parameters
  remain distinct from SQL statement construction.
- Remove generic startsWith-as-safety and cross-domain sanitizer exemptions.
  Only directly supported, rejecting containment checks may protect path flow.
  Unsupported guard/control flow remains advisory/unknown rather than silently
  safe. Do not label HTML escaping a SQL defense or numeric URL selection SSRF
  authorization.
- Keep all 673 IDs, fingerprints, severity/proof floors and corpus/precision
  thresholds. Run direct, Node, SARIF, packed and installed-skill parity. Maintain
  the original 500,000/1,870,000 artifact caps: benchmark methodology becomes
  source-only with online links; executable benchmarks and user guides stay.
- Reproduce old failures; test positive/negative/adversarial and mixed-use cases,
  aliases, shadows and source opacity. Replay pinned real projects and paired
  original/remediated corpora without changing labels or running target apps.
  Triage any new site before promotion; unknown behavior cannot become blocking
  proof merely because a safety exemption was removed.
- Complete full checks, fresh coverage, high self-scan, assurance and exact-head
  hosted CI. Commit/push tested fixes. No model API, network/default dependency,
  target execution, new command, release or automatic vulnerability suppression.

Three bounded implementation/review passes; checkpoint after 120 minutes or two
passes without progress. Evidence and frozen baseline live in the ignored
`.cache/sanitizer-contracts-20261028/`. Preserve all unrelated user work.

## Evidence boundary

This closes the explicitly identified semantic-sanitizer work, not every research
candidate or possible program behavior. Existing realistic-negative coverage debt
and unsupported compiler/framework semantics stay visible. No absent-vulnerability
or model precision/token claim is permitted.

## Implementation and review

Shared bounded transform contracts now separate provenance from safety for a
particular use. Python builtin/import identities and JS runtime imports require
an unshadowed binding. Transparent Python identity wrappers must have exactly
one ordinary argument and a sole return of that argument. Arbitrary `abs`/`round`
protocol results are not guaranteed primitive conversions. A protector-like name
never supplies safety; unresolved calls retain an advisory lead.

Python receiver methods retain their input provenance. Basic `if` branches join
their value states, and scalar conversion does not clear the original parameter
or a raw sibling path. SQL bind values remain separate from statement text.
SQLModel's `session.exec` is not classified as the Python execution builtin.
The source-only IR consumes the same transforms and resolves qualified helper
names before applying its existing unique-language candidate restriction.

JS contracts combine contributing values instead of trusting the first alias.
Conditional writes remain unresolved, and a guard cannot protect an earlier
sink or a later reassignment. Path checks need a directly normalized value,
separator-aware prefix and rejecting control flow. This is a lexical containment
check, not a filesystem/symlink proof. DOMPurify protection covers whole HTML
values with a bound default API; options, hooks, module escapes, mutations and
HTML embedding remain advisory. Numeric conversion cannot authorize a URL.

POSIX shell quoting requires a bound import and an earlier rejecting platform
guard. Quoting does not transfer into SQL, and composing a quoted token into
another shell quoting context remains unresolved. An argv sequence with no shell
is distinguished from shell interpretation. Expression/transform budget failures
enter incomplete graph accounting rather than creating a safe result.

Packet runtime identity now binds all 18 shipped native detector and packet
modules, including the new helper. A manifest-based test changes each module's
bytes without changing its length and checks invalidation. Source identity means
consistency only; it does not prove reviewer honesty or runtime exploitability.

The executable count remains 673. Gate floors, severities, corpus pins, labels,
remediation recipes and artifact byte caps are unchanged. Unknown processing
becomes advisory because its output is unresolved, not because a corpus result
was suppressed. Finding fingerprint construction is unchanged; correcting the
contributing carrier legitimately changes two Prefect tracking fingerprints.
No baseline was rewritten.

## Pinned-source triage

The final static replay compares the archived c5 baseline with current source in
14 projections: Umami/Shlink defaults and cross-file, CleanArchitecture, TodoApp,
LocalSend, four Luau libraries, Umami SQL migrations, FastAPI template cross-file
and Prefect API cross-file. The archived scanner, graph and IR blobs were checked
against c5. An exploratory helper had selected the earlier 6d archive; its
observations were discarded as comparison evidence and the corrected replay was
repeated. No target application's code, builds or tests executed.

- FastAPI `items.py:34` and `users.py:229`: remove two false SP101 gate reports
  from SQLModel session execution. This does not assert the whole application is
  safe; its existing Python 3.14-only syntax limitation remains visible on 3.12.
- Prefect `flow_runs.py:312`, `ui/flow_runs.py:119`, `ui/flows.py:65` and
  `ui/task_runs.py:150`: preserve previously lost query-builder receiver/input
  provenance as SP103 advisories. These are unresolved builder semantics, not
  established SQL injection vulnerabilities.
- Existing Prefect sites `concurrency_limits_v2.py:73,110`,
  `deployments.py:410,428`, and `ui/flows.py:157` stay visible as advisories rather
  than confirmed blocking SQL paths. Builder/helper behavior and injected database
  dependencies need semantic context. The deployment carrier correction changes
  evidence from `deployment_id` to `db` at the two existing sites.
- The other 12 projections retain their finding records. Existing binary/parser
  omissions remain recorded; this is not a whole-repository cleanliness claim.

Raw reports, module digests and run receipts remain in the ignored cohort cache.
The checked-in observations contain summaries rather than redistributed projects.

## Documentation and packaging

Benchmark/rule-assurance methodology and contribution/governance documents stay
in the repository, with canonical online README links. They are source-only in
the npm artifact. Runtime modules, executable benchmarks, both user languages,
skills, security guidance and license remain bundled. Edited text follows the
repository's existing LF policy. The original 500,000/1,870,000 caps stay fixed.

## Primary references

Context7's documentation quota was exhausted. These owner-maintained sources and
the pinned project source supplied the fallback, not copied detector code:

- [Python HTML escaping](https://docs.python.org/3/library/html.html): HTML encoding.
- [Python SQLite parameters](https://docs.python.org/3/library/sqlite3.html): bound values.
- [Python shell quoting](https://docs.python.org/3/library/shlex.html): POSIX token scope.
- [SQLModel session execution](https://sqlmodel.tiangolo.com/tutorial/select/): SQL API identity.
- [SQLAlchemy parameter binding](https://docs.sqlalchemy.org/en/20/tutorial/dbapi_transactions.html): values and SQL text.
- [Node path APIs](https://nodejs.org/api/path.html): normalization and separators.
- [ECMAScript Number](https://tc39.es/ecma262/multipage/numbers-and-dates.html#sec-number-constructor): primitive numeric conversion.
- [DOMPurify usage and configuration](https://github.com/cure53/DOMPurify): context, persistent settings and hooks.

## Verification boundary

Authored regressions include wrong contexts, import aliases/rebinding, identity
names, protected/raw siblings, overwrites, branching, parameterized SQL, quoting,
containment, mixed JS carriers, opaque source text, budgets, JSON/SARIF/Node parity
and isolated packed/installed Codex/Claude skill parity. A SQLite-only in-memory
fixture demonstrates HTML escaping failing to neutralize a numeric SQL predicate
while a bound parameter remains data. No public application, external database
or model executes for that fixture.

Verification is primary-agent review and automated gates; the helper handled
mechanical documentation and static replay, not independent security QA. Dynamic
dispatch, arbitrary control flow, custom framework/type semantics and indirect
aliases remain bounded-analysis limitations. Existing realistic-negative debt
remains 128 realistically covered rules and 409 high/critical rules without such
coverage. No zero-false-positive, model-quality or production-scale claim is made.

## Frozen verification results

`npm run check` passes with 1,086 Python tests (three local Windows symlink
privilege skips), two demo tests, Node/MCP source suites, exact package manifest
and isolated packed smoke. The 45 new regression tests include 44 contract cases
and a runtime identity invalidation test. Fresh coverage with branch measurement
enabled is 88%, above the unchanged 80% floor; the new contract module is 96%.

The paired benchmark retains all 30 original packages and 867 files, 130 original
application findings and 54 positive high/critical signatures. The remediated leg
has 72 findings, zero high/critical findings, zero blocked packages and 16 gate
high/medium findings. Existing reviewed lower-severity false positives remain;
their budgets do not worsen. These results are source-signature evidence, not an
aggregate precision claim. All 673 rule contracts pass without changing debt.

The artifact is 110 files, 473,247 packed / 1,868,677 unpacked bytes under the
original limits. Native high self-scan reports zero application findings and
complete supported coverage; deliberately unsafe test findings stay test-scoped.
Final scanner runtime identity is
`17ee239f240546bb10e2101d9f8741994cd5d806ad4b227c5c1241cfcae751b1`.

Comparable graph builds use the same driver/input digests for both c5 and current
source, one warmup and three samples, after other local test jobs finish:

| Synthetic workload | c5 median / max seconds | Current median / max seconds | c5 / current peak MiB |
| --- | --- | --- | --- |
| 500 files, 512 bytes each | 0.4993 / 0.5554 | 0.5107 / 0.5212 | 24.95 / 25.01 |
| 16 files, 459,152 bytes each | 1.4358 / 1.4426 | 1.5156 / 1.5393 | 28.31 / 28.59 |

Every arm meets the existing eight-second / 256-MiB ceilings. The maximum of three
samples is a conservative p95 proxy, not a measured production tail. The small
median overhead buys binding/value checks; no speedup or scale claim is made.
The oversized graph case still declares its 16 omissions instead of silently
reporting complete coverage.

Exact input hashes, samples, coverage summaries, field deltas and benchmark
receipts are in [the observations](sanitizer-contracts-observations-2026-10.json).
Exact-head hosted CI/MCP/coverage and manual benchmark links are maintained in
[PR #49](https://github.com/kingggg5/shipproof/pull/49) after pushing this cohort.
Version remains 0.12.0 with Unreleased changes.
