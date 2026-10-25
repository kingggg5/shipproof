# Value / defaults / trust cohort — 23 October 2026

## Engineering contract

- Baseline: clean `e4877bcc2ed4a104b318a5a6d6fc4fe3a8b67b73`, 666 executable
  rules, 939 Python tests / 86% coverage and green CI, Security and Benchmarks.
- Objective: add locally provable invalid-value/resource checks, extend typed TLS
  and Rust coverage, retire unsupported default-assumption warnings, and compare
  pinned real-source observations without lowering gates or relabeling real risks.
- Selected candidates: SP699 Rust NonZero unchecked zero, SP700 imported Node
  timer overflow, SP701 explicitly unlimited native SQLAlchemy QueuePool. Extend
  SP673 reference initialization and SP104 typed .NET TLS acceptance; reuse IDs
  for variants. Retire SP347/SP350 only after primary-source confirmation.
- Packaging: keep the rule guide and offline `explain` metadata, move the full
  source catalog to a source-only document with an explicit link. Preserve all
  catalog rows and assertions; no runtime feature/data deletion or budget increase.
- Acceptance: each addition >=3 positive / >=5 negative / >=2 adversarial cases;
  provenance, duplicate decisions, real walker, scope/anchors/redaction, native
  probes when safe, existing and new pinned-source replay, paired corpus, full
  check, coverage, MCP, self-scan and exact-head CI. Three bounded implementation /
  review passes, 90-minute checkpoint, stop on two no-progress passes.
- Budgets: unchanged 50,000 lexical tokens/API AST nodes, 1 MB scanned file,
  500,000/1,870,000 package bytes; comparable 1,000-file, 512-byte fixtures,
  1 warm-up / 3 samples / jobs=1, 8 s / 256 MiB. No speed-up claim without data.
- Scope: read-only/offline default, standard-library runtime only; no target code
  execution, network listeners, active exploits/load tests, new tools/dependencies,
  permissions, merge or release. Unsafe Rust samples are not executed.
- At most two new public source snapshots, pinned commit/license/context hashes,
  <=2,500 selected files and <=25 MB per project. Selection is explicit; no whole
  application safety claim. Existing corpora/labels/positive evidence are retained.
- Evidence: `.cache/value-cohort-20261023/`; concise provenance/results in research.
  User explicitly authorized commit/push. Version remains 0.12.0; PR #49 stays open.

Context7 resolution was attempted for SQLAlchemy; quota was exhausted. Owning
documentation/source is the fallback. The interrupted attempt's pinned snapshots
and partial documentation split were preserved and verified on continuation.

## Accepted checks and false-positive boundaries

- **SP699 — correctness:** fully qualified std/core primitive NonZero integer
  constructors with literal zero (including matching integer suffixes). Safe
  constructors, other values, visible module shadows and stringify token data
  do not establish this finding. Arbitrary macro expansion/type aliases and
  runtime reachability are not proven.
- **SP700 — performance:** imported Node timers/timers-promises use the correct
  delay position; exact decimal integers and bounded multiplication expressions
  above 2,147,483,647 ms are reported. Global/browser timers, other computed
  values, wrong argument positions and known-invalid callback literals stay
  silent. Products are capped at nine operands and exact integer range.
- **SP701 — scale:** import-bound native QueuePool construction explicitly sets
  pool_size=0 or max_overflow=-1. Defaults, engine factories, custom pool classes,
  unknown/duplicate/spread options and reassigned/escaped imports are unresolved.
  SQLAlchemy is never imported by the scanner.
- **SP104 extension — security:** a single-use typed SslStream receiver directly
  consumes inline client options with a four-parameter unconditional-true
  certificate callback. Conditional callbacks, custom types, duplicate properties,
  invalid duplicate parameter names (except discards) and rebinding stay silent.
- **SP673 extension:** qualified uninitialized reference construction joins
  zero-initialized references. Imported standard-looking modules, raw identifiers
  and stringify expressions are excluded; stringification ranges are disjoint to
  avoid repeated work across nested token data. Other types are unmodeled, not safe.

The three new IDs and these new source variants are advisory. Thresholds were not
changed. Node timer delay conversion is distinct from SP687 payload-size conversion;
NonZero integer validity is distinct from reference initialization. TLS retains
SP104 and reference variants retain SP673 rather than inflating the registry.

## Retired assumptions

SP347 and SP350 are retired and their IDs remain reserved:

- `gather` normally propagates the first exception to its awaiter; siblings are
  not automatically cancelled. Requiring return_exceptions=True everywhere can
  hide failures and is not a valid correctness policy.
- Missing pool_size/max_overflow in create_engine is not proof of unlimited
  capacity. QueuePool has bounded defaults, while engine pool selection depends
  on dialect and configuration. Explicit QueuePool opt-outs are a separate check.

The registry is **667 rules**: 666 + three additions − two retirements. Research
deduplication references were regenerated. Existing original corpus positives,
source pins and remediation recipes were not weakened or rewritten.

## Primary references and native probes

- [Rust NonZero validity](https://doc.rust-lang.org/std/num/struct.NonZero.html#method.new_unchecked),
  [uninitialized](https://doc.rust-lang.org/std/mem/fn.uninitialized.html) and
  [stringify](https://doc.rust-lang.org/std/macro.stringify.html).
- [Node timer range and overloads](https://nodejs.org/api/timers.html).
- [SQLAlchemy QueuePool](https://docs.sqlalchemy.org/en/20/core/pooling.html#sqlalchemy.pool.QueuePool).
- [Python gather](https://docs.python.org/3/library/asyncio-task.html#asyncio.gather).
- [SslClientAuthenticationOptions callback](https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslclientauthenticationoptions.remotecertificatevalidationcallback).

Bounded authored probes used installed runtimes, not downloaded application code:

- Node **24.22.1** retained the maximum valid delay and clamped a 30-day interval
  to 1 ms. The interval was immediately cancelled; the promises overload was also
  checked. No timer storm/load test or network listener was created.
- Python **3.12.10** / installed SQLAlchemy **2.0.51** verified pool defaults
  (size 5 / overflow 10), explicit zero size and -1 overflow without opening a
  database connection. Gather propagated a deliberate exception and its retained
  sibling completed without cancellation.
- Rust **1.96.0** verified checked zero rejection, valid unchecked construction
  with one, and stringify token behavior. No undefined-behavior case was executed.
- .NET **8.0.29 / 10.0.12** confirmed an unconditional callback accepted reported
  certificate errors while a conditional callback rejected them. No TLS handshake,
  socket or service was opened.

## Project evidence and limitations

The [new Python corpus](../benchmarks/value-cohort-repositories.json) adds:

| Snapshot | Scope | Selected / scanned on Python 3.12 | Observations before / after |
| --- | --- | ---: | ---: |
| Full Stack FastAPI Template (MIT) | All repository Python files; template, not deployed app | 43 / 42 | 20 / 19 |
| Prefect (Apache-2.0) | src/prefect Python projection; framework, not full repository | 857 / 857 | 375 / 364 |

All twelve removals are SP347/SP350 observations from unsupported policies.
No observations were added; the other 383 were preserved without relabeling them
as safe. This is not an independently measured false-positive rate or recall.

The FastAPI snapshot declares Python >=3.14 and uses
[PEP 758](https://peps.python.org/pep-0758/) syntax at
backend/app/api/deps.py:36. The available Python 3.12 cannot parse it. The source
was not rewritten or excluded: replay explicitly retains **INCOMPLETE / exit 2**,
one parser-limit omission and the raw observations. The evaluator now preserves
incomplete reports while continuing to fail the gate; hash errors/overwrites
still fail closed. A regression test enforces this distinction across runtimes.

The previous eight snapshots retain all 201 findings with identical fingerprints.
Across ten snapshots, **3,515 files are selected and 3,514 analyzed**. Nine snapshots
are complete; the FastAPI template is not. Licenses, ordinal source-tree hashes,
framework context (including backend pyproject) and before/after identity checks
are preserved. [Metadata-only observations](value-observations-2026-10.json) bind
the baseline/candidate source digests and raw report hashes. No target project was
built, imported or executed.

The existing paired corpus also passes: 30 packages / 867 files per leg, original
130 application observations and all 54 high/critical signature locations retained;
quiet leg 72 observations, zero high/critical, 16 gate-medium, no blocked packages
or FP-budget violations. The original risk leg remains intentionally non-clean.

## Verification and resource evidence

- 82 cohort cases: 21 positive, 44 negative/unresolved, 17 adversarial; an additional
  uninitialized-reference counterpart is in the original Rust contract generator.
- Full local check: **950 Python tests**, three Windows symlink-privilege skips,
  two demo tests, Node contracts, package allowlist and isolated CLI/Action/skills
  smoke passed. Runtime branch coverage remains **86%**, unchanged 80% floor.
  Source MCP exercises all five tools and new/retired-rule snippets; CI covers
  the existing six Node/Zod peer combinations and fresh packed consumers.
- High self-scan is complete: zero application findings / 32 pre-existing
  intentional test findings, no suppression or parser-limit omissions.
- Assurance: **667/667 complete**, 120 realistic-negative contracts; 547 near-miss
  only and 415 high/critical realistic-negative debt remain visible. The debt
  baseline only shrank; no quality minimum or performance ceiling was raised.
- The source catalog is retained in docs/rule-catalog.md, with unchanged complete
  row/severity assertions pointed to it. The shipped boundary guide retains its
  anchor/link and offline explain remains backed by runtime metadata. No runtime
  rule data was removed to fit the package budget.
- Final package: 110 files, 466,778 packed / 1,812,376 unpacked bytes; main scanner
  641,065 bytes. All original package and file ceilings remain unchanged.

Windows 11 / Python 3.12.10, 1,000 files, 512 bytes/file, one warm-up, three samples,
jobs=1. Before/after fixture digests match; all profiles emit zero findings.

| Profile | Median before / after | p95 before / after | Peak RSS before / after |
| --- | ---: | ---: | ---: |
| New mixed TS/Rust/Python value-config | 1.6707 / 1.7409 s | 1.6946 / 1.8217 s | 28.47 / 28.82 MiB |
| Existing TS configuration | 2.1748 / 2.1833 s | 2.1983 / 2.1846 s | 28.21 / 28.17 MiB |

Both remain below unchanged 8 s / 256 MiB budgets. The mixed workload became
slightly slower; no speed-up or production-scale guarantee is claimed. The new
value-config profile and its deterministic three-language fixture test are public.

## Review outcome

Primary-agent semantic review and integration, not an independent security audit.
The engineering skill kept budgets, paired evidence and unknowns explicit. No new
runtime dependency, source upload, permission change, merge or release. Remaining
work includes a Python 3.14 replay of the template and broader labelled deployment
cases; unsupported grammar/macros/type graphs do not constitute a clean verdict.
