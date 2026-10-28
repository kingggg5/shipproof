# Cross-file analysis coverage and response availability audit

Design recorded 2026-10-28 before changes. Baseline:
`6d9bd5968ed3cc213acc7504eb910fd63603fea0`.

## Confirmed scope

The bounded discovery pass found two reproducible correctness defects:

- A 459,154-byte JS source with a valid source-to-query example after a large
  comment prefix loses its small-file L2 trace, while `--cross-file` still reports
  complete coverage. The graph truncates JS input without reporting the limit.
- A valid packet completion followed by a packet timeout in the same response
  batch produces `review_complete=true`, zero failed items and zero rejections.
  An accepted availability error must not become successful review evidence.

The graph also uses a size precheck followed by an unbounded replacement-decoding
text read. Reproduce its file-change boundary with a controlled local fixture,
then replace it with guarded bounded reads and strict UTF-8. No target program,
external system, exploit, load test or model is executed.

## Engineering contract

1. Keep all native rules, fingerprints, corpus labels, proof/severity floors,
   default scan behavior and package/scanner caps unchanged. No new command,
   dependency, provider, network path, source execution, merge, tag or release.
2. Record observed graph file/function/body/argument/parameter/sink/callee/hop
   limits and expected read/parse failures. Preserve useful partial findings;
   never silently present an omitted analysis as complete or unreachable/low risk.
3. Cross-file integration updates the existing completeness counters. Strict
   scans fail closed on incomplete graph evidence; the existing explicit
   exploratory override retains a conditional report. No vulnerability is
   invented merely because analysis coverage is incomplete.
4. Respect the main scanner's exact eligible-file set, including tracked source
   inside normally pruned trees. Standalone graph reads reject links, races,
   invalid encoding and oversized files. Guard metadata itself is bounded.
5. A model timeout/error prevents `review_complete` and exits 2 in response mode
   even when all item decisions arrived first. Native findings and gate evidence
   remain unchanged. Fresh successful retries retain their existing behavior.
6. Regression tests cover each failure, exact-boundary negatives, scope and
   source/data opacity, direct Python/Node/SARIF parity, packed artifacts and
   installed skills. Full checks, fresh coverage, high self-scan and assurance
   must pass without relaxing a threshold.
7. Replay pinned public sources with and without cross-file analysis. Preserve
   source identity, native observations and genuine positive fixtures; document
   new incomplete-analysis reasons separately from vulnerability observations.
   Measure identical before/after workloads without competing workers.

Use three bounded implementation passes with a 90-minute checkpoint or stop
after two passes without improved evidence. Cache logs and a frozen baseline in
`.cache/analysis-coverage-20261028/`. Commit/push verified changes only.

## Review boundary

Cross-file summaries remain structural heuristics, not a compiler or complete
dataflow/reachability proof. Sanitizer name matching and sink-specific semantics
are separate review leads from the inventory; this cohort does not certify them
or change their detector contracts without dedicated reproductions and negatives.
No actual model precision/recall or production-scale behavior is claimed.

## Implemented boundaries

The graph now reuses guarded source reads, rejects invalid UTF-8, preserves
universal newline behavior, refuses known oversized files before opening, and
bounds concurrent-growth reads to the existing byte limit plus one lookahead
byte. Nonblocking opens prevent a replaced special file from blocking that read.
The scanner's selected-file set is authoritative, so explicitly selected tracked
source in normally pruned trees is not silently lost in the graph's own walk.

Observed JS file/function/body/argument/parameter/binding/sink/callee limits and
the existing six-hop propagation cap enter bounded omission accounting. Partial
findings remain available. Cross-file scans feed omissions into existing coverage
counters; strict scans fail closed while an explicit exploratory override keeps
a conditional report. Default scans do not invoke the graph or change findings.

Impact reports carry additive `completeness`; incomplete graphs have UNKNOWN
reachability/risk and exit 2 rather than claiming that a missing path is dead or
low risk. Missing/unsupported targets and nonpositive lines are invalid requests.
An out-of-scope target cannot poison later analyses on the same graph. The schema
retains legacy complete reports while requiring explicit incomplete metadata for
new zero-file/UNKNOWN diagnostics. Existing native command contracts are intact;
the impact fixture deliberately includes the new coverage object.

Packet completion now also requires zero accepted packet errors/timeouts. A
timeout after item completions leaves those original decisions visible but cannot
establish complete review or a successful response operation. Native findings
remain independent from these unverified bookkeeping inputs.

## Reproductions and scope

The same controlled examples run against the frozen baseline and candidate:

| Reproduction | Baseline | Candidate |
| --- | --- | --- |
| JS input beyond graph's 400,000-character budget | No L2 flow; coverage reported complete | No invented flow; parser-limit coverage is incomplete |
| File grows beyond a 32-byte allowance | Unbounded read consumes 576 bytes | Guard consumes 33 bytes including lookahead; oversized input rejected |
| Completion followed by packet timeout | `review_complete=true` | `review_complete=false`; response CLI exits 2 |

These are local regression examples, not a CVE assignment, active external
exploitation, or a live model evaluation. Each protects a stated input/coverage
contract. Sources in the public replay are read as data, never executed.

## Verification record

The frozen candidate passes `npm run check`: 1,040 Python tests (three Windows
symlink-privilege skips), two demo tests, Node/MCP contracts, exact package
verification and packed smoke. Fresh Python branch coverage is 88% with the
existing 80% floor. High self-scan has zero app findings, 32 existing test findings
and complete supported coverage. All 673 rule contracts remain complete.

The artifact has 113 files, 476,332 packed / 1,866,889 unpacked bytes, below the
original 500,000 / 1,870,000 caps. Impact's additive coverage fixture and schema
validate complete and incomplete diagnostics, retain legacy complete reports,
and reject a false LOW score on incomplete evidence. The preinstalled reference
validator uses local schema resources; no such dependency is added to core.

Eight source projections from seven pinned public repositories were replayed:
default scans of Umami, TodoApp, LocalSend and ProfileStore, plus cross-file scans
of Umami, Shlink, Full Stack FastAPI and the Prefect API subset. Findings compare
equal in all eight; default reports and all high-gate exit codes remain unchanged.
Umami's cross-file pass now reports ten graph-limited inputs previously hidden.
Existing binary omissions and Python 3.14-only syntax limitations remain explicit.
These observations are not clean-corpus or confirmed-vulnerability labels.

Identical graph benchmarks use one warmup and three samples without concurrent
validation workers. Both arms pass the declared 8-second p95 and 256-MiB RSS caps:

| Workload | Median before/after seconds | p95 before/after seconds | Peak RSS before/after MiB |
| --- | ---: | ---: | ---: |
| 500 clean 512-byte modules | 0.2386 / 0.4482 | 0.2386 / 0.5317 | 24.89 / 25.19 |
| 16 files beyond graph character cap | 1.3315 / 1.3378 | 1.3353 / 1.3707 | 28.12 / 28.48 |

Guarding every source path adds measurable cost; no speedup is claimed. The
over-limit case now declares 16 partial inputs instead of omitting the coverage
signal. Exact input hashes, samples, runtime digests, read-race results and replay
counters are in [the observations](analysis-coverage-observations-2026-10.json).

The source test set covers read races, strict encoding, CR/CRLF coordinates,
exact-boundary negatives, scope preservation, omission bookkeeping, format/exit
parity, and conflicting completion/availability signals. Existing rule IDs and
all native severity/proof/precision/resource thresholds remain unchanged.

Verification is primary-agent self-review plus automated gates. The helper made
mechanical documentation edits, not independent QA. Public applications and their
test suites were not executed. Remaining semantic/sanitizer questions above are
not settled by these coverage fixes, and no absence-of-vulnerabilities claim is
made. Version remains 0.12.0 with Unreleased changes; no merge, tag or release.
