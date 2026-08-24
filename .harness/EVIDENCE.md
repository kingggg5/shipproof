# Harness Conditional Evidence

- Schema version: 1
- Memory revision: 0
- Project ID: project-25bc2383-ce85-49b1-b32b-49387e479288
- Run ID: RUN-ff934524c3ec446b9b01047596b5d8d1
- Active lanes: release readiness, command contracts, rule assurance, performance/package budgets

## Discovery contract

- Objective: Close the highest-value remaining roadmap gaps without adding unproven detectors or weakening the production gate.
- Excluded scope: Release/tag/push, external mutations, active traffic/fuzz/DAST, dependency installation, and bulk rule promotion.
- Baseline known at discovery: ShipProof 0.9.0 was dependency-free on its default path; the prior full check and high-gate self-scan passed at commit `c9785ab`; explicit polarity manifests then covered 110 of roughly 620 executable rules.
- Assumption to verify: Existing output schemas and scattered tests can supply normalized golden fixtures without changing public command behavior.
- Open question: Which public JSON commands lack stable snapshots, and how many rules can be classified as explicit, legacy-observed, or uncovered without misrepresenting coverage?
- Baseline: repository checks, command enumeration, schema tests, explicit rule manifests, package budget, and local scanner benchmark on Node 24.15.0/Python 3.12.10.
- Bounds: Two discovery cycles maximum; local read-only diagnostics during discovery; no paid/external calls required for P0/P1.
- Plan-ready condition: Exact command/fixture matrix, executable-rule inventory, compatibility strategy, and focused verification commands are identified.

Discovery result: `READY_FOR_PLAN` and implemented under the approved plan. Eight public evidence commands have complete normalized v1 snapshots. The initial 60-complete/50-partial/510-uncontracted inventory drove the successor-contract work; the final gate is 620 complete, 0 partial, 0 uncontracted, and 0 metadata debt. Placeholder-only or empty cases cannot count as meaningful evidence.

## Performance and scale contract

| ID | Workload/dataset | Environment/runtime | Metric | Baseline | Threshold/SLO | Result/uncertainty | Evidence | Status |
|---|---|---|---|---|---|---|---|---|
| PERF-1 | Existing 1,000-file synthetic scanner benchmark, three runs | Windows; Node 24.15.0; Python 3.12.10 | median/p95 seconds, peak RSS, output determinism | Prior 0.6813 s and 24.79 MB RSS | <= 5 s repository budget; <= 256 MB; identical sample digest/counts | Median 0.9747 s, p95 0.9879 s, peak RSS 25.57 MB; deterministic; local synthetic evidence only | `scripts/benchmark-scanner.py` | PASS |
| PACK-1 | `npm pack --dry-run`/packed smoke fixture | Local npm/Node 24.15.0 | packed and unpacked bytes | Prior 111 files, 428774 packed, 1620931 unpacked | 500000 packed; 1800000 unpacked; exact allowlist | 113 files, 435220 packed, 1642530 unpacked; `.harness` excluded from artifact | package tests | PASS |

## External audit evidence

Exit/error that means unavailable is never a pass.

| Capability/backend | Command/method | Version/revision | Exit/verdict | Evidence | Confirmed limitation/follow-up |
|---|---|---|---|---|---|
| Harness doctor | `python .harness/runtime/scripts/memory_ops.py doctor --project . --logical-scope .` | 0.3.1 repository-pinned runtime | 0 / HEALTHY | Identity/store/runtime/writer-lock probes passed | Workflow QA is same-context, not independent. |
| ShipProof doctor | `node bin/shipproof.mjs doctor . --json` | 0.10.0 candidate based on `c9785ab` | 0 / PASS | Runtime, repository, CI, policy, skills, lockfile detected | Structural preflight does not prove production readiness. |
| ShipProof full gate | `npm run check` plus direct high-gate scan | 0.10.0 working tree | 0 / PASS_WITH_EVIDENCE | 602 Python tests plus 2 demo tests, all Node suites, 113-file package smoke, and 267-file self-scan pass with 0 findings | No independent reviewer or production runtime evidence. |

## P1 executable-rule contract evidence

| Contract family | Rules | Required cases | Assertions | Result |
|---|---:|---|---|---|
| Runtime secret providers | 50 | 2 positive, 2 negative, 1 adversarial per rule | Exact rule/path/line/severity/confidence/detection/proof/fingerprint | PASS |
| Regex/pattern manifests | 484 | Severity-minimum positives, 2 negatives, 1 adversarial per rule | Exact finding fields plus deterministic manifest/index hashes | PASS |
| Structural/AST manifests | 25 | Severity-minimum positives, 2 negatives, 1 adversarial per rule | Exact finding fields; AST validation for Python fixtures | PASS |
| Artifact manifest | 1 | Positive artifact plus negative/adversarial files | Exact artifact finding fields and stable fingerprint | PASS |

- Assurance result: 620 complete, 0 partial, 0 uncontracted, 0 metadata debt.
- Determinism: all three manifest builders pass in `--check` mode; their checked-in indexes include content hashes.
- Guardrail: the empty legacy baseline may shrink but cannot expand through `--update-baseline`.
- Limitation: generated pattern witnesses prove stable scanner behavior and polarity, not real-world precision. P2 promotion still requires separate primary-source semantics, duplicate analysis, representative corpus/shadow measurements, and benchmark deltas.
- Harness health note: the repository-pinned 0.3.1 runtime doctor is HEALTHY. The mutable external plugin copy reported generated-view drift, so pinned runtime rendering remains the authoritative fallback for this run.

## P2 batch-A promotion evidence

| Outcome | Count | Evidence boundary |
|---|---:|---|
| Fixture-ready | 3 | Narrow research-only matchers with 2 positive, 4 negative, and 2 adversarial cases each |
| Rejected from batch | 22 | Executable duplicate, candidate duplicate, missing framework semantics, misrouted ecosystem, policy context, or required data-flow/lifetime analysis |
| Promoted | 0 | No representative-repository shadow precision or benchmark delta was available; promotion failed closed |

- Decision record: `research/promotion-batch-a.json`, deterministically built by `scripts/build_promotion_batch_a.py` and enforced by `tests/test_promotion_batch_a.py`.
- Current owning-document checks included Context7 resolutions `/websites/learn_microsoft_en-us_aspnet`, `/websites/php_net_manual_en`, and `/websites/angular_dev`, plus current MITRE CWE, Go package, React, TypeScript, Node/PostgreSQL, and SEI material.
- `SP5301`: browser-supplied PHP upload MIME used directly in a decision; authoritative content validation may occur later, so shadow evidence is mandatory.
- `SP5951`: direct sensitive Go `http.Cookie` literal without `HttpOnly: true`; helper/object flow remains a known boundary.
- `SP6309`: direct command-line `argv` in a C/C++ format position; aliases and parameters remain an explicit taint-analysis boundary.
- Residuals are machine-readable and non-PASS: revision/license-reviewed representative corpus, per-candidate TP/FP/FN/TN, and performance delta.

## P3 adapter evidence

| Contract | Evidence | Result |
|---|---|---|
| Executable trust | Fixed commands/arguments; repository-contained TypeScript path; no shell | PASS |
| Consent | TypeScript/Rust execution requires `--allow-project-code`; unapproved TypeScript discovery does not execute its version probe | PASS |
| Availability/version | Tool-specific probes; empty/failing probe is unavailable; bounded analyzer version in report | PASS |
| Failure classification | Findings, unavailable, timeout, output cap, signal/crash and unexpected exit are distinct | PASS |
| Output safety | 2 MB child cap; 200 lines; 4,096 chars/line; credential-shaped diagnostics redacted | PASS |

- Regression tests include a repository-local compiler side-effect marker proving that unapproved discovery does not execute project code.
- Default scanning remains offline and dependency-free; adapters are explicit optional commands only.

## P4/P5 and CLI evidence

| Lane | Workload | Result |
|---|---|---|
| Controlled detection | Six fixture corpora, repeat 3, v2 sink/context labels | Thresholds PASS; positive corpora observed file precision/recall 1.0; secure corpora 0 findings |
| Clean throughput | 1,000 x 128-byte files, 3 samples, one worker | Median 0.9747 s; p95 0.9879 s; 25.57 MB; PASS under 5 s/256 MB |
| CI throughput | 1,000 x 128-byte files, 3 samples, four workers | Median 0.8236 s; p95 0.8952 s; 27.64 MB; PASS under 15 s |
| Adversarial regex | 250 x 4 KiB, 3 samples | Median 2.3894 s; p95 2.4173 s; 25.18 MB; PASS under 5 s/256 MB |
| Large files | 8 x 512 KiB, 3 samples | Median 8.3898 s; p95 8.4919 s; 27.53 MB; PASS under 10 s/256 MB |
| Real-world availability | Six full-commit/license-pinned public repositories | 1,805 files, 732 total/310 app findings; all alerts explicitly unreviewed |
| CLI migration | Every hidden legacy alias against simulated 1.0.0 | Rejected with replacement and exit-class contract; 0.x warnings retained |

- Benchmark reports now include exact fixture bytes/digest, runtime identity, sample timings, sample file/finding counts, median, p95 and peak RSS; nondeterministic samples fail the budget.
- Real-world Git runs are non-interactive and time-bounded with isolated system/global config plus an empty hook template. Fetch/revision/license failures return invalid evidence, never a skipped pass.
- External boundary: the six-repository run proves immutable corpus and evaluator availability only. Clean-baseline findings still require human labels; no representative precision claim or detector promotion is made.
