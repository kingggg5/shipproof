# Benchmarks and evaluation methodology

Every number on this page comes from a command you can run. If one does not reproduce, it is stale; please open an issue.

## Reproducing everything

```bash
# Fixture battery: precision / recall / F1 against shared labels
python benchmarks/head_to_head.py fixtures/vulnerable-node-api \
  fixtures/vulnerable-python-api fixtures/node-taint-crossfile \
  fixtures/adversarial-node fixtures/secure-node-api \
  fixtures/node-secure-crossfile --repeat 3

# Throughput
python scripts/benchmark-scanner.py --files 1000 --jobs 4

# Open-source battery (network required; clones depth-1 into benchmarks/.work)
python scripts/eval-realworld.py
```

CI runs the fixture battery and throughput check weekly ([.github/workflows/benchmarks.yml](../.github/workflows/benchmarks.yml)) with the real-world clone step behind an opt-in flag.

## Fixture battery

Six small repositories serve as executable contracts: two intentionally vulnerable single-file APIs, one multi-file Node corpus whose taint crosses three files, one adversarial suite of precision traps, and two secure counterparts that must produce zero findings. Labels mark which files genuinely contain issues; scoring is file-level against those labels.

Latest run (Windows 11, Python 3.13, `--cross-file`, median of 3):

| Corpus | Findings | Files flagged | Precision | Recall | F1 |
| :--- | ---: | ---: | ---: | ---: | ---: |
| vulnerable-node-api | 2 | 1 | 1.0 | 1.0 | 1.0 |
| vulnerable-python-api | 3 | 1 | 1.0 | 1.0 | 1.0 |
| node-taint-crossfile | 6 | 4 | 1.0 | 0.8 | 0.889 |
| adversarial-node | 4 | 4 | 1.0 | 0.667 | 0.8 |
| secure-node-api | 0 | 0 |: |: |: |
| node-secure-crossfile | 0 | 0 |: |: |: |

Two caveats. The adversarial corpus contains vulnerable-looking code confined to comments and string literals; detectors must stay silent there while still catching disguised chains elsewhere - both directions are asserted in tests. And `routes/orders.js` in the taint corpus is labeled vulnerable even though no sink-based tool flags pure sources; the label stays even though it costs recall.

## Open-source battery

`eval-realworld.py` clones six public repositories at depth 1 and reports findings split by scope (application vs test). Application scope is what the release gate acts on.

| Repository | Character | Files | App findings |
| :--- | :--- | ---: | ---: |
| expressjs/express | clean baseline (library) | 162 | 2 |
| pallets/flask | clean baseline | 221 | 5 |
| psf/requests | clean baseline | 93 | 3 |
| juice-shop/juice-shop | intentionally vulnerable | 1023 | ~153-180* |
| digininja/DVWA | intentionally vulnerable (PHP) | 225 | 74 |
| OWASP/NodeGoat | intentionally vulnerable | 81 | 20 |

\* juice-shop drifts between runs because upstream moves between clones; the range above brackets observed snapshots. Within every snapshot, secure corpora stay at zero and NodeGoat's documented `eval(req.body)` chain is confirmed by L2 taint evidence.

Clean baselines are the FP story: express lands at 2 application findings on 162 files because test-scope noise never reaches the gate verdict, and the fixes that got flask from 27 highs to 3 each carry their own regression tests.

## Performance

Measured by [scripts/benchmark-scanner.py](../scripts/benchmark-scanner.py) over generated Python repositories (warm-cache pass reported separately):

- Sequential: ~1,400 warm files/s at 1,000 files
- `--jobs 4`: ~2,100 files/s
- Peak RSS stays around 24 MB for the generated corpus shape

Throughput is re-checked after engine changes; the JS/TS analyzer and SARIF enrichment did not move it measurably.

## Scope and operating limits

ShipProof is one layer of an application-security stack. It scans source code deterministically, fully offline, with no repository or contributor limits. Capabilities that belong to other tool lanes are listed here so teams can pair dedicated products instead of expecting them from this gate:

| Capability | ShipProof today | Suggested pairing |
| :--- | :--- | :--- |
| Cross-file interprocedural taint | shipped (`--cross-file`, JS/TS + Python) | - |
| Secrets detection with redaction | shipped (50+ rules) | secret-history scanners for git history |
| Live credential validation | not claimed (requires network) | secret-validation platforms |
| SBOM / license compliance | not claimed | OSV-Scanner, Trivy |
| Dependency reachability analysis | not claimed | supply-chain scanners |
| Historical git scanning | shipped as bounded `scan --history` added-line evidence | Gitleaks for broader history validation and rotation workflows |

## Limitations

- Labels are file-level, not line-level, so a file flagged for any reason counts as a true positive; finer-grained labels are planned.
- Fixture corpora are authored in this repository. They prevent regressions and document intent, but they cannot substitute for third-party benchmark suites.
- The OSS battery uses upstream snapshots, so counts drift as projects evolve. Ranges are reported where drift was observed.
- No runtime numbers for other scanners appear here yet. A Linux CI job running semgrep with a caller-supplied config on these same corpora is the next planned measurement; until then we make no comparative speed or accuracy claims.
- Backlog triage uses keyword classification; individual targets get re-tiered on close inspection.

## Planned next measurements

1. Head-to-head runtime and accuracy runs against another scanner on a Linux runner over identical corpora, using the caller-supplied ruleset staged in [benchmarks/semgrep-comparison/](../benchmarks/semgrep-comparison/).
2. Line-level labels for the cross-file corpora so sink-line accuracy becomes measurable.
3. Adoption of a standard third-party benchmark corpus (OWASP Benchmark style) after license review.
4. Weekly workflow artifacts published as release checks once the first scheduled run completes.
