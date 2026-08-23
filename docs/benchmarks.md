# Benchmarks and evaluation methodology

This page documents how ShipProof measures itself, publishes every number we currently claim, and states plainly what we have *not* measured yet. If a number here cannot be reproduced by the commands shown, treat it as stale and open an issue.

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
| secure-node-api | 0 | 0 | — | — | — |
| node-secure-crossfile | 0 | 0 | — | — | — |

Two notes on honesty rather than score inflation. The adversarial corpus deliberately contains vulnerable-looking code confined to comments and string literals; detectors must stay silent there while still catching disguised chains elsewhere - both directions are asserted in tests. And `routes/orders.js` in the taint corpus is labeled vulnerable even though no sink-based tool flags pure sources; we keep the label because the file genuinely contains an issue, accepting the recall cost instead of bending labels toward our output.

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

Measured by [scripts/benchmark-scanner.py](scripts/benchmark-scanner.py) over generated Python repositories (warm-cache pass reported separately):

- Sequential: ~1,400 warm files/s at 1,000 files
- `--jobs 4`: ~2,100 files/s
- Peak RSS stays around 24 MB for the generated corpus shape

Throughput is re-checked after engine changes; the JS/TS analyzer and SARIF enrichment did not move it measurably.

## Comparison context

We publish feature context rather than head-to-head scores until both tools run on identical hardware. Against Semgrep's published tier table (checked August 2026):

| Capability | Semgrep Free | Semgrep Teams+ | ShipProof |
| :--- | :--- | :--- | :--- |
| Cross-file analysis | via Pro Engine/Pro Rules | included | **open core**, JS/TS + Python |
| Cross-function taint | yes | yes | yes (`--cross-file`) |
| Repositories scanned | 10 private max | 500 max | unlimited, local only |
| Contributors | 10 max | metered per contributor | unlimited |
| Network requirement | cloud infrastructure | cloud infrastructure | fully offline |
| Secrets detection | not in free tier | semantic + validation + history | 50+ redacting rules; no validation/history |
| Historical git scanning | paid beta | paid | not claimed (roadmap candidate) |
| SBOM / license compliance | separate product lane | included | out of scope; pair with OSV-Scanner/Trivy |
| Deterministic fingerprints across runs | varies with config resolution | varies | stable by contract, parity-tested |

The honest reading: ShipProof overlaps semgrep's free tier on detection breadth and beats it on operating limits and offline determinism, while semgrep's paid tiers cover product lanes (SCA reachability, secrets validation, platform management) that we explicitly recommend pairing with dedicated tools instead of reimplementing.

## Limitations

- Labels are file-level, not line-level, so a file flagged for any reason counts as a true positive; finer-grained labels are planned.
- Fixture corpora are authored in this repository. They prevent regressions and document intent, but they cannot substitute for third-party benchmark suites.
- The OSS battery uses upstream snapshots, so counts drift as projects evolve. Ranges are reported where drift was observed.
- No runtime numbers for other scanners appear here yet. A Linux CI job running semgrep with a caller-supplied config on these same corpora is the next planned measurement; until then we make no comparative speed or accuracy claims.
- Tier-A/B/C triage of the research backlog is keyword-classification based; individual targets can be re-tiered when someone examines them closely.

## Planned next measurements

1. Head-to-head against semgrep binary (Linux runner, identical corpora, caller-supplied ruleset already staged in [benchmarks/semgrep-comparison/](semgrep-comparison/)).
2. Line-level labels for the cross-file corpora so sink-line accuracy becomes measurable.
3. Adoption of a standard third-party benchmark corpus (OWASP Benchmark style) after license review.
4. Weekly workflow artifacts published as release checks once the first scheduled run completes.
