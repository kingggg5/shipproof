# Scanner benchmark

ShipProof benchmarks its deterministic scanner against generated, finding-free Python repositories. The script warms the OS file cache with one untimed pass, then reports a cold-state and a warm-state scan (seconds and files/second each) plus process peak resident memory; fixture generation is excluded from timing. Pass `--jobs N` to measure worker-process scanning and `--no-warmup` for cold-cache numbers only.

```bash
python scripts/benchmark-scanner.py --files 1000
python scripts/benchmark-scanner.py --files 1000 --jobs 4
python scripts/benchmark-scanner.py --files 10000
```

Reference numbers (Windows 11, 12 cores, Python 3.12): 1,000 files run at ~1,300–1,450 warm files/s sequentially and ~2,600 warm files/s with `--jobs 4` at 5,000 files (≈2x). The first scan of freshly written files additionally pays OS-level first-open cost (antivirus and directory metadata) that is not scanner work — that is why the harness reports warm numbers separately.

Hardware, OS, filesystem, Python version, and cold/warm cache state materially affect results. Published numbers must include the generated JSON and environment instead of being presented as universal promises. CI runs a deliberately broad regression budget; maintainers review tighter budgets on stable runners.

## Head-to-head harness (optional, offline)

`benchmarks/head_to_head.py` compares ShipProof with another scanner on identical local corpora, using median end-to-end wall time over N repeats and file-level precision/recall/F1 against a shared label file:

```bash
python benchmarks/head_to_head.py fixtures/vulnerable-node-api fixtures/node-taint-crossfile fixtures/node-secure-crossfile --repeat 3
python benchmarks/head_to_head.py <corpus> --comparison-scanner-config ./your-rules.yml --format json
```

Fairness rules, enforced by the harness design:

- Both tools scan the same directories on the same machine, timed from process start to report; no warm-up runs are hidden.
- ShipProof runs exactly as shipped (`scan_repo.py --format json`), never a cherry-picked rule subset.
- The other tool runs only with rule files the caller supplies via `--comparison-scanner-config` (repeatable). ShipProof never bundles, downloads, or copies third-party rules — including the comparison scanner's — and the harness performs no network access, per the repository's license and offline guarantees.
- Scoring is file-level: `benchmarks/head-to-head-labels.json` marks which corpus files contain real issues, and every tool is scored against the same labels. Results describe exactly these corpora, configs, and machine; they are not a general superiority claim, and published comparisons must include the corpora, configs, labels, and environment.

Without `--comparison-scanner-config` (or when the tool is not installed) the harness still reports the ShipProof leg, so it doubles as a repeatable self-benchmark on any repository.

## Comparison ruleset and latest self-results

`comparison-scanner-comparison/rules.yml` is an original minimal ruleset written for these corpora (no third-party rule text copied). Where the comparison scanner runs (Linux/macOS), compare with:

```bash
python benchmarks/head_to_head.py fixtures/node-taint-crossfile fixtures/node-secure-crossfile \
    --comparison-scanner-config benchmarks/comparison-scanner-comparison/rules.yml --repeat 3
```

Latest ShipProof self-leg over all shipped fixture corpora (Windows 11, Python 3.13, `--cross-file`, median of 3, 2026-08):

| Corpus | Findings | Files flagged | Precision | Recall | F1 |
| :--- | ---: | ---: | ---: | ---: | ---: |
| vulnerable-node-api | 2 | 1 | 1.0 | 1.0 | 1.0 |
| vulnerable-python-api | 3 | 1 | 1.0 | 1.0 | 1.0 |
| node-taint-crossfile | 6 | 4 | 1.0 | 0.8 | 0.889 |
| adversarial-node | 4 | 4 | 1.0 | 0.667 | 0.8 |
| secure-node-api | 0 | 0 | n/a | n/a | n/a |
| node-secure-crossfile | 0 | 0 | n/a | n/a | n/a |

`adversarial-node` stress-tests precision under hostile conditions: vulnerable-looking code confined to comments and string literals, method look-alikes (`snackBar.open`), sync I/O outside loops, and hardened Express/DOM patterns must all stay silent — while two-hop aliasing, destructured params, cookie-to-innerHTML chains, and a three-file taint chain must all fire. Both clean traps and all recall probes behave as labeled.

Scanner throughput is unchanged by the taint engine: ~1,400 warm files/s sequential and ~2,100 files/s with `--jobs 4` at small scale (`scripts/benchmark-scanner.py`), matching the reference budget above.

The two unlabeled-as-flagged files in `node-taint-crossfile` are pure taint sources (`routes/orders.js`) and the traversal sink helper is flagged via L2; source-only files produce no finding by design, matching how sink-based taint tools report.

## Real-world open-source evaluation

`python scripts/eval-realworld.py` clones well-known repositories (depth 1) into a gitignored scratch area and reports findings split by scope. Application-scope numbers are the decision-relevant ones: the release gate ignores test-scope findings. Reference run (Windows 11, Python 3.13):

| Repo | Type | Files | App findings | Notes |
| :--- | :--- | ---: | ---: | :--- |
| express | clean baseline | 162 | 2 | Library repo; test-suite noise stays out of the gate |
| flask | clean baseline | 221 | 5 | Tutorial example code accounts for the highs |
| requests | clean baseline | 93 | 3 | Remaining highs are mock-free timeout gaps in library internals |
| juice-shop | vulnerable app | 1023 | 153 | 29 critical + ~99 high; string-literal and method-look-alike noise removed by hardening pass |
| dvwa | vulnerable app | 225 | 74 | PHP ruleset: weak hash (SP140), SQLi interpolation (SP128) |
| nodegoat | vulnerable app | 81 | 20 | L2 taint confirms the documented `eval(req.body.*)` chain (SP101 x3) |

Hardening fixes discovered by this evaluation, each covered by regression tests:
SP109 now requires request-call context around loopback/metadata URLs; the Python
taint engine no longer treats bound-parameter tuples as SQL text; SP110 ignores
`.open(` method look-alikes; SP321 requires loop context; code-shaped matches
inside string literals are suppressed while content rules (OAuth URLs) stay exempt.

Cross-file taint (`--cross-file`) adds verified interprocedural evidence on top: NodeGoat's three `eval()` sinks and zero false flows on Flask's parameterized tutorial queries after the bind-parameter fix.
