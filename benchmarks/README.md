# Scanner benchmark

ShipProof benchmarks its deterministic scanner against generated, finding-free Python repositories. The script optionally warms the OS file cache with one untimed pass, then records every measured sample, median, p95, throughput, fixture digest, workload bytes, runtime identity, and process peak resident memory; fixture generation is excluded from timing. Pass `--jobs N` to measure worker-process scanning and `--no-warmup` for first-open numbers without the warmup pass.

```bash
python scripts/benchmark-scanner.py --files 1000 --samples 3
python scripts/benchmark-scanner.py --files 1000 --jobs 4
python scripts/benchmark-scanner.py --files 10000
python scripts/benchmark-scanner.py --files 250 --profile adversarial-regex --bytes-per-file 4096
```

Current local reference (Windows 11, 12 logical CPUs, Python 3.12.10, 2026-08-24): 1,000 clean 128-byte files had median 0.9747 s and p95 0.9879 s at 25.57 MB peak RSS. Machine, filesystem, antivirus, profile, bytes, sample count, finding/file-count samples, and digest are part of the evidence; these figures are not universal throughput promises.

Hardware, OS, filesystem, Python version, and cold/warm cache state materially affect results. Published numbers must include the generated JSON and environment instead of being presented as universal promises. CI runs a deliberately broad regression budget; maintainers review tighter budgets on stable runners.

## Head-to-head harness (optional, offline)

`benchmarks/head_to_head.py` compares ShipProof with another scanner on identical local corpora, using median end-to-end wall time over N repeats and file-level precision/recall/F1 against a shared label file:

```bash
python benchmarks/head_to_head.py fixtures/vulnerable-node-api fixtures/node-taint-crossfile fixtures/node-secure-crossfile --repeat 3
python benchmarks/head_to_head.py <corpus> --semgrep-config ./your-rules.yml --format json
```

Fairness rules, enforced by the harness design:

- Both tools scan the same directories on the same machine, timed from process start to report; no warm-up runs are hidden.
- ShipProof runs exactly as shipped (`scan_repo.py --format json`), never a cherry-picked rule subset.
- The other tool runs only with rule files the caller supplies via `--semgrep-config` (repeatable). ShipProof never bundles, downloads, or copies third-party rules — including the comparison scanner's — and the harness performs no network access, per the repository's license and offline guarantees.
- Scoring is file-level: `benchmarks/head-to-head-labels.json` marks which corpus files contain real issues, and every tool is scored against the same labels. Results describe exactly these corpora, configs, and machine; they are not a general superiority claim, and published comparisons must include the corpora, configs, labels, and environment.

Without `--semgrep-config` (or when the tool is not installed) the harness still reports the ShipProof leg, so it doubles as a repeatable self-benchmark on any repository.

## Comparison ruleset and latest self-results

`semgrep-comparison/rules.yml` is an original minimal ruleset written for these corpora (no third-party rule text copied). Where the comparison scanner runs (Linux/macOS), compare with:

```bash
python benchmarks/head_to_head.py fixtures/node-taint-crossfile fixtures/node-secure-crossfile \
    --semgrep-config benchmarks/semgrep-comparison/rules.yml --repeat 3
```

Latest ShipProof self-leg over all shipped fixture corpora (Windows 11, Python 3.12.10, `--cross-file`, median of 3, 2026-08-24). The v2 label contract separates expected finding locations from context-only chain files:

| Corpus | Findings | TP | FP | FN | TN | Context only | Precision | Recall | F1 |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| vulnerable-node-api | 2 | 1 | 0 | 0 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| vulnerable-python-api | 3 | 1 | 0 | 0 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| node-taint-crossfile | 6 | 4 | 0 | 0 | 1 | 1 | 1.0 | 1.0 | 1.0 |
| adversarial-node | 4 | 4 | 0 | 0 | 3 | 2 | 1.0 | 1.0 | 1.0 |
| secure-node-api | 0 | 0 | 0 | 0 | 1 | 0 | n/a | n/a | n/a |
| node-secure-crossfile | 0 | 0 | 0 | 0 | 6 | 0 | n/a | n/a | n/a |

`adversarial-node` stress-tests precision under hostile conditions: vulnerable-looking code confined to comments and string literals, method look-alikes (`snackBar.open`), sync I/O outside loops, and hardened Express/DOM patterns must all stay silent—while two-hop aliasing, destructured params, cookie-to-innerHTML chains, and a three-file taint chain must all fire. Version-2 labels score expected sink/root-cause locations and retain source/helper chain files separately as `context_only_files`.

The 1,000-file clean reference remains below the 5-second release budget. Separate adversarial-regex profiles exercise large and many-file behavior so a benign microbenchmark cannot hide regex scaling limits.

Source-only/helper chain files produce no finding by design and are not counted as false negatives; they remain named in the label artifact and included in its digest.

## Real-world open-source evaluation

`python scripts/eval-realworld.py` is an opt-in network workflow driven by [realworld-repositories.json](realworld-repositories.json). Every repository URL, full commit, classification, SPDX identifier, and license permalink is reviewed and checked before scanning. Output includes revision/license/corpus digests and marks finding review as `unreviewed`; it cannot turn a repository-wide “clean” or “vulnerable” label into per-alert precision automatically.

The reviewed 2026-08-24 run completed all six pinned repositories (1,805 files, 732 findings, 310 application-scope findings). Those counts confirm evaluator/corpus availability only; no OSS precision claim is made until maintainers check in per-finding labels.
