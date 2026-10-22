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

`benchmarks/head_to_head.py` compares ShipProof with another scanner on identical local corpora, using median end-to-end wall time over N repeats and shared file-level plus line-level labels:

```bash
python benchmarks/head_to_head.py fixtures/vulnerable-node-api fixtures/node-taint-crossfile fixtures/node-secure-crossfile --repeat 3
python benchmarks/head_to_head.py <corpus> --semgrep-config ./your-rules.yml --format json
```

Fairness rules, enforced by the harness design:

- Both tools scan the same directories on the same machine, timed from process start to report; no warm-up runs are hidden.
- ShipProof runs exactly as shipped (`scan_repo.py --format json`), never a cherry-picked rule subset.
- The other tool runs only with rule files the caller supplies via `--semgrep-config` (repeatable). ShipProof never bundles, downloads, or copies third-party rules — including the comparison scanner's — and the harness performs no network access, per the repository's license and offline guarantees.
- Scoring uses `benchmarks/head-to-head-labels.json`: file-level marks which corpus files contain real issues, and line-level marks the expected sink lines. Every tool is scored against the same labels. Line matching is path and line only so a comparison scanner does not need ShipProof rule IDs. Results describe exactly these corpora, configs, and machine; they are not a general superiority claim.

Without `--semgrep-config` (or when the tool is not installed) the harness still reports the ShipProof leg, so it doubles as a repeatable self-benchmark on any repository.

## Comparison ruleset and latest self-results

`semgrep-comparison/rules.yml` is an original minimal ruleset written for these corpora (no third-party rule text copied). Where the comparison scanner runs (Linux/macOS), compare with:

```bash
python benchmarks/head_to_head.py fixtures/node-taint-crossfile fixtures/node-secure-crossfile \
    --semgrep-config benchmarks/semgrep-comparison/rules.yml --repeat 3
```

Latest ShipProof self-leg over all shipped fixture corpora (Windows 11, Python 3.12.10, `--cross-file`, median of 3, 2026-08-24). The v3 label contract separates expected finding locations and sink lines from context-only chain files:

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

## Paired clean-corpus evaluation (opt-in)

Run the approved paired evaluation and validate the saved report:

```bash
python scripts/eval-clean-corpus.py --paired --json --labels --write-baseline benchmark-clean-corpus-paired.json
python scripts/check-precision-trend.py --require-paired --report benchmark-clean-corpus-paired.json
```

The original leg retains all 30 packages, 867 files, and original positive findings. Only reviewed byte-level source changes are applied to separate copies for the quiet leg; packages and findings are not removed to meet a budget. The opt-in evaluator installs the pinned packages, and both legs retain their source and finding evidence.

The reviewed [remediation plan](clean-corpus-remediations.json) records original/remediated hashes, exact edits, receipts, and expected positive recall. Its source pins cover the 15 packages without original manifest digests while leaving [clean-corpus.json](clean-corpus.json) unchanged. Unmodified MarkupSafe Linux and Windows source variants are individually hashed. Action references use exact commit SHAs from their original refs, including the branch-specific Rust toolchain and `dtolnay/install` variants; they are not replaced with a different default branch or current release.

Hash, receipt, and original-positive recall validation precede quiet-leg gating. The shell-free subprocess reference variant intentionally gives up vendor/API compatibility; it is not a drop-in vendor patch. The existing quiet thresholds remain unchanged: zero high/critical application findings and at most 22 gate high+medium findings, alongside the other checked-in limits.

The tested local run on 2026-10-22 reports 130 original application findings, including 54 high/critical; the quiet copies report 72 application findings, zero high/critical, and 16 gate medium findings. The ten existing label records are unchanged. These are corpus-specific measurements, not universal precision or complete application coverage: opaque non-source metadata remains in the completeness ledger.

## Real-world open-source evaluation

`python scripts/eval-realworld.py` is an opt-in network workflow driven by [realworld-repositories.json](realworld-repositories.json). Every repository URL, full commit, classification, SPDX identifier, and license permalink is reviewed and checked before scanning. Output includes revision/license/corpus digests and marks finding review as `unreviewed`; it cannot turn a repository-wide “clean” or “vulnerable” label into per-alert precision automatically.

The reviewed 2026-08-24 run completed all six pinned repositories (1,805 files, 732 findings, 310 application-scope findings). Those counts confirm evaluator/corpus availability only; no OSS precision claim is made until maintainers check in per-finding labels.
