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
python benchmarks/head_to_head.py fixtures/vulnerable-node-api fixtures/vulnerable-python-api fixtures/secure-node-api --repeat 3
python benchmarks/head_to_head.py <corpus> --semgrep-config ./your-rules.yml --format json
```

Fairness rules, enforced by the harness design:

- Both tools scan the same directories on the same machine, timed from process start to report; no warm-up runs are hidden.
- ShipProof runs exactly as shipped (`scan_repo.py --format json`), never a cherry-picked rule subset.
- The other tool runs only with rule files the caller supplies via `--semgrep-config` (repeatable). ShipProof never bundles, downloads, or copies third-party rules — including Semgrep's — and the harness performs no network access, per the repository's license and offline guarantees.
- Scoring is file-level: `benchmarks/head-to-head-labels.json` marks which corpus files contain real issues, and every tool is scored against the same labels. Results describe exactly these corpora, configs, and machine; they are not a general superiority claim, and published comparisons must include the corpora, configs, labels, and environment.

Without `--semgrep-config` (or when the tool is not installed) the harness still reports the ShipProof leg, so it doubles as a repeatable self-benchmark on any repository.
