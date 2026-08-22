# Scanner benchmark

ShipProof benchmarks its deterministic scanner against generated, finding-free Python repositories. The script reports wall-clock scan time, throughput, and process peak resident memory; file generation is excluded from timing.

```bash
python scripts/benchmark-scanner.py --files 1000
python scripts/benchmark-scanner.py --files 10000
```

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
