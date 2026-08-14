# Scanner benchmark

ShipProof benchmarks its deterministic scanner against generated, finding-free Python repositories. The script reports wall-clock scan time, throughput, and process peak resident memory; file generation is excluded from timing.

```bash
python scripts/benchmark-scanner.py --files 1000
python scripts/benchmark-scanner.py --files 10000
```

Hardware, OS, filesystem, Python version, and cold/warm cache state materially affect results. Published numbers must include the generated JSON and environment instead of being presented as universal promises. CI runs a deliberately broad regression budget; maintainers review tighter budgets on stable runners.
