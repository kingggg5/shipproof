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
python scripts/benchmark-scanner.py --files 1000 --samples 3 --jobs 4
python scripts/benchmark-scanner.py --files 250 --samples 3 --profile adversarial-regex --bytes-per-file 4096
python scripts/benchmark-scanner.py --files 8 --samples 3 --profile adversarial-regex --bytes-per-file 524288

# Open-source battery (network required; fetches reviewed immutable commits into benchmarks/.work)
python scripts/eval-realworld.py
```

CI runs the fixture battery and throughput check weekly ([.github/workflows/benchmarks.yml](../.github/workflows/benchmarks.yml)) with the real-world clone step behind an opt-in flag.

## Fixture battery

Six small repositories serve as executable contracts: two intentionally vulnerable single-file APIs, one multi-file Node corpus whose taint crosses three files, one adversarial suite of precision traps, and two secure counterparts that must produce zero findings. Labels mark which files genuinely contain issues; scoring is file-level against those labels.

Latest controlled-corpus run (Windows 11, Python 3.12.10, `--cross-file`, median of 3, 2026-08-26):

| Corpus | Findings | TP | FP | FN | TN | Context only | Precision | Recall | F1 |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| vulnerable-node-api | 2 | 1 | 0 | 0 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| vulnerable-python-api | 3 | 1 | 0 | 0 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| node-taint-crossfile | 6 | 4 | 0 | 0 | 1 | 1 | 1.0 | 1.0 | 1.0 |
| adversarial-node | 4 | 4 | 0 | 0 | 3 | 2 | 1.0 | 1.0 | 1.0 |
| secure-node-api | 0 | 0 | 0 | 0 | 1 | 0 | n/a | n/a | n/a |
| node-secure-crossfile | 0 | 0 | 0 | 0 | 6 | 0 | n/a | n/a | n/a |

Two caveats. The adversarial corpus contains vulnerable-looking code confined to comments and string literals; detectors must stay silent there while still catching disguised chains elsewhere—both directions are asserted in tests. The version-2 labels separately list source/helper files that participate in vulnerable chains but are not expected finding locations. They stay in the hashed artifact as `context_only_files` instead of being mislabeled as false negatives for a sink-reporting engine.

## Open-source battery

`eval-realworld.py` now reads [a reviewed manifest](../benchmarks/realworld-repositories.json), fetches full immutable commits with isolated Git configuration, an empty hook template, non-interactive credentials, and a per-command timeout, verifies the declared license file, and records revision, license and corpus digests. A failed fetch, timeout, revision mismatch, or missing license is invalid evidence (exit `2`), never a skipped pass. The output deliberately marks every finding `unreviewed`; repository-level labels such as “clean baseline” or “intentionally vulnerable” do not prove that an individual alert is a true or false positive. Historical moving-HEAD counts were removed because they were not reproducible evidence.

The 2026-08-24 manifest run fetched and scanned all six pinned revisions successfully: 1,805 files, 732 total findings, and 310 application-scope findings. These are inventory counts only. In particular, findings in the three clean-baseline repositories still require human review, so this run supplies no real-world precision or false-positive claim.

## Performance

Measured by [scripts/benchmark-scanner.py](../scripts/benchmark-scanner.py), which now records every sample, median, p95, fixture digest, workload bytes, warmup count, runtime identity, and peak RSS. A 2026-08-26 Windows/Python 3.12 local run measured:

- 1,000 clean 128-byte files: median 0.7675 s, p95 0.7744 s, peak RSS 28.68 MB (5-second reference budget passed).
- 250 adversarial-regex 4 KiB files: median 2.2336 s, p95 2.3359 s, peak RSS 26.53 MB (5-second stress budget passed).
- 8 adversarial-regex 512 KiB files: median 8.2779 s, p95 8.3140 s, peak RSS 28.32 MB (10-second large-file stress budget; the stricter 5-second exploratory target did not pass).

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

- Labels are file-level, not line-level, so a positive file flagged for any reason counts as a true positive; context-only files are explicitly excluded from that confusion matrix.
- Fixture corpora are authored in this repository. They prevent regressions and document intent, but they cannot substitute for third-party benchmark suites.
- The OSS battery is immutable by commit, but its findings still need manual per-alert review before precision claims.
- No runtime numbers for other scanners appear here yet. A Linux CI job running semgrep with a caller-supplied config on these same corpora is the next planned measurement; until then we make no comparative speed or accuracy claims.
- Backlog triage uses keyword classification; individual targets get re-tiered on close inspection.

## Planned next measurements

1. Head-to-head runtime and accuracy runs against another scanner on a Linux runner over identical corpora, using the caller-supplied ruleset staged in [benchmarks/semgrep-comparison/](../benchmarks/semgrep-comparison/).
2. Line-level labels for the cross-file corpora so sink-line accuracy becomes measurable.
3. Adoption of a standard third-party benchmark corpus (OWASP Benchmark style) after license review.
4. Weekly workflow artifacts published as release checks once the first scheduled run completes.
