# Contract fixtures

These tiny repositories are executable scanner contracts, not example application code. The test suite proves that vulnerable Node.js and Python samples produce their declared rule IDs, the secure Node.js sample stays quiet, and the performance sample blocks the budget gate.

```bash
shipproof scan fixtures/vulnerable-node-api --format json --fail-on high
shipproof scan fixtures/secure-node-api --format json --fail-on high
shipproof budget --baseline fixtures/performance-regression/baseline.json --current fixtures/performance-regression/current.json --budget fixtures/performance-regression/budget.json
```

The repository self-scan skips directories named `fixtures` so intentional vulnerabilities do not create misleading failures. Selecting a fixture directory as the scan root still analyzes it.

`golden-contract/` plus `expected-golden-scan.json` form the compatibility contract: the same fixture must produce identical findings and fingerprints through direct Python, the Node CLI, and the SARIF builder. Update the expectation deliberately whenever a detection change is intended.

`command-contracts/` snapshots the complete normalized JSON report for every public evidence command. The Node CLI must match those fixtures exactly, and the Python compatibility test keeps schema-version `1.0` snapshots valid across later field changes.

The multi-file corpora `node-taint-crossfile/` and `node-secure-crossfile/` extend the head-to-head benchmark: request input crosses file boundaries into concatenated SQL sinks, admin routes lack authorization middleware, and the secure counterpart parameterizes every query behind explicit auth guards. File-level labels live in `benchmarks/head-to-head-labels.json`.

The repository self-scan skips directories named `fixtures` so intentional vulnerabilities do not create misleading failures. Selecting a fixture directory as the scan root still analyzes it.
