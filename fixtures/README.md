# Contract fixtures

These tiny repositories are executable scanner contracts, not example application code. The test suite proves that vulnerable Node.js and Python samples produce their declared rule IDs, the secure Node.js sample stays quiet, and the performance sample blocks the budget gate.

```bash
shipproof scan fixtures/vulnerable-node-api --format json --fail-on high
shipproof scan fixtures/secure-node-api --format json --fail-on high
shipproof budget --baseline fixtures/performance-regression/baseline.json --current fixtures/performance-regression/current.json --budget fixtures/performance-regression/budget.json
```

The repository self-scan skips directories named `fixtures` so intentional vulnerabilities do not create misleading failures. Selecting a fixture directory as the scan root still analyzes it.
