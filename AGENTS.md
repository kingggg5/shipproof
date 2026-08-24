# AGENTS.md

Guidance for AI coding agents (Codex, Claude Code, Cursor, and others) working in this repository.

## What this repository is

ShipProof is a zero-dependency production gate for AI-written code: a static scanner (`skills/audit-production-readiness/scripts/scan_repo.py`), a resource-budget gate, a capacity model with k6 generation, and thin distribution adapters (npm CLI in `lib/`, GitHub Action, pre-commit hook, MCP server). Read [README.md](README.md) for the product contract and [CONTRIBUTING.md](CONTRIBUTING.md) before changing anything.

## Non-negotiable rules

- The default workflow stays read-only, offline, and dependency-free. Never add telemetry, network calls, install scripts, or dependency downloads to the default path.
- Never copy rules or guidance from Semgrep or any license-restricted source. Build detectors from primary sources (CWE, OWASP, framework docs, real CVEs) with your own implementation and fixtures.
- Every scanner rule needs a stable `SPxxx` ID, positive and negative tests, a CWE/control mapping, remediation text, and a false-positive analysis. Update both README rule tables when rules change — a structure test enforces this.
- Exit codes are a contract: `0` pass, `1` gate failure, `2` invalid or unavailable evidence. Do not change them casually.

## Verify before declaring done

```bash
npm run check        # lint + full test suite + pack check + packed-artifact smoke test
python skills/audit-production-readiness/scripts/scan_repo.py . --fail-on high
```

Both must pass with zero findings at the `high` gate. If your change adds findings in test fixtures, obfuscate the vulnerable literal (string concatenation) instead of weakening the gate.

## Where things live

- Scanner rules and engines: `skills/audit-production-readiness/scripts/scan_repo.py` (`RULES` tuple, `RULE_EXPLANATIONS`, regex + Python AST engines).
- Node CLI, policy parser, evidence adapters, MCP server: `lib/*.mjs`.
- Compatibility contract: `fixtures/golden-contract/` + `fixtures/expected-golden-scan.json` — identical findings and fingerprints through direct Python, the Node CLI, and SARIF. Update the expectation deliberately when a detection change is intended.
- Tests: `tests/` (Python) and `tests/node/` (Node). Both run in CI across Python 3.10/3.11/3.12/3.13/3.14 and Node 20/22/24.

## Common tasks

- Add a detector: follow "Adding a scanner rule" in [CONTRIBUTING.md](CONTRIBUTING.md), then update `RULES`, `RULE_EXPLANATIONS`, both README tables, and the fixture corpus in the same change.
- Change the CLI surface: keep `bin/shipproof.mjs` dependency-free, add a Node test for every parser/path/exit-code change, and keep `action.yml` inputs closed and validated in `scripts/run-action.mjs`.
- Cut a release: follow [docs/releasing.md](docs/releasing.md). Version numbers must match across `package.json`, both plugin manifests, and scanner metadata — a structure test enforces this.
