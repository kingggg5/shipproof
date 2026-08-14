# Contributing

Thank you for improving ShipProof. Keep contributions narrow, evidence-based, and safe to run on an untrusted repository.

## Before opening a pull request

```bash
python -m unittest discover -s tests -v
python -m compileall -q skills tests install.py
python skills/audit-production-readiness/scripts/scan_repo.py . --fail-on high
```

## Adding a scanner rule

Every rule must include:

- A stable `SPxxx` identifier, category, severity, confidence, CWE/control mapping, explanation, and actionable remediation.
- One positive test and at least one negative or placeholder test.
- A concise false-positive analysis in the pull request.
- Redaction when evidence may contain a credential or personal data.
- A reason this belongs in the fast heuristic layer rather than CodeQL, Semgrep, Gitleaks, Trivy, or manual review.

Prefer structural/AST checks over broad regexes. Do not add a high-severity rule that only recognizes a keyword without a plausible failure path.

## Safety

The default workflow must remain read-only and local-first. Do not add telemetry, code upload, dependency installation, network calls, active exploitation, or load generation to the default path. Any future active testing must require explicit scope and authorization.

## Pull requests

Explain the invariant being protected, the evidence produced, the test that proves the behavior, and any known limitation. Keep refactors separate from rule changes when practical.
