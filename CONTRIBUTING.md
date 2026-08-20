# Contributing

Thank you for improving ShipProof. Keep contributions narrow, evidence-based, and safe to run on an untrusted repository.

## Before opening a pull request

```bash
npm ci --ignore-scripts
python -m pip install -r requirements-dev.txt
npm run check
python skills/audit-production-readiness/scripts/scan_repo.py . --fail-on high
```

Use an issue or design proposal before a change that alters schemas, exit codes, rule identity, default trust boundaries, release behavior, or a large part of the CLI. Read [GOVERNANCE.md](GOVERNANCE.md) for the decision and compatibility process.

## Code style and naming

Follow each ecosystem's standard instead of applying one whitespace rule to every file:

- Python uses four spaces and descriptive `snake_case`; classes use `PascalCase`.
- JavaScript uses two spaces and descriptive `camelCase`; constants use `UPPER_SNAKE_CASE`.
- JSON, YAML, and Markdown use two spaces. YAML indentation must never use tabs.
- Makefile recipes use tabs because the format requires them.

Tabs do not reduce runtime memory: source indentation is not retained as application state. Optimize shipped JavaScript with the consumer's build/minification pipeline and optimize Python with measured algorithm, I/O, allocation, and concurrency changes. Do not shorten names solely to reduce source bytes.

Name functions after the behavior they perform (`build_capacity_model`, `runDoctorCommand`) and collections after what they contain (`budget_rules`, `installationResults`). Avoid vague names such as `data`, `obj`, `tmp`, or `result` when a domain-specific name is available. Keep abbreviations only when they are established domain units such as CPU, RAM, RPS, p95, or SARIF.

## Adding a scanner rule

Every rule must include:

- A stable `SPxxx` identifier, category, severity, confidence, CWE/control mapping, explanation, and actionable remediation.
- At least three positive, five negative, and two adversarial cases for a newly promoted detector. Placeholders do not count as evidence.
- A concise false-positive analysis in the pull request.
- Redaction when evidence may contain a credential or personal data.
- A reason this belongs in the fast heuristic layer rather than CodeQL, Semgrep, Gitleaks, Trivy, or manual review.

Prefer structural/AST checks over broad regexes. Do not add a high-severity rule that only recognizes a keyword without a plausible failure path.

Do not add broad rules claiming to detect kernel, browser-engine, parser, or protocol memory-safety defects. Route those classes to target-specific static analysis, sanitizers, fuzzing, and reproducible tests unless a deterministic low-noise rule can be demonstrated.

Research candidates are not executable rules. Community discussions and model output may identify a question, but promotion requires confirmation from the owning standard, vendor/framework documentation, language specification, or a real vulnerability record. Do not copy detector implementations, tests, prose, or rule packs from license-restricted sources. Record source provenance and explain what the source does—and does not—prove.

Before submitting, verify that the detector:

- runs only on applicable suffixes/manifests and through the real repository walker;
- has no duplicate semantic coverage under another rule ID;
- handles multiline input and generated/minified/test fixtures deliberately;
- preserves secret redaction in terminal, JSON, SARIF, and fix-prompt output;
- does not claim reachability, exploitability, or runtime state beyond its proof level;
- updates both README rule tables and all versioned contract fixtures.

## Changing engineering guidance or budgets

Keep the two skills consistent and update the relevant reference rather than duplicating advice. A new performance metric needs a defined unit, direction, workload, variance expectation, relative threshold, absolute limit when applicable, and a test for missing/invalid evidence. Do not weaken a threshold merely to make CI pass.

## Changing the npm CLI

Keep the front door dependency-free and cross-platform. Do not execute shell strings, repository-supplied commands, install lifecycle scripts, or arbitrary prompt paths. Route deterministic Python gates to their existing implementation rather than duplicating them in JavaScript or another installer. Add a Node test for every parser, path, overwrite, and exit-code change, then inspect `npm pack --dry-run` for unintended files.

## Safety

The default workflow must remain read-only and local-first. Do not add telemetry, code upload, dependency installation, network calls, active exploitation, or load generation to the default path. Any future active testing must require explicit scope and authorization.

## Pull requests

Explain the invariant being protected, the evidence produced, the test that proves the behavior, and any known limitation. Keep refactors separate from rule changes when practical.
