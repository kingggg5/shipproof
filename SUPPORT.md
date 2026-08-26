# Support

ShipProof is a maintainer-led open-source project. Public support is best effort; there is no commercial SLA.

## Before opening a request

1. Run `shipproof doctor .` and record the ShipProof, Node.js, Python, and operating-system versions.
2. Reduce the problem to a sanitized repository or the smallest code sample that still reproduces it.
3. Search existing issues and discussions for the rule ID, command, or error text.
4. Remove credentials, private source, personal data, internal hostnames, and proprietary artifacts.

Use a [bug report](https://github.com/kingggg5/shipproof/issues/new?template=bug_report.yml) for reproducible incorrect behavior, including false positives and false negatives. Use [Discussions](https://github.com/kingggg5/shipproof/discussions) for setup questions, design exploration, and usage patterns. Propose new detectors with the rule-proposal form so the observable invariant and false-positive boundary are explicit before implementation.

Security vulnerabilities belong in a [private security advisory](https://github.com/kingggg5/shipproof/security/advisories/new), not a public issue. Follow [SECURITY.md](SECURITY.md) for disclosure expectations.

## What makes a report actionable

- exact command and exit code;
- minimal sanitized input;
- expected and actual result;
- JSON or SARIF excerpt with secrets removed;
- whether the result changes with `--min-confidence high`, `--changed-since`, or `--cross-file`;
- a proposed regression fixture when practical.

Maintainers may close reports that cannot be reproduced, contain no safe evidence, duplicate an existing request, or ask ShipProof to claim facts that static evidence cannot establish. A closed request can be reopened when new reproducible evidence is available.
