# Governance

ShipProof is an independent open-source project. It uses a maintainer-led, evidence-first model intended to keep releases safe, reviewable, and compatible while the contributor community grows.

## Principles

- Safety and evidence take precedence over feature count or release speed.
- The default workflow remains read-only, offline, and free of runtime package dependencies.
- A clean result is bounded evidence, not a security or compliance certification.
- Stable contracts—rule IDs, schemas, fingerprints, CLI behavior, and exit codes—change only through explicit review and compatibility evidence.
- Community reports and model-generated proposals are discovery inputs, not sufficient proof for an executable rule.

## Roles

### Users

Users run ShipProof, report defects, propose use cases, and provide reproducible evidence. No project role is required to participate in public technical discussions.

### Contributors

Contributors submit documentation, fixtures, rules, code, or design proposals under the repository license. Contributions are reviewed against [CONTRIBUTING.md](CONTRIBUTING.md), the test contract, and the trust boundaries in this document.

### Maintainers

Maintainers triage issues, review and merge changes, manage releases, coordinate security response, and enforce the Code of Conduct. Maintainer authority is custodial: decisions must protect the public contract and should include the evidence and trade-offs that motivated them.

New maintainers may be invited after sustained, constructive contributions and demonstrated judgment across compatibility, security, testing, and community review. Inactive maintainers may step down or be moved to an emeritus role without losing attribution.

## Decision process

Routine fixes and documentation changes are decided through pull-request review. Changes with broad impact should begin as an issue or design proposal and include:

1. the invariant or user problem;
2. the proposed behavior and alternatives considered;
3. security, privacy, performance, and compatibility impact;
4. test and migration evidence;
5. known limitations and rollback plan.

The maintainer responsible for a release makes the final merge decision after review. When consensus is not possible, the decision and rationale should be recorded publicly unless doing so would expose a vulnerability or private information.

## Rule lifecycle

An executable rule must pass every promotion gate defined in [CONTRIBUTING.md](CONTRIBUTING.md). Rule proposals remain research candidates until they have a stable ID, local observable invariant, bounded detector, mappings, remediation, false-positive analysis, and the required positive, negative, and adversarial fixtures.

Severity and proof level are reviewed separately. New uncertain heuristics start review-first and non-blocking. A rule may be narrowed, demoted, disabled, or retired when field evidence shows unacceptable noise or an invalid assumption. IDs are not silently reused.

## Compatibility and deprecation

The public compatibility surface includes command names and options, exit codes, JSON/SARIF/MCP schemas, rule IDs, fingerprints, policy files, Action inputs/outputs, and packed file contents.

- Additive changes require contract tests and release notes.
- Deprecations require a documented replacement and at least one release of notice when safety permits.
- Breaking changes require an explicit release boundary and migration guidance.
- Security fixes may shorten the notice period; the reason must be recorded after coordinated disclosure.

## Releases

Releases follow [docs/releasing.md](docs/releasing.md). A release requires green CI, exact package-content verification, packed-artifact smoke tests, a clean high-severity self-scan, synchronized version metadata, and release notes. Publication failures must fail closed; moving tags are updated only after the immutable release succeeds.

## Security and private decisions

Potential vulnerabilities follow [SECURITY.md](SECURITY.md) and are handled privately until a coordinated disclosure is safe. Security response may temporarily limit public discussion, but fixes, affected versions, and user actions should be published once disclosure no longer increases risk.

## Conduct and conflicts of interest

All participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Reviewers should disclose relationships or interests that could reasonably affect a technical or release decision and recuse themselves when impartial review is not practical.

## Governance changes

Changes to this document use the same public review process as other high-impact project contracts. The current governance file on the default branch is authoritative.
