# Security Policy

## Supported versions

Security fixes are applied to the latest release on the default branch. Older public-beta releases may not receive backports. A security advisory will identify affected and fixed versions when a vulnerability is confirmed.

| Version | Supported |
| :--- | :--- |
| Latest `0.6.x` / default branch | Yes |
| Earlier public-beta releases | Best effort |

## Report a vulnerability

Please use GitHub's **Report a vulnerability** private security-advisory flow for this repository. Do not open a public issue with an exploitable proof, credential, private source code, or personal data. If private advisories are temporarily unavailable, open a public issue containing only a request for a private contact channel.

Include the affected version, exact component, impact, minimal reproduction, and any suggested mitigation. Remove or replace live secrets before attaching evidence. You should receive an acknowledgement within five business days. Validation, remediation, and disclosure timing depend on severity and complexity; the maintainer will coordinate those milestones with the reporter.

## Coordinated disclosure

Please allow reasonable time to reproduce, fix, test, and release before publishing technical details. The project will credit reporters who want attribution and will not request secrecy beyond what is needed to protect users. Reports made in good faith under this policy are welcome; do not access data you do not own, degrade a third-party service, or use active exploitation against systems without authorization.

## Security boundaries

Particularly important trust boundaries include repository path isolation, secret redaction, subprocess arguments, policy parsing, generated load-test content, GitHub Action permissions, MCP schemas, packed-artifact contents, and release identity. A scanner false negative by itself is normally a quality defect, but it may be security-sensitive when documentation or output creates a materially false assurance claim.

## Scanner output

ShipProof findings are leads, not a security certification. Confirm reachability and impact before disclosure. If ShipProof prints a real secret, rotate it immediately even when the finding is later classified as a false positive.
