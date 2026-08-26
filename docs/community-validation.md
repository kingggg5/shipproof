# Community validation plan

ShipProof has a broad executable catalog and a larger research backlog. After v0.10.0, the highest-value work is representative use, precision review, and integration reliability—not another bulk rule-count increase.

This plan is a measurement protocol, not a claim that the targets have already been met.

## What to validate

| Question | Evidence to retain | Success signal |
| :--- | :--- | :--- |
| Can a new user obtain a useful result? | Runtime versions, command, duration, exit code, and sanitized failure point | A documented path from clone or Action install to first evidence report |
| Are findings actionable? | Rule ID, ecosystem, human label, remediation outcome, and duplicate root cause | Reviewed TP/FP/needs-context counts with sample sizes |
| Does ShipProof stay quiet on healthy code? | Revision-pinned, license-reviewed clean repositories and negative fixtures | Zero observed false positives for blocking high/critical rules in the reviewed sample |
| Do adapters preserve the same contract? | Finding fingerprints from Python, Node CLI, Action, SARIF, and MCP | Semantic parity or a documented adapter limitation |
| Does it fit normal CI budgets? | Files, bytes, elapsed time, peak RSS, runner, and configuration digest | Results remain inside the published corpus-specific budgets |

“Zero observed” applies only to the named sample. It is never a universal absence-of-false-positives claim.

## Initial field cohort

Recruit a small, reviewable cohort before widening promotion:

- at least ten revision-pinned repositories;
- at least five ecosystems, including a monorepo and a generated-code-heavy repository;
- a mix of services, CLIs, libraries, infrastructure, and frontend applications;
- clean baselines and intentionally vulnerable fixtures kept separate;
- public licenses and immutable revisions recorded before any source is fetched.

The default scanner must not download these repositories. Evaluation remains an explicit maintainer workflow through the existing real-world harness.

## Review record

Each reviewed finding should retain only non-sensitive metadata:

```yaml
repository_revision: full-commit-sha
ecosystem: typescript
shipproof_version: 0.10.0
rule_id: SPxxx
label: true_positive | false_positive | needs_context | duplicate
proof_level: L0 | L1 | L2
application_scope: true
remediation_verified: false
notes: sanitized rationale
```

Never copy private source or credentials into issues, fixtures, or benchmark artifacts. Convert useful reports into the smallest synthetic regression fixture that preserves the relevant syntax and semantics.

## Promotion and release decisions

- Do not promote a candidate because it appears frequently; frequency is prioritization evidence only.
- A new blocking rule still needs its complete contract plus representative clean-corpus review.
- Narrow, downgrade, or reject rules that generate repeated context-only alerts.
- Publish observed metrics with corpus identity and sample counts; do not publish a single precision percentage without the underlying confusion matrix.
- Treat installation failures, documentation gaps, and time-to-first-evidence as product defects with the same priority as new detection ideas.

## How users can help

Users can open a sanitized bug report for incorrect findings, submit a rule proposal with positive and negative examples, or share workflow feedback in GitHub Discussions. Private or exploitable evidence must use the security-advisory channel described in [SECURITY.md](../SECURITY.md).

Progress belongs in reproducible artifacts and issue links. Stars, download counts, and raw finding totals may describe reach, but they do not establish scanner quality.
