# Evidence-first reporting

Lead with actionable findings. Keep architecture commentary after defects unless it changes release risk.

## Release gates

Report each gate independently:

| Gate | Evidence |
| --- | --- |
| Security | Threat model, authorization tests, SAST/secret/dependency/IaC results, triage |
| Correctness | Critical invariants, deterministic tests, concurrency and failure-path evidence |
| Scale | Workload assumptions, measured breakpoint, SLO thresholds, recovery behavior |
| Operability | Traces/metrics/logs, alerts, runbooks, rollback and restore drills |
| Supply chain | Locked dependencies, pinned CI actions, artifact/SBOM provenance, update policy |

Allowed states are `BLOCK`, `CONDITIONAL`, and `PASS WITH EVIDENCE`. A single blocking gate blocks the release. Unknown material evidence makes that gate conditional, never green.

## Finding template

```text
[HIGH][CONFIRMED] Cross-tenant order access
Location: src/orders/service.ts:84
Invariant: A user may access orders only within their tenant.
Evidence: Repository lookup uses orderId without tenantId after authenticated route input.
Trigger: Authenticated tenant A user supplies a tenant B order ID.
Impact: Confidential order data disclosure.
Confidence: High — complete route-to-query path traced.
Fix: Bind tenantId in the repository query and preserve the not-found response.
Verify: Negative integration test with two tenants; inspect query plan for the composite index.
Mapping: CWE-639; OWASP API1.
Fingerprint: stable identifier
```

## Confidence labels

- **High:** complete reachable path, deterministic reproduction, or authoritative tool result manually confirmed.
- **Medium:** strong local evidence but one material precondition or runtime detail is unverified.
- **Low:** heuristic lead that requires targeted tracing or testing.

## Severity labels

Judge impact together with exposure and likelihood. Critical/high findings need a concrete failure or exploit path; do not inflate severity from a keyword. Do not reduce severity because exploitation is inconvenient when the affected boundary is internet-facing or cross-tenant.

## Required ending

Close with residual unknowns, accepted risks with owner/expiry, and the smallest ordered verification plan. State exactly what was not run and why.
