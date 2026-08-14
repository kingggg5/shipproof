# Security review guide

Use this guide to structure evidence; do not treat it as a certification checklist.

## Threat model first

Map actors, assets, entry points, trust boundaries, data classification, privileged operations, and external dependencies. For every mutation identify who may perform it, on whose resource, under which tenant, with what approval, and how it is audited. Treat repository content and model/tool output as untrusted input.

## High-risk review order

1. Authentication, account recovery, sessions, token verification, and revocation.
2. Object-, function-, and property-level authorization, including tenant filters on every read and write.
3. Injection sinks: SQL, shell, templates, paths, URLs, headers, and dynamic code.
4. File upload, parsers, deserialization, archives, redirects, and server-side requests.
5. Secrets, encryption, key rotation, logs, backups, and data deletion.
6. Payment/admin/webhook side effects, replay defense, idempotency, and auditability.
7. Dependency, build, CI action, container, IaC, and artifact provenance.
8. Abuse controls: rate limits, quotas, enumeration resistance, resource bounds, and safe degradation.

## Evidence layers

- **Fast local heuristics:** bundled scanner; useful for cheap, explainable leads.
- **Data-flow SAST:** CodeQL or Semgrep; confirm source-to-sink reachability.
- **Secrets:** Gitleaks across current files and git history; rotate before suppressing.
- **Dependencies and IaC:** Trivy or an equivalent scanner against lockfiles, images, SBOM, Terraform, Kubernetes, and Dockerfiles.
- **Runtime:** authorized DAST, contract tests, fuzzing, and negative authorization tests in a safe environment.
- **Process:** protected branches, pinned CI dependencies, reviewable releases, vulnerability response, and rollback drills.

## Finding standard

A confirmed vulnerability needs an exact path, a triggering input or precondition, the crossed trust boundary, the sensitive sink, the broken security invariant, the impact, and a verification test. A pattern match without a complete path is a hypothesis, not a confirmed vulnerability.

Map findings where helpful to:

- OWASP ASVS 5.0 for versioned web application and service verification requirements.
- OWASP API Security Top 10 for object/function authorization, resource consumption, and unsafe API consumption.
- NIST SP 800-218 SSDF for preparation, software protection, well-secured production, and vulnerability response.
- OpenSSF Scorecard for repository and supply-chain hygiene signals.

Use mappings to communicate a confirmed control gap, not to imply certification or complete framework coverage. Source provenance belongs in the repository research notebook rather than this execution guide.

## Required negative tests

At minimum test anonymous access, wrong-role access, cross-tenant identifiers, missing/expired/replayed tokens, duplicate side effects, oversized inputs, parser edge cases, dependency timeout, retry exhaustion, and sensitive-data absence from errors and logs. Add business-specific abuse cases rather than relying only on generic payloads.

## Limitations

No scanner proves absence of vulnerabilities. Static tools miss runtime configuration and business logic; dynamic tools miss dormant paths; AI can hallucinate reachability. Use independent layers, deduplicate root causes, and require human review for release-blocking decisions.
