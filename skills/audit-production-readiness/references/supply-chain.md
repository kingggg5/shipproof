# Software supply-chain review

Review the path from source and contributor identity to the exact artifact deployed. A clean dependency scan does not prove build integrity, and provenance does not prove code is benign.

## Dependency intake

- Require a lockfile or immutable resolution, known registry/source, license policy, update owner, and removal plan.
- Minimize dependencies and install-time scripts. Review new maintainers, ownership changes, typosquatting risk, release age, transitive graph, native code, network/install behavior, and security posture.
- Use the ecosystem's advisory audit plus an authoritative scanner against lockfiles and SBOMs. Confirm reachability and compensating controls before severity changes.
- Patch known exploited or reachable critical issues on a defined SLA; test compatibility and rollback rather than pinning vulnerable versions indefinitely.

## CI and build integrity

- Pin third-party CI actions and reusable workflows to reviewed immutable commits. Minimize job permissions and isolate untrusted pull requests from secrets and release credentials.
- Prevent pull-request-controlled code, cache keys, artifact names, paths, or outputs from crossing into privileged workflows without validation.
- Separate build, test, approval, signing, and deploy identities. Prefer short-lived OIDC credentials over long-lived tokens.
- Make builds reproducible enough to explain inputs. Generate an SBOM and signed provenance from the trusted build platform, retain checksums, and verify before deployment.
- Protect tags/releases, require reviewed source commits, and avoid release-time dependency resolution or network-fetched executable scripts.

## Agent and plugin intake

Treat skills, plugins, MCP servers, hooks, prompts, and tool metadata as executable supply-chain components. Inspect them before installation, pin versions or commits, restrict filesystem/network/tool scopes, and test prompt-injection and data-exfiltration behavior. Never grant a third-party agent extension production credentials by default.

## Release evidence

Record source commit, build workflow identity, dependency lock digest, tests, scanner versions/database age, SBOM, provenance/signature, artifact digest, approvals, environment, deployment result, and rollback artifact. Verify the chain in a clean environment periodically.
