# Research synthesis

ShipProof was designed after reviewing CodeVibes, primary security standards, scanner documentation, SRE/load-testing guidance, and public engineering failure reports. Community sources supplied hypotheses; primary sources determined the implementation.

## Findings that changed the design

### Deterministic first, AI second

CodeVibes demonstrates the value of combining deterministic patterns with contextual AI review. ShipProof keeps that strength but moves deterministic work local, emits stable fingerprints, supports reviewed baselines, and treats AI conclusions as hypotheses until a complete path or test confirms them.

### No single score

A numeric score can hide one catastrophic defect behind many clean files. ShipProof instead has independent Security, Correctness, Scale, Operability, and Supply Chain gates. A blocking gate blocks the release; missing material evidence is conditional.

### Registered users are not load

Stack Overflow discussions about 1M/10M-user tests repeatedly expose an ambiguous denominator: stored accounts, DAU, active sessions, virtual users, and requests per second are different quantities. Google SRE and k6 guidance center measurable throughput, latency/error thresholds, breakpoint behavior, and recovery. The capacity model therefore exposes every conversion ratio and labels its result a hypothesis.

### Scaling failures appear between layers

The 2026 Medium account describes query slowdown, dangerous jobs, stale caches, logging cost, authentication growth, and deployment stress. Reddit discussions add DB locks, I/O, production-shaped data, traffic bursts, and monitoring. ShipProof reviews system boundaries and failure amplification rather than recommending a fashionable architecture.

### Scanner breadth needs independent layers

OWASP ASVS and NIST SSDF cover more than source patterns. GitHub CodeQL/SARIF, Gitleaks, Trivy, and OpenSSF Scorecard each cover different evidence. ShipProof's built-in scanner remains deliberately small and dependency-free, then the skill routes reviewers to mature tools when they are available and relevant.

## Deliberate limitations

- The bundled scanner is heuristic and cannot prove reachability, exploitability, or absence of vulnerabilities.
- It does not query a vulnerability database, inspect git history, build a full AST across languages, or run a target.
- Capacity arithmetic cannot predict nonlinear overload or infrastructure limits; only production-like tests can establish a breakpoint.
- AI review can miss defects or invent paths. Confirm findings and retain human release authority.

## Source index

- [CodeVibes](https://github.com/danish296/codevibes)
- [OWASP ASVS 5.0](https://github.com/OWASP/ASVS/tree/master/5.0)
- [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)
- [GitHub CodeQL CLI](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli)
- [GitHub SARIF](https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files)
- [OpenSSF Scorecard](https://scorecard.dev/)
- [Trivy filesystem scanning](https://trivy.dev/docs/latest/target/filesystem/)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Grafana k6 thresholds](https://grafana.com/docs/k6/latest/using-k6/thresholds/)
- [Google SRE: cascading failures](https://sre.google/sre-book/addressing-cascading-failures/)
- [Medium: We Hit 1M Users](https://medium.com/real-world-net/we-hit-1m-users-heres-what-broke-first-in-our-net-system-68617da49a33)
- [Stack Overflow: stored users vs concurrent load](https://stackoverflow.com/questions/5645393/how-to-do-load-testing-using-jmeter-and-visualvm)
- [Stack Overflow: connection-pool exhaustion](https://stackoverflow.com/questions/57974810/how-dbcontext-and-connections-to-db-should-be-implemented-to-handle-load-testing)
- [Reddit: building highly scalable distributed systems](https://www.reddit.com/r/ExperiencedDevs/comments/y39rgz/building_highly_scalable_distributed_systems/)
