# Research synthesis

ShipProof was designed after reviewing CodeVibes, current Codex and Claude Code extension formats, primary security standards, mature scanners and fuzzers, SRE/load-testing guidance, and public engineering failure reports. Community sources supplied hypotheses; primary sources determined the implementation.

## Findings that changed the design

### Deterministic first, AI second

CodeVibes demonstrates the value of prioritizing risky files and combining deterministic candidates with contextual AI review. Its MIT license permits reuse, but ShipProof independently implements only the high-level workflow ideas. It does not copy CodeVibes' application, prompts, scoring, or source.

NVIDIA SkillSpector independently reinforces bounded ingestion, a static-first/optional-semantic pipeline, baselines, and machine-readable output. Vercel deepsec adds useful operational patterns for expensive agent review: resumable stages, explicit cost/time caps, and a separate revalidation pass. ShipProof applies the same safety properties to a much smaller local-first skill and CI-gate scope.

### One skill source, two agent hosts

Current Codex and Claude Code documentation both use `SKILL.md` as the reusable instruction entrypoint and support a root `skills/` directory in plugins. Their manifests and personal installation locations differ, so ShipProof keeps one shared skill tree with `.codex-plugin/plugin.json`, `.claude-plugin/plugin.json`, and a dual-target installer. This avoids divergent security advice between agents.

### No single score

A numeric score can hide one catastrophic defect behind many clean files. ShipProof instead has independent Security, Correctness, Scale, Operability, and Supply Chain gates. A blocking gate blocks the release; missing material evidence is conditional.

### Registered users are not load

Stack Overflow discussions about 1M/10M-user tests repeatedly expose an ambiguous denominator: stored accounts, DAU, active sessions, virtual users, and requests per second are different quantities. Google SRE and k6 guidance center measurable throughput, latency/error thresholds, breakpoint behavior, and recovery. The capacity model therefore exposes every conversion ratio and labels its result a hypothesis.

### Scaling failures appear between layers

The 2026 Medium account describes query slowdown, dangerous jobs, stale caches, logging cost, authentication growth, and deployment stress. Reddit discussions add DB locks, I/O, production-shaped data, traffic bursts, and monitoring. ShipProof reviews system boundaries and failure amplification rather than recommending a fashionable architecture.

### Scanner breadth needs independent layers

OWASP ASVS and NIST SSDF cover more than source patterns. GitHub CodeQL/SARIF, Gitleaks, Trivy, and OpenSSF Scorecard each cover different evidence. ShipProof's built-in scanner remains deliberately small and dependency-free, then the skill routes reviewers to mature tools when they are available and relevant.

### Mature systems need dynamic evidence

The Linux kernel documents race and memory-safety sanitizers; syzkaller is a coverage-guided kernel fuzzer for Linux, FreeBSD, and other kernels; LLVM recommends combining coverage-guided fuzzing with sanitizers; OSS-Fuzz retains and continuously executes corpora across many languages. These tools shaped ShipProof's systems evidence ladder. Broad regex rules would create false confidence for use-after-free, type-confusion, parser-state, and concurrency defects, so the built-in scanner does not pretend to detect them deeply.

### Vulnerability-claim fact check

The supplied counts 107 Critical + 990 High + 1,286 Medium + 53 Low total 2,436. Searches across primary vendor material, GitHub, and exact-number web queries did not locate a public source connecting that distribution to a 40-year-old flaw, Linux kernel use-after-free, WebKit memory handling, and FreeBSD parameter validation. ShipProof records the claim as unverified and does not use it as a benchmark.

Anthropic's published Claude Mythos material does document serious AI-assisted findings in mature operating-system and browser code, but its public examples and ages differ from the supplied numbers. This supports broader systems coverage without validating the exact statistic.

## Deliberate limitations

- The bundled scanner is heuristic and cannot prove reachability, exploitability, or absence of vulnerabilities.
- The engineering skill provides a review method, not a substitute for language/runtime expertise or an authorized security program.
- It does not query a vulnerability database, inspect git history, build a full AST across languages, or run a target.
- The CPU/RAM budget gate evaluates supplied measurements; it does not create reliable benchmarks by itself.
- Capacity arithmetic cannot predict nonlinear overload or infrastructure limits; only production-like tests can establish a breakpoint.
- AI review can miss defects or invent paths. Confirm findings and retain human release authority.

## Source index

- [CodeVibes](https://github.com/danish296/codevibes)
- [Codex: Build skills](https://learn.chatgpt.com/docs/build-skills)
- [Claude Code: Skills](https://code.claude.com/docs/en/skills)
- [Claude Code: Plugins reference](https://code.claude.com/docs/en/plugins-reference)
- [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector)
- [Vercel deepsec](https://github.com/vercel-labs/deepsec)
- [OWASP ASVS 5.0](https://github.com/OWASP/ASVS/tree/master/5.0)
- [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)
- [GitHub CodeQL CLI](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli)
- [GitHub SARIF](https://docs.github.com/en/code-security/concepts/code-scanning/sarif-files)
- [OpenSSF Scorecard](https://scorecard.dev/)
- [OSV-Scanner](https://github.com/google/osv-scanner)
- [Trivy filesystem scanning](https://trivy.dev/docs/latest/target/filesystem/)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Grafana k6 thresholds](https://grafana.com/docs/k6/latest/using-k6/thresholds/)
- [LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html)
- [Linux Kernel Concurrency Sanitizer](https://docs.kernel.org/dev-tools/kcsan.html)
- [syzkaller](https://github.com/google/syzkaller)
- [OSS-Fuzz](https://github.com/google/oss-fuzz)
- [Anthropic: Assessing Claude Mythos Preview's cybersecurity capabilities](https://www.anthropic.com/research/mythos-preview)
- [Google SRE: cascading failures](https://sre.google/sre-book/addressing-cascading-failures/)
- [Medium: We Hit 1M Users](https://medium.com/real-world-net/we-hit-1m-users-heres-what-broke-first-in-our-net-system-68617da49a33)
- [Stack Overflow: stored users vs concurrent load](https://stackoverflow.com/questions/5645393/how-to-do-load-testing-using-jmeter-and-visualvm)
- [Stack Overflow: connection-pool exhaustion](https://stackoverflow.com/questions/57974810/how-dbcontext-and-connections-to-db-should-be-implemented-to-handle-load-testing)
- [Reddit: building highly scalable distributed systems](https://www.reddit.com/r/ExperiencedDevs/comments/y39rgz/building_highly_scalable_distributed_systems/)
