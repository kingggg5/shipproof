# ShipProof research notebook

Last reviewed: 2026-08-14.

This notebook records the external pages consulted while ShipProof was designed. It is intentionally separate from the [production playbook](production-playbook.md): the playbook contains ShipProof's operating model; this file preserves provenance, challenges assumptions, and makes later re-verification possible.

ShipProof does not copy another project's source, prompts, or documentation. Community discussions are useful for discovering failure questions, but no ShipProof control is accepted solely because a post, comment, or competing repository recommends it.

## Reading protocol

For each research pass:

1. Write the decision question before opening sources.
2. Prefer the owning specification, standards body, or project documentation.
3. Record the smallest observation that changes a ShipProof decision; do not paste the source into this repository.
4. Record what ShipProof deliberately does **not** infer from the page.
5. Put operational guidance in a focused skill reference and keep the source link here.
6. Re-check dated or fast-moving material when a release depends on exact syntax or behavior.

## Decision ledger

| ShipProof decision | Reasoning retained by this project | What would change it |
| --- | --- | --- |
| Keep release gates independent | A clean majority cannot cancel one broken critical invariant | Evidence that a combined score preserves veto-level risk without hiding unknowns |
| Start from authorization and business invariants | Scanners cannot reconstruct product ownership and permitted state transitions reliably | A repository supplies an executable policy model that can become the stronger source of truth |
| Keep the bundled scanner conservative | Broad pattern matching creates false confidence for reachability, memory safety, and protocol state | A new detector has precise positive/negative tests, a complete path model, and acceptable noise |
| Prefer a small architecture first | Distribution creates retries, partial failure, coordination, and operational cost | Measured scaling, isolation, ownership, or deployment constraints justify a boundary |
| Make capacity inputs explicit | Registered accounts, DAU, peak sessions, concurrency, and RPS describe different things | Product analytics and production-shaped tests replace assumptions with measured values |
| Treat AI as an untrusted decision component | Natural language and retrieved content cannot grant authority | A deterministic policy boundary still must authorize effects even if models improve |
| Separate read and consequential write tools | Narrow capabilities reduce confused-deputy and excessive-agency risk | Low-risk writes may be policy-approved when bounded, reversible, and fully audited |
| Keep runtime and dependency count small | Fewer execution paths simplify installation, review, and supply-chain evidence | A dependency removes more maintained risk than it introduces and has a clear owner |

## Source notes

Only primary pages that directly affected a decision are retained below. A link is evidence of what was consulted, not an endorsement and not proof that ShipProof implements every requirement on that page.

### Application security

#### OWASP Application Security Verification Standard 5.0.0

- **Page opened:** [OWASP ASVS project](https://owasp.org/www-project-application-security-verification-standard/)
- **Question:** Which web security controls can be mapped to stable, testable requirement identifiers?
- **Observation:** ASVS 5.0.0 is a verification baseline and recommends version-qualified identifiers because identifiers can change between versions.
- **ShipProof decision:** Use ASVS only as an optional mapping after a concrete invariant and test exist. Never market the local scanner as ASVS certification or full coverage.
- **Not inferred:** Passing ShipProof proves ASVS compliance or absence of vulnerabilities.

#### OWASP API Security Top 10

- **Page opened:** [OWASP API Security](https://owasp.org/API-Security/)
- **Question:** Which boundary failures deserve early manual tracing in API reviews?
- **Observation:** Object/function authorization, property exposure, resource consumption, and unsafe downstream API use are distinct failure classes.
- **ShipProof decision:** Trace caller, tenant, object, action, allowed fields, resource limits, and downstream trust separately.
- **Not inferred:** A category list replaces a product-specific threat model.

#### CISA Secure by Design guidance

- **Page opened:** [CISA product security bad practices](https://www.cisa.gov/news-events/alerts/2025/01/17/cisa-and-fbi-release-updated-guidance-product-security-bad-practices)
- **Question:** Should prevention of whole bug classes appear before scanner selection?
- **Observation:** Producer-owned secure defaults and class-level prevention are stronger than shifting responsibility to customers.
- **ShipProof decision:** Prefer safe APIs, memory-safe components where feasible, explicit authorization, safe defaults, and bounded behavior before adding detection layers.
- **Not inferred:** One language, scanner, or platform makes a product secure by default.

### Development and supply chain

#### NIST Secure Software Development Framework

- **Page opened:** [NIST SSDF](https://csrc.nist.gov/projects/ssdf)
- **Question:** Where does a source-code-only review stop being sufficient?
- **Observation:** Secure development spans preparation, protected development, well-secured software, provenance, and vulnerability response.
- **ShipProof decision:** Review the source-to-artifact path, release identity, response process, rollback, and recovery alongside code.
- **Not inferred:** A checklist proves an organization's actual process is operating.

#### SLSA build track

- **Page opened:** [SLSA v1.2 build track basics](https://slsa.dev/spec/v1.2/build-track-basics)
- **Question:** What claims can build provenance support?
- **Observation:** Build integrity levels describe properties of how artifacts are produced and attested.
- **ShipProof decision:** Preserve source commit, builder identity, inputs, artifact digest, and provenance verification as release evidence.
- **Not inferred:** Provenance proves that source code is correct or non-malicious.

#### npm trusted publishing

- **Page opened:** [npm trusted publishers](https://docs.npmjs.com/trusted-publishers/)
- **Question:** How should an npm release avoid long-lived write credentials?
- **Observation:** Supported CI systems can publish through short-lived OIDC identity; eligible public workflows can receive provenance automatically. Exact runtime and CLI prerequisites change and must be checked before release.
- **ShipProof decision:** Keep publication human-gated, prefer trusted publishing when configured, allowlist package contents, and verify `npm pack` before release.
- **Not inferred:** ShipProof is published to the registry before the owner configures and completes that release.

### AI agents and MCP

#### MCP authorization and security guidance

- **Pages opened:** [dated authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) and [security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- **Question:** Which authorization boundary must survive model and tool composition?
- **Observation:** HTTP authorization requires resource/audience binding, token validation, narrow consent, and no token passthrough. MCP evolves, so implementation work must select and test against an explicit protocol version.
- **ShipProof decision:** Re-authorize tool calls at execution, bind credentials to the destination, minimize scopes, split read/write capabilities, and treat tool metadata as untrusted.
- **Not inferred:** MCP supplies business authorization or makes a tool safe automatically.

#### Agentic application threat catalog

- **Page opened:** [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
- **Question:** Which failures appear when a model can plan, remember, and call tools?
- **Observation:** Goal hijacking, tool misuse, privilege abuse, poisoned context, unexpected execution, and agent supply-chain risks cross traditional component boundaries.
- **ShipProof decision:** Test policy compliance separately from task success and keep retrieved content, memory, model output, and other agents below the authorization boundary.
- **Not inferred:** A taxonomy predicts every product-specific agent failure.

### Scale, data, and observability

#### PostgreSQL query plans

- **Page opened:** [PostgreSQL EXPLAIN](https://www.postgresql.org/docs/current/using-explain.html)
- **Question:** What evidence should precede database architecture changes?
- **Observation:** Plans expose estimated and actual execution behavior that code shape alone cannot establish.
- **ShipProof decision:** Require production-shaped plans, pool/lock evidence, and growth data before recommending indexes, replicas, partitioning, or sharding.
- **Not inferred:** One plan from a small dataset predicts production behavior.

#### Overload and load-test thresholds

- **Pages opened:** [Google SRE on cascading failures](https://sre.google/sre-book/addressing-cascading-failures/) and [Grafana k6 thresholds](https://grafana.com/docs/k6/latest/using-k6/thresholds/)
- **Question:** How should ShipProof distinguish capacity arithmetic from readiness evidence?
- **Observation:** Overload controls, measurable objectives, and staged tests matter more than a raw maximum RPS number.
- **ShipProof decision:** Model assumptions explicitly, then test steady, peak, breakpoint, spike, soak, impaired dependency, shedding, and recovery behavior.
- **Not inferred:** A universal error rate, latency target, traffic ratio, or instance size applies to every product.

#### OpenTelemetry semantic conventions

- **Page opened:** [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/concepts/semantic-conventions/)
- **Question:** How can telemetry remain portable without becoming a cost or privacy hazard?
- **Observation:** Shared naming improves correlation across signals, while product-specific attributes still require governance.
- **ShipProof decision:** Prefer standard names where applicable and bound labels, fields, payloads, retention, and sensitive data.
- **Not inferred:** Instrumentation alone creates useful alerts, ownership, or incident readiness.

### Deep systems verification

#### Sanitizers and fuzzing ecosystems

- **Pages opened:** [LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html), [Linux KCSAN](https://docs.kernel.org/dev-tools/kcsan.html), [syzkaller](https://github.com/google/syzkaller), and [OSS-Fuzz](https://github.com/google/oss-fuzz)
- **Question:** What evidence is credible for memory-unsafe, concurrent, parser-heavy, kernel, browser, and protocol code?
- **Observation:** Target-specific instrumentation, runtime checking, coverage feedback, corpora, and minimized reproducers expose defect classes that regex and general AI review cannot establish.
- **ShipProof decision:** Keep the built-in scan fast and conservative; route deep work through an evidence ladder in an authorized isolated environment.
- **Not inferred:** One sanitizer or fuzzer configuration proves absence of defects.

### Distribution and ecosystem adapters

#### GitHub composite actions

- **Page opened:** [GitHub composite action tutorial](https://docs.github.com/en/actions/tutorials/create-actions/create-a-composite-action)
- **Question:** What is the smallest reusable pull-request integration that can live with ShipProof's source?
- **Observation:** A root action metadata file can define explicit inputs, outputs, and composite shell steps, and releases can be consumed through version tags.
- **ShipProof decision:** Start with `action.yml` in this repository, explicit inputs, minimal caller permissions, and tested major/immutable tags. Avoid a second action repository until it has a distinct lifecycle.
- **Not inferred:** A composite action automatically has safe permissions or makes third-party version tags immutable.

#### Grafana k6 scenarios and thresholds

- **Pages opened:** [k6 scenarios](https://grafana.com/docs/k6/latest/using-k6/scenarios/) and [k6 thresholds](https://grafana.com/docs/k6/latest/using-k6/thresholds/)
- **Question:** Which parts of capacity math can become a runnable load-test artifact without inventing product behavior?
- **Observation:** k6 scripts can declare separate scenarios, checks, and pass/fail thresholds, while the tested routes, data, and objectives remain product inputs.
- **ShipProof decision:** Generate a deterministic script only from reviewed route/workload/SLO configuration, keep base URL and credentials in environment variables, and require separate authorization to run it.
- **Not inferred:** Capacity estimates supply valid endpoints, payloads, user journeys, or safe production traffic automatically.

#### MCP TypeScript SDK stdio server

- **Page opened:** [MCP TypeScript SDK v1.29 server guide](https://github.com/modelcontextprotocol/typescript-sdk/blob/v1.29.0/docs/server.md)
- **Question:** How can ShipProof expose native AI tools without opening a network service or duplicating core logic?
- **Observation:** The SDK supports a local stdio transport and registered tools with structured input/output schemas and explicit error results.
- **ShipProof decision:** Build MCP as an optional TypeScript adapter, begin with stdio and narrow read-only tools, and reuse the same versioned evidence contracts as the CLI.
- **Not inferred:** MCP tool registration provides repository path isolation, business authorization, output bounds, or safe arguments by itself.

## Originality and clean-room boundary

- ShipProof's skills, prompts, CLI, scanners, capacity model, budget gate, tests, and prose were implemented independently for this repository.
- Community repositories and posts are treated as question discovery, not authoritative requirements. Their code and prompts are not imported.
- Generic industry terms such as threat model, idempotency, SLO, provenance, and human approval are used in their normal technical meaning.
- Each retained rule must connect to a ShipProof invariant, a verification method, and a limitation. Rules that cannot meet that standard are omitted or labeled experimental.

## Deliberate limitations

- Static and AI review cannot prove reachability, exploitability, runtime configuration, dependency safety, or absence of vulnerabilities.
- Capacity arithmetic cannot predict nonlinear overload; production-shaped tests are required.
- Source pages and versions change. Re-check the primary page before making a release depend on exact syntax, support, or conformance.
- ShipProof does not replace product owners, privacy or legal review, independent security assessment, incident response, or platform-specific testing.
