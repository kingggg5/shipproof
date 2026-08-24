# ShipProof research notebook

Last reviewed: 2026-08-20.

This notebook records the external pages consulted while ShipProof was designed. It is intentionally separate from the [production playbook](production-playbook.md): the playbook contains ShipProof's operating model; this file preserves provenance, challenges assumptions, and makes later re-verification possible.

ShipProof does not copy another project's source, prompts, or documentation. Community discussions are useful for discovering failure questions, but no ShipProof control is accepted solely because a post, comment, or competing repository recommends it.

## Research status

This notebook is an engineering provenance record, not a peer-reviewed publication and not evidence that ShipProof is endorsed by any referenced organization. As of the review date:

| Corpus | Count | Status |
| --- | ---: | --- |
| Executable scanner rules | 620 | Versioned behavior; covered by structure and regression tests |
| Expert research candidates | 1,000 | Non-executable hypotheses |
| Annual 2021–2026 candidates | 1,800 | Non-executable time-bounded signals |
| Language/ecosystem candidates | 5,000 | Non-executable deduplicated research slots |
| Reserved promotion slots | 1,000 | Deliberate namespace reservation; not catalog evidence |

Candidate count measures catalog coverage, not detector quality. Candidates have no runtime effect, cannot emit a finding, and must not be presented as shipped product capability.

## Reading protocol

For each research pass:

1. Write the decision question before opening sources.
2. Prefer the owning specification, standards body, or project documentation.
3. Record the smallest observation that changes a ShipProof decision; do not paste the source into this repository.
4. Record what ShipProof deliberately does **not** infer from the page.
5. Put operational guidance in a focused skill reference and keep the source link here.
6. Re-check dated or fast-moving material when a release depends on exact syntax or behavior.

## Rule promotion protocol

A candidate may be proposed for promotion only when all of the following are present:

1. **Provenance:** an owning specification, vendor/framework document, language specification, or real vulnerability record identifies the failure class.
2. **Local invariant:** the repository contains a condition that can be observed without guessing deployment state, business intent, or cross-file reachability the engine does not implement.
3. **Deduplication:** no existing detector already covers the same syntax, cause, and evidence boundary.
4. **Bounded implementation:** applicable suffixes/manifests, multiline behavior, generated/test code handling, redaction, and complexity are explicit.
5. **Quality corpus:** at least three positive, five negative, and two adversarial fixtures pass through the real repository walker.
6. **Finding contract:** stable ID, severity, confidence, proof level, category, CWE/control mapping, explanation, remediation, fingerprint, and documented false-positive boundary.
7. **Compatibility evidence:** English and Thai rule tables, schemas/fixtures where applicable, package tests, full test suite, and high-severity self-scan pass.

New uncertain heuristics begin as review-first and non-blocking. Promotion to a blocking default requires representative repository evaluation and recorded precision evidence. A detector is narrowed or retired when field evidence invalidates its assumptions; its ID is not reassigned.

## Source hierarchy and reproducibility

Sources are ranked by their authority for the question being answered:

1. owning standards body, platform/framework documentation, or language specification;
2. vendor advisories and CVE/KEV/CWE records;
3. reproducible local fixtures, measurements, and versioned compatibility contracts;
4. community discussions as question-discovery signals only;
5. model output as an untrusted hypothesis only.

Offline catalogs record stable identifiers, source URLs, retrieval/review dates where available, and deterministic generation inputs. A URL proves only that a page was consulted. It does not prove reachability, prevalence, exploitability, conformance, or ownership of the referenced project. Re-running a catalog generator must not silently promote, delete, or change executable rules.

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

#### OpenViking progressive context and observability review

- **Page opened:** [Volcengine OpenViking](https://github.com/volcengine/OpenViking)
- **Question:** Which context-management ideas improve ShipProof without importing a server, vector database, embedding model, or network dependency?
- **Observation:** OpenViking presents context at progressively richer levels and treats retrieval/decision observability as an explicit concern rather than returning every detail for every request.
- **ShipProof decision:** Implement a clean-room, domain-specific adaptation only: `summary`/`overview`/`full` disclosure for explanations and fix prompts, plus an opt-in deterministic scan decision trace made only from bounded counts. Keep all default execution local, offline, read-only, and dependency-free.
- **Not inferred:** OpenViking's storage, retrieval, session, embedding, telemetry, or server architecture is appropriate for a static production gate. No OpenViking code, runtime dependency, protocol, or AGPL-covered implementation is copied into ShipProof.

#### Annual NVD/CISA/CWE research snapshot

- **Pages and APIs opened:** [NVD data feeds and API guidance](https://nvd.nist.gov/vuln/data-feeds), [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and the [MITRE CWE catalog](https://cwe.mitre.org/data/).
- **Question:** How can a large current rule backlog remain traceable without bulk-enabling thousands of noisy patterns?
- **Observation:** CVEs provide time-bounded incident signals, KEV distinguishes observed exploitation, and CWE provides stable weakness taxonomy. None of them alone specifies a precise source detector.
- **ShipProof decision:** Keep 1,800 annual CVE signals and 1,000 CWE records as offline research-only snapshots. Route CVEs to dependency evidence by default and require the normal fixture/precision gates before any CWE-derived detector is promoted.
- **Not inferred:** The sampled records are a global top 300, a CVE is reachable in a scanned repository, or a CWE title is an implementable regex specification.

#### Community question discovery, 2021–2026

- **Pages opened:** selected question and discussion URLs from Stack Overflow and Reddit, plus Google security and supply-chain publications. The repository-only URL ledger is in [`research/community-signals.json`](https://github.com/kingggg5/shipproof/blob/main/research/community-signals.json).
- **Question:** Which production mistakes recur in practitioner questions after 2021?
- **Observation:** Build-secret handling, privileged pull-request workflows, mutable CI dependencies, build-time environment exposure, unsafe cluster changes, and missing production lifecycle controls recur across years.
- **ShipProof decision:** Use community pages only to prioritize a question, then confirm it against owning documentation such as Docker, GitHub Actions, Kubernetes, Next.js, NIST, CISA, or SLSA.
- **Not inferred:** A post is accurate, representative, independently verified, or sufficient evidence for a scanner finding. Post bodies, answers, and code are not copied into ShipProof.

#### Language and framework applicability pass

- **Pages opened:** [.NET code analysis](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/overview), [TypeScript project references](https://www.typescriptlang.org/docs/handbook/project-references), [PHP database security](https://www.php.net/manual/en/security.database.php), [React reactive-effect lifecycle](https://react.dev/learn/lifecycle-of-reactive-effects), [Go security best practices](https://go.dev/doc/security/best-practices), [Go vulnerability database](https://go.dev/doc/security/vuln/database), [SEI CERT C++](https://wiki.sei.cmu.edu/confluence/pages/viewpage.action?pageId=88046682), [Angular security](https://angular.dev/best-practices/security), [Node.js security best practices](https://nodejs.org/en/learn/getting-started/security-best-practices), [PostgreSQL prepared statements](https://www.postgresql.org/docs/current/sql-prepare.html), [Python security considerations](https://docs.python.org/3/library/security_warnings.html), [Oracle Java security guide](https://docs.oracle.com/en/java/javase/17/security/index.html), [Rust unsafe contracts](https://doc.rust-lang.org/stable/nomicon/safe-unsafe-meaning.html), [Android/Kotlin security checklist](https://developer.android.com/privacy-and-security/security-tips), [Android/Kotlin performance](https://developer.android.com/topic/performance/overview), [Apple secure coding](https://developer.apple.com/library/archive/documentation/Security/Conceptual/SecureCodingGuide/Introduction.html), and [Apple secure decoding](https://developer.apple.com/documentation/foundation/nssecurecoding).
- **Question:** How can 5,000 language-focused ideas be prioritized without treating a generic CWE name or model recollection as a valid detector?
- **Observation:** The same weakness needs different syntax, lifecycle, and evidence in each ecosystem. Official documents expose precise boundaries such as parameterized SQL, React effect synchronization, Angular sanitization/Trusted Types, Go vulnerability evidence, .NET analyzer scope, C++ memory/concurrency contracts, Rust unsafe invariants, Android lifecycle/resource budgets, and secure Apple decoding.
- **ShipProof decision:** Create one unique `(ecosystem, CWE)` research record, reject explicit incompatible CWE language declarations, record official ecosystem sources and CWE applicability/consequences, and compare every record with executable CWE/suffix coverage. Keep scale and performance non-blocking until a missing bound, lifecycle error, query pattern, or measured regression is locally provable.
- **Not inferred:** An official best-practice page defines 5,000 scanner patterns, a repeated CWE root is a duplicate across different syntax ecosystems, or a security consequence can be proven through a source regex alone.

#### Current framework configuration sources

- **Pages opened:** [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/), [GitHub Actions secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use), and [Next.js environment-variable guidance](https://nextjs.org/docs/app/guides/environment-variables).
- **Question:** Which framework states are explicit enough for low-noise static analysis?
- **Observation:** Explicit unsafe values and privileged workflow/data boundaries are stronger local proof than absence-based guesses. Framework version and document ownership matter.
- **ShipProof decision:** Prefer structural checks for explicit unsafe configuration. Missing controls remain manual, admission-policy, or runtime evidence unless repository structure proves full scope.
- **Not inferred:** A single manifest is the rendered deployment, an environment variable name proves secrecy, or every privileged workflow is exploitable.

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

## Measured evaluation

Benchmark methodology, current precision/recall results, open-source battery outcomes, comparison context against commercial tier tables, and stated limitations live in [docs/benchmarks.md](benchmarks.md). Numbers there are regenerated by committed scripts and pinned to release commits.
