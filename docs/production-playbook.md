# ShipProof production engineering playbook

This is ShipProof's owner-authored operating model for building and releasing production systems. It is a decision guide, not a copied standards catalog, a certification, or a promise that one architecture fits every workload.

The focused skill references remain the execution detail. This playbook explains how the pieces fit together and what ShipProof considers non-negotiable.

## Contents

1. [How to use this playbook](#how-to-use-this-playbook)
2. [ShipProof doctrine](#shipproof-doctrine)
3. [Application and API security](#1-application-and-api-security)
4. [Data and concurrency](#2-data-and-concurrency)
5. [Architecture and failure containment](#3-architecture-and-failure-containment)
6. [Capacity and scale](#4-capacity-and-scale)
7. [CPU, memory, and latency](#5-cpu-memory-and-latency)
8. [AI, RAG, and tool execution](#6-ai-rag-and-tool-execution)
9. [Systems software](#7-systems-software)
10. [Supply chain, operations, and release](#8-supply-chain-operations-and-release)
11. [Release record](#release-record)

## How to use this playbook

1. Write a short engineering contract: critical journey, owner, trust boundaries, data, workload, SLO, resource budget, and recovery behavior.
2. Apply only the control planes touched by the change. Do not turn the whole playbook into a generic checklist.
3. Label each material choice:
   - **Required** — a baseline invariant for the scoped system.
   - **Context-dependent** — adopt only when a measured constraint or threat justifies it.
   - **Experimental** — isolate, benchmark, and define an exit path before production use.
4. Collect evidence from the real repository and runtime. A named tool, pattern, or standard is not evidence by itself.
5. End with separate release gates for Security, Correctness, Data & Privacy, Scale, Operability, and Supply Chain.

Use the [engineering skill](../skills/engineer-production-systems/SKILL.md) while changing a system and the [audit skill](../skills/audit-production-readiness/SKILL.md) before release.

## ShipProof doctrine

1. **Start from invariants, not products.** Define who may do what, to which object, in which state, under which workload.
2. **Bound every amplifier.** Cap input, output, concurrency, fan-out, queues, caches, retries, model tokens, logs, and retained state.
3. **Prefer the smallest architecture that meets measured needs.** Distribution must pay for its new failure modes.
4. **Keep policy next to the protected action.** UI visibility, prompts, gateways, and upstream checks are not authorization boundaries.
5. **Separate decisions from effects.** Pure policy is testable; I/O and privileged mutations need explicit adapters and authority.
6. **Treat tools and AI findings as leads.** Confirm reachability and impact with a complete path, reproducer, focused test, or runtime evidence.
7. **Make recovery part of the design.** Timeouts, cancellation, replay, rollback, repair, and ownership are normal paths.
8. **Let evidence decide the release.** Missing evidence stays unknown; it does not become a passing score.

## 1. Application and API security

**Invariant:** authenticate the caller, authorize the exact action and object, validate the allowed shape, and minimize the response at every trust boundary.

- Scope every tenant-owned query and mutation by tenant and object ownership. Prefer a non-enumerating not-found response when policy requires it.
- Parse input into explicit command objects. Never pass raw request, model, webhook, or form payloads to persistence APIs.
- Return intentionally shaped DTOs rather than storage models containing internal or sensitive fields.
- Treat server actions, webhooks, GraphQL resolvers, background jobs, and admin routes as independent entry points.
- For outbound requests, restrict schemes and destinations, resolve and re-check addresses, control redirects, and block local, metadata, and private networks unless explicitly required.
- Protect cookie-authenticated mutations against CSRF; validate origins and redirects; bound uploads and decompression; encode output for its destination.

**Evidence:** anonymous, wrong-role, cross-tenant, mass-assignment, replay, oversized-input, unsafe-redirect, and dependency-failure tests.

Read next: [application engineering](../skills/engineer-production-systems/references/engineering.md), [architecture](../skills/engineer-production-systems/references/architecture.md), and [security review](../skills/audit-production-readiness/references/security.md).

## 2. Data and concurrency

**Invariant:** the durable store enforces durable business rules, while application code makes transaction and retry behavior explicit.

- Encode uniqueness, valid relationships, tenant identity, state bounds, and important numeric constraints in the schema where practical.
- Choose optimistic checks, conditional updates, or locks from the conflict pattern; do not cargo-cult one locking strategy.
- Keep transactions short and free of remote calls. Use an outbox or reconciliation path when storage and messaging cannot commit together.
- Make externally visible writes idempotent with durable keys, request fingerprints, stored outcomes, and defined behavior for in-progress duplicates.
- Define the read-after-write requirement from the user journey. Measure replication lag and route only the affected reads as strongly as needed; do not hardcode a universal sticky window.
- Inspect production-shaped query plans and pool wait before adding caches, replicas, partitioning, or sharding.

**Evidence:** constraint tests, concurrent-update tests, duplicate delivery, crash-between-steps, migration rehearsal, query plans, lock/pool telemetry, and restore drills.

Read next: [data engineering](../skills/engineer-production-systems/references/data.md).

## 3. Architecture and failure containment

**Invariant:** every boundary has an owner, compatibility contract, failure budget, and recovery path.

- Prefer a modular monolith until independent scaling, isolation, ownership, or deployment evidence requires a remote boundary.
- Keep domain policy independent of HTTP, UI, queues, databases, model vendors, and cloud SDKs.
- Add deadlines, cancellation, bounded retries, backpressure, idempotency, tracing, and replay handling whenever a call becomes remote or asynchronous.
- Reject unbounded queues as an availability strategy. Define admission control, shedding order, and degraded behavior.
- Record material decisions in short ADRs with context, alternatives, consequences, evidence, owner, and revisit trigger.
- Partition into cells or services only when the failure domain, tenancy model, and operational ownership are measurable and testable.

**Evidence:** contract tests, mixed-version tests, dependency-failure tests, queue replay, degraded-mode exercises, and rollback or forward-fix rehearsal.

Read next: [architecture](../skills/engineer-production-systems/references/architecture.md) and [operability](../skills/audit-production-readiness/references/operations.md).

## 4. Capacity and scale

**Invariant:** registered users are not workload. Architecture follows measured requests, bytes, concurrency, storage, and recovery behavior.

Start with explicit inputs:

```text
peak_requests = peak_sessions x actions_per_session x requests_per_action
design_peak_rps = peak_requests / peak_window_seconds x burst_multiplier
in_flight_work ~= throughput x service_time_seconds
instances = ceil(design_peak_rps x headroom / measured_sustainable_rps_per_instance)
```

- Replace every ratio with analytics and every per-instance number with a production-shaped benchmark.
- Test smoke, average, peak, breakpoint, spike, soak, and impaired-dependency conditions.
- Measure the first constrained resource and recovery curve, not only the highest throughput number.
- Introduce caching, queues, replicas, partitioning, services, or orchestration only for a named bottleneck or isolation need.

**Evidence:** versioned workload assumptions, load scripts and data shape, SLO thresholds, traces, CPU/memory profiles, database/queue/cache saturation, and recovery time.

Read next: [scale guide](../skills/audit-production-readiness/references/scale.md) and use `shipproof labs capacity` to make assumptions reviewable.

## 5. CPU, memory, and latency

**Invariant:** optimize a named workload with before-and-after measurements while preserving correctness and operability.

- Profile before changing code. Fix algorithmic complexity, repeated work, round trips, copying, parsing, and serialization before syntax-level tuning.
- Stream large data and propagate backpressure. Bound caches, buffers, worker pools, queues, batches, and cardinality.
- Reuse expensive immutable state; pool objects only after allocation evidence shows a benefit.
- Move CPU-bound work off latency-sensitive event loops only when the transfer, scheduling, and memory cost is measured.
- Gate stable signals with reviewed relative and absolute budgets. Never move a threshold only to make CI green.
- Follow language formatters. Whitespace and shorter identifiers do not reduce application RAM.

**Evidence:** workload definition, profiler output, correctness tests, warmup and sample count, variance, p50/p95/p99, throughput, CPU, allocation rate, RSS/heap, I/O, errors, and cost.

Read next: [performance](../skills/engineer-production-systems/references/performance.md) and use `shipproof gate budget` for reproducible regressions.

## 6. AI, RAG, and tool execution

**Invariant:** the model proposes; policy authorizes; a narrow tool executes; the system records the outcome.

- Treat prompts, retrieved documents, memory, web content, tool descriptions, model output, and agent messages as untrusted data.
- Re-authorize each tool call using the current principal, tenant, target object, action, state, and scope.
- Prefer task-specific read and write tools over raw shell, SQL, filesystem, browser-session, or cloud-admin access.
- Require preview and human confirmation for consequential effects such as payments, deletion, publication, identity, permissions, or production changes. Lower-risk writes may be policy-approved when bounded, reversible, and audited.
- Filter RAG by document and chunk authorization before ranking and before use. Preserve source/version/page metadata and refuse unsupported claims.
- Validate closed structured output; bound tool arguments, output, retries, time, cost, and tokens; provide per-tool disable switches and a global kill switch.
- For MCP over HTTP, bind tokens to the intended audience, minimize scopes, and never pass inbound tokens through to upstream services.

**Evidence:** golden task and policy cases, prompt-injection tests, cross-tenant retrieval tests, invalid citation tests, tool-authorization tests, approval records, traces, cost limits, rollback, and incident replay.

Read next: [agent security](../skills/engineer-production-systems/references/agent-security.md).

## 7. Systems software

**Invariant:** privileged, parser-heavy, concurrent, and memory-unsafe code requires layered runtime evidence; static review alone cannot establish safety.

- Prefer memory-safe components for new exposed code when platform and interoperability constraints allow.
- Validate lengths and arithmetic before allocation, casting, pointer movement, indexing, copying, or nested parsing.
- Make lifetime, ownership, cleanup, lock ordering, state transitions, re-entry, teardown, and cancellation explicit.
- Bound recursion, decompression, reassembly, retransmission, state per peer, and all attacker-controlled work.
- Treat hardware memory tagging, eBPF policy, confidential computing, formal methods, and new I/O paths as context-dependent controls, not universal fixes.
- Convert confirmed crashes into minimized reproducers and permanent regression inputs.

**Evidence ladder:** compiler warnings and types; boundary/property/state tests; data-flow analysis; sanitizers; coverage-guided or structure-aware fuzzing; concurrency/fault injection; minimized reproducer; monitored rollout.

Read next: [systems review](../skills/engineer-production-systems/references/systems.md) and [tool routing](../skills/engineer-production-systems/references/tool-routing.md).

## 8. Supply chain, operations, and release

**Invariant:** trace the deployed artifact to reviewed source, verified dependencies, a controlled build identity, and a recoverable deployment.

- Lock dependency resolution, minimize install scripts, review new maintainers and native code, and retain removal ownership.
- Isolate untrusted pull requests from credentials. Pin third-party automation and minimize workflow permissions.
- Prefer short-lived workload identity over long-lived release tokens. Generate and verify SBOM, provenance, signatures, and artifact digests where the platform supports them.
- Correlate traces, metrics, logs, audit events, deployments, and feature flags while bounding cardinality and excluding secrets.
- Define SLOs, alert ownership, RPO/RTO, restore, rollback, kill switches, degraded modes, and customer communication before release.
- Keep releases human-gated. Provenance proves origin and process claims; it does not prove the code is safe.

**Evidence:** clean build, lock digest, tests, scanner versions, SBOM/provenance, artifact digest, approval, staged rollout, abort signals, restore/rollback exercise, and incident owner.

Read next: [supply chain](../skills/audit-production-readiness/references/supply-chain.md), [operations](../skills/audit-production-readiness/references/operations.md), and [reporting](../skills/audit-production-readiness/references/reporting.md).

## Release record

Every production decision should leave a compact record:

| Field | Required content |
| --- | --- |
| Scope | Commit, artifact, environment, critical journeys, excluded areas |
| Invariants | Authorization, tenancy, correctness, privacy, durability, recovery |
| Workload | Dataset, traffic mix, concurrency, bursts, dependency conditions |
| Evidence | Tests, scans, plans, profiles, load results, restore/rollback results |
| Findings | Confirmed defects, hypotheses, accepted residual risk, owners |
| Gates | Independent decisions for each ShipProof release gate |
| Decision | Release, conditional release, or block; approver and timestamp |

The supporting [research notebook](research.md) records which external pages were consulted and how they affected ShipProof. It is traceability for this playbook, not a substitute for ShipProof's own reasoning.
