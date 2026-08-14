# Production engineering method

Use this reference for application, API, worker, data, and infrastructure code.

## Shape the design

1. Trace the current path before introducing an abstraction.
2. Write invariants in observable terms: who may perform which action, on which object, in which state, and exactly once or at-least-once.
3. Prefer a single process and data store until a measured constraint requires distribution.
4. Put policy in one named function or module. Keep configuration external, typed, validated at startup, and safe by default.
5. Keep domain decisions pure where practical. Put clocks, randomness, network, database, filesystem, and model calls behind narrow boundaries.
6. Follow the repository's formatter and each language's indentation convention. Do not convert spaces to tabs or shorten identifiers as a memory optimization; source whitespace and identifier length are not application state.
7. Represent money, identifiers, time, units, states, and permissions with types that prevent accidental mixing.

## Bound every amplifier

Set and test limits for request bodies, decompression, collection sizes, pagination, nesting, regex work, concurrency, fan-out, retries, queues, caches, logs, model tokens, uploads, exports, and retained history. Reject or shed excess work predictably. Never make an unbounded queue the default availability strategy.

## Failure semantics

- Propagate cancellation and deadlines to dependencies.
- Retry only transient, idempotent operations with jitter, a cap, and a total time budget.
- Use idempotency keys or durable state transitions for externally visible writes.
- Make partial failure and replay safe. Use transactions for invariants, not for long remote calls.
- Separate user-safe errors from diagnostic context; never leak secrets or internals.
- Emit structured logs, metrics, and traces with correlation IDs, but keep label cardinality bounded.

## Maintainability checks

- Name code after domain behavior, not implementation fashion.
- Prefer short functions with one reason to change; avoid classes that only wrap one function or global singleton state.
- Remove duplication only after the repeated concept is stable. Similar-looking code with different invariants may deserve separation.
- Delete dead paths and stale feature flags with evidence. Do not preserve speculative extension points.
- Document decisions and non-obvious constraints, not syntax.

## Verification matrix

Cover normal behavior, empty and maximum values, malformed and adversarial input, authorization boundaries, concurrency, dependency timeouts, retry exhaustion, process restart, duplicate delivery, storage failure, and rollback. Property tests and fuzzers complement examples for parsers and state machines; they do not replace invariant-based tests.
