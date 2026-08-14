# Production architecture

Architecture is a set of enforced boundaries and tradeoffs, not a diagram of fashionable components.

## Decision sequence

1. Define critical journeys, business invariants, trust boundaries, data ownership, availability targets, recovery objectives, and regulatory constraints.
2. Trace synchronous calls, asynchronous messages, persistence, caches, external dependencies, and operator actions for each journey.
3. Identify the measured constraint: throughput, latency, isolation, team ownership, deployment risk, data residency, or failure containment.
4. Choose the smallest topology that meets it. Prefer a modular monolith until independent scaling, isolation, or ownership is proven necessary.
5. Record material choices in short ADRs: context, decision, alternatives, consequences, evidence, owner, and revisit trigger.

## Boundary rules

- Keep domain policy independent from HTTP, UI, queues, databases, model providers, and cloud SDKs.
- Make module ownership and dependency direction explicit. Reject cycles and cross-module database access that bypasses policy.
- Version public APIs and events. Use consumer-driven contract tests and additive compatibility before removal.
- Authenticate at the edge but authorize the exact object and action at the protected operation. Never trust UI visibility as authorization.
- Use one canonical identifier, time representation, money representation, error taxonomy, and correlation context across boundaries.
- Keep secrets and environment policy outside source. Validate configuration once at startup and fail closed for production.

## Distributed systems only when justified

If a boundary becomes remote, add deadlines, cancellation, idempotency, replay handling, bounded retries, backpressure, tracing, and a recovery owner. Define the consistency model and failure behavior before choosing a broker or cache. Avoid dual writes; use a transaction, outbox, reconciliation, or an explicitly accepted inconsistency window.

## Frontend and API

- Keep credentials server-side; use secure, HttpOnly, SameSite cookies where the architecture permits.
- Enforce CSP, output encoding, CSRF protection where cookies authenticate, origin validation, upload limits, and safe redirects.
- Design loading, empty, retry, offline, expired-session, permission-denied, and partial-failure states.
- Make list APIs cursor- or keyset-paginated with stable ordering and server-enforced maximums.
- Avoid exposing internal database models directly. Return intentionally shaped DTOs and minimize personal data.

## Readiness questions

Can one component fail without corrupting another? Can a release roll forward and back across mixed versions? Can operators identify the owner and affected customer? Can the system shed optional work? Can data be restored and reconciled? If not, the architecture is incomplete regardless of diagram quality.
