# Correctness and reliability review guide

Start from business invariants, not style. Examples: money is neither created nor lost, an order changes state only along allowed edges, a tenant never observes another tenant's object, and a side effect happens at most once for one idempotency key.

## Trace each critical flow

1. Entry validation and normalization.
2. Authorization before data disclosure or mutation.
3. Transaction boundary and consistency model.
4. External calls, deadlines, cancellation, and retry policy.
5. Queue publication/consumption and delivery semantics.
6. Partial failure, compensation, and user-visible state.
7. Logs, metrics, trace correlation, and audit events.

## Failure modes

- **Concurrency:** lost update, check-then-act race, double submit, stale read, lock inversion, missing uniqueness constraint.
- **Retries:** non-idempotent handlers, retry storms, duplicate messages, no jitter, poison messages, unbounded attempts.
- **Transactions:** remote call inside a long transaction, missing rollback, outbox gap, inconsistent multi-store write.
- **Resources:** missing timeout, leaked file/socket/DB handle, unbounded body/result/queue, blocking work on an event loop.
- **Data:** timezone and currency errors, overflow, truncation, schema drift, unsafe default, ambiguous null state.
- **Lifecycle:** bad migration ordering, incompatible rolling deploy, missing rollback, stale workers, cache version mismatch.

## Verification ladder

Prefer the cheapest test that proves the invariant:

1. Unit/property test for pure logic and boundaries.
2. Integration test for database constraints, transactions, and adapters.
3. Contract test for external protocols and error mappings.
4. Concurrency test for races, duplicates, and ordering.
5. Fault-injection test for timeout, retry, dependency loss, and recovery.
6. End-to-end test only for a small set of critical user journeys.

Require the test to fail before the fix when practical. Avoid tests that assert implementation detail but do not prove the broken invariant.
