# Data and database engineering

Treat the database as the final enforcer of durable invariants, not a passive persistence detail.

## Schema and isolation

- Encode uniqueness, required relationships, valid states, and numeric/date bounds with reviewed constraints where practical.
- Give every tenant-owned row an immutable tenant key. Include it in reads, writes, uniqueness constraints, foreign keys or equivalent integrity checks, indexes, cache keys, jobs, exports, and audit events.
- Use parameter binding. Never concatenate user or model output into SQL, query operators, identifiers, paths, or administrative commands.
- Minimize stored sensitive data, classify it, encrypt in transit and at rest, separate keys, define retention/deletion, and test access and erasure workflows.

## Transactions and concurrency

- State the isolation and consistency requirement per invariant. Do not assume framework defaults prevent lost updates, write skew, or duplicate side effects.
- Keep transactions short and exclude remote calls. Use constraints, conditional updates, row/version checks, or explicit locks with a documented order.
- Make externally visible writes idempotent. Use durable idempotency records and an outbox or reconciliation path when storage and messaging cannot commit atomically.
- Test concurrent updates, duplicate delivery, retry after timeout, process crash between steps, replica lag, and failover.

## Queries and indexes

- Inspect real query plans with production-shaped cardinality. Track rows estimated versus actual, rows scanned/returned, sort/hash spill, lock wait, I/O, and execution time.
- Build indexes from access patterns and selectivity. Prefer the smallest index that supports filtering and stable ordering; measure write amplification and storage.
- Avoid unbounded results, offset pagination at deep pages, N+1 round trips, over-wide rows, and loading large values when summaries suffice.
- Bound connection pools from database capacity across all app instances, workers, jobs, migrations, and operator tools. Measure pool wait separately from query time.

## Migrations and recovery

Use expand-and-contract for online changes: add compatible schema, deploy dual-compatible code, backfill in resumable bounded batches, verify, switch reads/writes, then remove old schema later. Define lock and statement timeouts, cancellation, throttling, progress, rollback, and mixed-version behavior.

Set RPO and RTO from business impact. Encrypt backups, isolate access, monitor completion, retain per policy, and perform scheduled restore drills that validate application queries and reconciliation—not merely that a file exists. A backup without a tested restore is an assumption.

## Scale triggers

Do not shard from registered-user count. First measure query plans, CPU, IOPS, cache hit ratio, locks, pool saturation, replication lag, maintenance, hot keys, and data growth. Add replicas, partitioning, caching, archival, or sharding only for a named limit with ownership and failure tests.
