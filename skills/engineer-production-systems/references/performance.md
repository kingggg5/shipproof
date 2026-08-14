# CPU, memory, latency, and throughput

Performance work is an experiment, not a style preference.

## Measurement contract

Record the workload, dataset shape, concurrency, hardware/container limits, runtime version, build mode, warmup, sample count, variance, and profiler overhead. Compare like with like. Track p50 plus tail latency, throughput, CPU time, allocation rate, peak RSS or heap, garbage-collection or pause time, I/O, locks, queue depth, errors, and cost as applicable.

Reject benchmark results that omit correctness checks, use debug builds accidentally, compare different workloads, hide variance, or report only the fastest run.

## Investigation order

1. Confirm the bottleneck with a CPU profile, flame graph, allocation/heap profile, I/O trace, lock profile, database plan, or runtime counters.
2. Fix algorithmic complexity and repeated work before micro-optimizing syntax.
3. Remove unnecessary allocation, copying, parsing, serialization, logging, syscalls, network round trips, and database queries.
4. Improve locality and batching without creating unbounded memory or unacceptable latency.
5. Add caching only with a size policy, TTL/invalidation rule, stampede control, tenant isolation, and hit-rate evidence.
6. Add concurrency only when work can be parallelized safely and downstream capacity is bounded. Measure contention and context-switch cost.
7. Re-profile after every meaningful change; bottlenecks move.

## Resource-safe patterns

- Stream large data and apply backpressure instead of buffering whole inputs.
- Preallocate only from validated, capped sizes.
- Reuse expensive immutable state; avoid pooling cheap objects without evidence.
- Use bounded worker pools and queues. Expose saturation and rejection metrics.
- Avoid per-request clients, thread pools, model loads, schema compilation, or connection pools.
- Keep telemetry non-blocking and cardinality-bounded, but never remove the signals needed to diagnose regressions.
- Test steady state, bursts, long soaks, cold starts, cache loss, dependency slowdown, and recovery.

## CI budgets

Gate stable signals with both relative and absolute thresholds. Relative thresholds detect regressions; absolute limits protect the service objective. Keep noisy microbenchmarks informational until variance is understood. Never move a threshold merely to turn CI green—record the hardware/runtime change or update the baseline through review.
