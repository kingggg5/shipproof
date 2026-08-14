# Scale and capacity guide

"One million users" is not a workload. Convert business usage into requests, bytes, database work, queue work, and concurrency before changing architecture.

## Workload equations

Use explicit inputs:

```text
DAU = registered_users × dau_ratio
peak_hour_users = DAU × peak_hour_ratio
peak_hour_requests = peak_hour_users × actions_per_session × requests_per_action
design_peak_rps = peak_hour_requests ÷ 3600 × burst_multiplier
in_flight_work ≈ throughput × service_time_seconds
instances = ceil(design_peak_rps × headroom ÷ measured_sustainable_rps_per_instance)
```

The last two equations are estimates, not capacity proof. Replace every assumed ratio with analytics and every throughput value with a production-like load test.

## Test ladder

- **Smoke:** verify scripts, test data, checks, and telemetry at minimal load.
- **Average:** establish resource and latency baselines under steady realistic traffic.
- **Peak:** prove endpoint-level latency and error SLOs at the design peak.
- **Stress/breakpoint:** increase load until an SLO fails; identify the first constrained resource.
- **Spike:** verify admission control, load shedding, autoscaling delay, and recovery.
- **Soak:** expose leaks, queue growth, cache churn, storage growth, and scheduled-job interactions.
- **Failure:** repeat peak load with an instance, cache, database replica, or dependency impaired.

Use protocol-level traffic for most load and a smaller browser workload for end-user timing. Encode thresholds so CI fails on SLO breach, but do not mistake a single pass/fail result for complete release evidence.

## Bottleneck checklist

- API: p50/p95/p99 latency, error rate, saturation, event-loop or thread-pool delay, payload size.
- Database: query plans, scanned rows, locks, pool wait, connection count, CPU, IOPS, replication lag, vacuum/maintenance.
- Cache: hit ratio by route, hot keys, stampede protection, eviction, cold-start behavior, invalidation correctness.
- Queue: arrival/service rate, depth, oldest age, redelivery, poison messages, backpressure, dead-letter recovery.
- Dependencies: deadline budget, connection reuse, retry amplification, circuit state, quotas, regional failure.
- Infrastructure: CPU throttling, memory/GC, file descriptors, ephemeral ports, bandwidth, load-generator limits.
- Operations: SLO/error budget, paging signals, dashboards, runbooks, safe rollback, and recovery time.

## Architecture decision rule

Prefer the simplest design that meets measured SLO, durability, isolation, and recovery needs. Add caching, queues, replicas, sharding, service separation, or orchestration only for a named bottleneck or organizational boundary. Every new component adds failure modes and operational cost.

Primary references: [Google SRE on cascading failures](https://sre.google/sre-book/addressing-cascading-failures/) and [Grafana k6 thresholds](https://grafana.com/docs/k6/latest/using-k6/thresholds/).
