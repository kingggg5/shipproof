# Operability, resilience, and incident readiness

Production readiness includes detecting, containing, recovering, and learning from failure.

## Service objectives and telemetry

- Define user-visible SLIs and SLOs for availability, correctness, latency, freshness, and durability. Tie alerts to actionable error-budget burn or hard safety invariants.
- Correlate traces, metrics, logs, profiles, audit events, deploys, feature flags, and dependency health with stable resource and trace identifiers.
- Use standard semantic conventions where available. Bound metric labels and log fields; never place raw tokens, credentials, payment data, or unnecessary personal data in telemetry.
- Measure saturation: CPU throttling, memory/GC, event-loop/thread delay, pool wait, locks, queue age/depth, retries, cache churn, file descriptors, disk/IOPS, and downstream quotas.

## Safe change and recovery

- Use backward-compatible rollout, health/readiness checks, staged exposure, explicit success/abort signals, and a tested rollback or forward-fix path.
- Keep feature flags owned, observable, permissioned, time-bounded, and removable. A kill switch must work when a dependency or model provider is unavailable.
- Define RTO/RPO, failover assumptions, degraded modes, data repair, customer communication, and decision authority.
- Exercise restore, rollback, dependency loss, overload, regional/component failure, queue replay, cache loss, and expired credentials in a safe environment.

## Incident loop

1. Preserve evidence and establish incident command, scope, severity, and communication channel.
2. Contain using the lowest-risk reversible action; do not destroy evidence or rotate blindly without recording dependencies.
3. Build a timeline from telemetry and changes. Separate observations, hypotheses, and confirmed causal links.
4. Eradicate the root cause, recover service and data, validate customer impact, and monitor recurrence.
5. Produce blameless actions that remove a class of failure: invariant, owner, due date, verification, and follow-up signal.

Audit logs for sensitive changes should be append-oriented and tamper-evident, with actor, tenant, action, target, policy result, approval, timestamp, request/trace ID, and outcome. Restrict and monitor access to the logs themselves.
