#!/usr/bin/env python3
"""Turn registered-user targets into explicit, testable capacity assumptions."""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import asdict, dataclass
from typing import Sequence


@dataclass(frozen=True)
class CapacityInputs:
    users: int
    dau_ratio: float = 0.20
    peak_hour_ratio: float = 0.15
    actions_per_session: float = 10.0
    requests_per_action: float = 2.0
    burst_multiplier: float = 2.0
    read_ratio: float = 0.85
    cache_hit_ratio: float = 0.70
    queries_per_read: float = 1.5
    queries_per_write: float = 2.0
    p95_latency_ms: float = 300.0
    db_time_ms: float = 40.0
    instance_rps: float = 200.0
    cpu_ms_per_request: float = 5.0
    memory_mb_per_instance: float = 512.0
    headroom: float = 1.5


def validate(inputs: CapacityInputs) -> None:
    if inputs.users <= 0:
        raise ValueError("users must be positive")
    for name in ("dau_ratio", "peak_hour_ratio", "read_ratio", "cache_hit_ratio"):
        value = getattr(inputs, name)
        if not 0 <= value <= 1:
            raise ValueError(f"{name} must be between 0 and 1")
    for name in ("actions_per_session", "requests_per_action", "burst_multiplier", "queries_per_read",
                 "queries_per_write", "p95_latency_ms", "db_time_ms", "instance_rps",
                 "cpu_ms_per_request", "memory_mb_per_instance", "headroom"):
        if getattr(inputs, name) <= 0:
            raise ValueError(f"{name} must be positive")
    if inputs.headroom < 1:
        raise ValueError("headroom must be at least 1")


def model(inputs: CapacityInputs) -> dict[str, object]:
    validate(inputs)
    daily_active_users = inputs.users * inputs.dau_ratio
    peak_hour_users = daily_active_users * inputs.peak_hour_ratio
    peak_hour_requests = peak_hour_users * inputs.actions_per_session * inputs.requests_per_action
    average_peak_rps = peak_hour_requests / 3600
    design_peak_rps = average_peak_rps * inputs.burst_multiplier
    read_rps = design_peak_rps * inputs.read_ratio
    write_rps = design_peak_rps - read_rps
    db_read_qps = read_rps * (1 - inputs.cache_hit_ratio) * inputs.queries_per_read
    db_write_qps = write_rps * inputs.queries_per_write
    db_qps = db_read_qps + db_write_qps
    in_flight_requests = design_peak_rps * inputs.p95_latency_ms / 1000
    in_flight_db = db_qps * inputs.db_time_ms / 1000
    instances = max(1, math.ceil(design_peak_rps * inputs.headroom / inputs.instance_rps))
    cpu_cores = design_peak_rps * inputs.cpu_ms_per_request / 1000 * inputs.headroom
    app_memory_mb = instances * inputs.memory_mb_per_instance
    db_connections = max(2, math.ceil(in_flight_db * inputs.headroom))
    test_stages = [
        {"name": "smoke", "target_rps": round(max(1, design_peak_rps * 0.05), 2), "purpose": "Validate script and telemetry"},
        {"name": "average", "target_rps": round(design_peak_rps * 0.50, 2), "purpose": "Establish steady-state baseline"},
        {"name": "peak", "target_rps": round(design_peak_rps, 2), "purpose": "Prove SLO at design peak"},
        {"name": "stress", "target_rps": round(design_peak_rps * 1.50, 2), "purpose": "Find the first bottleneck"},
        {"name": "spike", "target_rps": round(design_peak_rps * 2.00, 2), "purpose": "Verify shedding and recovery"},
        {"name": "soak", "target_rps": round(design_peak_rps, 2), "purpose": "Detect leaks and queue growth"},
    ]
    return {
        "schema_version": "1.0",
        "inputs": asdict(inputs),
        "derived": {
            "daily_active_users": round(daily_active_users),
            "users_in_peak_hour": round(peak_hour_users),
            "average_peak_rps": round(average_peak_rps, 2),
            "design_peak_rps": round(design_peak_rps, 2),
            "read_rps": round(read_rps, 2),
            "write_rps": round(write_rps, 2),
            "database_query_rps_after_cache": round(db_qps, 2),
            "estimated_in_flight_requests_at_p95": round(in_flight_requests, 2),
            "estimated_in_flight_database_work": round(in_flight_db, 2),
            "minimum_app_instances_with_headroom": instances,
            "estimated_cpu_cores_with_headroom": round(cpu_cores, 2),
            "estimated_app_memory_mb": round(app_memory_mb, 2),
            "estimated_db_connections_with_headroom": db_connections,
        },
        "load_test_stages": test_stages,
        "required_evidence": [
            "Measured sustainable RPS per instance at the latency and error SLO",
            "CPU time per request and peak RSS per instance from a production-shaped benchmark",
            "Endpoint-level traffic mix, payload sizes, and think time from analytics",
            "Database CPU, locks, slow queries, pool wait time, and storage IOPS at each stage",
            "Queue depth, retry volume, dependency latency, and rate-limit behavior",
            "Recovery after overload, instance loss, cache loss, and dependency failure",
        ],
        "warning": "This is a workload hypothesis, not proof of capacity. Replace assumptions and run authorized tests in a production-like environment.",
    }


def markdown_report(payload: dict[str, object]) -> str:
    inputs = payload["inputs"]
    derived = payload["derived"]
    stages = payload["load_test_stages"]
    lines = [
        "# ShipProof capacity hypothesis", "",
        f"Registered users are **not** treated as concurrent users. This model converts `{inputs['users']:,}` registered users into an explicit workload.", "",
        "## Derived design targets", "",
        "| Signal | Value |", "| --- | ---: |",
    ]
    labels = {
        "daily_active_users": "Daily active users",
        "users_in_peak_hour": "Users represented in peak hour",
        "average_peak_rps": "Average RPS within peak hour",
        "design_peak_rps": "Design peak RPS after burst multiplier",
        "read_rps": "Read RPS",
        "write_rps": "Write RPS",
        "database_query_rps_after_cache": "Database query RPS after cache",
        "estimated_in_flight_requests_at_p95": "Estimated in-flight requests at p95",
        "estimated_in_flight_database_work": "Estimated in-flight database work",
        "minimum_app_instances_with_headroom": "Minimum app instances with headroom",
        "estimated_cpu_cores_with_headroom": "Estimated CPU cores with headroom",
        "estimated_app_memory_mb": "Estimated app memory (MB)",
        "estimated_db_connections_with_headroom": "Estimated DB connections with headroom",
    }
    lines.extend(f"| {labels[key]} | {value:,} |" for key, value in derived.items())
    lines.extend(["", "## Load-test ladder", "", "| Stage | Target RPS | Purpose |", "| --- | ---: | --- |"])
    lines.extend(f"| {stage['name']} | {stage['target_rps']:,} | {stage['purpose']} |" for stage in stages)
    lines.extend(["", "## Assumptions to replace", "", "| Input | Value |", "| --- | ---: |"])
    lines.extend(f"| `{key}` | {value} |" for key, value in inputs.items())
    lines.extend(["", "## Required release evidence", ""])
    lines.extend(f"- {item}" for item in payload["required_evidence"])
    lines.extend(["", f"> {payload['warning']}", ""])
    return "\n".join(lines)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--users", type=int, required=True)
    parser.add_argument("--dau-ratio", type=float, default=0.20)
    parser.add_argument("--peak-hour-ratio", type=float, default=0.15)
    parser.add_argument("--actions-per-session", type=float, default=10)
    parser.add_argument("--requests-per-action", type=float, default=2)
    parser.add_argument("--burst-multiplier", type=float, default=2)
    parser.add_argument("--read-ratio", type=float, default=0.85)
    parser.add_argument("--cache-hit-ratio", type=float, default=0.70)
    parser.add_argument("--queries-per-read", type=float, default=1.5)
    parser.add_argument("--queries-per-write", type=float, default=2)
    parser.add_argument("--p95-latency-ms", type=float, default=300)
    parser.add_argument("--db-time-ms", type=float, default=40)
    parser.add_argument("--instance-rps", type=float, default=200)
    parser.add_argument("--cpu-ms-per-request", type=float, default=5)
    parser.add_argument("--memory-mb-per-instance", type=float, default=512)
    parser.add_argument("--headroom", type=float, default=1.5)
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument("--output", type=argparse.FileType("w", encoding="utf-8"))
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    values = vars(args).copy()
    output = values.pop("output")
    output_format = values.pop("format")
    inputs = CapacityInputs(**{key.replace("-", "_"): value for key, value in values.items()})
    try:
        payload = model(inputs)
    except ValueError as exc:
        print(f"shipproof: {exc}", file=sys.stderr)
        return 2
    rendered = markdown_report(payload) if output_format == "markdown" else json.dumps(payload, indent=2)
    if output:
        output.write(rendered + ("" if rendered.endswith("\n") else "\n"))
        output.close()
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
