#!/usr/bin/env python3
"""Turn registered-user targets into explicit, testable capacity assumptions."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass, fields
from pathlib import Path

VERSION = "0.4.0"
K6_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")
ROUTE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
DURATION = re.compile(r"^[1-9][0-9]*(?:ms|s|m|h)$")


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


def validate_capacity_inputs(inputs: CapacityInputs) -> None:
    if isinstance(inputs.users, bool) or not isinstance(inputs.users, int) or inputs.users <= 0:
        raise ValueError("users must be a positive integer")
    for name in ("dau_ratio", "peak_hour_ratio", "read_ratio", "cache_hit_ratio"):
        value = getattr(inputs, name)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise ValueError(f"{name} must be a finite number")
        if not 0 <= value <= 1:
            raise ValueError(f"{name} must be between 0 and 1")
    for name in (
        "actions_per_session",
        "requests_per_action",
        "burst_multiplier",
        "queries_per_read",
        "queries_per_write",
        "p95_latency_ms",
        "db_time_ms",
        "instance_rps",
        "cpu_ms_per_request",
        "memory_mb_per_instance",
        "headroom",
    ):
        value = getattr(inputs, name)
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise ValueError(f"{name} must be a finite number")
        if value <= 0:
            raise ValueError(f"{name} must be positive")
    if inputs.headroom < 1:
        raise ValueError("headroom must be at least 1")


def build_capacity_model(inputs: CapacityInputs) -> dict[str, object]:
    validate_capacity_inputs(inputs)
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
        {
            "name": "smoke",
            "target_rps": round(max(1, design_peak_rps * 0.05), 2),
            "purpose": "Validate script and telemetry",
        },
        {
            "name": "average",
            "target_rps": round(design_peak_rps * 0.50, 2),
            "purpose": "Establish steady-state baseline",
        },
        {
            "name": "peak",
            "target_rps": round(design_peak_rps, 2),
            "purpose": "Prove SLO at design peak",
        },
        {
            "name": "stress",
            "target_rps": round(design_peak_rps * 1.50, 2),
            "purpose": "Find the first bottleneck",
        },
        {
            "name": "spike",
            "target_rps": round(design_peak_rps * 2.00, 2),
            "purpose": "Verify shedding and recovery",
        },
        {
            "name": "soak",
            "target_rps": round(design_peak_rps, 2),
            "purpose": "Detect leaks and queue growth",
        },
    ]
    return {
        "schema_version": "1.0",
        "tool": {"name": "ShipProof", "version": VERSION, "command": "capacity"},
        "verdict": "CONDITIONAL",
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
        "limitations": [
            "Capacity is estimated from declared assumptions rather than observed production traffic.",
            "The model does not discover dependency quotas, database limits, or load-generator limits.",
        ],
    }


def _require_positive_integer(value: object, name: str, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} must be at most {maximum}")
    return value


def _require_finite_number(value: object, name: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number")
    number = float(value)
    if not minimum <= number < maximum:
        raise ValueError(f"{name} must be at least {minimum} and less than {maximum}")
    return number


def validate_k6_config(raw_config: object) -> dict[str, object]:
    if not isinstance(raw_config, dict):
        raise ValueError("k6 config must be a JSON object")
    allowed_fields = {
        "base_url_env",
        "auth_token_env",
        "duration",
        "error_rate_threshold",
        "p95_latency_ms",
        "preallocated_vus",
        "max_vus",
        "routes",
    }
    unknown_fields = sorted(set(raw_config) - allowed_fields)
    if unknown_fields:
        raise ValueError(f"unknown k6 config fields: {', '.join(unknown_fields)}")

    base_url_env = raw_config.get("base_url_env", "BASE_URL")
    auth_token_env = raw_config.get("auth_token_env")
    duration = raw_config.get("duration", "1m")
    for value, name in ((base_url_env, "base_url_env"), (auth_token_env, "auth_token_env")):
        if value is not None and (
            not isinstance(value, str) or not ENVIRONMENT_NAME.fullmatch(value)
        ):
            raise ValueError(f"{name} must be an uppercase environment variable name")
    if not isinstance(duration, str) or not DURATION.fullmatch(duration):
        raise ValueError("duration must be a positive k6 duration such as 30s or 5m")

    error_rate = _require_finite_number(
        raw_config.get("error_rate_threshold", 0.01),
        "error_rate_threshold",
        0.000000001,
        1,
    )
    p95_latency_ms = _require_finite_number(
        raw_config.get("p95_latency_ms", 300),
        "p95_latency_ms",
        0.000001,
        86_400_000,
    )
    routes = raw_config.get("routes")
    if not isinstance(routes, list) or not 1 <= len(routes) <= 100:
        raise ValueError("k6 routes must contain between 1 and 100 route objects")

    normalized_routes: list[dict[str, object]] = []
    route_names: set[str] = set()
    allowed_route_fields = {"name", "path", "method", "weight", "expected_statuses", "body"}
    for index, route in enumerate(routes):
        if not isinstance(route, dict):
            raise ValueError(f"k6 route {index} must be a JSON object")
        unknown_route_fields = sorted(set(route) - allowed_route_fields)
        if unknown_route_fields:
            raise ValueError(
                f"unknown fields for k6 route {index}: {', '.join(unknown_route_fields)}"
            )
        name = route.get("name")
        path = route.get("path")
        method = route.get("method", "GET")
        if not isinstance(name, str) or not ROUTE_NAME.fullmatch(name):
            raise ValueError(f"k6 route {index} has an invalid name")
        if name in route_names:
            raise ValueError(f"k6 route name is duplicated: {name}")
        route_names.add(name)
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path.startswith("//")
            or "://" in path
            or len(path) > 2048
        ):
            raise ValueError(f"k6 route {name} path must be a relative HTTP path")
        if not isinstance(method, str) or method.upper() not in K6_METHODS:
            raise ValueError(f"k6 route {name} has an unsupported method")
        weight = _require_positive_integer(
            route.get("weight", 1), f"k6 route {name} weight", 10_000
        )
        statuses = route.get("expected_statuses", [200])
        if not isinstance(statuses, list) or not statuses:
            raise ValueError(f"k6 route {name} expected_statuses must be a non-empty array")
        normalized_statuses = sorted(
            {
                _require_positive_integer(status, f"k6 route {name} status", 599)
                for status in statuses
            }
        )
        if normalized_statuses[0] < 100:
            raise ValueError(f"k6 route {name} statuses must be between 100 and 599")
        body = route.get("body")
        try:
            encoded_body = json.dumps(
                body, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"k6 route {name} body must be JSON serializable") from exc
        if len(encoded_body.encode("utf-8")) > 100_000:
            raise ValueError(f"k6 route {name} body must be at most 100000 bytes")
        normalized_routes.append(
            {
                "name": name,
                "path": path,
                "method": method.upper(),
                "weight": weight,
                "expected_statuses": normalized_statuses,
                "body": body,
            }
        )

    normalized: dict[str, object] = {
        "base_url_env": base_url_env,
        "duration": duration,
        "error_rate_threshold": error_rate,
        "p95_latency_ms": p95_latency_ms,
        "routes": normalized_routes,
    }
    if auth_token_env:
        normalized["auth_token_env"] = auth_token_env
    for field_name in ("preallocated_vus", "max_vus"):
        if field_name in raw_config:
            normalized[field_name] = _require_positive_integer(raw_config[field_name], field_name)
    if (
        "preallocated_vus" in normalized
        and "max_vus" in normalized
        and normalized["max_vus"] < normalized["preallocated_vus"]
    ):
        raise ValueError("max_vus must be at least preallocated_vus")
    return normalized


def render_k6_script(capacity: dict[str, object], raw_config: object) -> str:
    config = validate_k6_config(raw_config)
    design_peak_rps = float(capacity["derived"]["design_peak_rps"])
    rate = max(1, math.ceil(design_peak_rps))
    estimated_vus = max(
        1,
        math.ceil(
            rate * float(config["p95_latency_ms"]) / 1000 * float(capacity["inputs"]["headroom"])
        ),
    )
    preallocated_vus = int(config.get("preallocated_vus", estimated_vus))
    max_vus = int(config.get("max_vus", preallocated_vus))
    if max_vus < preallocated_vus:
        raise ValueError("max_vus must be at least preallocated_vus")

    routes_json = json.dumps(
        config["routes"], ensure_ascii=False, separators=(",", ":"), allow_nan=False
    )
    routes_json = routes_json.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    source_digest = hashlib.sha256(
        json.dumps(
            {"inputs": capacity["inputs"], "derived": capacity["derived"], "k6": config},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()[:16]
    auth_line = "const authToken = null;"
    auth_header = ""
    if config.get("auth_token_env"):
        auth_environment = json.dumps(config["auth_token_env"])
        auth_line = f"const authToken = __ENV[{auth_environment}] || null;"
        auth_header = "\n  if (authToken) headers.Authorization = `Bearer ${authToken}`;"
    base_environment = json.dumps(config["base_url_env"])
    return f"""// Generated by ShipProof {VERSION}; input digest: {source_digest}
// One iteration performs one request. Review the traffic model before any authorized run.
import http from "k6/http";
import {{ check }} from "k6";

const baseUrl = __ENV[{base_environment}];
if (!baseUrl) throw new Error("Set the {config["base_url_env"]} environment variable");
{auth_line}
const routes = {routes_json};
const totalWeight = routes.reduce((sum, route) => sum + route.weight, 0);

export const options = {{
  discardResponseBodies: true,
  scenarios: {{
    design_peak: {{
      executor: "constant-arrival-rate",
      rate: {rate},
      timeUnit: "1s",
      duration: {json.dumps(config["duration"])},
      preAllocatedVUs: {preallocated_vus},
      maxVUs: {max_vus},
    }},
  }},
  thresholds: {{
    http_req_failed: ["rate<{config["error_rate_threshold"]}"],
    http_req_duration: ["p(95)<{config["p95_latency_ms"]}"],
  }},
}};

export default function () {{
  let slot = __ITER % totalWeight;
  let route = routes[0];
  for (const candidate of routes) {{
    if (slot < candidate.weight) {{
      route = candidate;
      break;
    }}
    slot -= candidate.weight;
  }}
  const headers = route.body === null ? {{}} : {{ "Content-Type": "application/json" }};{auth_header}
  const body = route.body === null ? null : JSON.stringify(route.body);
  const response = http.request(route.method, `${{baseUrl}}${{route.path}}`, body, {{
    headers,
    tags: {{ route: route.name }},
  }});
  check(response, {{ "status is expected": (result) => route.expected_statuses.includes(result.status) }});
}}
"""


def render_markdown_report(payload: dict[str, object]) -> str:
    inputs = payload["inputs"]
    derived = payload["derived"]
    stages = payload["load_test_stages"]
    lines = [
        "# ShipProof capacity hypothesis",
        "",
        f"Registered users are **not** treated as concurrent users. This model converts `{inputs['users']:,}` registered users into an explicit workload.",
        "",
        "## Derived design targets",
        "",
        "| Signal | Value |",
        "| --- | ---: |",
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
    lines.extend(
        ["", "## Load-test ladder", "", "| Stage | Target RPS | Purpose |", "| --- | ---: | --- |"]
    )
    lines.extend(
        f"| {stage['name']} | {stage['target_rps']:,} | {stage['purpose']} |" for stage in stages
    )
    lines.extend(["", "## Assumptions to replace", "", "| Input | Value |", "| --- | ---: |"])
    lines.extend(f"| `{key}` | {value} |" for key, value in inputs.items())
    lines.extend(["", "## Required release evidence", ""])
    lines.extend(f"- {item}" for item in payload["required_evidence"])
    lines.extend(["", f"> {payload['warning']}", ""])
    return "\n".join(lines)


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="Load inputs from a JSON configuration file")
    parser.add_argument("--users", type=int)
    parser.add_argument("--dau-ratio", type=float)
    parser.add_argument("--peak-hour-ratio", type=float)
    parser.add_argument("--actions-per-session", type=float)
    parser.add_argument("--requests-per-action", type=float)
    parser.add_argument("--burst-multiplier", type=float)
    parser.add_argument("--read-ratio", type=float)
    parser.add_argument("--cache-hit-ratio", type=float)
    parser.add_argument("--queries-per-read", type=float)
    parser.add_argument("--queries-per-write", type=float)
    parser.add_argument("--p95-latency-ms", type=float)
    parser.add_argument("--db-time-ms", type=float)
    parser.add_argument("--instance-rps", type=float)
    parser.add_argument("--cpu-ms-per-request", type=float)
    parser.add_argument("--memory-mb-per-instance", type=float)
    parser.add_argument("--headroom", type=float)
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument("--output", type=Path, help="Write report to a file instead of stdout")
    parser.add_argument("--export-k6", type=Path, help="Write a deterministic k6 script")
    parser.add_argument("--force", action="store_true", help="Replace an existing k6 script")
    return parser.parse_args(argv)


def load_config(config_path: Path) -> tuple[dict[str, object], object | None]:
    config_payload = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(config_payload, dict):
        raise ValueError("config file must contain a JSON object")

    if "capacity" in config_payload:
        unknown_top_level = sorted(set(config_payload) - {"$schema", "schema_version", "capacity"})
        if unknown_top_level:
            raise ValueError(f"unknown config fields: {', '.join(unknown_top_level)}")
        if config_payload.get("schema_version", "1.0") != "1.0":
            raise ValueError("unsupported config schema_version")
        capacity_section = config_payload["capacity"]
    else:
        capacity_section = config_payload
    if not isinstance(capacity_section, dict):
        raise ValueError("capacity config must be a JSON object")

    if "inputs" in capacity_section:
        unknown_capacity_fields = sorted(set(capacity_section) - {"inputs", "k6", "schema_version"})
        if unknown_capacity_fields:
            raise ValueError(
                f"unknown capacity config fields: {', '.join(unknown_capacity_fields)}"
            )
        config_inputs = capacity_section["inputs"]
    else:
        config_inputs = {
            key: value
            for key, value in capacity_section.items()
            if key not in {"schema_version", "k6"}
        }
    if not isinstance(config_inputs, dict):
        raise ValueError("config inputs must be a JSON object")
    return dict(config_inputs), capacity_section.get("k6")


def write_new_file(path: Path, content: str, force: bool) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing to replace a symbolic link: {path}")
    if path.exists() and not force:
        raise ValueError(f"refusing to replace existing file without --force: {path}")
    if not path.parent.exists() or not path.parent.is_dir():
        raise ValueError(f"output directory does not exist: {path.parent}")
    path.write_text(content + ("" if content.endswith("\n") else "\n"), encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    arguments = parse_arguments(argv)
    argument_values = vars(arguments).copy()
    config_path = argument_values.pop("config")
    output_path = argument_values.pop("output")
    output_format = argument_values.pop("format")
    export_k6_path = argument_values.pop("export_k6")
    force = argument_values.pop("force")

    merged_inputs: dict[str, object] = {}
    k6_config: object | None = None
    if config_path:
        try:
            config_inputs, k6_config = load_config(config_path)
            merged_inputs.update(
                {key.replace("-", "_"): value for key, value in config_inputs.items()}
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"shipproof: {exc}", file=sys.stderr)
            return 2

    # Explicit CLI values override configuration; dataclass defaults fill omitted values.
    for key, value in argument_values.items():
        clean_key = key.replace("-", "_")
        if value is not None:
            merged_inputs[clean_key] = value

    if "users" not in merged_inputs or merged_inputs["users"] is None:
        print("shipproof: error: --users is required (either via CLI or --config)", file=sys.stderr)
        return 2

    try:
        valid_fields = {f.name for f in fields(CapacityInputs)}
        unknown_fields = sorted(set(merged_inputs) - valid_fields)
        if unknown_fields:
            raise ValueError(f"unknown config inputs: {', '.join(unknown_fields)}")
        capacity_inputs = CapacityInputs(**merged_inputs)
        report_payload = build_capacity_model(capacity_inputs)
        if export_k6_path:
            if k6_config is None:
                raise ValueError("--export-k6 requires a k6 section in --config")
            k6_script = render_k6_script(report_payload, k6_config)
            write_new_file(export_k6_path, k6_script, force)
            report_payload["artifacts"] = [
                {
                    "type": "k6",
                    "path": export_k6_path.as_posix(),
                    "sha256": hashlib.sha256(k6_script.encode()).hexdigest(),
                }
            ]
    except (OSError, ValueError, TypeError) as exc:
        print(f"shipproof: {exc}", file=sys.stderr)
        return 2
    rendered_report = (
        render_markdown_report(report_payload)
        if output_format == "markdown"
        else json.dumps(report_payload, indent=2)
    )
    try:
        if output_path:
            output_path.write_text(
                rendered_report + ("" if rendered_report.endswith("\n") else "\n"),
                encoding="utf-8",
            )
        else:
            print(rendered_report)
    except OSError as exc:
        print(f"shipproof: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
