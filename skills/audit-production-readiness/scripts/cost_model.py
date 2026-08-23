#!/usr/bin/env python3
"""Deterministic, offline AI agent token and cost budget modeler."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

VERSION = "0.8.1"

# 2026 Model Pricing catalog (USD per 1 Million tokens)
# Format: input_per_m, output_per_m, cache_read_per_m, cache_write_per_m
MODEL_PRICING: dict[str, dict[str, float]] = {
    "claude-sonnet-5": {
        "input": 2.00,
        "output": 10.00,
        "cache_read": 0.20,
        "cache_write": 2.50,
    },
    "claude-3-7-sonnet": {
        "input": 3.00,
        "output": 15.00,
        "cache_read": 0.30,
        "cache_write": 3.75,
    },
    "claude-3-5-sonnet": {
        "input": 3.00,
        "output": 15.00,
        "cache_read": 0.30,
        "cache_write": 3.75,
    },
    "claude-3-5-haiku": {
        "input": 0.80,
        "output": 4.00,
        "cache_read": 0.08,
        "cache_write": 1.00,
    },
    "claude-3-opus": {
        "input": 15.00,
        "output": 75.00,
        "cache_read": 1.50,
        "cache_write": 18.75,
    },
    "gpt-4.5": {
        "input": 75.00,
        "output": 150.00,
        "cache_read": 37.50,
        "cache_write": 75.00,
    },
    "gpt-4o": {
        "input": 2.50,
        "output": 10.00,
        "cache_read": 1.25,
        "cache_write": 2.50,
    },
    "gpt-4o-mini": {
        "input": 0.15,
        "output": 0.60,
        "cache_read": 0.075,
        "cache_write": 0.15,
    },
    "o1": {
        "input": 15.00,
        "output": 60.00,
        "cache_read": 7.50,
        "cache_write": 15.00,
    },
    "o3-mini": {
        "input": 1.10,
        "output": 4.40,
        "cache_read": 0.55,
        "cache_write": 1.10,
    },
    "o4-mini": {
        "input": 1.10,
        "output": 4.40,
        "cache_read": 0.55,
        "cache_write": 1.10,
    },
    "gemini-3-7-flash": {
        "input": 0.75,
        "output": 3.75,
        "cache_read": 0.1875,
        "cache_write": 0.75,
    },
    "gemini-2-0-flash": {
        "input": 0.10,
        "output": 0.40,
        "cache_read": 0.025,
        "cache_write": 0.10,
    },
    "gemini-2-0-flash-lite": {
        "input": 0.075,
        "output": 0.30,
        "cache_read": 0.01875,
        "cache_write": 0.075,
    },
    "gemini-2-0-pro": {
        "input": 1.25,
        "output": 5.00,
        "cache_read": 0.3125,
        "cache_write": 1.25,
    },
    "gemini-1-5-pro": {
        "input": 1.25,
        "output": 5.00,
        "cache_read": 0.3125,
        "cache_write": 1.25,
    },
    "gemini-1-5-flash": {
        "input": 0.075,
        "output": 0.30,
        "cache_read": 0.01875,
        "cache_write": 0.075,
    },
    "deepseek-v4-flash": {
        "input": 0.14,
        "output": 0.28,
        "cache_read": 0.014,
        "cache_write": 0.14,
    },
    "deepseek-v4-pro": {
        "input": 0.435,
        "output": 0.87,
        "cache_read": 0.0435,
        "cache_write": 0.435,
    },
    "deepseek-v3": {
        "input": 0.14,
        "output": 0.28,
        "cache_read": 0.014,
        "cache_write": 0.14,
    },
    "deepseek-r1": {
        "input": 0.55,
        "output": 2.19,
        "cache_read": 0.14,
        "cache_write": 0.55,
    },
    "mistral-large": {
        "input": 2.00,
        "output": 6.00,
        "cache_read": 0.20,
        "cache_write": 2.00,
    },
    "codestral": {
        "input": 0.30,
        "output": 0.90,
        "cache_read": 0.03,
        "cache_write": 0.30,
    },
    "llama-3.3-70b": {
        "input": 0.70,
        "output": 0.80,
        "cache_read": 0.07,
        "cache_write": 0.70,
    },
}

CADENCE_MULTIPLIERS = {
    "once": 1,
    "per-pr": 1,
    "hourly": 24 * 30,  # 720 runs/month
    "daily": 30,  # 30 runs/month
    "weekly": 4,  # 4 runs/month
    "monthly": 1,
}

BYTES_PER_CODE_TOKEN = 3.8
DEFAULT_PROMPT_OVERHEAD_TOKENS = 3500
DEFAULT_OUTPUT_TOKENS_PER_ITERATION = 1200


@dataclass(frozen=True)
class CostEstimate:
    model: str
    iterations: int
    context_tokens: int
    output_tokens_per_iteration: int
    total_input_tokens: int
    total_output_tokens: int
    cached_input_tokens: int
    fresh_input_tokens: int
    estimated_cost_usd_single_run: float
    cadence: str
    monthly_estimated_cost_usd: float
    budget_usd: float | None
    budget_status: str
    savings_from_caching_usd: float


def estimate_codebase_tokens(
    root: Path, max_file_bytes: int = 500_000, exclude_dirs: set[str] | None = None
) -> int:
    """Estimate context token count of scannable text files in directory."""
    if not root.exists():
        raise ValueError(f"path does not exist: {root}")
    if not root.is_file() and not root.is_dir():
        raise ValueError(f"path is not a regular file or directory: {root}")
    if exclude_dirs is None:
        exclude_dirs = {
            ".git",
            "node_modules",
            "vendor",
            "dist",
            "build",
            ".venv",
            "venv",
            ".next",
            "__pycache__",
            ".work",
        }
    total_bytes = 0
    scannable_suffixes = {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".go",
        ".rs",
        ".java",
        ".cs",
        ".rb",
        ".php",
        ".json",
        ".yaml",
        ".yml",
        ".md",
        ".sql",
    }
    if root.is_file():
        try:
            total_bytes = root.stat().st_size
        except OSError:
            total_bytes = 0
    elif root.is_dir():
        for directory, subdirs, files in os.walk(root):
            subdirs[:] = [d for d in subdirs if d not in exclude_dirs]
            for f in files:
                p = Path(directory, f)
                if p.suffix.lower() in scannable_suffixes:
                    try:
                        sz = p.stat().st_size
                        if sz <= max_file_bytes:
                            total_bytes += sz
                    except OSError:
                        continue
    return max(500, int(total_bytes / BYTES_PER_CODE_TOKEN)) + DEFAULT_PROMPT_OVERHEAD_TOKENS


def calculate_cost(
    model: str,
    context_tokens: int,
    output_tokens_per_iteration: int = DEFAULT_OUTPUT_TOKENS_PER_ITERATION,
    iterations: int = 3,
    use_prompt_caching: bool = True,
    cadence: str = "once",
    budget_usd: float | None = None,
) -> CostEstimate:
    """Compute deterministic AI cost and token consumption model."""
    if context_tokens < 1:
        raise ValueError("context_tokens must be positive")
    if output_tokens_per_iteration < 1:
        raise ValueError("output_tokens_per_iteration must be positive")
    if iterations < 1:
        raise ValueError("iterations must be at least 1")
    if budget_usd is not None and budget_usd <= 0:
        raise ValueError("budget_usd must be positive")
    pricing = MODEL_PRICING.get(model.lower(), MODEL_PRICING["claude-3-5-sonnet"])
    total_output_tokens = output_tokens_per_iteration * iterations

    if iterations <= 1:
        fresh_input_tokens = context_tokens
        cached_input_tokens = 0
        total_input_tokens = context_tokens
    else:
        # First iteration sends fresh context; subsequent iterations hit prompt cache if enabled
        if use_prompt_caching:
            fresh_input_tokens = context_tokens
            cached_input_tokens = context_tokens * (iterations - 1)
            total_input_tokens = fresh_input_tokens + cached_input_tokens
        else:
            fresh_input_tokens = context_tokens * iterations
            cached_input_tokens = 0
            total_input_tokens = fresh_input_tokens

    # Cost without prompt caching
    cost_no_cache = (total_input_tokens / 1_000_000.0) * pricing["input"] + (
        total_output_tokens / 1_000_000.0
    ) * pricing["output"]

    # Actual cost with prompt caching
    cost_fresh_input = (fresh_input_tokens / 1_000_000.0) * pricing["input"]
    cost_cached_input = (cached_input_tokens / 1_000_000.0) * pricing["cache_read"]
    cost_output = (total_output_tokens / 1_000_000.0) * pricing["output"]
    total_cost_single = cost_fresh_input + cost_cached_input + cost_output
    savings = max(0.0, cost_no_cache - total_cost_single)

    cadence_mult = CADENCE_MULTIPLIERS.get(cadence.lower(), 1)
    monthly_cost = total_cost_single * cadence_mult

    if budget_usd is not None and budget_usd > 0:
        budget_status = "PASS" if total_cost_single <= budget_usd else "EXCEEDED"
    else:
        budget_status = "UNSET"

    return CostEstimate(
        model=model,
        iterations=iterations,
        context_tokens=context_tokens,
        output_tokens_per_iteration=output_tokens_per_iteration,
        total_input_tokens=total_input_tokens,
        total_output_tokens=total_output_tokens,
        cached_input_tokens=cached_input_tokens,
        fresh_input_tokens=fresh_input_tokens,
        estimated_cost_usd_single_run=round(total_cost_single, 5),
        cadence=cadence,
        monthly_estimated_cost_usd=round(monthly_cost, 4),
        budget_usd=budget_usd,
        budget_status=budget_status,
        savings_from_caching_usd=round(savings, 5),
    )


def format_terminal(estimate: CostEstimate) -> str:
    """Format a clean terminal report card."""
    lines = [
        "----------------------------------------------------------------------",
        f"  ShipProof AI Cost & Token Budget ({estimate.model})",
        "----------------------------------------------------------------------",
        f"  Iterations:          {estimate.iterations} turns / prompt loop",
        f"  Context Footprint:   {estimate.context_tokens:,} tokens",
        f"  Output Tokens:       {estimate.total_output_tokens:,} tokens ({estimate.output_tokens_per_iteration:,}/turn)",
        f"  Cached Tokens:       {estimate.cached_input_tokens:,} tokens (Prompt Caching enabled)",
        f"  Est. Cost (Run):     ${estimate.estimated_cost_usd_single_run:.4f} USD",
        f"  Cache Savings:       ${estimate.savings_from_caching_usd:.4f} USD saved",
    ]
    if estimate.cadence != "once":
        lines.append(
            f"  Monthly Projection:  ${estimate.monthly_estimated_cost_usd:.2f} USD ({estimate.cadence} cadence)"
        )
    if estimate.budget_usd is not None:
        status_symbol = "[PASS]" if estimate.budget_status == "PASS" else "[FAIL: BUDGET EXCEEDED]"
        lines.append(
            f"  Budget Gate:         {status_symbol} (Max: ${estimate.budget_usd:.4f} USD, Actual: ${estimate.estimated_cost_usd_single_run:.4f} USD)"
        )
    lines.append("----------------------------------------------------------------------")
    return "\n".join(lines)


def format_markdown(estimate: CostEstimate) -> str:
    """Format Markdown report table."""
    status = (
        "**PASS**"
        if estimate.budget_status == "PASS"
        else ("**EXCEEDED**" if estimate.budget_status == "EXCEEDED" else "INFO")
    )
    return f"""# ShipProof AI Cost & Token Budget Report

**Verdict:** {status} | **Model:** `{estimate.model}` | **Run Cost:** `${estimate.estimated_cost_usd_single_run:.4f}`

| Metric | Value |
| :--- | :--- |
| **Model Profile** | `{estimate.model}` |
| **Agent Iterations** | {estimate.iterations} |
| **Context Tokens** | {estimate.context_tokens:,} |
| **Total Input Tokens** | {estimate.total_input_tokens:,} ({estimate.cached_input_tokens:,} cached) |
| **Total Output Tokens** | {estimate.total_output_tokens:,} |
| **Single Run Cost** | **${estimate.estimated_cost_usd_single_run:.4f} USD** |
| **Prompt Cache Savings** | ${estimate.savings_from_caching_usd:.4f} USD |
| **Cadence / Monthly** | {estimate.cadence} (${estimate.monthly_estimated_cost_usd:.2f}/mo) |
| **Budget Gate** | {estimate.budget_status} (Cap: ${estimate.budget_usd if estimate.budget_usd else "None"}) |
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ShipProof AI Agent Cost & Token Budgeting Engine")
    parser.add_argument("path", nargs="?", default=".", help="Repository or directory path to scan")
    parser.add_argument(
        "--model",
        default="claude-3-5-sonnet",
        choices=sorted(MODEL_PRICING.keys()),
        help="AI Model pricing profile",
    )
    parser.add_argument(
        "--iterations", type=int, default=3, help="Estimated agent loop turns per task (default: 3)"
    )
    parser.add_argument(
        "--context-tokens",
        type=int,
        default=None,
        help="Override codebase context token footprint",
    )
    parser.add_argument(
        "--output-tokens",
        type=int,
        default=DEFAULT_OUTPUT_TOKENS_PER_ITERATION,
        help="Expected generated tokens per iteration",
    )
    parser.add_argument(
        "--cadence",
        default="once",
        choices=list(CADENCE_MULTIPLIERS.keys()),
        help="Frequency cadence for monthly projections",
    )
    parser.add_argument(
        "--budget-usd",
        type=float,
        default=None,
        help="Maximum allowable cost per task before failing gate",
    )
    parser.add_argument(
        "--no-cache", action="store_true", help="Disable prompt caching calculations"
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "markdown", "json"],
        default="terminal",
        help="Output format",
    )

    args = parser.parse_args(argv)

    if args.iterations < 1:
        sys.stderr.write("Error: --iterations must be at least 1\n")
        return 2
    if args.output_tokens < 1:
        sys.stderr.write("Error: --output-tokens must be positive\n")
        return 2
    if args.context_tokens is not None and args.context_tokens < 1:
        sys.stderr.write("Error: --context-tokens must be positive\n")
        return 2
    if args.budget_usd is not None and args.budget_usd <= 0:
        sys.stderr.write("Error: --budget-usd must be positive\n")
        return 2

    target_path = Path(args.path).resolve()
    if not target_path.exists():
        sys.stderr.write(f"Error: path does not exist: {target_path}\n")
        return 2
    if not target_path.is_file() and not target_path.is_dir():
        sys.stderr.write(f"Error: path is not a regular file or directory: {target_path}\n")
        return 2

    if args.context_tokens is not None:
        context_tokens = args.context_tokens
    else:
        context_tokens = estimate_codebase_tokens(target_path)

    estimate = calculate_cost(
        model=args.model,
        context_tokens=context_tokens,
        output_tokens_per_iteration=args.output_tokens,
        iterations=args.iterations,
        use_prompt_caching=not args.no_cache,
        cadence=args.cadence,
        budget_usd=args.budget_usd,
    )

    if args.format == "json":
        payload = {
            "schema_version": "1.0",
            "tool": {"name": "ShipProof", "version": VERSION, "command": "cost"},
            "verdict": "BLOCK" if estimate.budget_status == "EXCEEDED" else "CONDITIONAL",
            "root": str(target_path),
            **asdict(estimate),
            "limitations": [
                "Costs are estimates based on declared token counts and versioned price assumptions.",
                "Provider discounts, batch pricing, tool calls, and future price changes may differ.",
            ],
        }
        print(json.dumps(payload, indent=2))
    elif args.format == "markdown":
        print(format_markdown(estimate))
    else:
        print(format_terminal(estimate))

    if estimate.budget_status == "EXCEEDED":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
