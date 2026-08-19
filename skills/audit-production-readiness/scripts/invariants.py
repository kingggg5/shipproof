#!/usr/bin/env python3
"""Repository Invariants Verification Engine for ShipProof.

Enforces system-level architectural and security invariants (such as auth boundaries,
tenant isolation parameters, and transaction-safety rules) across codebases.
Strictly offline and zero-dependency.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

VERSION = "0.6.0"

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".venv",
    ".work",
    "venv",
    "env",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    ".cache",
    ".npm-cache",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "target",
    "__pycache__",
}


@dataclass(frozen=True)
class InvariantViolation:
    invariant_id: str
    title: str
    path: str
    line: int
    severity: str  # "critical", "high", "medium"
    message: str
    remediation: str
    proof_level: str = "L3"


def check_auth_boundary(root: Path, file_path: Path, content: str) -> list[InvariantViolation]:
    violations: list[InvariantViolation] = []
    rel_str = str(file_path.relative_to(root)).replace("\\", "/")
    lines = content.splitlines()

    # Python FastAPI / Flask auth check on admin routes
    if file_path.suffix == ".py":
        try:
            tree = ast.parse(content, filename=rel_str)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for dec in node.decorator_list:
                        route_path = ""
                        if isinstance(dec, ast.Call):
                            for arg in dec.args:
                                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                    route_path = arg.value
                        if (
                            "/admin" in route_path
                            or "/internal" in route_path
                            or "admin_" in node.name
                        ):
                            # Check keywords in route decorator (like dependencies=[...]) or function arguments
                            has_auth_kw = False
                            if isinstance(dec, ast.Call):
                                for kw in dec.keywords:
                                    kw_str = (
                                        ast.unparse(kw.value) if hasattr(ast, "unparse") else ""
                                    ).lower()
                                    if any(
                                        term in kw_str
                                        for term in (
                                            "auth",
                                            "admin",
                                            "depends",
                                            "permission",
                                            "security",
                                            "role",
                                        )
                                    ):
                                        has_auth_kw = True
                            has_auth_arg = any(
                                any(
                                    term in a.arg.lower()
                                    for term in (
                                        "auth",
                                        "admin",
                                        "permission",
                                        "security",
                                        "role",
                                        "current_user",
                                    )
                                )
                                for a in node.args.args
                            )
                            if not (has_auth_kw or has_auth_arg):
                                violations.append(
                                    InvariantViolation(
                                        invariant_id="INV-AUTH-01",
                                        title="Administrative Route Missing Authorization Guard",
                                        path=rel_str,
                                        line=node.lineno,
                                        severity="high",
                                        message=f"Endpoint '{node.name}' handles admin path '{route_path or node.name}' without explicit authorization dependency.",
                                        remediation="Add an authorization guard dependency (e.g. Depends(require_admin)) or role verification.",
                                    )
                                )
        except SyntaxError:
            pass

    # Express / TS router auth check
    elif file_path.suffix in (".ts", ".js", ".mjs"):
        admin_route_pattern = re.compile(
            r"""\b(?:router|app)\.(?:get|post|put|delete|patch)\s*\(\s*['"]([^'"]*(?:admin|internal)[^'"]*)['"]\s*,\s*(?:async\s*)?\((?:req|ctx)""",
            re.IGNORECASE,
        )
        for i, line in enumerate(lines, 1):
            match = admin_route_pattern.search(line)
            if match:
                route = match.group(1)
                violations.append(
                    InvariantViolation(
                        invariant_id="INV-AUTH-01",
                        title="Administrative Route Missing Authorization Guard",
                        path=rel_str,
                        line=i,
                        severity="high",
                        message=f"Route '{route}' mounts administrative handler without auth middleware.",
                        remediation="Insert requireAdmin or authenticate middleware before the route handler function.",
                    )
                )

    return violations


def check_tenant_boundary(root: Path, file_path: Path, content: str) -> list[InvariantViolation]:
    violations: list[InvariantViolation] = []
    rel_str = str(file_path.relative_to(root)).replace("\\", "/")

    if ("repo" in rel_str.lower() or "model" in rel_str.lower()) and file_path.suffix == ".py":
        try:
            tree = ast.parse(content, filename=rel_str)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                    node.name.startswith("find_")
                    or node.name.startswith("get_")
                    or node.name.startswith("update_")
                ):
                    args = [a.arg for a in node.args.args if a.arg != "self" and a.arg != "cls"]
                    has_tenant = any(
                        "tenant" in a.lower() or "org" in a.lower() or "account" in a.lower()
                        for a in args
                    )
                    if args and not has_tenant and any("id" in a.lower() for a in args):
                        violations.append(
                            InvariantViolation(
                                invariant_id="INV-TENANT-01",
                                title="Tenant Repository Method Missing Tenant Scope",
                                path=rel_str,
                                line=node.lineno,
                                severity="high",
                                message=f"Repository method '{node.name}' queries by identifier without accepting tenant_id or account scope.",
                                remediation="Add tenant_id parameter and include WHERE tenant_id = :tenant_id in query filter.",
                            )
                        )
        except SyntaxError:
            pass

    return violations


def check_transaction_hygiene(
    root: Path, file_path: Path, content: str
) -> list[InvariantViolation]:
    violations: list[InvariantViolation] = []
    rel_str = str(file_path.relative_to(root)).replace("\\", "/")

    if file_path.suffix == ".py":
        try:
            tree = ast.parse(content, filename=rel_str)
            for node in ast.walk(tree):
                if isinstance(node, ast.With):
                    is_tx = any(
                        "transaction"
                        in (
                            ast.unparse(item.context_expr).lower()
                            if hasattr(ast, "unparse")
                            else ""
                        )
                        for item in node.items
                    )
                    if is_tx:
                        for child in ast.walk(node):
                            if isinstance(child, ast.Call):
                                call_repr = (
                                    ast.unparse(child.func).lower()
                                    if hasattr(ast, "unparse")
                                    else ""
                                )
                                if any(
                                    net in call_repr
                                    for net in (
                                        "requests.",
                                        "httpx.",
                                        "stripe.",
                                        "boto3.",
                                        "sendgrid",
                                    )
                                ):
                                    violations.append(
                                        InvariantViolation(
                                            invariant_id="INV-TX-01",
                                            title="External Network Operation Inside Database Transaction",
                                            path=rel_str,
                                            line=child.lineno,
                                            severity="high",
                                            message=f"Outbound network call '{call_repr}' executed inside active database transaction block.",
                                            remediation="Move external side-effects outside database transaction, or use Outbox pattern / two-phase commit.",
                                        )
                                    )
        except SyntaxError:
            pass

    return violations


def evaluate_invariants(root: Path, config_file: Path | None = None) -> list[InvariantViolation]:
    violations: list[InvariantViolation] = []

    for directory, subdirs, filenames in os.walk(root, topdown=True, onerror=lambda _: None):
        subdirs[:] = [d for d in subdirs if d not in SKIP_DIRS]
        for filename in filenames:
            path = Path(directory, filename)
            if path.is_symlink():
                continue
            if path.suffix not in {".py", ".ts", ".js", ".mjs", ".tsx", ".jsx"}:
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            violations.extend(check_auth_boundary(root, path, content))
            violations.extend(check_tenant_boundary(root, path, content))
            violations.extend(check_transaction_hygiene(root, path, content))

    return violations


def render_invariants_markdown(violations: list[InvariantViolation]) -> str:
    lines = [
        "# ShipProof Repository Invariant Verification",
        "",
        f"**Verdict:** {'PASS' if not violations else 'VIOLATION_DETECTED'}",
        f"Found `{len(violations)}` invariant violations across repository.",
        "",
    ]

    for v in violations:
        lines.append(f"### \u26a0\ufe0f {v.invariant_id}: {v.title}")
        lines.append(f"- **Location:** `{v.path}:{v.line}`")
        lines.append(f"- **Severity:** `{v.severity.upper()}` · Proof Level: `{v.proof_level}`")
        lines.append(f"- **Violation:** {v.message}")
        lines.append(f"- **Remediation:** {v.remediation}")
        lines.append("")

    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", type=Path, help="Repository root directory")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args(argv)

    violations = evaluate_invariants(args.root)

    if args.format == "json":
        payload = {
            "status": "PASS" if not violations else "FAIL",
            "total_violations": len(violations),
            "violations": [asdict(v) for v in violations],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(render_invariants_markdown(violations))

    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
