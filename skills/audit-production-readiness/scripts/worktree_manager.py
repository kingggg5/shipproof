#!/usr/bin/env python3
"""Safe, offline Git worktree isolation manager for AI agent sandboxing."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

VERSION = "0.8.0"
VALID_TASK_NAME = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


@dataclass(frozen=True)
class WorktreeInfo:
    task_name: str
    path: str
    branch: str
    head_commit: str
    status: str


def run_git(args: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    """Execute git command without shell interpretation."""
    git_bin = shutil.which("git") or "git"
    try:
        proc = subprocess.run(  # noqa: S603
            [git_bin, *args],
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=False,
            check=False,
        )
        stdout = proc.stdout.decode("utf-8", errors="replace").strip() if proc.stdout else ""
        stderr = proc.stderr.decode("utf-8", errors="replace").strip() if proc.stderr else ""
        return proc.returncode, stdout, stderr
    except FileNotFoundError:
        return 2, "", "git executable not found in PATH"


def get_repo_root() -> Path:
    """Find repository root using git."""
    code, stdout, _ = run_git(["rev-parse", "--show-toplevel"])
    if code != 0 or not stdout:
        return Path.cwd()
    return Path(stdout).resolve()


def create_worktree(repo_root: Path, task_name: str) -> int:
    """Create an isolated worktree under .work/<task_name>."""
    if not VALID_TASK_NAME.match(task_name):
        sys.stderr.write(
            f"Error: invalid task name '{task_name}'. Use alphanumeric, '-' and '_'.\n"
        )
        return 2

    worktree_dir = repo_root / ".work" / task_name
    branch_name = f"shipproof/{task_name}"

    if worktree_dir.exists():
        sys.stderr.write(f"Error: worktree already exists at {worktree_dir}\n")
        return 2

    # Check if branch exists
    code, _, _ = run_git(["show-ref", "--verify", f"refs/heads/{branch_name}"], cwd=repo_root)
    branch_flag = ["-b", branch_name] if code != 0 else [branch_name]

    worktree_dir.parent.mkdir(parents=True, exist_ok=True)
    code, stdout, stderr = run_git(
        ["worktree", "add", str(worktree_dir), *branch_flag], cwd=repo_root
    )
    if code != 0:
        sys.stderr.write(f"Error creating worktree: {stderr or stdout}\n")
        return 1

    print("Created isolated AI sandbox worktree:")
    print(f"  Path:   {worktree_dir}")
    print(f"  Branch: {branch_name}")
    print(f"\nAI Agent can now safely iterate in: {worktree_dir}")
    print(f"Run `shipproof worktree check {task_name}` to verify before merging.")
    return 0


def list_worktrees(repo_root: Path, as_json: bool = False) -> int:
    """List all active ShipProof worktrees."""
    work_dir = repo_root / ".work"
    items: list[WorktreeInfo] = []

    if work_dir.is_dir():
        for entry in sorted(work_dir.iterdir()):
            if entry.is_dir() and (entry / ".git").exists():
                code, stdout, _ = run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=entry)
                branch = stdout if code == 0 else "unknown"
                code, stdout, _ = run_git(["rev-parse", "--short", "HEAD"], cwd=entry)
                commit = stdout if code == 0 else "unknown"
                items.append(
                    WorktreeInfo(
                        task_name=entry.name,
                        path=str(entry),
                        branch=branch,
                        head_commit=commit,
                        status="ACTIVE",
                    )
                )

    if as_json:
        print(json.dumps([asdict(item) for item in items], indent=2))
        return 0

    if not items:
        print("No active ShipProof worktrees in .work/")
        return 0

    print(f"Active ShipProof Worktrees ({len(items)}):")
    print("----------------------------------------------------------------------")
    for item in items:
        print(f"  [{item.task_name}]")
        print(f"    Branch: {item.branch} ({item.head_commit})")
        print(f"    Path:   {item.path}")
    print("----------------------------------------------------------------------")
    return 0


def check_worktree(repo_root: Path, task_name: str) -> int:
    """Run production readiness check inside worktree."""
    if not VALID_TASK_NAME.match(task_name):
        sys.stderr.write(f"Error: invalid task name '{task_name}'\n")
        return 2

    worktree_dir = repo_root / ".work" / task_name
    if not worktree_dir.exists():
        sys.stderr.write(f"Error: worktree not found at {worktree_dir}\n")
        return 2

    scanner_path = repo_root / "skills" / "audit-production-readiness" / "scripts" / "scan_repo.py"
    if not scanner_path.exists():
        sys.stderr.write("Error: scan_repo.py not found\n")
        return 2

    print(f"Verifying production gates in worktree: {task_name}...")
    proc = subprocess.run(  # noqa: S603
        [sys.executable, str(scanner_path), str(worktree_dir), "--fail-on", "high"],
        cwd=str(repo_root),
        check=False,
    )
    return proc.returncode


def merge_worktree(repo_root: Path, task_name: str) -> int:
    """Verify production gates, then merge task branch if clean."""
    if not VALID_TASK_NAME.match(task_name):
        sys.stderr.write(f"Error: invalid task name '{task_name}'\n")
        return 2

    worktree_dir = repo_root / ".work" / task_name
    if not worktree_dir.exists():
        sys.stderr.write(f"Error: worktree not found at {worktree_dir}\n")
        return 2

    # Verify gates first
    check_code = check_worktree(repo_root, task_name)
    if check_code != 0:
        sys.stderr.write("\n[GATE BLOCKED] Cannot merge: worktree has high/critical findings.\n")
        sys.stderr.write("Fix findings before merging.\n")
        return 1

    branch_name = f"shipproof/{task_name}"
    code, stdout, stderr = run_git(["merge", "--ff-only", branch_name], cwd=repo_root)
    if code != 0:
        # Fallback to standard merge
        code, stdout, stderr = run_git(["merge", branch_name], cwd=repo_root)
        if code != 0:
            sys.stderr.write(f"Error merging branch {branch_name}: {stderr or stdout}\n")
            return 1

    print(f"\n[PASS] Successfully verified and merged {branch_name} into current branch!")
    print(f"Run `shipproof worktree remove {task_name}` to clean up.")
    return 0


def remove_worktree(repo_root: Path, task_name: str, force: bool = False) -> int:
    """Clean up worktree and delete its branch."""
    if not VALID_TASK_NAME.match(task_name):
        sys.stderr.write(f"Error: invalid task name '{task_name}'\n")
        return 2

    worktree_dir = repo_root / ".work" / task_name
    branch_name = f"shipproof/{task_name}"

    if worktree_dir.exists():
        force_flag = ["--force"] if force else []
        code, stdout, stderr = run_git(
            ["worktree", "remove", str(worktree_dir), *force_flag], cwd=repo_root
        )
        if code != 0:
            sys.stderr.write(f"Error removing worktree: {stderr or stdout}\n")
            return 1

    # Delete branch
    del_flag = "-D" if force else "-d"
    run_git(["branch", del_flag, branch_name], cwd=repo_root)
    print(f"Removed worktree and branch for task '{task_name}'.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="ShipProof Git Worktree Isolation Sandbox for AI Agents"
    )
    subparsers = parser.add_subparsers(dest="action", help="Worktree action")

    create_p = subparsers.add_parser("create", help="Create a new isolated agent worktree")
    create_p.add_argument("task", help="Name of the task / sandbox (e.g. fix-auth)")

    list_p = subparsers.add_parser("list", help="List active agent worktrees")
    list_p.add_argument("--json", action="store_true", help="Output list in JSON format")

    check_p = subparsers.add_parser("check", help="Run production gate in worktree")
    check_p.add_argument("task", help="Name of the task / sandbox")

    merge_p = subparsers.add_parser(
        "merge", help="Verify and merge worktree back to current branch"
    )
    merge_p.add_argument("task", help="Name of the task / sandbox")

    remove_p = subparsers.add_parser("remove", help="Remove worktree and cleanup branch")
    remove_p.add_argument("task", help="Name of the task / sandbox")
    remove_p.add_argument(
        "-f", "--force", action="store_true", help="Force remove even if unmerged"
    )

    parser.add_argument("--json", action="store_true", help="Output list in JSON format")

    args = parser.parse_args(argv)

    if not args.action:
        parser.print_help()
        return 2

    repo_root = get_repo_root()

    if args.action == "create":
        return create_worktree(repo_root, args.task)
    elif args.action == "list":
        return list_worktrees(repo_root, as_json=args.json)
    elif args.action == "check":
        return check_worktree(repo_root, args.task)
    elif args.action == "merge":
        return merge_worktree(repo_root, args.task)
    elif args.action == "remove":
        return remove_worktree(repo_root, args.task, force=args.force)
    return 0


if __name__ == "__main__":
    sys.exit(main())
