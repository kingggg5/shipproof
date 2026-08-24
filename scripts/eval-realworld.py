#!/usr/bin/env python3
"""Scan revision-pinned, license-reviewed open-source repositories.

Fetches each immutable commit from the reviewed manifest into a gitignored
scratch area, verifies revision and license-file presence, runs ShipProof, and
prints bounded observations. Finding counts remain unreviewed until a human
labels them; this tool does not manufacture precision claims.

Usage:
  python scripts/eval-realworld.py [--only express,flask] [--json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from scan_repo import scan_repository  # noqa: E402

MANIFEST = ROOT / "benchmarks" / "realworld-repositories.json"
NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
REVISION_PATTERN = re.compile(r"[0-9a-f]{40}")
CLASSIFICATIONS = {"clean_baseline", "intentionally_vulnerable"}
GIT_TIMEOUT_SECONDS = 180


def run_git(*arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    command = ["git", *arguments]
    environment = {}
    for key, value in os.environ.items():
        normalized_key = key.upper()
        if normalized_key.startswith("GIT_CONFIG_") or normalized_key == "GIT_TEMPLATE_DIR":
            continue
        environment[key] = value
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    try:
        return subprocess.run(  # noqa: S603
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            env=environment,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, 124, "", "git command timed out")


def _force_delete(func, path, _exc) -> None:
    """Clear the read-only attribute git sets on pack files before deleting
    (Windows denies unlinking them otherwise)."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except OSError:
        pass


def load_manifest(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError("real-world manifest schema_version must be 1")
    repositories = payload.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise ValueError("real-world manifest must contain repositories")
    names: set[str] = set()
    for item in repositories:
        if not isinstance(item, dict):
            raise ValueError("real-world repository entries must be objects")
        name = item.get("name")
        if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name) or name in names:
            raise ValueError(f"invalid or duplicate repository name: {name!r}")
        names.add(name)
        url = item.get("url")
        if not isinstance(url, str) or not re.fullmatch(
            r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git", url
        ):
            raise ValueError(f"{name}: URL must be a fixed HTTPS GitHub repository")
        if not isinstance(item.get("revision"), str) or not REVISION_PATTERN.fullmatch(
            item["revision"]
        ):
            raise ValueError(f"{name}: revision must be a full lowercase commit")
        if item.get("classification") not in CLASSIFICATIONS:
            raise ValueError(f"{name}: unsupported classification")
        for field in ("license_spdx", "license_path", "license_url"):
            if not isinstance(item.get(field), str) or not item[field]:
                raise ValueError(f"{name}: {field} is required")
        license_path = Path(item["license_path"])
        if license_path.is_absolute() or ".." in license_path.parts:
            raise ValueError(f"{name}: license_path must stay repository-relative")
        if not item["license_url"].startswith("https://github.com/"):
            raise ValueError(f"{name}: license_url must be an HTTPS GitHub permalink")
        repository_slug = url.removeprefix("https://github.com/").removesuffix(".git")
        license_prefix = f"https://github.com/{repository_slug}/blob/{item['revision']}/"
        if not item["license_url"].startswith(license_prefix):
            raise ValueError(
                f"{name}: license_url must pin the reviewed revision in the same repository"
            )
    return payload


def sha256_tree(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(
        (
            candidate
            for candidate in root.rglob("*")
            if candidate.is_symlink() or candidate.is_file()
        ),
        key=lambda candidate: candidate.relative_to(root).as_posix(),
    ):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"SYMLINK\0")
            digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
        else:
            digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def prepare(specification: dict[str, str], workspace: Path) -> Path:
    target = (workspace / specification["name"]).resolve()
    if target.parent != workspace.resolve():
        raise RuntimeError("refusing to prepare a repository outside the evaluation workspace")
    if target.exists():
        if sys.version_info >= (3, 12):
            shutil.rmtree(target, onexc=_force_delete)
        else:
            shutil.rmtree(target, onerror=_force_delete)
    # A fresh empty template prevents a stale workspace directory or symlink
    # from injecting Git hooks into the evaluation checkout.
    with tempfile.TemporaryDirectory(prefix=".empty-git-template-", dir=workspace) as template:
        initialized = run_git(
            "init", "--quiet", f"--template={template}", str(target), cwd=workspace
        )
    if initialized.returncode != 0:
        raise RuntimeError(f"{specification['name']}: git init failed")
    added = run_git(
        "-C", str(target), "remote", "add", "origin", specification["url"], cwd=workspace
    )
    if added.returncode != 0:
        raise RuntimeError(f"{specification['name']}: git remote setup failed")
    fetched = run_git(
        "-C",
        str(target),
        "fetch",
        "--depth",
        "1",
        "--filter=blob:none",
        "origin",
        specification["revision"],
        cwd=workspace,
    )
    if fetched.returncode != 0:
        raise RuntimeError(f"{specification['name']}: immutable revision fetch failed")
    checked_out = run_git(
        "-C", str(target), "checkout", "--quiet", "--detach", "FETCH_HEAD", cwd=workspace
    )
    if checked_out.returncode != 0:
        raise RuntimeError(f"{specification['name']}: immutable revision checkout failed")
    head = run_git("-C", str(target), "rev-parse", "HEAD", cwd=workspace)
    if head.returncode != 0 or head.stdout.strip() != specification["revision"]:
        raise RuntimeError(f"{specification['name']}: checked-out revision does not match manifest")
    license_file = (target / specification["license_path"]).resolve()
    try:
        license_file.relative_to(target)
    except ValueError as exc:
        raise RuntimeError(f"{specification['name']}: license file escaped checkout") from exc
    if not license_file.is_file():
        raise RuntimeError(f"{specification['name']}: reviewed license file is missing")
    return target


def evaluate(specification: dict[str, str], workspace: Path) -> dict[str, object]:
    target = prepare(specification, workspace)
    started = time.perf_counter()
    findings, stats = scan_repository(target)
    elapsed = round(time.perf_counter() - started, 2)
    by_rule: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    app_by_severity: dict[str, int] = {}
    for finding in findings:
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        if finding.scope == "app":
            # The gate verdict evaluates application code only; test-scope
            # findings are downranked noise for this measurement.
            app_by_severity[finding.severity] = app_by_severity.get(finding.severity, 0) + 1
    return {
        "repo": specification["name"],
        "status": "scanned",
        "revision": specification["revision"],
        "classification": specification["classification"],
        "license_spdx": specification["license_spdx"],
        "license_url": specification["license_url"],
        "license_file_sha256": hashlib.sha256(
            (target / specification["license_path"]).read_bytes()
        ).hexdigest(),
        "corpus_sha256": sha256_tree(target),
        "files": stats["files_scanned"],
        "seconds": elapsed,
        "findings": len(findings),
        "app_findings": sum(app_by_severity.values()),
        "by_severity": dict(sorted(by_severity.items())),
        "app_by_severity": dict(sorted(app_by_severity.items())),
        "by_rule": dict(sorted(by_rule.items(), key=lambda item: -item[1])),
        "finding_review_status": "unreviewed",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--only", help="comma-separated reviewed repository names")
    parser.add_argument("--json", action="store_true", help="print raw JSON")
    arguments = parser.parse_args()

    workspace = ROOT / "benchmarks" / ".work" / "oss-eval"
    workspace.mkdir(parents=True, exist_ok=True)

    try:
        manifest_path = arguments.manifest.resolve()
        manifest = load_manifest(manifest_path)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"real-world evaluation: invalid manifest: {exc}", file=sys.stderr)
        return 2
    targets = manifest["repositories"]
    if arguments.only is not None:
        requested = {value.strip() for value in arguments.only.split(",") if value.strip()}
        if not requested:
            print("real-world evaluation: --only must name a reviewed repository", file=sys.stderr)
            return 2
        known = {item["name"] for item in targets}
        unknown = sorted(requested - known)
        if unknown:
            print(f"real-world evaluation: unreviewed repository names: {unknown}", file=sys.stderr)
            return 2
        targets = [item for item in targets if item["name"] in requested]
    results = []
    unavailable = []
    for specification in targets:
        try:
            results.append(evaluate(specification, workspace))
        except (OSError, RuntimeError) as exc:
            unavailable.append(str(exc))
    payload = {
        "schema_version": "1.0",
        "tool": {"name": "ShipProof", "command": "eval-realworld"},
        "verdict": "INVALID_EVIDENCE" if unavailable else "PASS_WITH_EVIDENCE",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "limitations": [
            "Repository classifications do not label individual findings; manual review is required before precision claims.",
            "This opt-in maintainer workflow requires network access and is never part of the default scanner path.",
        ],
        "repos": results,
        "unavailable": unavailable,
    }
    if arguments.json:
        print(json.dumps(payload, indent=2))
        return 2 if unavailable else 0
    for result in results:
        if result["status"] != "scanned":
            continue
        print(
            f"{result['repo']:14} {result['files']:5} files {result['seconds']:6}s "
            f"findings={result['findings']:4} app={result['app_findings']:3} "
            f"app_by_severity={result['app_by_severity']}"
        )
        top = list(result["by_rule"].items())[:8]
        if top:
            print(f"{'':14} top rules: {', '.join(f'{rule}x{count}' for rule, count in top)}")
    for message in unavailable:
        print(f"UNAVAILABLE: {message}")
    return 2 if unavailable else 0


if __name__ == "__main__":
    sys.exit(main())
