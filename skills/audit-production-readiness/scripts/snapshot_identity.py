#!/usr/bin/env python3
"""Canonical snapshot + config identity for ShipProof evidence (Q01).

Offline, read-only, dependency-free. Versioned contract ``snapshot-identity/1.0``.

Target identity binds:
  relative posix path, file bytes digest, selected set, relevant dependency
  context, scanner/rules identity, and effective policy digest. It never
  includes absolute install paths. Secret-shaped config values are replaced
  with a placeholder before config hashing so credentials never affect
  identity and never leak through digests.

Workspace mode hashes the bytes actually read through TOCTOU-guarded reads.
Git mode additionally pins the resolved commit. Any byte change (including
same-size/same-mtime edits), deletion, rename/move, policy/rule change, or
foreign root invalidates reuse via digest mismatch.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat as stat_module
from pathlib import Path
from typing import Any

IDENTITY_VERSION = "1.0"
IDENTITY_SCHEME = "snapshot-identity/1.0"
SECRET_VALUE_RE = re.compile(r"(?i)(?:sk-|ghp_|github_pat_|xox[baprs]-|Bearer\s+)[A-Za-z0-9._\-]+")
SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|token|secret|api[_-]?key|authorization|cookie|private[_-]?key)"
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def scanner_code_identity() -> str:
    """Bind rule and analysis implementations, not just their count/version."""
    scripts = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for name in (
        "scan_repo.py",
        "impact_graph.py",
        "snapshot_identity.py",
        "taint_contracts.py",
        "archive_inspect.py",
        "dart_transport_checks.py",
        "dotnet_cookie_checks.py",
        "js_config_checks.py",
        "luau_quality_checks.py",
        "node_advisories.py",
        "php_advisories.py",
        "polyglot_checks.py",
        "precision.py",
        "python_runtime_checks.py",
        "sql_checks.py",
        "rule_explanations.py",
        "review_context.py",
        "review_packets.py",
    ):
        content = read_bytes_guarded(scripts / name, 2_000_000)
        digest.update(name.encode("utf-8") + b"\x00" + hashlib.sha256(content).digest())
    return digest.hexdigest()


def _redact_value(key: str, value: Any) -> Any:
    if isinstance(value, str):
        if SECRET_KEY_RE.search(key):
            return "[REDACTED]"
        return SECRET_VALUE_RE.sub("[REDACTED]", value)
    if isinstance(value, dict):
        return {str(k): _redact_value(str(k), v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_value(key, item) for item in value]
    return value


def sanitize_config_for_identity(config: dict[str, Any]) -> dict[str, Any]:
    """Return effective policy without secret credentials for identity hashing."""
    if not isinstance(config, dict):
        raise ValueError("config must be an object")
    return {str(key): _redact_value(str(key), value) for key, value in config.items()}


def config_digest_for(config: dict[str, Any]) -> str:
    sanitized = sanitize_config_for_identity(config)
    canonical = json.dumps(sanitized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(
        ("shipproof-config-identity\x00" + IDENTITY_VERSION + "\x00" + canonical).encode("utf-8")
    ).hexdigest()


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    if stat_module.S_ISLNK(metadata.st_mode):
        return True
    return bool(getattr(metadata, "st_file_attributes", 0) & 0x400)


class SourceSizeError(ValueError):
    """A guarded source exceeds its byte budget, including a concurrent growth."""


def read_bytes_guarded(path: Path, limit: int) -> bytes:
    """Read a regular file without following a final symlink; fail closed on change."""
    try:
        before = path.lstat()
        if not stat_module.S_ISREG(before.st_mode) or _is_link_or_reparse(before):
            raise ValueError(f"refused non-regular file: {path}")
        if before.st_size > limit:
            raise SourceSizeError(f"file exceeds byte limit: {path}")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat_module.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                raise ValueError(f"file changed during open: {path}")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                content = stream.read(limit + 1)
            after = os.fstat(descriptor)
            if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError(f"file changed during read: {path}")
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ValueError(f"unavailable file bytes: {path}") from exc
    if len(content) > limit:
        raise SourceSizeError(f"file exceeds byte limit: {path}")
    return content


def _is_within_root(candidate: Path, root: Path) -> bool:
    """Canonical-root containment with Windows case/alias tolerance.

    ``Path.resolve()`` follows symlinks/reparse points and expands 8.3 short
    names, so identity never depends on the spelling used to reach the file.
    On Windows the comparison is additionally case-insensitive because the
    filesystem is case-preserving but not case-sensitive.
    """
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        pass
    import sys as _sys

    if _sys.platform == "win32" or os.name == "nt":
        child = os.path.normcase(os.fspath(candidate))
        parent = os.path.normcase(os.fspath(root))
        return child == parent or child.startswith(parent.rstrip("\\/") + "\\")
    return False


def contains(root_resolved: Path, candidate_resolved: Path) -> bool:
    """Public canonical-root containment check over resolved paths."""
    return _is_within_root(candidate_resolved, root_resolved)


def resolve_root(root: Path) -> Path:
    candidate = Path(os.path.abspath(os.fspath(root)))
    resolved = candidate.resolve()
    if not resolved.is_dir():
        raise ValueError(f"not a directory: {root}")
    return resolved


def resolved_commit(root: Path) -> str | None:
    if not any((directory / ".git").exists() for directory in (root, *root.parents)):
        return None
    from scan_repo import _run_git_bounded

    status, output, _ = _run_git_bounded(
        root, ["rev-parse", "--verify", "HEAD"], timeout_seconds=10, max_output_bytes=4096
    )
    commit = output.strip()
    if status != 0 or not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise ValueError("snapshot Git identity is unavailable")
    return commit


def snapshot_identity(
    root: Path,
    *,
    files: list[Path] | None = None,
    max_file_bytes: int = 1_000_000,
    policy: dict[str, Any] | None = None,
    scanner_version: str = "unknown",
    rules_identity: str = "unknown",
    dependency_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute a stable identity for the exact bytes reviewed."""
    resolved = resolve_root(root)
    if type(max_file_bytes) is not int or max_file_bytes < 1:
        raise ValueError("max_file_bytes must be a positive integer")
    if files is None:
        candidates = []
        for directory, subdirs, filenames in os.walk(resolved, followlinks=False):
            subdirs[:] = sorted(name for name in subdirs if name not in {".git", ".hg", ".svn"})
            for name in subdirs:
                if _is_link_or_reparse((Path(directory) / name).lstat()):
                    raise ValueError("snapshot scope contains a linked directory")
            candidates.extend(Path(directory) / name for name in sorted(filenames))
            if len(candidates) > 5000:
                raise ValueError(
                    "snapshot exceeds 5000 files; supply an explicit bounded selection"
                )
    else:
        candidates = files
    if len(candidates) > 5000:
        raise ValueError("snapshot exceeds 5000 files")
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    for absolute in candidates:
        try:
            canonical = Path(absolute).resolve()
        except OSError as exc:
            raise ValueError(f"path escapes scan root: {absolute}") from exc
        if not _is_within_root(canonical, resolved):
            raise ValueError(f"path escapes scan root: {absolute}")
        try:
            relative = canonical.relative_to(resolved).as_posix()
        except ValueError as exc:
            fallback = os.path.relpath(os.fspath(canonical), os.fspath(resolved))
            if fallback == ".." or fallback.startswith(f"..{os.sep}"):
                raise ValueError(f"path escapes scan root: {absolute}") from exc
            relative = Path(fallback).as_posix()
        content = read_bytes_guarded(Path(absolute), max_file_bytes)
        total_bytes += len(content)
        if total_bytes > 64 * 1024 * 1024:
            raise ValueError("snapshot exceeds the 64 MiB input budget")
        entries.append(
            {
                "path": relative,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    entries.sort(key=lambda item: item["path"])
    selection = "\n".join(f"{e['path']}\x00{e['size']}\x00{e['sha256']}" for e in entries)
    selection_digest = hashlib.sha256(selection.encode("utf-8")).hexdigest()
    policy_digest = config_digest_for(policy or {})
    dep_canonical = json.dumps(
        sanitize_config_for_identity(dependency_context or {}),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    commit = resolved_commit(resolved)
    root_kind = "git" if commit else "workspace"
    framing = "\x00".join(
        [
            "shipproof-snapshot-identity",
            IDENTITY_VERSION,
            f"root-kind:{root_kind}",
            f"commit:{commit or ''}",
            f"scanner:{scanner_version}",
            f"rules:{rules_identity}",
            f"policy:{policy_digest}",
            f"selection:{selection_digest}",
            f"dependencies:{hashlib.sha256(dep_canonical.encode('utf-8')).hexdigest()}",
            selection,
        ]
    )
    target_digest = hashlib.sha256(framing.encode("utf-8")).hexdigest()
    return {
        "identity_version": IDENTITY_SCHEME,
        "root_kind": root_kind,
        "commit": commit,
        "scanner_version": scanner_version,
        "rules_identity": rules_identity,
        "policy_digest": policy_digest,
        "config_digest": policy_digest,
        "selection_digest": selection_digest,
        "target_digest": target_digest,
        "files": entries,
        "file_count": len(entries),
    }


def check_digest(value: str | None, *, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise ValueError(f"{field} must be 64-character lowercase hex")
    return value
