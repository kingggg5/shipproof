"""Offline replay of a pinned language-source projection; never fetch or build projects."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
from collections import Counter
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
MAX_FILES = 2500
MAX_BYTES = 25_000_000


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def relative_name(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or ".." in path.parts
        or "\\" in value
        or ":" in value
        or "\x00" in value
    ):
        raise ValueError("unsafe manifest path")
    return value


def read_regular(path: Path) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("nonregular or reparse-point source")
    if info.st_size > MAX_BYTES:
        raise ValueError("file exceeds projection byte budget")
    with path.open("rb") as stream:
        content = stream.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise ValueError("file grew beyond projection budget")
    return content


def verify_projection(root: Path, spec: dict) -> frozenset[str]:
    """Match all language bytes and context files before allowing a scanner read."""
    extensions = set(spec["source_extensions"])
    if not extensions or not extensions <= {
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".mts",
        ".cts",
        ".cs",
        ".dart",
        ".lua",
        ".luau",
        ".py",
        ".sql",
    }:
        raise ValueError("unsupported language projection")
    if (
        not root.is_dir()
        or root.is_symlink()
        or getattr(root.lstat(), "st_file_attributes", 0) & 0x400
    ):
        raise ValueError("source root missing or linked")
    files = {}
    total = 0
    visited = 0
    for directory, subdirectories, names in os.walk(root, followlinks=False):
        visited += len(names) + len(subdirectories)
        if visited > 10000:
            raise ValueError("projection walk budget exceeded")
        subdirectories[:] = sorted(name for name in subdirectories if name != ".git")
        for name in subdirectories:
            child = Path(directory, name)
            info = child.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("linked directory in projection")
        for name in names:
            path = Path(directory, name)
            if path.suffix.lower() not in extensions:
                continue
            if len(files) >= MAX_FILES:
                raise ValueError("projection file budget exceeded")
            content = read_regular(path)
            total += len(content)
            if total > MAX_BYTES:
                raise ValueError("projection byte budget exceeded")
            files[path.relative_to(root).as_posix()] = digest(content)
    tree = digest(
        "".join(f"{path}\0{value}\n" for path, value in sorted(files.items())).encode("utf-8")
    )
    if len(files) != spec["expected_source_files"] or tree != spec["source_tree_sha256"]:
        raise ValueError("language projection differs from the pinned source inventory")
    context = spec.get("context_files")
    if not isinstance(context, dict) or not 1 <= len(context) <= 128:
        raise ValueError("pinned framework/context hashes are required")
    for relative, expected in context.items():
        path = root / relative_name(relative)
        for parent in path.parents:
            if parent == root:
                break
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("linked context parent")
        content = read_regular(path)
        total += len(content)
        if total > MAX_BYTES:
            raise ValueError("source/context byte budget exceeded")
        if digest(content) != expected:
            raise ValueError("framework/context file differs from pinned bytes")
    if context.get(spec["license_path"]) != spec["license_sha256"]:
        raise ValueError("license identity mismatch")
    return frozenset(files)


def load_scanner(directory: Path):
    # This is the caller's trusted scanner code, never a module from an evaluated project.
    sys.path.insert(0, str(directory))
    spec = importlib.util.spec_from_file_location("scan_repo", directory / "scan_repo.py")
    if spec is None or spec.loader is None:
        raise ValueError("scanner code unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workspace",
        type=Path,
        required=True,
        help="Prepared source snapshots; no automatic download",
    )
    parser.add_argument(
        "--manifest", type=Path, default=ROOT / "benchmarks/field-cohort-repositories.json"
    )
    parser.add_argument(
        "--scanner-dir",
        type=Path,
        default=ROOT / "skills/audit-production-readiness/scripts",
        help="Trusted scanner code, not a target project",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New report path; existing reports are never overwritten",
    )
    args = parser.parse_args()
    try:
        if args.output.exists() or args.output.is_symlink():
            raise ValueError("output already exists; preserve observations and choose a new path")
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        if manifest["schema_version"] != 1 or not 1 <= len(manifest["projects"]) <= 20:
            raise ValueError("invalid cohort manifest")
        scanner = load_scanner(args.scanner_dir.resolve())
        results = []
        complete = True
        finding_count = 0
        seen = set()
        for project in manifest["projects"]:
            if (
                not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", project["slug"])
                or project["slug"] in seen
            ):
                raise ValueError("invalid project slug")
            seen.add(project["slug"])
            if (
                not re.fullmatch(r"[a-f0-9]{40}", project["revision"])
                or type(project["expected_source_files"]) is not int
                or not 1 <= project["expected_source_files"] <= MAX_FILES
            ):
                raise ValueError("invalid source identity/count")
            root = args.workspace.resolve() / project["slug"]
            selection = verify_projection(root, project)
            findings, stats = scanner.scan_repository(root, include_paths=selection, jobs=1)
            finding_count += len(findings)
            if finding_count > 10000:
                raise ValueError("cohort observation budget exceeded")
            if verify_projection(root, project) != selection:
                raise ValueError("projection changed during scanning")
            report = scanner.build_json_report(root, findings, stats)
            report.update(
                repository=project["repository"],
                declared_revision=project["revision"],
                source_tree_sha256=project["source_tree_sha256"],
                selected_source_files=len(selection),
            )
            results.append(report)
            if stats["files_scanned"] != len(selection) or not stats["completeness"]["is_complete"]:
                complete = False
        scanner_sources = sorted(args.scanner_dir.glob("*.py"))
        payload = {
            "schema_version": 1,
            "verdict": "PASS_WITH_EVIDENCE" if complete else "INCOMPLETE",
            "manifest_sha256": digest(args.manifest.read_bytes()),
            "scanner_sources_sha256": digest(
                "".join(
                    f"{path.name}\0{digest(path.read_bytes())}\n" for path in scanner_sources
                ).encode("utf-8")
            ),
            "limitations": [
                "Read-only compatibility observations, not independent precision/recall or a clean-repository assertion.",
                "Only declared language source and pinned framework context are verified; applications are not built or executed.",
            ],
            "projects": results,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        rendered = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
        if len(rendered.encode("utf-8")) > 32_000_000:
            raise ValueError("cohort report byte budget exceeded")
        with args.output.open("x", encoding="utf-8") as output:
            output.write(rendered)
        print(
            json.dumps(
                {
                    "projects": len(results),
                    "files": sum(row["selected_source_files"] for row in results),
                    "rules": dict(
                        sorted(
                            Counter(
                                f["rule_id"] for row in results for f in row["findings"]
                            ).items()
                        )
                    ),
                    "complete": complete,
                }
            )
        )
        return 0 if complete else 2
    except (OSError, ValueError, KeyError, TypeError, ImportError) as exc:
        print(f"field evaluation unavailable: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
