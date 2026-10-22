#!/usr/bin/env python3
"""Install pinned clean-corpus packages and scan them with default ShipProof.

This is an opt-in maintainer workflow. It needs network access for pip and npm,
installs into a gitignored workspace, and never becomes part of the default
scanner path. Install or digest failures exit 2 instead of reporting a quiet pass.

Usage:
  python scripts/eval-clean-corpus.py [--only flask,ajv] [--json] [--labels]
  python scripts/eval-clean-corpus.py --pin-digests --write-baseline benchmarks/clean-corpus-baseline.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import venv
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from finding_labels import (  # noqa: E402
    fp_budget_violations,
    index_labels,
    load_label_records,
    score_findings,
)
from paired_corpus import canonical_sha, load_plan, remediate_copy, validate_report  # noqa: E402
from scan_repo import (  # noqa: E402
    TEXT_SUFFIXES,
    VERSION,
    determine_verdict,
    scan_repository,
)

MANIFEST = ROOT / "benchmarks" / "clean-corpus.json"
LABEL_DIR = ROOT / "benchmarks" / "labels"
NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
VERSION_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")
SPDX_PATTERN = re.compile(r"^[A-Za-z0-9.+-]{3,64}$")
INSTALL_TIMEOUT_SECONDS = 180
TOOLCHAIN_TIMEOUT_SECONDS = 300
MAX_FINDING_RECORDS = 500
LICENSE_FILENAMES = (
    "LICENSE",
    "LICENSE.txt",
    "LICENSE.md",
    "LICENSE.rst",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "COPYING",
    "COPYING.txt",
    "COPYING.rst",
    "LICENCE",
    "LICENCE.txt",
)
GO_MODULE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
RUST_CRATE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
ECOSYSTEMS = frozenset({"python", "javascript", "go", "rust"})


def run_command(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = INSTALL_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(  # noqa: S603
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            env=env,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, 124, "", "command timed out")


def load_manifest(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError("clean-corpus manifest schema_version must be 1")
    packages = payload.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ValueError("clean-corpus manifest must contain packages")
    names: set[str] = set()
    for item in packages:
        if not isinstance(item, dict):
            raise ValueError("clean-corpus package entries must be objects")
        name = item.get("name")
        if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name) or name in names:
            raise ValueError(f"invalid or duplicate package name: {name!r}")
        names.add(name)
        if item.get("ecosystem") not in ECOSYSTEMS:
            raise ValueError(f"{name}: ecosystem must be python, javascript, go, or rust")
        version = item.get("version")
        if (
            not isinstance(version, str)
            or not VERSION_PATTERN.fullmatch(version)
            or version.lower() in {"latest", "*"}
        ):
            raise ValueError(f"{name}: version must be an exact pin")
        license_spdx = item.get("license_spdx")
        if not isinstance(license_spdx, str) or not SPDX_PATTERN.fullmatch(license_spdx):
            raise ValueError(f"{name}: license_spdx is required")
        digest = item.get("source_sha256")
        if digest is not None and (
            not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise ValueError(f"{name}: source_sha256 must be a 64-character lowercase digest")
        ecosystem = item["ecosystem"]
        if ecosystem == "python":
            for field in ("pypi", "import_name"):
                value = item.get(field)
                if not isinstance(value, str) or not value or "/" in value or "\\" in value:
                    raise ValueError(f"{name}: {field} must be a bare package name")
        elif ecosystem == "javascript":
            npm_name = item.get("npm")
            if not isinstance(npm_name, str) or not npm_name or npm_name.startswith("."):
                raise ValueError(f"{name}: npm package name is required")
        elif ecosystem == "go":
            module = item.get("module")
            if (
                not isinstance(module, str)
                or not GO_MODULE_PATTERN.fullmatch(module)
                or ".." in module
            ):
                raise ValueError(f"{name}: module must be a Go module path")
        else:
            crate = item.get("crate")
            if not isinstance(crate, str) or not RUST_CRATE_PATTERN.fullmatch(crate):
                raise ValueError(f"{name}: crate must be a crates.io name")
    return payload


def scannable_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root)
        if any(
            part in {".git", "__pycache__", "node_modules", "target", ".cargo"}
            for part in relative.parts
        ):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name.lower() not in {
            "dockerfile",
            "containerfile",
            "makefile",
        }:
            continue
        files.append(path)
    files.sort(key=lambda item: item.relative_to(root).as_posix())
    return files


def sha256_scannable(root: Path) -> str:
    digest = hashlib.sha256()
    for path in scannable_files(root):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def isolated_env(base: dict[str, str] | None = None) -> dict[str, str]:
    environment = dict(base or os.environ)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    environment["NPM_CONFIG_IGNORE_SCRIPTS"] = "true"
    environment["NPM_CONFIG_AUDIT"] = "false"
    environment["NPM_CONFIG_FUND"] = "false"
    environment.pop("PYTHONPATH", None)
    return environment


def python_executable(venv_root: Path) -> Path:
    if os.name == "nt":
        return venv_root / "Scripts" / "python.exe"
    return venv_root / "bin" / "python"


def is_inside(path: Path, root: Path) -> bool:
    try:
        resolved = path.resolve()
        base = root.resolve()
        resolved.relative_to(base)
        return True
    except (OSError, ValueError):
        try:
            path_text = os.path.normcase(os.path.normpath(str(path.resolve())))
            root_text = os.path.normcase(os.path.normpath(str(root.resolve())))
        except (OSError, ValueError):
            return False
        return path_text == root_text or path_text.startswith(root_text + os.sep)


def venv_package_root(venv_root: Path, executable: Path, import_name: str) -> Path:
    locator = run_command(
        [
            str(executable),
            "-c",
            (
                "import importlib.util, json, pathlib, site, sys; "
                f"name = {import_name!r}; "
                "spec = importlib.util.find_spec(name); "
                "origin = str(pathlib.Path(spec.origin).resolve()) if spec and spec.origin else ''; "
                "sites = [str(pathlib.Path(item).resolve()) for item in site.getsitepackages()]; "
                "print(json.dumps({'origin': origin, 'prefix': str(pathlib.Path(sys.prefix).resolve()), 'sites': sites}))"
            ),
        ],
        cwd=venv_root,
        env=isolated_env(),
    )
    if locator.returncode != 0 or not locator.stdout.strip():
        raise RuntimeError(f"{import_name}: installed module was not importable")
    try:
        payload = json.loads(locator.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{import_name}: could not locate the installed package") from exc
    venv = venv_root.resolve()
    for site_dir in payload.get("sites") or []:
        site_path = Path(site_dir)
        if not is_inside(site_path, venv):
            continue
        package_dir = site_path / import_name
        if package_dir.is_dir():
            return package_dir
        module_file = site_path / f"{import_name}.py"
        if module_file.is_file():
            return module_file.parent
    origin = Path(payload.get("origin") or "")
    if origin.is_file() and is_inside(origin, venv):
        return origin.parent
    raise RuntimeError(f"{import_name}: installed files escaped the virtualenv")


def install_python_package(specification: dict[str, str], workspace: Path) -> Path:
    target = (workspace / specification["name"]).resolve()
    if target.parent != workspace.resolve():
        raise RuntimeError("refusing to prepare a package outside the evaluation workspace")
    if target.exists():
        shutil.rmtree(target)
    venv.create(target, with_pip=True, symlinks=(os.name != "nt"))
    executable = python_executable(target)
    requirement = f"{specification['pypi']}=={specification['version']}"
    installed = run_command(
        [
            str(executable),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-compile",
            "--no-input",
            requirement,
        ],
        cwd=target,
        env=isolated_env(),
    )
    if installed.returncode != 0:
        raise RuntimeError(
            f"{specification['name']}: pip install failed: "
            f"{installed.stderr.strip() or installed.stdout.strip()}"
        )
    package_root = venv_package_root(target, executable, specification["import_name"])
    if not is_inside(package_root, target):
        raise RuntimeError(f"{specification['name']}: installed files escaped the virtualenv")
    return package_root


def install_javascript_package(specification: dict[str, str], workspace: Path) -> Path:
    target = (workspace / specification["name"]).resolve()
    if target.parent != workspace.resolve():
        raise RuntimeError("refusing to prepare a package outside the evaluation workspace")
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    package_json = {
        "name": f"shipproof-clean-{specification['name']}",
        "private": True,
        "dependencies": {specification["npm"]: specification["version"]},
    }
    (target / "package.json").write_text(
        json.dumps(package_json, indent=2) + "\n", encoding="utf-8"
    )
    npm = shutil.which("npm")
    if npm is None:
        raise RuntimeError(f"{specification['name']}: npm is not installed")
    installed = run_command(
        [npm, "install", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=false"],
        cwd=target,
        env=isolated_env(),
    )
    if installed.returncode != 0:
        raise RuntimeError(
            f"{specification['name']}: npm install failed: {installed.stderr.strip() or installed.stdout.strip()}"
        )
    package_root = (target / "node_modules" / specification["npm"]).resolve()
    if not is_inside(package_root, target):
        raise RuntimeError(f"{specification['name']}: installed files escaped the workspace")
    if not package_root.is_dir():
        raise RuntimeError(f"{specification['name']}: npm package directory is missing")
    return package_root


def install_go_package(specification: dict[str, str], workspace: Path) -> Path:
    target = (workspace / specification["name"]).resolve()
    if target.parent != workspace.resolve():
        raise RuntimeError("refusing to prepare a package outside the evaluation workspace")
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    go = shutil.which("go")
    if go is None:
        raise RuntimeError(f"{specification['name']}: go toolchain is not installed")
    module_cache = target / "modcache"
    environment = isolated_env()
    environment["GOMODCACHE"] = str(module_cache)
    environment["GOFLAGS"] = "-mod=mod"
    environment["GOTOOLCHAIN"] = "local"
    version = specification["version"]
    query = f"{specification['module']}@{version}"
    downloaded = run_command(
        [go, "mod", "download", "-json", query],
        cwd=target,
        env=environment,
        timeout=TOOLCHAIN_TIMEOUT_SECONDS,
    )
    if downloaded.returncode != 0 or not downloaded.stdout.strip():
        raise RuntimeError(
            f"{specification['name']}: go mod download failed: "
            f"{downloaded.stderr.strip() or downloaded.stdout.strip()}"
        )
    try:
        payload = json.loads(downloaded.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"{specification['name']}: go mod download returned invalid JSON"
        ) from exc
    if payload.get("Error"):
        raise RuntimeError(f"{specification['name']}: {payload['Error']}")
    directory = Path(str(payload.get("Dir") or ""))
    if not directory.is_dir() or not is_inside(directory, module_cache):
        raise RuntimeError(f"{specification['name']}: downloaded module escaped the workspace")
    return directory


def install_rust_package(specification: dict[str, str], workspace: Path) -> Path:
    target = (workspace / specification["name"]).resolve()
    if target.parent != workspace.resolve():
        raise RuntimeError("refusing to prepare a package outside the evaluation workspace")
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    cargo = shutil.which("cargo")
    if cargo is None:
        raise RuntimeError(f"{specification['name']}: cargo toolchain is not installed")
    crate_workspace = target / "crate-ws"
    crate_workspace.mkdir()
    (crate_workspace / "src").mkdir()
    (crate_workspace / "src" / "lib.rs").write_text("\n", encoding="utf-8")
    crate = specification["crate"]
    version = specification["version"]
    (crate_workspace / "Cargo.toml").write_text(
        "[package]\n"
        f'name = "shipproof-clean-{specification["name"]}"\n'
        'version = "0.0.0"\n'
        'edition = "2021"\n'
        "\n"
        "[dependencies]\n"
        f'{crate} = "={version}"\n',
        encoding="utf-8",
    )
    cargo_home = target / "cargo-home"
    environment = isolated_env()
    environment["CARGO_HOME"] = str(cargo_home)
    fetched = run_command(
        [cargo, "fetch"],
        cwd=crate_workspace,
        env=environment,
        timeout=TOOLCHAIN_TIMEOUT_SECONDS,
    )
    if fetched.returncode != 0:
        raise RuntimeError(
            f"{specification['name']}: cargo fetch failed: "
            f"{fetched.stderr.strip() or fetched.stdout.strip()}"
        )
    registry = cargo_home / "registry" / "src"
    matches = sorted(registry.glob(f"*/{crate}-{version}"))
    if len(matches) != 1 or not matches[0].is_dir() or not is_inside(matches[0], cargo_home):
        raise RuntimeError(f"{specification['name']}: fetched crate directory is missing")
    return matches[0]


def _metadata_distribution_name(metadata_text: str) -> str | None:
    for line in metadata_text.splitlines():
        if line.lower().startswith("name:"):
            value = line.split(":", 1)[1].strip().replace("_", "-").casefold()
            return value or None
    return None


def _dist_info_matches_package(dist_info: Path, package_name: str) -> bool:
    dist_name = dist_info.name[: -len(".dist-info")].rsplit("-", 1)[0]
    if dist_name.replace("_", "-").casefold() == package_name:
        return True
    metadata = dist_info / "METADATA"
    if not metadata.is_file():
        return False
    declared = _metadata_distribution_name(metadata.read_text(encoding="utf-8", errors="replace"))
    return declared == package_name


def _license_in_dist_info(dist_info: Path) -> bool:
    for name in LICENSE_FILENAMES:
        if (dist_info / name).is_file():
            return True
        if (dist_info / "licenses" / name).is_file():
            return True
    for folder in (dist_info, dist_info / "licenses"):
        if not folder.is_dir():
            continue
        try:
            for path in folder.iterdir():
                if path.is_file() and path.name.upper().startswith("LICENSE"):
                    return True
        except OSError:
            continue
    metadata = dist_info / "METADATA"
    if not metadata.is_file():
        return False
    text = metadata.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if lower.startswith(("license:", "license-expression:")):
            return True
        if lower.startswith("classifier:") and "license ::" in lower:
            return True
        if lower.startswith("license-file:") and stripped.split(":", 1)[1].strip():
            return True
    return False


def license_present(package_root: Path) -> bool:
    for name in LICENSE_FILENAMES:
        if (package_root / name).is_file():
            return True
    try:
        for path in package_root.iterdir():
            if path.is_file() and path.name.upper().startswith(("LICENSE", "COPYING", "LICENCE")):
                return True
    except OSError:
        pass
    package_name = package_root.name.replace("_", "-").casefold()
    parent = package_root.parent
    try:
        siblings = list(parent.iterdir())
    except OSError:
        siblings = []
    for entry in siblings:
        if not entry.is_dir() or not entry.name.endswith(".dist-info"):
            continue
        if _dist_info_matches_package(entry, package_name) and _license_in_dist_info(entry):
            return True
    package_json = package_root / "package.json"
    if package_json.is_file():
        try:
            payload = json.loads(package_json.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return False
        license_field = payload.get("license")
        if isinstance(license_field, str) and license_field.strip():
            return True
    return False


def finding_record(finding: object) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "proof_level": finding.proof_level,
        "scope": finding.scope,
        "path": finding.path,
        "line": finding.line,
        "fingerprint": finding.fingerprint,
        "detection": finding.detection,
        "tier": getattr(finding, "tier", "gate"),
        "match_confidence": getattr(finding, "match_confidence", finding.confidence),
    }


def evaluate(
    specification: dict[str, str], workspace: Path, *, remediation: dict[str, Any] | None = None
) -> dict[str, object]:
    ecosystem = specification["ecosystem"]
    if ecosystem == "python":
        package_root = install_python_package(specification, workspace)
    elif ecosystem == "javascript":
        package_root = install_javascript_package(specification, workspace)
    elif ecosystem == "go":
        package_root = install_go_package(specification, workspace)
    else:
        package_root = install_rust_package(specification, workspace)
    original = scan_package(specification, package_root)
    if remediation is not None:
        try:
            quiet, receipt = remediate_copy(
                specification,
                package_root,
                workspace,
                original,
                remediation,
                scan_package,
                sha256_scannable,
            )
            original["_quiet"] = quiet
            original["_receipt"] = receipt
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
            # A lost positive or rejected recipe must leave the original raw
            # evidence in the uploaded failure report, not drop that package.
            original["_pair_error"] = str(exc)
    return original


def scan_package(
    specification: dict[str, str], package_root: Path, *, verify_source: bool = True
) -> dict[str, object]:
    if verify_source and not license_present(package_root):
        raise RuntimeError(f"{specification['name']}: reviewed license file is missing")
    digest = sha256_scannable(package_root)
    expected = specification.get("source_sha256")
    if verify_source and isinstance(expected, str) and expected and expected != digest:
        raise RuntimeError(
            f"{specification['name']}: source digest {digest} does not match manifest {expected}"
        )
    started = time.perf_counter()
    findings, stats = scan_repository(package_root)
    # This benchmark binds scannable source, not opaque wheel metadata such as
    # py.typed. Retain the full default ledger, and reject every source omission.
    if any(
        stats.get("completeness", {}).get(key)
        for key in (
            "unreadable",
            "parser_limit",
            "line_limit",
            "oversized",
            "symlinks",
            "containers",
        )
    ):
        raise RuntimeError(
            f"{specification['name']}: incomplete scan coverage {stats.get('completeness')}"
        )
    elapsed = round(time.perf_counter() - started, 2)
    app_findings = [item for item in findings if item.scope == "app"]
    by_rule: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_confidence: dict[str, int] = {}
    for finding in app_findings:
        by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_confidence[finding.confidence] = by_confidence.get(finding.confidence, 0) + 1
    if len(app_findings) > MAX_FINDING_RECORDS:
        raise RuntimeError(f"{specification['name']}: finding record limit exceeded")
    records = [finding_record(item) for item in app_findings]
    return {
        "package": specification["name"],
        "status": "scanned",
        "ecosystem": specification["ecosystem"],
        "version": specification["version"],
        "license_spdx": specification["license_spdx"],
        "source_sha256": digest,
        "files": stats["files_scanned"],
        "seconds": elapsed,
        "findings": len(findings),
        "app_findings": len(app_findings),
        "by_severity": dict(sorted(by_severity.items())),
        "by_confidence": dict(sorted(by_confidence.items())),
        "by_rule": dict(sorted(by_rule.items(), key=lambda item: -item[1])),
        "verdict": determine_verdict(findings, completeness=stats.get("completeness")),
        "scan_profile": stats.get("scan_profile"),
        "completeness": stats.get("completeness"),
        "finding_review_status": "unreviewed",
        "app_finding_records": records,
    }


def pin_digests(manifest_path: Path, results: list[dict[str, object]]) -> None:
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    digests = {
        item["package"]: item["source_sha256"]
        for item in results
        if item.get("status") == "scanned"
    }
    for package in payload["packages"]:
        digest = digests.get(package["name"])
        if digest:
            package["source_sha256"] = digest
    manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def summarize(results: list[dict[str, object]]) -> dict[str, object]:
    blocked = [item["package"] for item in results if item.get("verdict") == "BLOCK"]
    app_findings = sum(int(item.get("app_findings") or 0) for item in results)
    files = sum(int(item.get("files") or 0) for item in results)
    return {
        "packages": len(results),
        "files": files,
        "app_findings": app_findings,
        "blocked_packages": blocked,
        "blocked_count": len(blocked),
    }


def apply_labels(results: list[dict[str, object]], label_dir: Path) -> dict[str, object]:
    records = load_label_records(label_dir)
    labels = index_labels(records)
    combined_findings: list[dict[str, Any]] = []
    scored_packages = []
    for item in results:
        package_score = score_findings(
            list(item.get("app_finding_records") or []),
            labels,
            corpus="clean-corpus",
            package=str(item["package"]),
            revision=str(item["version"]),
        )
        item["labels"] = package_score
        if package_score["unreviewed"] == 0:
            item["finding_review_status"] = "reviewed"
        combined_findings.extend(item.get("app_finding_records") or [])
        scored_packages.append(package_score)
    by_rule: dict[str, dict[str, int]] = {}
    for package_score in scored_packages:
        for rule_id, stats in package_score["by_rule"].items():
            current = by_rule.setdefault(
                rule_id,
                {
                    "true_positive": 0,
                    "false_positive": 0,
                    "needs_context": 0,
                    "duplicate": 0,
                    "reviewed": 0,
                },
            )
            for key in current:
                current[key] += int(stats[key])
    merged = {
        rule_id: {
            **stats,
            "precision": (
                stats["true_positive"] / stats["reviewed"] if stats["reviewed"] else None
            ),
        }
        for rule_id, stats in by_rule.items()
    }
    high_critical_ids = {
        str(finding.get("rule_id"))
        for finding in combined_findings
        if finding.get("severity") in {"high", "critical"}
    }
    unreviewed_high_critical = 0
    for item in results:
        package = str(item["package"])
        revision = str(item["version"])
        for finding in item.get("app_finding_records") or []:
            if finding.get("severity") not in {"high", "critical"}:
                continue
            key = (
                "clean-corpus",
                package,
                revision,
                str(finding.get("fingerprint") or ""),
            )
            if key not in labels:
                unreviewed_high_critical += 1
    return {
        "records": len(records),
        "by_rule": merged,
        "fp_budget_violations": fp_budget_violations(
            merged, high_critical_rule_ids=high_critical_ids
        ),
        "unreviewed": sum(int(item["labels"]["unreviewed"]) for item in results),
        "unreviewed_high_critical": unreviewed_high_critical,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--only", help="comma-separated package names")
    parser.add_argument("--json", action="store_true", help="print raw JSON")
    parser.add_argument("--labels", action="store_true", help="score reviewed JSONL labels")
    parser.add_argument(
        "--paired",
        action="store_true",
        help="retain original positive findings and evaluate reviewed remediated copies against unchanged quiet thresholds",
    )
    parser.add_argument(
        "--require-digests",
        action="store_true",
        help="fail when a package has no pinned source_sha256",
    )
    parser.add_argument(
        "--pin-digests",
        action="store_true",
        help="write computed source digests back into the manifest",
    )
    parser.add_argument("--write-baseline", type=Path, help="write the result JSON to this path")
    parser.add_argument(
        "--workspace", type=Path, default=ROOT / "benchmarks" / ".work" / "clean-corpus"
    )
    arguments = parser.parse_args()

    try:
        manifest_path = arguments.manifest.resolve()
        manifest = load_manifest(manifest_path)
        if arguments.paired and (arguments.only is not None or arguments.pin_digests):
            raise ValueError(
                "--paired requires the complete original pinned corpus; --only/--pin-digests are not allowed"
            )
        plan = load_plan(manifest=manifest) if arguments.paired else None
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(f"clean-corpus evaluation: invalid manifest: {exc}", file=sys.stderr)
        return 2

    targets = list(manifest["packages"])
    if arguments.only is not None:
        requested = {value.strip() for value in arguments.only.split(",") if value.strip()}
        if not requested:
            print("clean-corpus evaluation: --only must name a package", file=sys.stderr)
            return 2
        known = {item["name"] for item in targets}
        unknown = sorted(requested - known)
        if unknown:
            print(f"clean-corpus evaluation: unknown package names: {unknown}", file=sys.stderr)
            return 2
        targets = [item for item in targets if item["name"] in requested]
    if arguments.require_digests:
        missing = [item["name"] for item in targets if not item.get("source_sha256")]
        if missing:
            print(
                f"clean-corpus evaluation: source_sha256 missing for {missing}",
                file=sys.stderr,
            )
            return 2

    workspace = arguments.workspace
    workspace.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, object]] = []
    quiet_results: list[dict[str, object]] = []
    receipts: list[dict[str, object]] = []
    unavailable: list[str] = []
    for specification in targets:
        try:
            if plan is None:
                results.append(evaluate(specification, workspace))
            else:
                entry = next(
                    item for item in plan["packages"] if item["package"] == specification["name"]
                )
                original = evaluate(specification, workspace, remediation=entry)
                pair_error = original.pop("_pair_error", None)
                if pair_error is not None:
                    unavailable.append(f"{specification['name']}: {pair_error}")
                else:
                    quiet_results.append(original.pop("_quiet"))
                    receipts.append(original.pop("_receipt"))
                results.append(original)
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
            unavailable.append(str(exc))

    payload = {
        "schema_version": "2.0" if plan is not None else "1.0",
        "tool": {"name": "ShipProof", "version": VERSION, "command": "eval-clean-corpus"},
        "verdict": "INVALID_EVIDENCE" if unavailable else "PASS_WITH_EVIDENCE",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "manifest_canonical_sha256": canonical_sha(manifest),
        "limitations": [
            "Installed packages are not a vulnerability-free guarantee; findings stay unreviewed until labeled.",
            "Digests cover scannable source files only so compiled wheels do not make the fingerprint platform-specific.",
            "This opt-in maintainer workflow requires network access and is never part of the default scanner path.",
            "The default completeness ledger includes opaque non-source metadata; source omissions invalidate this benchmark. A quiet benchmark leg is not a complete application security verdict.",
        ],
        "summary": summarize(results),
        "packages": results,
        "unavailable": unavailable,
    }
    if arguments.labels:
        try:
            payload["label_report"] = apply_labels(results, LABEL_DIR)
        except ValueError as exc:
            print(f"clean-corpus evaluation: invalid labels: {exc}", file=sys.stderr)
            return 2
    if plan is not None:
        quiet = {"summary": summarize(quiet_results), "packages": quiet_results}
        if arguments.labels:
            quiet["label_report"] = apply_labels(quiet_results, LABEL_DIR)
        payload["paired"] = {
            "schema_version": 1,
            "plan_canonical_sha256": canonical_sha(plan),
            "quiet": quiet,
            "receipts": receipts,
        }
        if not unavailable:
            try:
                validate_report(payload, plan)
            except (ValueError, KeyError, TypeError) as exc:
                print(f"clean-corpus evaluation: invalid paired evidence: {exc}", file=sys.stderr)
                return 2
    if arguments.pin_digests and not unavailable:
        pin_digests(manifest_path, results)
        payload["manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    if arguments.write_baseline is not None and not unavailable:
        baseline_path = arguments.write_baseline
        if not baseline_path.is_absolute():
            baseline_path = ROOT / baseline_path
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if arguments.json:
        print(json.dumps(payload, indent=2))
        return 2 if unavailable else 0
    for result in results:
        print(
            f"{result['package']:14} {result['files']:5} files {result['seconds']:6}s "
            f"app={result['app_findings']:3} verdict={result['verdict']} "
            f"app_by_severity={result['by_severity']}"
        )
        top = list(result["by_rule"].items())[:8]
        if top:
            print(f"{'':14} top rules: {', '.join(f'{rule}x{count}' for rule, count in top)}")
    if arguments.labels and "label_report" in payload:
        report = payload["label_report"]
        print(
            f"labels: records={report['records']} unreviewed={report['unreviewed']} "
            f"fp_budget_violations={report['fp_budget_violations']}"
        )
    for message in unavailable:
        print(f"UNAVAILABLE: {message}")
    return 2 if unavailable else 0


if __name__ == "__main__":
    sys.exit(main())
