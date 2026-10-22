"""Reviewed paired-corpus evidence. Never imported by the distributed scanner.

The positive leg is the untouched pinned corpus. Only explicitly reviewed byte
replacements produce the quiet leg; every file and finding record stays visible.
This is a source-signature benchmark, not a vendor patch or an exploitability test.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = ROOT / "benchmarks/clean-corpus-remediations.json"
MANIFEST_PATH = ROOT / "benchmarks/clean-corpus.json"
SOURCE_OMISSIONS = (
    "unreadable",
    "parser_limit",
    "line_limit",
    "oversized",
    "symlinks",
    "containers",
)


def canonical_sha(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def finding_keys(package: dict[str, Any]) -> Counter[tuple[str, str, int]]:
    return Counter(
        (finding["rule_id"], finding["path"], finding["line"])
        for finding in package["app_finding_records"]
        if finding["severity"] in {"high", "critical"}
    )


def load_plan(path: Path = PLAN_PATH, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    manifest = (
        manifest if manifest is not None else json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    )
    plan = json.loads(path.read_text(encoding="utf-8"))
    if plan.get("schema_version") != 1 or plan.get("manifest_canonical_sha256") != canonical_sha(
        manifest
    ):
        raise ValueError("paired plan does not bind the exact source manifest")
    specs = {item["name"]: item for item in manifest["packages"]}
    entries = plan.get("packages", [])
    if len(entries) != len(specs) or {item["package"] for item in entries} != set(specs):
        raise ValueError("paired plan must retain every original package exactly once")
    for item in entries:
        spec = specs[item["package"]]
        if item["version"] != spec["version"] or (
            spec.get("source_sha256") and item["source_sha256"] != spec["source_sha256"]
        ):
            raise ValueError("paired plan changed a source pin")
        digests = [
            item["source_sha256"],
            item["remediated_source_sha256"],
            *item.get("source_sha256_variants", []),
        ]
        if not all(
            isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) for value in digests
        ):
            raise ValueError("paired plan must pin every source digest")
        if item.get("source_sha256_variants") and item["edits"]:
            raise ValueError("edited source variants require separately reviewed recipes")
        seen: set[str] = set()
        for edit in item["edits"]:
            path_value = edit["path"]
            relative = Path(path_value)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or "\\" in path_value
                or ":" in path_value
                or path_value in seen
            ):
                raise ValueError("paired edit path is unsafe or duplicated")
            seen.add(path_value)
            for replacement in edit["replacements"]:
                before, after = (
                    bytes.fromhex(replacement["before_hex"]),
                    bytes.fromhex(replacement["after_hex"]),
                )
                if (
                    not before
                    or not after
                    or before == after
                    or replacement["count"] < 1
                    or b"shipproof:ignore" in after
                ):
                    raise ValueError(
                        "paired edit must be a nonempty reviewed remediation, not suppression"
                    )
    return plan


def paired_digest(entry: dict[str, Any], original_digest: str) -> str:
    if original_digest == entry["source_sha256"]:
        return entry["remediated_source_sha256"]
    if not entry["edits"] and original_digest in entry.get("source_sha256_variants", []):
        return original_digest
    raise ValueError("paired source digest is not in the reviewed source pins")


def check_original(package: dict[str, Any], entry: dict[str, Any]) -> int:
    expected = Counter(
        (item["rule_id"], item["path"], item["line"]) for item in entry["expected_findings"]
    )
    if finding_keys(package) != expected:
        raise ValueError(
            f"{package['package']}: original positive findings changed; review required"
        )
    return sum(expected.values())


def remediate_copy(
    specification: dict[str, str],
    source: Path,
    workspace: Path,
    original: dict[str, Any],
    entry: dict[str, Any],
    scan: Callable[..., dict[str, Any]],
    digest: Callable[[Path], str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    positives = check_original(original, entry)
    original_digest = original["source_sha256"]
    quiet_digest = paired_digest(entry, original_digest)
    receipts = []
    with tempfile.TemporaryDirectory(prefix="shipproof-paired-", dir=workspace) as directory:
        destination = Path(directory) / source.name
        destination.mkdir()
        copied_bytes = copied_files = 0
        for path in source.rglob("*"):
            if path.is_symlink() or not path.resolve().is_relative_to(source.resolve()):
                raise ValueError("paired source contains a link or path escape")
            if not path.is_file():
                continue
            copied_files += 1
            copied_bytes += path.stat().st_size
            if copied_files > 10_000 or copied_bytes > 64 * 1024 * 1024:
                raise ValueError("paired copy resource budget exceeded")
            target = destination / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)  # No execution or permission-bit propagation.
        if digest(destination) != original_digest:
            raise ValueError("paired copy does not preserve original source coverage")
        for edit in entry["edits"]:
            path = destination / edit["path"]
            before = path.read_bytes()
            if hashlib.sha256(before).hexdigest() != edit["before_sha256"]:
                raise ValueError("paired source bytes differ from the reviewed recipe")
            after = before
            for replacement in edit["replacements"]:
                old, new = (
                    bytes.fromhex(replacement["before_hex"]),
                    bytes.fromhex(replacement["after_hex"]),
                )
                if after.count(old) != replacement["count"]:
                    raise ValueError("paired replacement occurrence count changed")
                after = after.replace(old, new)
            if hashlib.sha256(after).hexdigest() != edit["after_sha256"]:
                raise ValueError("paired remediation output differs from the reviewed recipe")
            path.write_bytes(after)
            receipts.append({key: edit[key] for key in ("path", "before_sha256", "after_sha256")})
        if digest(source) != original_digest or digest(destination) != quiet_digest:
            raise ValueError("paired run modified the original or changed remediation output")
        quiet = scan(specification, destination, verify_source=False)
        if (
            quiet["files"] != original["files"]
            or quiet["scan_profile"] != original["scan_profile"]
            or quiet["completeness"] != original["completeness"]
        ):
            raise ValueError("paired source coverage or default scan profile changed")
    return quiet, {
        "package": original["package"],
        "source_sha256": original["source_sha256"],
        "remediated_source_sha256": quiet["source_sha256"],
        "positive_expected": positives,
        "positive_observed": positives,
        "edits": receipts,
    }


def validate_report(payload: dict[str, Any], plan: dict[str, Any] | None = None) -> dict[str, Any]:
    """Recompute the positive leg and bind all quiet evidence before gating it."""
    plan = load_plan() if plan is None else plan
    paired = payload.get("paired")
    if (
        payload.get("schema_version") != "2.0"
        or not isinstance(paired, dict)
        or paired.get("schema_version") != 1
    ):
        raise ValueError("a versioned paired-corpus report is required")
    if paired.get("plan_canonical_sha256") != canonical_sha(plan):
        raise ValueError("paired report does not match the reviewed remediation plan")
    if payload.get("manifest_canonical_sha256") != plan["manifest_canonical_sha256"]:
        raise ValueError("paired report source manifest changed")
    if payload.get("unavailable") or payload.get("verdict") != "PASS_WITH_EVIDENCE":
        raise ValueError("paired report has unavailable evidence")
    original = payload.get("packages", [])
    quiet_report = paired.get("quiet", {})
    quiet = quiet_report.get("packages", [])
    receipts = paired.get("receipts", [])
    entries = {item["package"]: item for item in plan["packages"]}
    for rows in (original, quiet, receipts):
        if len(rows) != len(entries) or {row["package"] for row in rows} != set(entries):
            raise ValueError("paired report is missing, duplicating or replacing a package")
    quiet_by_name = {item["package"]: item for item in quiet}
    receipts_by_name = {item["package"]: item for item in receipts}
    observed = 0
    for item in original:
        name = item["package"]
        entry, fixed, receipt = entries[name], quiet_by_name[name], receipts_by_name[name]
        expected_quiet = paired_digest(entry, item["source_sha256"])
        for record, expected_digest in ((item, item["source_sha256"]), (fixed, expected_quiet)):
            if (
                record.get("status") != "scanned"
                or record.get("version") != entry["version"]
                or record.get("source_sha256") != expected_digest
                or record.get("files") != entry["files"]
            ):
                raise ValueError("paired package identity or source digest changed")
            ledger = record.get("completeness", {})
            if not all(
                type(ledger.get(key)) is int and ledger[key] >= 0 for key in SOURCE_OMISSIONS
            ):
                raise ValueError("paired source coverage ledger is missing or invalid")
            if any(record.get("completeness", {}).get(key) for key in SOURCE_OMISSIONS):
                raise ValueError("paired report omitted source coverage")
            if len(record["app_finding_records"]) != record["app_findings"]:
                raise ValueError("paired findings were truncated")
            if any(finding.get("scope") != "app" for finding in record["app_finding_records"]):
                raise ValueError("paired application findings changed scope")
        if (
            item["files"] != fixed["files"]
            or item["scan_profile"] != fixed["scan_profile"]
            or item["completeness"] != fixed["completeness"]
        ):
            raise ValueError("paired coverage or default profile differs")
        count = check_original(item, entry)
        observed += count
        expected_receipt = {
            "package": name,
            "source_sha256": item["source_sha256"],
            "remediated_source_sha256": expected_quiet,
            "positive_expected": count,
            "positive_observed": count,
            "edits": [
                {key: edit[key] for key in ("path", "before_sha256", "after_sha256")}
                for edit in entry["edits"]
            ],
        }
        if receipt != expected_receipt:
            raise ValueError("paired remediation receipts or positive observations differ")
    if not observed:
        raise ValueError("paired positive leg cannot be empty")
    for report in (payload, quiet_report):
        packages = report["packages"]
        if report.get("summary") != {
            "packages": len(packages),
            "files": sum(p["files"] for p in packages),
            "app_findings": sum(p["app_findings"] for p in packages),
            "blocked_packages": [p["package"] for p in packages if p["verdict"] == "BLOCK"],
            "blocked_count": sum(p["verdict"] == "BLOCK" for p in packages),
        }:
            raise ValueError("paired summary differs from its raw package records")
    return quiet_report
