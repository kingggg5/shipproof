#!/usr/bin/env python3
"""Initialize a portable, project-pinned Harness without overwriting user instructions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import uuid
from pathlib import Path

sys.dont_write_bytecode = True

from memory_ops import (
	PROJECT_ID_PATTERN,
	ACTIVE_RUN_STATES,
	MemoryErrorWithCode,
	assert_current_identity,
	atomic_delete,
	atomic_replace,
	configure_utf8_stdio,
	ensure_within,
	parse_time,
	path_is_link_or_junction,
	pretty_json,
	read_regular_file_bounded,
	read_json_bytes,
	render_project_views,
	repository_identity,
	target_file_lock,
	utc_now,
	validate_identity,
	validate_store,
)


TEMPLATE_FILES = (
	"IDENTITY.json",
	"MEMORY.json",
	"INDEX.md",
	"CONFIG.md",
	"CONTEXT.md",
	"PREFERENCES.md",
	"DECISIONS.md",
	"STATE.json",
	"WORKFLOW.md",
)

MODEL_FILES = {
	"codex": ("AGENTS.md", "AGENTS.md.fragment"),
	"claude": ("CLAUDE.md", "CLAUDE.md.fragment"),
	"gemini": ("GEMINI.md", "GEMINI.md.fragment"),
	"generic": ("AI-HARNESS.md", "GENERIC.md"),
}

PROJECT_ID_LINE = re.compile(r"^- Project ID(?: or GLOBAL)?:[ \t]*([^\r\n]*)$", re.MULTILINE)
GITIGNORE_BLOCK = "# harness local-only data\n.harness/.cache/\n.harness/local-capabilities.md\n"
RUNTIME_MANIFEST = "HARNESS-RUNTIME.json"
MANAGED_START = "<!-- harness:start -->"
MANAGED_END = "<!-- harness:end -->"
CURRENT_MARKDOWN_SCHEMAS = {
	"INDEX.md": 2,
	"CONFIG.md": 2,
	"CONTEXT.md": 4,
	"PREFERENCES.md": 2,
	"DECISIONS.md": 3,
	"WORKFLOW.md": 4,
}
CURRENT_JSON_SCHEMAS = {"IDENTITY.json": 1, "MEMORY.json": 1, "STATE.json": 2}
STATE_OPERATIONS = {"start", "resume", "review", "init", "memory"}


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Create missing Harness state, a pinned runtime, and thin provider adapters")
	parser.add_argument("--project", required=True, help="Existing project directory")
	parser.add_argument("--models", default="all", help="Comma-separated extra launchers; canonical AGENTS.md is always installed")
	parser.add_argument("--project-id", help="Optional exact project UUID in project-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx form")
	parser.add_argument("--rebind-identity", action="store_true", help="Preview/apply rebinding an idle current project while preserving its Project ID")
	parser.add_argument("--approve", help="Exact preview digest required to apply --rebind-identity")
	parser.add_argument("--dry-run", action="store_true", help="Report changes without writing")
	parser.add_argument("--json", action="store_true", help="Print structured output")
	return parser.parse_args()


def read_utf8(path: Path) -> str:
	try:
		return path.read_text(encoding="utf-8")
	except UnicodeDecodeError as exc:
		raise MemoryErrorWithCode("NON_UTF8", f"Refusing non-UTF-8 file: {path}") from exc


def parse_models(raw: str) -> list[str]:
	if raw.strip().lower() == "all":
		requested = list(MODEL_FILES)
	else:
		requested = [item.strip().lower() for item in raw.split(",") if item.strip()]
	unknown = sorted(set(requested) - set(MODEL_FILES))
	if unknown:
		raise MemoryErrorWithCode("UNKNOWN_MODEL", f"Unknown model adapter(s): {', '.join(unknown)}")
	if not requested:
		raise MemoryErrorWithCode("MODEL_REQUIRED", "At least one model adapter is required")
	return ["codex", *[model for model in dict.fromkeys(requested) if model != "codex"]]


def stored_project_ids(harness_dir: Path) -> set[str]:
	result: set[str] = set()
	if not harness_dir.exists():
		return result
	for path in harness_dir.iterdir():
		if not path.is_file() or path_is_link_or_junction(path) or path.suffix.lower() not in {".md", ".json"}:
			continue
		if path.suffix.lower() == ".json":
			try:
				data = json.loads(read_utf8(path))
			except json.JSONDecodeError as exc:
				raise MemoryErrorWithCode("INVALID_EXISTING_JSON", f"Invalid existing JSON: {path}") from exc
			value = data.get("project_id", "") if isinstance(data, dict) else ""
			if isinstance(value, str) and value:
				if not PROJECT_ID_PATTERN.fullmatch(value):
					raise MemoryErrorWithCode("INVALID_PROJECT_ID", f"Invalid Project ID in {path}: {value}")
				result.add(value)
			continue
		for match in PROJECT_ID_LINE.finditer(read_utf8(path)):
			value = match.group(1).strip()
			if not value or value == "GLOBAL":
				continue
			if not PROJECT_ID_PATTERN.fullmatch(value):
				raise MemoryErrorWithCode("INVALID_PROJECT_ID", f"Invalid Project ID in {path}: {value}")
			result.add(value)
	return result


def is_current_layout(harness_dir: Path) -> bool:
	for name, schema in CURRENT_MARKDOWN_SCHEMAS.items():
		path = harness_dir / name
		if not path.is_file() or path_is_link_or_junction(path):
			return False
		match = re.search(r"^- Schema version:[ \t]*(\d+)[ \t]*$", read_utf8(path), re.MULTILINE)
		if not match or int(match.group(1)) != schema:
			return False
	for name, schema in CURRENT_JSON_SCHEMAS.items():
		path = harness_dir / name
		if not path.is_file() or path_is_link_or_junction(path):
			return False
		try:
			data = json.loads(read_utf8(path))
		except json.JSONDecodeError:
			return False
		if not isinstance(data, dict) or data.get("schema_version") != schema:
			return False
	return True


def select_project_id(existing_ids: set[str], supplied: str | None, dry_run: bool) -> str:
	if len(existing_ids) > 1:
		raise MemoryErrorWithCode("IDENTITY_CONFLICT", f"Conflicting Project IDs require human migration: {sorted(existing_ids)}")
	if supplied and not PROJECT_ID_PATTERN.fullmatch(supplied):
		raise MemoryErrorWithCode("INVALID_PROJECT_ID", "--project-id must use project-UUID form")
	if existing_ids:
		existing = next(iter(existing_ids))
		if supplied and supplied != existing:
			raise MemoryErrorWithCode("IDENTITY_CONFLICT", "Supplied Project ID conflicts with existing canonical files")
		return existing
	if supplied:
		return supplied
	if dry_run:
		return "<generated-on-write>"
	return f"project-{uuid.uuid4()}"


def render_template(path: Path, project: Path, project_id: str) -> bytes:
	content = read_utf8(path)
	if path.name == "IDENTITY.json":
		return (json.dumps(repository_identity(project, project_id), ensure_ascii=False, indent="\t") + "\n").encode("utf-8")
	if path.suffix.lower() == ".json":
		data = json.loads(content)
		data["project_id"] = project_id
		return (json.dumps(data, ensure_ascii=False, indent="\t") + "\n").encode("utf-8")
	content = re.sub(r"^- Project ID(?: or GLOBAL)?:[ \t]*$", f"- Project ID: {project_id}", content, flags=re.MULTILINE)
	return content.encode("utf-8")


def source_tree_files(skill_root: Path) -> list[Path]:
	links = sorted(path for path in skill_root.rglob("*") if path_is_link_or_junction(path))
	if links:
		raise MemoryErrorWithCode("BUNDLE_INVALID", f"Symlinks are not allowed in a pinned runtime: {links[0]}")
	generated = sorted(path for path in skill_root.rglob("*") if path.name == "__pycache__" or path.suffix.lower() == ".pyc")
	if generated:
		raise MemoryErrorWithCode("BUNDLE_INVALID", f"Generated Python caches are not allowed in a pinned runtime: {generated[0]}")
	return sorted(
		(path for path in skill_root.rglob("*") if path.is_file()),
		key=lambda path: path.relative_to(skill_root).as_posix(),
	)


def tree_digest(root: Path, files: list[Path] | None = None) -> str:
	digest = hashlib.sha256()
	selected = files if files is not None else source_tree_files(root)
	for path in selected:
		relative = path.relative_to(root).as_posix().encode("utf-8")
		digest.update(len(relative).to_bytes(4, "big"))
		digest.update(relative)
		data = path.read_bytes()
		digest.update(len(data).to_bytes(8, "big"))
		digest.update(data)
	return f"sha256:{digest.hexdigest()}"


def plugin_version(plugin_root: Path) -> str:
	try:
		data = json.loads(read_utf8(plugin_root / ".codex-plugin" / "plugin.json"))
	except (OSError, json.JSONDecodeError):
		return "unknown"
	return str(data.get("version", "unknown"))


def identity_rebind_digest(project: Path, identity_bytes: bytes, memory_bytes: bytes, state_bytes: bytes, proposed_identity: dict[str, object]) -> str:
	digest = hashlib.sha256()
	stable_proposal = {
		"schema_version": proposed_identity["schema_version"],
		"project_id": proposed_identity["project_id"],
		"logical_scope": proposed_identity["logical_scope"],
		"repository": proposed_identity["repository"],
	}
	for label, value in (
		("canonical_project_path", str(project).encode("utf-8")),
		("mode", b"shared-project-id"),
		("identity_before", identity_bytes),
		("memory_before", memory_bytes),
		("state_before", state_bytes),
		("identity_after", json.dumps(stable_proposal, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")),
	):
		label_bytes = label.encode("utf-8")
		digest.update(len(label_bytes).to_bytes(4, "big")); digest.update(label_bytes)
		digest.update(len(value).to_bytes(8, "big")); digest.update(value)
	return f"sha256:{digest.hexdigest()}"


def validate_runtime_manifest(data: object, path: Path) -> dict[str, object]:
	if not isinstance(data, dict):
		raise MemoryErrorWithCode("RUNTIME_MANIFEST_INVALID", f"Runtime manifest must be a JSON object: {path}")
	required = {"schema_version", "source_version", "source_digest", "created_at", "update_policy"}
	if set(data) != required or data.get("schema_version") != 1:
		raise MemoryErrorWithCode("RUNTIME_MANIFEST_INVALID", f"Runtime manifest has unsupported fields or schema: {path}")
	if not isinstance(data.get("source_version"), str) or not data["source_version"]:
		raise MemoryErrorWithCode("RUNTIME_MANIFEST_INVALID", f"Runtime manifest source_version is invalid: {path}")
	if not isinstance(data.get("source_digest"), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", data["source_digest"]):
		raise MemoryErrorWithCode("RUNTIME_MANIFEST_INVALID", f"Runtime manifest source_digest is invalid: {path}")
	if not isinstance(data.get("created_at"), str):
		raise MemoryErrorWithCode("RUNTIME_MANIFEST_INVALID", f"Runtime manifest created_at is invalid: {path}")
	try:
		parse_time(data["created_at"])
	except MemoryErrorWithCode as exc:
		raise MemoryErrorWithCode("RUNTIME_MANIFEST_INVALID", f"Runtime manifest created_at is invalid: {path}") from exc
	if data.get("update_policy") != "pinned; replace only after human-reviewed package update":
		raise MemoryErrorWithCode("RUNTIME_MANIFEST_INVALID", f"Runtime manifest update_policy is invalid: {path}")
	return data


def validate_target(path: Path, project: Path, allow_directory: bool = False) -> None:
	ensure_within(path, project, "initializer target")
	if path_is_link_or_junction(path):
		raise MemoryErrorWithCode("SYMLINK_REJECTED", f"Refusing symlink target: {path}")
	if path.exists() and not (path.is_dir() if allow_directory else path.is_file()):
		raise MemoryErrorWithCode("INVALID_TARGET", f"Existing target has wrong type: {path}")
	parent = path.parent
	while parent != project and parent != parent.parent:
		if parent.exists() and path_is_link_or_junction(parent):
			raise MemoryErrorWithCode("SYMLINK_REJECTED", f"Refusing symlinked parent: {parent}")
		parent = parent.parent


def adapter_bytes(existing: bytes, block: str) -> bytes:
	newline = b"\r\n" if b"\r\n" in existing else b"\n"
	block_bytes = block.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n").encode("utf-8").replace(b"\n", newline)
	if not existing:
		return block_bytes + newline
	separator = newline if existing.endswith((b"\n", b"\r")) else newline + newline
	return existing + separator + block_bytes + newline


def plan_file(path: Path, content: bytes, events: list[dict[str, str]]) -> tuple[Path, bytes, bytes | None] | None:
	if path.exists():
		events.append({"path": str(path), "action": "unchanged", "reason": "exists"})
		return None
	events.append({"path": str(path), "action": "create"})
	return path, content, None


def plan_adapter(path: Path, block: str, marker: str, events: list[dict[str, str]]) -> tuple[Path, bytes, bytes | None] | None:
	existed = path.exists()
	existing = path.read_bytes() if existed else b""
	try:
		decoded = existing.decode("utf-8")
	except UnicodeDecodeError as exc:
		raise MemoryErrorWithCode("NON_UTF8", f"Refusing non-UTF-8 instruction file: {path}") from exc
	normalized_existing = decoded.replace("\r\n", "\n").replace("\r", "\n")
	normalized_block = block.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
	if marker == MANAGED_START:
		start_count = normalized_existing.count(MANAGED_START)
		end_count = normalized_existing.count(MANAGED_END)
		if start_count or end_count:
			if start_count != 1 or end_count != 1:
				raise MemoryErrorWithCode("MANAGED_BLOCK_INVALID", f"Expected exactly one Harness managed block in {path}")
			start = normalized_existing.find(MANAGED_START)
			end = normalized_existing.find(MANAGED_END)
			start_after = start + len(MANAGED_START)
			end_after = end + len(MANAGED_END)
			markers_are_lines = (
				(start == 0 or normalized_existing[start - 1] == "\n")
				and normalized_existing[start_after:start_after + 1] == "\n"
				and normalized_existing[end - 1:end] == "\n"
				and (end_after == len(normalized_existing) or normalized_existing[end_after] == "\n")
			)
			if end <= start or not markers_are_lines:
				raise MemoryErrorWithCode("MANAGED_BLOCK_INVALID", f"Harness managed block markers are malformed in {path}")
			if normalized_existing[start:end_after] != normalized_block:
				raise MemoryErrorWithCode("MANAGED_BLOCK_INVALID", f"Harness managed block differs from the bundled adapter in {path}; use migration or upgrade")
			events.append({"path": str(path), "action": "unchanged", "reason": "exact adapter already present"})
			return None
	elif marker in normalized_existing:
		if normalized_existing.count(marker) != 1:
			raise MemoryErrorWithCode("MANAGED_BLOCK_INVALID", f"Expected exactly one managed block marker in {path}")
		block_start = normalized_existing.find(normalized_block)
		block_end = block_start + len(normalized_block)
		block_is_lines = block_start >= 0 and (block_start == 0 or normalized_existing[block_start - 1] == "\n") and (block_end == len(normalized_existing) or normalized_existing[block_end] == "\n")
		if not block_is_lines:
			raise MemoryErrorWithCode("MANAGED_BLOCK_INVALID", f"Managed block is incomplete or modified in {path}")
		events.append({"path": str(path), "action": "unchanged", "reason": "exact managed block already present"})
		return None
	events.append({"path": str(path), "action": "append" if existing else "create"})
	return path, adapter_bytes(existing, block), existing if existed else None


def runtime_plan(
	project: Path,
	skill_root: Path,
	plugin_root: Path,
	events: list[dict[str, str]],
	expected_source_digest: str | None = None,
	expected_version: str | None = None,
) -> tuple[Path, str, str] | None:
	runtime_root = project / ".harness" / "runtime"
	manifest_path = runtime_root / RUNTIME_MANIFEST
	validate_target(runtime_root, project, allow_directory=True)
	validate_target(manifest_path, project)
	source_files = source_tree_files(skill_root)
	actual_source_digest = tree_digest(skill_root, source_files)
	if expected_source_digest is not None and actual_source_digest != expected_source_digest:
		raise MemoryErrorWithCode("BUNDLE_CHANGED", "Harness package changed after the reviewed migration snapshot")
	source_digest = expected_source_digest or actual_source_digest
	version = expected_version or plugin_version(plugin_root)
	if runtime_root.exists():
		if not (runtime_root / "SKILL.md").is_file() or not manifest_path.is_file() or path_is_link_or_junction(manifest_path):
			raise MemoryErrorWithCode("RUNTIME_INCOMPLETE", "Pinned runtime is incomplete; require a human-reviewed repair")
		manifest = validate_runtime_manifest(json.loads(read_utf8(manifest_path)), manifest_path)
		recorded_digest = manifest.get("source_digest")
		runtime_files = [path for path in source_tree_files(runtime_root) if path.name != RUNTIME_MANIFEST]
		actual_digest = tree_digest(runtime_root, runtime_files)
		if actual_digest != recorded_digest:
			raise MemoryErrorWithCode("RUNTIME_MODIFIED", "Pinned runtime differs from its recorded digest; do not overwrite user changes")
		if source_digest != recorded_digest:
			events.append({"path": str(runtime_root), "action": "unchanged", "reason": f"pinned runtime update available: {manifest.get('source_version')} -> {version}"})
		else:
			events.append({"path": str(runtime_root), "action": "unchanged", "reason": "pinned runtime current"})
		return None
	events.append({"path": str(runtime_root), "action": "create", "reason": "project-pinned portable skill"})
	return runtime_root, source_digest, version


def install_runtime(plan: tuple[Path, str, str], skill_root: Path) -> tuple[Path, str, str, bytes]:
	runtime_root, source_digest, version = plan
	runtime_root.parent.mkdir(parents=True, exist_ok=True)
	staging = runtime_root.parent / f".rt-{uuid.uuid4().hex[:8]}"
	try:
		shutil.copytree(skill_root, staging, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
		staged_files = [path for path in source_tree_files(staging) if path.name != RUNTIME_MANIFEST]
		if tree_digest(staging, staged_files) != source_digest:
			raise MemoryErrorWithCode("BUNDLE_CHANGED", "Pinned runtime source changed while it was being copied")
		manifest = {
			"schema_version": 1,
			"source_version": version,
			"source_digest": source_digest,
			"created_at": utc_now(),
			"update_policy": "pinned; replace only after human-reviewed package update",
		}
		manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent="\t") + "\n").encode("utf-8")
		(staging / RUNTIME_MANIFEST).write_bytes(manifest_bytes)
		if runtime_root.exists() or path_is_link_or_junction(runtime_root):
			raise MemoryErrorWithCode("TARGET_EXISTS", f"Runtime target appeared concurrently: {runtime_root}")
		os.replace(staging, runtime_root)
		return runtime_root, source_digest, version, manifest_bytes
	finally:
		if staging.exists():
			shutil.rmtree(staging)


def rollback_initialization(
	applied: list[tuple[Path, bytes, bytes | None]],
	runtime: tuple[Path, str, str, bytes] | None,
) -> list[str]:
	errors: list[str] = []
	for path, written, previous in reversed(applied):
		try:
			if previous is None:
				atomic_delete(path, written)
			else:
				atomic_replace(path, previous, expected=written)
		except (OSError, MemoryErrorWithCode) as exc:
			errors.append(str(exc))
	if runtime is not None:
		runtime_root, expected_digest, _, expected_manifest_bytes = runtime
		try:
			manifest_path = runtime_root / RUNTIME_MANIFEST
			if path_is_link_or_junction(runtime_root) or not runtime_root.is_dir() or not manifest_path.is_file() or path_is_link_or_junction(manifest_path):
				raise MemoryErrorWithCode("ROLLBACK_CONFLICT", f"Runtime changed type during rollback: {runtime_root}")
			if read_regular_file_bounded(manifest_path, len(expected_manifest_bytes), "runtime manifest") != expected_manifest_bytes:
				raise MemoryErrorWithCode("ROLLBACK_CONFLICT", f"Runtime manifest changed concurrently during rollback: {runtime_root}")
			actual_files = [path for path in source_tree_files(runtime_root) if path.name != RUNTIME_MANIFEST]
			if tree_digest(runtime_root, actual_files) != expected_digest:
				raise MemoryErrorWithCode("ROLLBACK_CONFLICT", f"Runtime changed concurrently during rollback: {runtime_root}")
			def remove_readonly(function, path, _error):
				os.chmod(path, stat.S_IWRITE)
				function(path)
			shutil.rmtree(runtime_root, onerror=remove_readonly)
		except (OSError, MemoryErrorWithCode) as exc:
			errors.append(str(exc))
	return errors


def main() -> int:
	configure_utf8_stdio()
	args = parse_args()
	try:
		project = Path(args.project).expanduser().resolve(strict=True)
		if not project.is_dir():
			raise MemoryErrorWithCode("PROJECT_UNAVAILABLE", f"Project is not a directory: {project}")
		models = parse_models(args.models)
		skill_root = Path(__file__).resolve().parents[1]
		plugin_root = Path(__file__).resolve().parents[3]
		template_root = skill_root / "assets" / "templates"
		adapter_root = plugin_root / "adapters" / "project"
		harness_dir = project / ".harness"
		validate_target(harness_dir, project, allow_directory=True)
		for name in TEMPLATE_FILES:
			source = template_root / name
			if not source.is_file() or path_is_link_or_junction(source):
				raise MemoryErrorWithCode("BUNDLE_INVALID", f"Missing or symlinked bundled template: {source}")
			read_utf8(source)
		for model in models:
			fragment = adapter_root / MODEL_FILES[model][1]
			if not fragment.is_file() or path_is_link_or_junction(fragment):
				raise MemoryErrorWithCode("BUNDLE_INVALID", f"Missing or symlinked bundled adapter: {fragment}")
			read_utf8(fragment)
		existing_ids = stored_project_ids(harness_dir)
		existing_canonical = harness_dir.exists() and any((harness_dir / name).exists() for name in TEMPLATE_FILES)
		if existing_canonical and not is_current_layout(harness_dir):
			raise MemoryErrorWithCode("MIGRATION_REQUIRED", "Legacy or mixed Harness schemas detected; preview scripts/migrate_project.py --dry-run, then apply its exact approval digest")
		if existing_canonical and not existing_ids:
			raise MemoryErrorWithCode("MIGRATION_REQUIRED", "Existing Harness files have no valid Project ID; run an additive migration")
		if args.rebind_identity and not existing_canonical:
			raise MemoryErrorWithCode("IDENTITY_UNAVAILABLE", "--rebind-identity requires an initialized current Harness project")
		if args.approve and not args.rebind_identity:
			raise MemoryErrorWithCode("INVALID_ARGUMENT", "--approve is only valid with --rebind-identity")
		project_id = select_project_id(existing_ids, args.project_id, args.dry_run)
		events: list[dict[str, str]] = []
		writes: list[tuple[Path, bytes, bytes | None]] = []
		rebound_identity: tuple[bytes, bytes] | None = None
		identity_plan_digest = ""
		identity_review: dict[str, object] = {}
		if existing_canonical:
			identity_path = harness_dir / "IDENTITY.json"
			identity, identity_bytes = read_json_bytes(identity_path)
			identity_errors = validate_identity(identity)
			if identity_errors:
				raise MemoryErrorWithCode("IDENTITY_INVALID", "; ".join(identity_errors))
			if args.rebind_identity:
				state, state_bytes = read_json_bytes(harness_dir / "STATE.json")
				state_value = state.get("state")
				operation_value = state.get("operation")
				run_id_value = state.get("run_id")
				if (
					state.get("schema_version") != 2 or state.get("project_id") != identity["project_id"]
					or not isinstance(state_value, str) or state_value not in ACTIVE_RUN_STATES | {"DONE"}
					or not isinstance(operation_value, str) or operation_value not in STATE_OPERATIONS
					or not isinstance(run_id_value, str)
				):
					raise MemoryErrorWithCode("STATE_INVALID", "STATE.json is not a recognized canonical state for identity rebind")
				if not (state_value == "DONE" or (state_value == "INTAKE" and not run_id_value)):
					raise MemoryErrorWithCode("ACTIVE_RUN", "Close the active run before rebinding project identity")
				memory, memory_bytes = read_json_bytes(harness_dir / "MEMORY.json")
				memory_errors = validate_store(memory, identity["project_id"])
				if memory_errors:
					raise MemoryErrorWithCode("STORE_INVALID", "; ".join(memory_errors))
				if any(record.get("scope") == "task" for record in memory["records"]):
					raise MemoryErrorWithCode("TASK_MEMORY_OPEN", "Close all task-scoped memory before rebinding project identity")
				updated_identity = repository_identity(project, identity["project_id"], identity["logical_scope"])
				updated_identity["created_at"] = identity["created_at"]
				identity_review = {
					"mode": "shared-project-id",
					"before": {"project_id":identity["project_id"],"logical_scope":identity["logical_scope"],"repository":identity["repository"]},
					"after": {"project_id":updated_identity["project_id"],"logical_scope":updated_identity["logical_scope"],"repository":updated_identity["repository"]},
				}
				identity_plan_digest = identity_rebind_digest(project, identity_bytes, memory_bytes, state_bytes, updated_identity)
				if not args.dry_run and args.approve != identity_plan_digest:
					raise MemoryErrorWithCode("APPROVAL_REQUIRED", f"Re-run with --approve {identity_plan_digest} after reviewing the dry-run")
				updated_bytes = pretty_json(updated_identity)
				if updated_bytes != identity_bytes:
					rebound_identity = (updated_bytes, identity_bytes)
			else:
				try:
					assert_current_identity(project, identity, identity["logical_scope"])
				except MemoryErrorWithCode as exc:
					raise MemoryErrorWithCode("IDENTITY_MISMATCH", f"{exc}; review the repository identity, then rerun with --rebind-identity") from exc
		for name in TEMPLATE_FILES:
			target = harness_dir / name
			validate_target(target, project)
			if name == "IDENTITY.json" and rebound_identity is not None:
				content, expected = rebound_identity
				events.append({"path": str(target), "action": "update", "reason": "human-confirmed repository identity rebind"})
				writes.append((target, content, expected))
				continue
			content = b"" if args.dry_run and project_id == "<generated-on-write>" else render_template(template_root / name, project, project_id)
			planned = plan_file(target, content, events)
			if planned:
				writes.append(planned)
		for model in models:
			target_name, fragment_name = MODEL_FILES[model]
			target = project / target_name
			validate_target(target, project)
			block = read_utf8(adapter_root / fragment_name)
			marker = MANAGED_START
			planned = plan_adapter(target, block, marker, events)
			if planned:
				writes.append(planned)
		gitignore = project / ".gitignore"
		validate_target(gitignore, project)
		planned_ignore = plan_adapter(gitignore, GITIGNORE_BLOCK, "# harness local-only data", events)
		if planned_ignore:
			writes.append(planned_ignore)
		runtime = runtime_plan(project, skill_root, plugin_root, events)
		if not args.dry_run:
			applied: list[tuple[Path, bytes, bytes | None]] = []
			installed_runtime: tuple[Path, str, str, bytes] | None = None
			with target_file_lock(harness_dir / "MEMORY.json"):
				try:
					if runtime:
						installed_runtime = install_runtime(runtime, skill_root)
					for path, content, expected in writes:
						path.parent.mkdir(parents=True, exist_ok=True)
						atomic_replace(path, content, expected=expected)
						applied.append((path, content, expected))
				except (OSError, MemoryErrorWithCode) as exc:
					rollback_errors = rollback_initialization(applied, installed_runtime)
					if rollback_errors:
						raise MemoryErrorWithCode("ROLLBACK_FAILED", f"{exc}; rollback issues: {'; '.join(rollback_errors)}") from exc
					raise
				try:
					final_store, _ = read_json_bytes(harness_dir / "MEMORY.json")
					rendered = render_project_views(project, final_store)
					events.append({"path": ", ".join(rendered), "action": "render", "reason": "derived views from canonical memory"})
				except (OSError, MemoryErrorWithCode) as exc:
					events.append({"path": ".harness/*.md", "action": "warn", "reason": f"canonical memory committed but derived views left unrendered: {exc}"})
		result = {
			"ok": True, "project": str(project), "project_id": project_id, "models": models, "dry_run": args.dry_run,
			"identity_rebind": rebound_identity is not None, "identity_mode": "shared-project-id" if args.rebind_identity else "not-requested",
			"identity_plan_digest": identity_plan_digest, "approval_required": identity_plan_digest if args.rebind_identity else "",
			"identity_review": identity_review, "events": events,
		}
		if args.json:
			print(json.dumps(result, ensure_ascii=False, indent=2))
		else:
			print(f"Harness initialized for {project_id} ({'dry run' if args.dry_run else 'written'})")
			for event in events:
				print(f"- {event['action']}: {event['path']}")
		return 0
	except (OSError, MemoryErrorWithCode, json.JSONDecodeError) as exc:
		if isinstance(exc, OSError) and not isinstance(exc, MemoryErrorWithCode):
			import traceback
			traceback.print_exc(file=sys.stderr)
		code = exc.code if isinstance(exc, MemoryErrorWithCode) else "INIT_ERROR"
		result = {"ok": False, "code": code, "error": str(exc)}
		if args.json:
			print(json.dumps(result, ensure_ascii=False, indent=2))
		else:
			print(f"Harness initialization failed: {exc}", file=sys.stderr)
		return 1


if __name__ == "__main__":
	raise SystemExit(main())
