#!/usr/bin/env python3
"""Preview and apply a project-pinned Harness runtime/adapter upgrade."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import uuid
from pathlib import Path

sys.dont_write_bytecode = True

from init_project import (
	MODEL_FILES,
	RUNTIME_MANIFEST,
	is_current_layout,
	parse_models,
	plugin_version,
	read_utf8,
	rollback_initialization,
	source_tree_files,
	tree_digest,
	validate_runtime_manifest,
	validate_target,
)
from memory_ops import (
	MemoryErrorWithCode,
	assert_current_identity,
	atomic_replace,
	configure_utf8_stdio,
	pretty_json,
	path_is_link_or_junction,
	read_regular_file_bounded,
	read_json_bytes,
	target_file_lock,
	utc_now,
	validate_identity,
)
from migrate_project import managed_adapter
from validate_portability import check_project, exact_managed_block


MAX_RUNTIME_FILES = 4096
MAX_RUNTIME_FILE_BYTES = 64 * 1024 * 1024
MAX_RUNTIME_TOTAL_BYTES = 128 * 1024 * 1024


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Upgrade a pinned Harness runtime and only its managed adapter blocks")
	parser.add_argument("--project", required=True)
	parser.add_argument("--models", default="all")
	parser.add_argument("--dry-run", action="store_true")
	parser.add_argument("--approve", help="Exact sha256 digest returned by --dry-run")
	parser.add_argument("--json", action="store_true")
	return parser.parse_args()


def remove_tree(path: Path) -> None:
	def remove_readonly(function, item, _error):
		os.chmod(item, stat.S_IWRITE)
		function(item)
	shutil.rmtree(path,onerror=remove_readonly)


def tree_snapshot(root: Path) -> dict[str, bytes]:
	files = source_tree_files(root)
	if len(files) > MAX_RUNTIME_FILES:
		raise MemoryErrorWithCode("RUNTIME_TOO_LARGE", f"Runtime has more than {MAX_RUNTIME_FILES} files: {root}")
	snapshot: dict[str, bytes] = {}
	total = 0
	for path in files:
		data = read_regular_file_bounded(path, MAX_RUNTIME_FILE_BYTES, "runtime file")
		total += len(data)
		if total > MAX_RUNTIME_TOTAL_BYTES:
			raise MemoryErrorWithCode("RUNTIME_TOO_LARGE", f"Runtime exceeds {MAX_RUNTIME_TOTAL_BYTES} bytes: {root}")
		snapshot[path.relative_to(root).as_posix()] = data
	return snapshot


def snapshot_digest(snapshot: dict[str, bytes], exclude_manifest: bool = False) -> str:
	digest = hashlib.sha256()
	for relative in sorted(snapshot):
		if exclude_manifest and Path(relative).name == RUNTIME_MANIFEST:
			continue
		name = relative.encode("utf-8"); data = snapshot[relative]
		digest.update(len(name).to_bytes(4, "big")); digest.update(name)
		digest.update(len(data).to_bytes(8, "big")); digest.update(data)
	return f"sha256:{digest.hexdigest()}"


def runtime_state(runtime: Path) -> tuple[str | None, dict[str, object] | None, dict[str, bytes]]:
	if not runtime.exists():
		return None, None, {}
	if path_is_link_or_junction(runtime) or not runtime.is_dir():
		raise MemoryErrorWithCode("RUNTIME_INCOMPLETE", f"Runtime target is invalid: {runtime}")
	manifest_path = runtime / RUNTIME_MANIFEST
	if not manifest_path.is_file() or path_is_link_or_junction(manifest_path):
		raise MemoryErrorWithCode("RUNTIME_INCOMPLETE", f"Runtime manifest is missing: {manifest_path}")
	snapshot = tree_snapshot(runtime)
	try:
		manifest = validate_runtime_manifest(json.loads(snapshot[RUNTIME_MANIFEST].decode("utf-8")),manifest_path)
	except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
		raise MemoryErrorWithCode("RUNTIME_MANIFEST_INVALID", f"Runtime manifest is invalid: {manifest_path}") from exc
	actual = snapshot_digest(snapshot, exclude_manifest=True)
	if actual != manifest["source_digest"]:
		raise MemoryErrorWithCode("RUNTIME_MODIFIED", "Pinned runtime differs from its manifest; require human repair")
	return actual, manifest, snapshot


def approval_digest(
	project: Path,
	identity: dict[str, object],
	source_digest: str,
	source_version: str,
	runtime_snapshot: dict[str, bytes],
	adapters: dict[str, bytes],
	adapter_sources: dict[str, bytes],
) -> str:
	digest = hashlib.sha256()
	stable_identity = {
		"schema_version": identity["schema_version"],
		"project_id": identity["project_id"],
		"logical_scope": identity["logical_scope"],
		"repository": identity["repository"],
	}
	for value in (
		str(project), json.dumps(stable_identity,ensure_ascii=False,sort_keys=True,separators=(",", ":")),
		source_digest, source_version, snapshot_digest(runtime_snapshot) if runtime_snapshot else "ABSENT",
	):
		data = value.encode("utf-8"); digest.update(len(data).to_bytes(4,"big")); digest.update(data)
	for name_value in sorted(adapters):
		data = adapters[name_value]
		name = name_value.encode("utf-8"); digest.update(len(name).to_bytes(4,"big")); digest.update(name)
		digest.update(len(data).to_bytes(8,"big")); digest.update(data)
	for name_value in sorted(adapter_sources):
		data = adapter_sources[name_value]; name = name_value.encode("utf-8")
		digest.update(len(name).to_bytes(4,"big")); digest.update(name)
		digest.update(len(data).to_bytes(8,"big")); digest.update(data)
	return f"sha256:{digest.hexdigest()}"


def stage_runtime(runtime: Path, skill_root: Path, source_digest: str, version: str) -> Path:
	staging = runtime.parent / f".rt-upgrade-{uuid.uuid4().hex[:8]}"
	shutil.copytree(skill_root,staging)
	manifest = {"schema_version":1,"source_version":version,"source_digest":source_digest,"created_at":utc_now(),"update_policy":"pinned; replace only after human-reviewed package update"}
	(staging / RUNTIME_MANIFEST).write_bytes(pretty_json(manifest))
	return staging


def main() -> int:
	configure_utf8_stdio()
	args = parse_args()
	try:
		project = Path(args.project).expanduser().resolve(strict=True)
		if not project.is_dir() or not is_current_layout(project / ".harness"):
			raise MemoryErrorWithCode("MIGRATION_REQUIRED", "Upgrade requires current schemas; run migrate_project.py first")
		models = parse_models(args.models)
		script_root = Path(__file__).resolve().parent
		skill_root = script_root.parent
		plugin_root = skill_root.parents[1]
		adapter_root = plugin_root / "adapters" / "project"
		identity_path = project / ".harness" / "IDENTITY.json"
		identity, identity_bytes = read_json_bytes(identity_path)
		identity_errors = validate_identity(identity)
		if identity_errors:
			raise MemoryErrorWithCode("IDENTITY_INVALID", "; ".join(identity_errors))
		assert_current_identity(project, identity, str(identity["logical_scope"]))
		runtime = project / ".harness" / "runtime"
		validate_target(runtime,project,allow_directory=True)
		old_digest, old_manifest, old_runtime_snapshot = runtime_state(runtime)
		source_snapshot = tree_snapshot(skill_root)
		source_digest = snapshot_digest(source_snapshot)
		source_version = plugin_version(plugin_root)
		adapter_paths = [project / MODEL_FILES[model][0] for model in models]
		adapter_sources = [adapter_root / MODEL_FILES[model][1] for model in models]
		adapter_snapshot: dict[str, bytes] = {}
		adapter_source_snapshot: dict[str, bytes] = {}
		writes: list[tuple[Path,bytes,bytes | None]] = []
		events: list[dict[str,str]] = []
		for model, path, source_path in zip(models,adapter_paths,adapter_sources):
			validate_target(path,project)
			if path.exists():
				read_utf8(path)
			previous = read_regular_file_bounded(path, MAX_RUNTIME_FILE_BYTES, "project adapter") if path.exists() else None
			if not source_path.is_file() or path_is_link_or_junction(source_path):
				raise MemoryErrorWithCode("BUNDLE_INVALID", f"Bundled adapter is missing or linked: {source_path}")
			source_bytes = read_regular_file_bounded(source_path, MAX_RUNTIME_FILE_BYTES, "bundled adapter")
			try:
				source_text = source_bytes.decode("utf-8")
			except UnicodeDecodeError as exc:
				raise MemoryErrorWithCode("BUNDLE_INVALID", f"Bundled adapter is not UTF-8: {source_path}") from exc
			adapter_snapshot[path.name] = previous or b""
			adapter_source_snapshot[source_path.name] = source_bytes
			desired = managed_adapter(previous or b"",source_text,path.name)
			if desired != (previous or b""):
				writes.append((path,desired,previous))
				events.append({"path":str(path),"action":"update managed Harness block"})
		if source_digest != old_digest:
			events.append({"path":str(runtime),"action":"install" if old_digest is None else "upgrade","from":str(old_manifest.get("source_version")) if old_manifest else "absent","to":source_version})
		digest = approval_digest(project,identity,source_digest,source_version,old_runtime_snapshot,adapter_snapshot,adapter_source_snapshot)
		if not events:
			result = {"ok":True,"result":"ALREADY_CURRENT","project":str(project),"plan_digest":digest,"events":[]}
			print(json.dumps(result,ensure_ascii=False,indent=2) if args.json else "Pinned Harness runtime is already current")
			return 0
		result = {"ok":True,"result":"PREVIEW" if args.dry_run else "UPGRADED","project":str(project),"plan_digest":digest,"approval_required":digest,"source_digest":source_digest,"previous_digest":old_digest,"dry_run":args.dry_run,"events":events}
		if args.dry_run:
			print(json.dumps(result,ensure_ascii=False,indent=2) if args.json else f"Upgrade preview: approve {digest}")
			return 0
		if args.approve != digest:
			raise MemoryErrorWithCode("APPROVAL_REQUIRED", f"Re-run with --approve {digest} after reviewing the dry-run")
		applied: list[tuple[Path,bytes,bytes | None]] = []
		staging: Path | None = None
		archive: Path | None = None
		new_runtime_installed = False
		try:
			with target_file_lock(project / ".harness" / "MEMORY.json"):
				try:
					current_identity = read_regular_file_bounded(identity_path, len(identity_bytes), "upgrade identity")
				except MemoryErrorWithCode as exc:
					raise MemoryErrorWithCode("REVISION_CONFLICT", "Project identity changed after approval planning") from exc
				if current_identity != identity_bytes:
					raise MemoryErrorWithCode("REVISION_CONFLICT", "Project identity changed after approval planning")
				if source_digest != old_digest:
					staging = stage_runtime(runtime,skill_root,source_digest,source_version)
					staged_digest, staged_manifest, _ = runtime_state(staging)
					if staged_digest != source_digest or staged_manifest is None or staged_manifest.get("source_version") != source_version:
						raise MemoryErrorWithCode("BUNDLE_CHANGED", "Harness package changed while staging the approved runtime")
					if runtime.exists():
						archive = project / ".harness" / "runtime-history" / f"{old_digest.removeprefix('sha256:')[:16]}-{digest.removeprefix('sha256:')[:8]}"
						validate_target(archive,project,allow_directory=True)
						archive.parent.mkdir(parents=True,exist_ok=True)
						if archive.exists():
							raise MemoryErrorWithCode("ARCHIVE_EXISTS", f"Runtime archive already exists: {archive}")
						os.replace(runtime,archive)
						try:
							if tree_snapshot(archive) != old_runtime_snapshot:
								raise MemoryErrorWithCode("REVISION_CONFLICT", "Pinned runtime changed after approval planning")
						except (OSError, MemoryErrorWithCode):
							if not runtime.exists() and archive.exists():
								os.replace(archive,runtime)
								archive = None
							raise
					os.replace(staging,runtime); staging = None; new_runtime_installed = True
				for path,content,expected in writes:
					atomic_replace(path,content,expected=expected); applied.append((path,content,expected))
				validation_errors: list[str] = []
				for model, path, source_path in zip(models, adapter_paths, adapter_sources):
					expected_adapter = adapter_source_snapshot[source_path.name].decode("utf-8")
					if not path.is_file() or path_is_link_or_junction(path) or not exact_managed_block(read_utf8(path), expected_adapter):
						validation_errors.append(f"Selected project adapter missing or invalid after upgrade: {path.name}")
				check_project(project,require_adapters=set(models)==set(MODEL_FILES),errors=validation_errors)
				if validation_errors:
					raise MemoryErrorWithCode("UPGRADE_VALIDATION_FAILED","; ".join(validation_errors))
		except (OSError,UnicodeDecodeError,MemoryErrorWithCode) as exc:
			rollback_errors: list[str] = []
			recovery: Path | None = None
			with target_file_lock(project / ".harness" / "MEMORY.json"):
				if new_runtime_installed and runtime.exists():
					try:
						recovery = project / ".harness" / "runtime-recovery" / f"failed-{digest.removeprefix('sha256:')[:16]}-{uuid.uuid4().hex[:8]}"
						validate_target(recovery,project,allow_directory=True)
						recovery.parent.mkdir(parents=True,exist_ok=True)
						os.replace(runtime,recovery)
					except (OSError,MemoryErrorWithCode) as recovery_exc:
						rollback_errors.append(f"could not preserve failed runtime: {recovery_exc}")
				if archive is not None and archive.exists():
					try:
						if runtime.exists():
							raise MemoryErrorWithCode("ROLLBACK_CONFLICT", f"Runtime path is occupied; reviewed runtime remains at {archive}")
						os.replace(archive,runtime)
					except (OSError,MemoryErrorWithCode) as restore_exc:
						rollback_errors.append(f"could not restore reviewed runtime from {archive}: {restore_exc}")
				rollback_errors.extend(rollback_initialization(applied,None))
			if rollback_errors:
				raise MemoryErrorWithCode("ROLLBACK_FAILED",f"{exc}; rollback issues: {'; '.join(rollback_errors)}") from exc
			if recovery is not None:
				raise MemoryErrorWithCode(exc.code if isinstance(exc,MemoryErrorWithCode) else "UPGRADE_ERROR",f"{exc}; failed runtime preserved at {recovery}") from exc
			raise
		finally:
			if staging is not None and staging.exists():
				remove_tree(staging)
		print(json.dumps(result,ensure_ascii=False,indent=2) if args.json else f"Harness runtime upgraded: {digest}")
		return 0
	except (OSError,UnicodeDecodeError,MemoryErrorWithCode,json.JSONDecodeError) as exc:
		code = exc.code if isinstance(exc,MemoryErrorWithCode) else "UPGRADE_ERROR"
		result = {"ok":False,"code":code,"error":str(exc)}
		if args.json:
			print(json.dumps(result,ensure_ascii=False,indent=2))
		else:
			print(f"Harness upgrade failed: {exc}",file=sys.stderr)
		return 1


if __name__ == "__main__":
	raise SystemExit(main())
