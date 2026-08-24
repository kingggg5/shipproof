#!/usr/bin/env python3
"""Preview and transactionally migrate the supported Harness v1 Markdown store."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from init_project import (
	GITIGNORE_BLOCK,
	MODEL_FILES,
	TEMPLATE_FILES,
	install_runtime,
	is_current_layout,
	parse_models,
	read_utf8,
	render_template,
	rollback_initialization,
	runtime_plan,
	source_tree_files,
	validate_target,
)
from memory_ops import (
	ID_PATTERN,
	PROJECT_ID_PATTERN,
	SHA256_PATTERN,
	MemoryErrorWithCode,
	atomic_replace,
	configure_utf8_stdio,
	empty_store,
	make_record,
	parse_time,
	path_is_link_or_junction,
	pretty_json,
	project_view_payloads,
	read_regular_file_bounded,
	repository_identity,
	sha256_bytes,
	target_file_lock,
	utc_now,
	validate_store,
)
from validate_portability import check_project, exact_managed_block


LEGACY_MARKDOWN_SCHEMAS = {
	"INDEX.md": 1,
	"CONFIG.md": 1,
	"CONTEXT.md": 3,
	"PREFERENCES.md": 1,
	"DECISIONS.md": 2,
	"WORKFLOW.md": 3,
}
LEGACY_STATE_SCHEMA = 1
MANAGED_START = "<!-- harness:start -->"
MANAGED_END = "<!-- harness:end -->"
LEGACY_GENERIC = """# Harness Generic Agent Launcher

When the user invokes Harness:

1. Read the nearest `AGENTS.md`.
2. Read `.harness/INDEX.md` and validate `.harness/STATE.json` when present.
3. Read the installed or supplied `skills/best-in-code/SKILL.md` completely.
4. Follow provider-neutral capability fallbacks; do not invent missing tools, memory, or isolated QA.

Canonical invocation: `Harness: <task>`.
"""
LEGACY_GENERIC_MINIMAL = """# Harness Generic Agent Launcher

Read the installed or supplied `skills/best-in-code/SKILL.md`.
"""
MAX_MIGRATION_INPUT_BYTES = 8 * 1024 * 1024
MAX_MIGRATION_TOTAL_BYTES = 64 * 1024 * 1024


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Migrate supported Harness v1 files with preview-bound human approval")
	parser.add_argument("--project", required=True)
	parser.add_argument("--models", default="all", help="Comma-separated codex,claude,gemini,generic or all")
	parser.add_argument("--dry-run", action="store_true", help="Preview only; emits the approval digest")
	parser.add_argument("--approve", help="Exact sha256 plan digest returned by --dry-run")
	parser.add_argument("--json", action="store_true")
	return parser.parse_args()


def markdown_schema(path: Path) -> int | None:
	match = re.search(r"^- Schema version:[ \t]*(\d+)[ \t]*$", read_utf8(path), re.MULTILINE)
	return int(match.group(1)) if match else None


def snapshot_paths(paths: list[Path]) -> dict[Path, bytes]:
	snapshot: dict[Path, bytes] = {}
	total = 0
	for path in dict.fromkeys(paths):
		data = read_regular_file_bounded(path, MAX_MIGRATION_INPUT_BYTES, "migration input")
		total += len(data)
		if total > MAX_MIGRATION_TOTAL_BYTES:
			raise MemoryErrorWithCode("MIGRATION_TOO_LARGE", f"Migration inputs exceed {MAX_MIGRATION_TOTAL_BYTES} bytes")
		snapshot[path] = data
	return snapshot


def snapshot_text(path: Path, snapshot: dict[Path, bytes]) -> str:
	try:
		return snapshot[path].decode("utf-8")
	except UnicodeDecodeError as exc:
		raise MemoryErrorWithCode("NON_UTF8", f"Refusing non-UTF-8 migration input: {path}") from exc


def snapshot_tree_digest(root: Path, snapshot: dict[Path, bytes]) -> str:
	digest = hashlib.sha256()
	for path in sorted(snapshot, key=lambda item: item.relative_to(root).as_posix()):
		relative = path.relative_to(root).as_posix().encode("utf-8")
		data = snapshot[path]
		digest.update(len(relative).to_bytes(4, "big")); digest.update(relative)
		digest.update(len(data).to_bytes(8, "big")); digest.update(data)
	return f"sha256:{digest.hexdigest()}"


def render_snapshot_template(path: Path, content: bytes, project_id: str, identity: dict[str, object]) -> bytes:
	try:
		text = content.decode("utf-8")
	except UnicodeDecodeError as exc:
		raise MemoryErrorWithCode("BUNDLE_INVALID", f"Bundled template is not UTF-8: {path}") from exc
	if path.name == "IDENTITY.json":
		return pretty_json(identity)
	if path.suffix.lower() == ".json":
		data = json.loads(text)
		if not isinstance(data, dict):
			raise MemoryErrorWithCode("BUNDLE_INVALID", f"Bundled JSON template must be an object: {path}")
		data["project_id"] = project_id
		return pretty_json(data)
	text = re.sub(r"^- Project ID(?: or GLOBAL)?:[ \t]*$", f"- Project ID: {project_id}", text, flags=re.MULTILINE)
	return text.encode("utf-8")


def require_legacy_layout(harness: Path, snapshot: dict[Path, bytes] | None = None) -> dict[str, Any]:
	def text(path: Path) -> str:
		return snapshot_text(path, snapshot) if snapshot is not None else read_utf8(path)

	for name, schema in LEGACY_MARKDOWN_SCHEMAS.items():
		path = harness / name
		match = re.search(r"^- Schema version:[ \t]*(\d+)[ \t]*$", text(path), re.MULTILINE) if path.is_file() and not path_is_link_or_junction(path) else None
		if match is None or int(match.group(1)) != schema:
			raise MemoryErrorWithCode("UNSUPPORTED_MIGRATION", f"Expected legacy {name} schema {schema}")
	state_path = harness / "STATE.json"
	if not state_path.is_file() or path_is_link_or_junction(state_path):
		raise MemoryErrorWithCode("UNSUPPORTED_MIGRATION", "Expected legacy STATE.json")
	try:
		state = json.loads(text(state_path))
	except json.JSONDecodeError as exc:
		raise MemoryErrorWithCode("UNSUPPORTED_MIGRATION", "Legacy STATE.json is invalid") from exc
	if not isinstance(state, dict) or state.get("schema_version") != LEGACY_STATE_SCHEMA:
		raise MemoryErrorWithCode("UNSUPPORTED_MIGRATION", "Only STATE.json schema 1 is supported")
	if (harness / "IDENTITY.json").exists() or (harness / "MEMORY.json").exists() or (harness / "runtime").exists():
		raise MemoryErrorWithCode("UNSUPPORTED_MIGRATION", "Mixed/partially migrated layouts require manual repair; no files were changed")
	if state.get("run_id") or state.get("state") not in {"INTAKE", "DONE"}:
		raise MemoryErrorWithCode("ACTIVE_RUN_MIGRATION_BLOCKED", "Finish or explicitly archive the active legacy run before migration")
	project_id = state.get("project_id")
	if not isinstance(project_id, str) or not PROJECT_ID_PATTERN.fullmatch(project_id):
		raise MemoryErrorWithCode("INVALID_PROJECT_ID", "Legacy STATE.json has no valid Project ID")
	for name in LEGACY_MARKDOWN_SCHEMAS:
		values = re.findall(r"^- Project ID(?: or GLOBAL)?:[ \t]*([^\r\n]+)$", text(harness / name), re.MULTILINE)
		if values and any(value.strip() not in {project_id, "GLOBAL"} for value in values):
			raise MemoryErrorWithCode("IDENTITY_CONFLICT", f"Legacy Project ID conflict in {name}")
	return state


def split_row(line: str) -> list[str]:
	value = line.strip()
	if value.startswith("|"):
		value = value[1:]
	if value.endswith("|"):
		value = value[:-1]
	cells: list[str] = []
	buffer: list[str] = []
	escaped = False
	for char in value:
		if escaped:
			buffer.append(char)
			escaped = False
		elif char == "\\":
			escaped = True
		elif char == "|":
			cells.append("".join(buffer).strip())
			buffer = []
		else:
			buffer.append(char)
	if escaped:
		buffer.append("\\")
	cells.append("".join(buffer).strip())
	return cells


def header_key(value: str) -> str:
	return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def markdown_tables(path: Path, snapshot: dict[Path, bytes] | None = None) -> list[tuple[list[str], list[dict[str, str]]]]:
	lines = (snapshot_text(path, snapshot) if snapshot is not None else read_utf8(path)).splitlines()
	result: list[tuple[list[str], list[dict[str, str]]]] = []
	index = 0
	while index + 1 < len(lines):
		if not lines[index].lstrip().startswith("|") or not re.fullmatch(r"[|:\- \t]+", lines[index + 1].strip()):
			index += 1
			continue
		headers = [header_key(cell) for cell in split_row(lines[index])]
		rows: list[dict[str, str]] = []
		index += 2
		while index < len(lines) and lines[index].lstrip().startswith("|"):
			cells = split_row(lines[index])
			if any(cells):
				cells += [""] * (len(headers) - len(cells))
				rows.append(dict(zip(headers, cells)))
			index += 1
		result.append((headers, rows))
	return result


def find_rows(path: Path, first_header: str, required: set[str], snapshot: dict[Path, bytes] | None = None) -> list[dict[str, str]]:
	for headers, rows in markdown_tables(path, snapshot):
		if headers and headers[0] == first_header and required.issubset(headers):
			return rows
	return []


def stable_key(prefix: str, value: str) -> str:
	clean = re.sub(r"[^a-z0-9._/-]+", "-", value.casefold()).strip("-")
	return f"{prefix}.{clean or sha256_bytes(value.encode('utf-8'))[:12]}"


def safe_time(value: str, fallback: str) -> str:
	if not value:
		return fallback
	try:
		parse_time(value)
		return value
	except MemoryErrorWithCode:
		return fallback


def record_namespace(spec: dict[str, str]) -> argparse.Namespace:
	return argparse.Namespace(
		kind=spec["kind"], key=spec["key"], value=spec["value"], applies=spec.get("applies", "always"),
		tag=[], authority=spec.get("authority"), source=spec.get("source"),
		source_fingerprint=spec.get("source_fingerprint", ""), verification=spec.get("verification"),
		last_verified=spec.get("last_verified"), confidence=spec.get("confidence", "confirmed"),
		review_trigger=spec.get("review_trigger", ""), run_id="",
	)


def collect_legacy_specs(harness: Path, snapshot: dict[Path, bytes] | None = None) -> tuple[list[dict[str, str]], list[dict[str, str]], list[str]]:
	now = utc_now()
	specs: list[dict[str, str]] = []
	tombstones: list[dict[str, str]] = []
	warnings: list[str] = []
	context = harness / "CONTEXT.md"
	for row in find_rows(context, "id", {"kind", "key", "statement", "source", "verification policy", "status"}, snapshot):
		legacy_id = row.get("id", "")
		if not legacy_id:
			continue
		verification = row.get("verification policy") or "on-read"
		fingerprint = row.get("source fingerprint version", "")
		status = row.get("status") or "Stale"
		authority = "repository" if row.get("source", "").startswith("file:") and verification == "on-source-change" and SHA256_PATTERN.fullmatch(fingerprint) else "human-project"
		if verification == "on-source-change" and authority != "repository":
			verification = "on-read"
			status = "Stale"
			warnings.append(f"{legacy_id}: invalid source fingerprint was downgraded to Stale/on-read")
		specs.append({
			"legacy_id": legacy_id, "kind": row.get("kind") or "fact", "key": row.get("key") or stable_key("legacy", legacy_id),
			"value": row.get("statement", ""), "source": row.get("source") or f"migration:CONTEXT.md:{legacy_id}",
			"source_fingerprint": fingerprint if authority == "repository" else "", "verification": verification,
			"last_verified": safe_time(row.get("last verified", ""), now), "confidence": row.get("confidence") or "legacy",
			"authority": authority, "status": status, "supersedes_legacy": "", "replaced_by_legacy": row.get("replaced by", ""),
		})
	unsupported = {
		"area": "Architecture map",
		"component": "Technology and versions",
		"command": "Reproducible commands",
		"workload dataset": "Measured workloads and budgets",
	}
	for first, label in unsupported.items():
		rows = find_rows(context, first, {first}, snapshot)
		if rows:
			raise MemoryErrorWithCode("MANUAL_MIGRATION_REQUIRED", f"{label} contains legacy rows; review and convert them to atomic verified records before migration")
	question_rows = find_rows(context, "id", {"question", "state"}, snapshot)
	if question_rows:
		warnings.append(f"{len(question_rows)} open-question row(s) remain in the byte-exact archive; they are not durable truth")
	for row in find_rows(context, "id", {"contract invariant", "owner", "evidence", "verification policy", "status"}, snapshot):
		legacy_id = row.get("id", "")
		if legacy_id:
			specs.append({"legacy_id":legacy_id,"kind":"contract","key":stable_key("contract",legacy_id),"value":row.get("contract invariant", ""),"source":row.get("evidence") or f"migration:CONTEXT.md:{legacy_id}","verification":"on-read","last_verified":now,"confidence":"legacy","authority":"human-project","status":row.get("status") or "Stale","supersedes_legacy":"","replaced_by_legacy":""})
	for row in find_rows(context, "id", {"risk", "impact", "mitigation", "evidence", "status"}, snapshot):
		legacy_id = row.get("id", "")
		if legacy_id:
			value = f"{row.get('risk', '')}; impact: {row.get('impact', '')}; mitigation: {row.get('mitigation', '')}"
			specs.append({"legacy_id":legacy_id,"kind":"risk","key":stable_key("risk",legacy_id),"value":value,"source":row.get("evidence") or f"migration:CONTEXT.md:{legacy_id}","verification":"on-read","last_verified":now,"confidence":"legacy","authority":"human-project","status":row.get("status") or "Stale","supersedes_legacy":"","replaced_by_legacy":""})
	preferences = harness / "PREFERENCES.md"
	for row in find_rows(preferences, "id", {"key", "value", "scope", "applies when", "status", "supersedes", "replaced by"}, snapshot):
		legacy_id = row.get("id", "")
		if not legacy_id:
			continue
		if row.get("scope", "project").casefold() != "project":
			raise MemoryErrorWithCode("MANUAL_MIGRATION_REQUIRED", f"{legacy_id}: global legacy preference requires a separately authorized global migration")
		specs.append({"legacy_id":legacy_id,"kind":"preference","key":row.get("key", ""),"value":row.get("value", ""),"applies":row.get("applies when") or "always","source":f"migration:PREFERENCES.md:{legacy_id}","verification":"manual","last_verified":safe_time(row.get("last confirmed", ""),now),"confidence":"confirmed","authority":"human-project","status":row.get("status") or "Active","review_trigger":row.get("review trigger", ""),"supersedes_legacy":row.get("supersedes", ""),"replaced_by_legacy":row.get("replaced by", "")})
	for row in find_rows(preferences, "id", {"scope", "revoked at", "cache sync"}, snapshot):
		if row.get("id"):
			tombstones.append(row)
	decisions = harness / "DECISIONS.md"
	for row in find_rows(decisions, "id", {"date", "decision", "status", "supersedes", "replaced by"}, snapshot):
		legacy_id = row.get("id", "")
		if legacy_id:
			specs.append({"legacy_id":legacy_id,"kind":"decision","key":stable_key("decision",legacy_id),"value":row.get("decision", ""),"source":row.get("evidence tradeoffs") or f"migration:DECISIONS.md:{legacy_id}","verification":"manual","last_verified":safe_time(row.get("date", ""),now),"confidence":"confirmed","authority":"human-project","status":row.get("status") or "Active","review_trigger":row.get("revisit condition", ""),"supersedes_legacy":row.get("supersedes", ""),"replaced_by_legacy":row.get("replaced by", "")})
	legacy_ids = [spec["legacy_id"] for spec in specs]
	if len(legacy_ids) != len(set(legacy_ids)):
		raise MemoryErrorWithCode("MEMORY_CONFLICT", "Duplicate legacy record IDs require human resolution")
	return specs, tombstones, warnings


def build_store(project_id: str, specs: list[dict[str, str]], legacy_tombstones: list[dict[str, str]], plan_digest: str) -> tuple[dict[str, Any], dict[str, str], dict[str, str]]:
	store = empty_store(project_id)
	remaining = {spec["legacy_id"]: spec for spec in specs}
	id_map: dict[str, str] = {}
	records: list[dict[str, Any]] = []
	record_by_legacy: dict[str, dict[str, Any]] = {}
	while remaining:
		progress = False
		for legacy_id, spec in list(remaining.items()):
			supersedes_legacy = spec.get("supersedes_legacy", "")
			if supersedes_legacy and supersedes_legacy not in id_map:
				continue
			record = make_record(record_namespace(spec), "project", supersedes=id_map.get(supersedes_legacy, ""))
			status = spec.get("status", "Active")
			if status not in {"Active", "Stale", "Conflict", "Superseded"}:
				status = "Stale"
			record["status"] = status
			records.append(record)
			record_by_legacy[legacy_id] = record
			id_map[legacy_id] = record["id"]
			del remaining[legacy_id]
			progress = True
		if not progress:
			raise MemoryErrorWithCode("MEMORY_CONFLICT", f"Unresolved/cyclic legacy supersession links: {sorted(remaining)}")
	for spec in specs:
		record = record_by_legacy[spec["legacy_id"]]
		replacement = spec.get("replaced_by_legacy", "")
		if replacement:
			if replacement not in id_map:
				raise MemoryErrorWithCode("MEMORY_CONFLICT", f"Missing legacy replacement {replacement}")
			record["replaced_by"] = id_map[replacement]
	store["records"] = records
	tombstone_map: dict[str, str] = {}
	for item in legacy_tombstones:
		legacy_id = item["id"]
		prefix = "PREF" if legacy_id.upper().startswith("PREF") else "DEC" if legacy_id.upper().startswith("DEC") else "FACT"
		canonical_id = f"{prefix}-P-{sha256_bytes(('legacy-tombstone:'+legacy_id).encode('utf-8'))[:16]}"
		if not ID_PATTERN.fullmatch(canonical_id):
			raise MemoryErrorWithCode("MIGRATION_INVALID", f"Cannot map tombstone {legacy_id}")
		tombstone_map[legacy_id] = canonical_id
		store["tombstones"].append({"id":canonical_id,"scope":"project","revoked_at":safe_time(item.get("revoked at", ""),utc_now()),"cache_sync":"NOT_CONFIGURED"})
	if records or legacy_tombstones:
		store["revision"] = 1
		store["last_transaction"] = {"id":f"TX-00000001-{sha256_bytes(('migration:'+plan_digest).encode('utf-8'))[:12]}","operation":"migrate-v1","record_id":"MIGRATION","before_revision":0,"after_revision":1,"committed_at":utc_now()}
	errors = validate_store(store, project_id)
	if errors:
		raise MemoryErrorWithCode("MIGRATION_INVALID", "; ".join(errors))
	return store, id_map, tombstone_map


def plan_digest(
	project: Path,
	identity: dict[str, object],
	paths: list[Path],
	input_snapshot: dict[Path, bytes],
	skill_root: Path,
	skill_snapshot: dict[Path, bytes],
	bundle_paths: list[Path],
	bundle_snapshot: dict[Path, bytes],
) -> str:
	digest = hashlib.sha256()
	stable_identity = {
		"schema_version": identity["schema_version"],
		"project_id": identity["project_id"],
		"logical_scope": identity["logical_scope"],
		"repository": identity["repository"],
	}
	for label, value in (
		("canonical_project_path", str(project)),
		("repository_identity", json.dumps(stable_identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"))),
	):
		label_bytes = label.encode("utf-8")
		value_bytes = value.encode("utf-8")
		digest.update(len(label_bytes).to_bytes(4, "big")); digest.update(label_bytes)
		digest.update(len(value_bytes).to_bytes(8, "big")); digest.update(value_bytes)
	for path in sorted(paths, key=lambda item: item.relative_to(project).as_posix()):
		relative = path.relative_to(project).as_posix().encode("utf-8")
		data = input_snapshot[path]
		digest.update(len(relative).to_bytes(4, "big")); digest.update(relative)
		digest.update(len(data).to_bytes(8, "big")); digest.update(data)
	for path in sorted(skill_snapshot, key=lambda item: item.relative_to(skill_root).as_posix()):
		relative = path.relative_to(skill_root).as_posix().encode("utf-8")
		data = skill_snapshot[path]
		digest.update(len(relative).to_bytes(4, "big")); digest.update(relative)
		digest.update(len(data).to_bytes(8, "big")); digest.update(data)
	for path in sorted(bundle_paths,key=lambda item:str(item)):
		data = bundle_snapshot[path]; label = path.name.encode("utf-8")
		digest.update(len(label).to_bytes(4,"big")); digest.update(label)
		digest.update(len(data).to_bytes(8,"big")); digest.update(data)
	return f"sha256:{digest.hexdigest()}"


def managed_adapter(existing: bytes, desired_text: str, name: str) -> bytes:
	newline = b"\r\n" if b"\r\n" in existing else b"\n"
	desired = desired_text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n").encode("utf-8").replace(b"\n", newline) + newline
	start_marker = MANAGED_START.encode("utf-8")
	end_marker = MANAGED_END.encode("utf-8")
	start_count = existing.count(start_marker)
	end_count = existing.count(end_marker)
	if start_count or end_count:
		if start_count != 1 or end_count != 1:
			raise MemoryErrorWithCode("MANAGED_BLOCK_INVALID", f"Expected exactly one Harness managed block in {name}")
		start = existing.find(start_marker)
		end = existing.find(end_marker)
		start_after = start + len(start_marker)
		end_after = end + len(end_marker)
		markers_are_lines = (
			(start == 0 or existing[start - 1:start] == b"\n")
			and existing[start_after:start_after + 1] in {b"\r", b"\n"}
			and existing[end - 1:end] == b"\n"
			and (end_after == len(existing) or existing[end_after:end_after + 1] in {b"\r", b"\n"})
		)
		if end <= start or not markers_are_lines:
			raise MemoryErrorWithCode("MANAGED_BLOCK_INVALID", f"Harness managed block markers are out of order in {name}")
		end = end_after
		if existing[end:end + len(newline)] == newline:
			end += len(newline)
		return existing[:start] + desired + existing[end:]
	if name == "AI-HARNESS.md" and b"# Harness Generic Agent Launcher" in existing:
		normalized_existing = existing.replace(b"\r\n",b"\n").replace(b"\r",b"\n").strip()
		known_legacy_variants = {
			LEGACY_GENERIC.encode("utf-8").strip(),
			LEGACY_GENERIC_MINIMAL.encode("utf-8").strip(),
		}
		if normalized_existing in known_legacy_variants:
			return desired
		raise MemoryErrorWithCode("MANAGED_BLOCK_INVALID", "Unmarked AI-HARNESS.md contains custom content; merge it manually")
	if not existing:
		return desired
	raise MemoryErrorWithCode("MANAGED_BLOCK_INVALID", f"Cannot safely locate legacy Harness block in {name}")


def migrated_state(old: dict[str, Any], project_id: str, revision: int) -> dict[str, Any]:
	selected = old.get("selected_scale")
	if not old.get("run_id"):
		selected = None
	return {
		"schema_version":2,"state_revision":0,"memory_revision_seen":revision,"project_id":project_id,
		"run_id":"","operation":"start","requested_scale":old.get("requested_scale","auto"),"selected_scale":selected,
		"selection_reason":old.get("selection_reason", ""),"state":"INTAKE","next_action":"","active_blocker_id":None,
		"attempts_for_active_blocker":0,"discovery_cycles":0,"total_transitions":0,
		"approvals":{"plan":"NOT_REQUIRED","design":"NOT_REQUIRED","decision":"NOT_REQUIRED","acceptance":"PENDING"},
		"cache_state":"UNAVAILABLE","created_at":old.get("created_at") or utc_now(),"updated_at":utc_now(),
	}


def main() -> int:
	configure_utf8_stdio()
	args = parse_args()
	try:
		project = Path(args.project).expanduser().resolve(strict=True)
		if not project.is_dir():
			raise MemoryErrorWithCode("PROJECT_UNAVAILABLE", f"Project is not a directory: {project}")
		harness = project / ".harness"
		if is_current_layout(harness):
			result = {"ok":True,"result":"ALREADY_CURRENT","project":str(project),"dry_run":args.dry_run,"events":[]}
			print(json.dumps(result,ensure_ascii=False,indent=2) if args.json else "Harness project is already current")
			return 0
		models = parse_models(args.models)
		script_root = Path(__file__).resolve().parent
		skill_root = script_root.parent
		plugin_root = skill_root.parents[1]
		template_root = skill_root / "assets" / "templates"
		adapter_root = plugin_root / "adapters" / "project"
		legacy_paths = [harness / name for name in (*LEGACY_MARKDOWN_SCHEMAS, "STATE.json")]
		for model in models:
			path = project / MODEL_FILES[model][0]
			if path.exists():
				validate_target(path, project)
				read_utf8(path)
				if path not in legacy_paths:
					legacy_paths.append(path)
		if (project / ".gitignore").is_file():
			legacy_paths.append(project / ".gitignore")
		for path in legacy_paths:
			if path_is_link_or_junction(path) or not path.is_file():
				raise MemoryErrorWithCode("SYMLINK_REJECTED", f"Migration input must be a regular file: {path}")
		bundle_paths = [adapter_root / MODEL_FILES[model][1] for model in models] + [plugin_root / ".codex-plugin" / "plugin.json"]
		for path in bundle_paths:
			if not path.is_file() or path_is_link_or_junction(path):
				raise MemoryErrorWithCode("BUNDLE_INVALID", f"Missing or linked migration bundle input: {path}")
		input_snapshot = snapshot_paths(legacy_paths)
		old_state = require_legacy_layout(harness, input_snapshot)
		bundle_snapshot = snapshot_paths(bundle_paths)
		skill_files = source_tree_files(skill_root)
		skill_snapshot = snapshot_paths(skill_files)
		source_digest = snapshot_tree_digest(skill_root, skill_snapshot)
		try:
			plugin_manifest = json.loads(snapshot_text(plugin_root / ".codex-plugin" / "plugin.json", bundle_snapshot))
		except json.JSONDecodeError as exc:
			raise MemoryErrorWithCode("BUNDLE_INVALID", "Plugin manifest is invalid JSON") from exc
		if not isinstance(plugin_manifest, dict) or not isinstance(plugin_manifest.get("version"), str) or not plugin_manifest["version"]:
			raise MemoryErrorWithCode("BUNDLE_INVALID", "Plugin manifest has no valid version")
		project_id = old_state["project_id"]
		planned_identity = repository_identity(project, project_id)
		digest = plan_digest(project, planned_identity, legacy_paths, input_snapshot, skill_root, skill_snapshot, bundle_paths, bundle_snapshot)
		specs, legacy_tombstones, warnings = collect_legacy_specs(harness, input_snapshot)
		store, id_map, tombstone_map = build_store(project_id, specs, legacy_tombstones, digest)
		state = migrated_state(old_state, project_id, store["revision"])
		archive_relative = Path("migrations") / digest.removeprefix("sha256:")[:16] / "legacy"
		events: list[dict[str, str]] = []
		writes: list[tuple[Path, bytes, bytes | None]] = []
		for source in legacy_paths:
			relative = source.relative_to(project)
			target = harness / archive_relative / relative
			validate_target(target, project)
			writes.append((target, input_snapshot[source], None))
			events.append({"path":str(target),"action":"archive","source":str(source)})
		current_payloads = {
			name: render_snapshot_template(template_root / name, skill_snapshot[template_root / name], project_id, planned_identity)
			for name in TEMPLATE_FILES
		}
		current_payloads["IDENTITY.json"] = pretty_json(planned_identity)
		current_payloads["MEMORY.json"] = pretty_json(store)
		current_payloads["STATE.json"] = pretty_json(state)
		current_payloads.update(project_view_payloads(store))
		for name, content in current_payloads.items():
			target = harness / name
			validate_target(target, project)
			previous = input_snapshot.get(target) if target.exists() else None
			writes.append((target, content, previous))
			events.append({"path":str(target),"action":"replace" if previous is not None else "create"})
		for model in models:
			target_name, fragment_name = MODEL_FILES[model]
			target = project / target_name
			validate_target(target, project)
			previous = input_snapshot.get(target) if target.exists() else None
			content = managed_adapter(previous or b"", snapshot_text(adapter_root / fragment_name, bundle_snapshot), target_name)
			writes.append((target, content, previous))
			events.append({"path":str(target),"action":"update managed Harness block"})
		gitignore = project / ".gitignore"
		validate_target(gitignore, project)
		previous_ignore = input_snapshot.get(gitignore) if gitignore.exists() else None
		if b"# harness local-only data" not in (previous_ignore or b""):
			newline = b"\r\n" if previous_ignore and b"\r\n" in previous_ignore else b"\n"
			block = GITIGNORE_BLOCK.encode("utf-8").replace(b"\n", newline)
			content = (previous_ignore or b"") + (newline if previous_ignore and not previous_ignore.endswith((b"\n",b"\r")) else b"") + block
			writes.append((gitignore,content,previous_ignore))
		migration = {
			"schema_version":1,"status":"complete","source_layout":"harness-markdown-v1","plan_digest":digest,
			"applied_at":utc_now(),"archive":archive_relative.as_posix(),"legacy_record_id_map":id_map,
			"legacy_tombstone_id_map":tombstone_map,"warnings":warnings,
		}
		migration_path = harness / "MIGRATION.json"
		validate_target(migration_path, project)
		writes.append((migration_path,pretty_json(migration),None))
		events.append({"path":str(migration_path),"action":"create migration ledger"})
		runtime_events: list[dict[str, str]] = []
		runtime = runtime_plan(project, skill_root, plugin_root, runtime_events, source_digest, plugin_manifest["version"])
		events.extend(runtime_events)
		result = {"ok":True,"result":"PREVIEW" if args.dry_run else "MIGRATED","project":str(project),"project_id":project_id,"plan_digest":digest,"approval_required":digest,"dry_run":args.dry_run,"records":len(store["records"]),"tombstones":len(store["tombstones"]),"warnings":warnings,"events":events}
		if args.dry_run:
			print(json.dumps(result,ensure_ascii=False,indent=2) if args.json else f"Migration preview: approve {digest}")
			return 0
		if args.approve != digest:
			raise MemoryErrorWithCode("APPROVAL_REQUIRED", f"Re-run with --approve {digest} after reviewing the dry-run")
		applied: list[tuple[Path, bytes, bytes | None]] = []
		installed_runtime = None
		try:
			with target_file_lock(harness / "MEMORY.json"):
				if runtime:
					installed_runtime = install_runtime(runtime, skill_root)
				for path, content, expected in writes:
					path.parent.mkdir(parents=True, exist_ok=True)
					atomic_replace(path,content,expected=expected)
					applied.append((path,content,expected))
				validation_errors: list[str] = []
				for model in models:
					target_name, fragment_name = MODEL_FILES[model]
					target = project / target_name
					expected_adapter = snapshot_text(adapter_root / fragment_name, bundle_snapshot)
					if not target.is_file() or path_is_link_or_junction(target) or not exact_managed_block(read_utf8(target), expected_adapter):
						validation_errors.append(f"Selected project adapter missing or invalid after migration: {target_name}")
				check_project(project, require_adapters=set(models) == set(MODEL_FILES), errors=validation_errors)
				if validation_errors:
					raise MemoryErrorWithCode("MIGRATION_VALIDATION_FAILED", "; ".join(validation_errors))
		except (OSError, UnicodeDecodeError, MemoryErrorWithCode) as exc:
			with target_file_lock(harness / "MEMORY.json"):
				rollback_errors = rollback_initialization(applied, installed_runtime)
			if rollback_errors:
				raise MemoryErrorWithCode("ROLLBACK_FAILED", f"{exc}; rollback issues: {'; '.join(rollback_errors)}") from exc
			raise
		print(json.dumps(result,ensure_ascii=False,indent=2) if args.json else f"Harness migration completed: {digest}")
		return 0
	except (OSError, UnicodeDecodeError, MemoryErrorWithCode, json.JSONDecodeError) as exc:
		code = exc.code if isinstance(exc, MemoryErrorWithCode) else "MIGRATION_ERROR"
		result = {"ok":False,"code":code,"error":str(exc)}
		if args.json:
			print(json.dumps(result,ensure_ascii=False,indent=2))
		else:
			print(f"Harness migration failed: {exc}",file=sys.stderr)
		return 1


if __name__ == "__main__":
	raise SystemExit(main())
