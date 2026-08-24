#!/usr/bin/env python3
"""Dependency-free structural and initialized-project checks for Harness."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from memory_ops import PROJECT_ID_PATTERN, MemoryErrorWithCode, configure_utf8_stdio, parse_time, path_is_link_or_junction, validate_project_memory


ALLOWED_OPERATIONS = {"start", "resume", "review", "init", "memory"}
ALLOWED_SCALES = {"auto", "quick", "standard", "full"}
ALLOWED_STATES = {
	"INTAKE", "DISCOVERY", "PLAN", "WAITING_PLAN", "DESIGN", "WAITING_DESIGN",
	"BUILD", "INTEGRATE", "VERIFY", "REWORK", "WAITING_DECISION",
	"WAITING_ACCEPTANCE", "DONE", "BLOCKED",
}

REQUIRED_FILES = (
	".codex-plugin/plugin.json",
	".claude-plugin/plugin.json",
	"gemini-extension.json",
	"README.md",
	"adapters/project/AGENTS.md.fragment",
	"adapters/project/CLAUDE.md.fragment",
	"adapters/project/GEMINI.md.fragment",
	"adapters/project/GENERIC.md",
	"skills/best-in-code/SKILL.md",
	"skills/best-in-code/agents/openai.yaml",
	"skills/best-in-code/references/mode-routing.md",
	"skills/best-in-code/references/workflow-graph.md",
	"skills/best-in-code/references/capability-contract.md",
	"skills/best-in-code/references/provider-adapters.md",
	"skills/best-in-code/references/memory-loop.md",
	"skills/best-in-code/references/harness-evaluation.md",
	"skills/best-in-code/scripts/init_project.py",
	"skills/best-in-code/scripts/memory_ops.py",
	"skills/best-in-code/scripts/migrate_project.py",
	"skills/best-in-code/scripts/run_memory_evals.py",
	"skills/best-in-code/scripts/upgrade_project.py",
	"skills/best-in-code/scripts/validate_portability.py",
	"skills/best-in-code/assets/evals/router-cases.json",
	"skills/best-in-code/assets/evals/memory-cases.json",
	"skills/best-in-code/assets/templates/IDENTITY.json",
	"skills/best-in-code/assets/templates/MEMORY.json",
	"skills/best-in-code/assets/templates/INDEX.md",
	"skills/best-in-code/assets/templates/CONFIG.md",
	"skills/best-in-code/assets/templates/CONTEXT.md",
	"skills/best-in-code/assets/templates/PREFERENCES.md",
	"skills/best-in-code/assets/templates/DECISIONS.md",
	"skills/best-in-code/assets/templates/STATE.json",
	"skills/best-in-code/assets/templates/WORKFLOW.md",
	"skills/best-in-code/assets/templates/ROLE-PACKET.md",
	"skills/best-in-code/assets/templates/EVIDENCE.md",
	"skills/best-in-code/assets/templates/EVALUATION.md",
)

SCHEMA_EXPECTATIONS = {
	"INDEX.md": 2,
	"CONFIG.md": 2,
	"CONTEXT.md": 4,
	"PREFERENCES.md": 2,
	"DECISIONS.md": 3,
	"WORKFLOW.md": 4,
	"ROLE-PACKET.md": 1,
	"EVIDENCE.md": 1,
	"EVALUATION.md": 1,
	"DESIGN.md": 2,
}
MANAGED_START = "<!-- harness:start -->"
MANAGED_END = "<!-- harness:end -->"


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Validate Harness portability and an optional initialized project")
	parser.add_argument("--root", help="Harness plugin root; defaults to script-derived root")
	parser.add_argument("--project", help="Optional initialized project to validate")
	parser.add_argument("--project-only", action="store_true", help="Validate only --project, without scanning the package root")
	parser.add_argument("--require-adapters", action="store_true", help="Require all four project adapters")
	parser.add_argument("--json", action="store_true", help="Print structured output")
	return parser.parse_args()


def load_json(path: Path, errors: list[str]) -> Any:
	try:
		return json.loads(path.read_text(encoding="utf-8"))
	except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
		errors.append(f"Invalid UTF-8 JSON {path}: {exc}")
		return None


def load_text(path: Path, errors: list[str]) -> str | None:
	try:
		return path.read_text(encoding="utf-8")
	except (OSError, UnicodeDecodeError) as exc:
		errors.append(f"Invalid UTF-8 text {path}: {exc}")
		return None


def exact_managed_block(content: str, expected: str) -> bool:
	normalized = content.replace("\r\n", "\n").replace("\r", "\n")
	normalized_expected = expected.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
	if normalized.count(MANAGED_START) != 1 or normalized.count(MANAGED_END) != 1:
		return False
	start = normalized.find(MANAGED_START)
	end = normalized.find(MANAGED_END)
	start_after = start + len(MANAGED_START)
	end_after = end + len(MANAGED_END)
	if end <= start:
		return False
	if (
		(start != 0 and normalized[start - 1] != "\n") or normalized[start_after:start_after + 1] != "\n"
		or normalized[end - 1:end] != "\n" or (end_after != len(normalized) and normalized[end_after] != "\n")
	):
		return False
	return normalized[start:end_after] == normalized_expected


def check_required(root: Path, errors: list[str]) -> None:
	for relative in REQUIRED_FILES:
		if not (root / relative).is_file():
			errors.append(f"Missing required file: {relative}")


def check_tree_hygiene(root: Path, errors: list[str]) -> None:
	for path in root.rglob("*"):
		if path_is_link_or_junction(path):
			errors.append(f"Package contains unsupported symlink: {path.relative_to(root)}")
		if path.name == "__pycache__" or path.suffix.lower() == ".pyc":
			errors.append(f"Package contains generated Python cache: {path.relative_to(root)}")


def check_json_files(root: Path, errors: list[str]) -> None:
	for path in root.rglob("*.json"):
		load_json(path, errors)


def check_skill(root: Path, errors: list[str]) -> None:
	path = root / "skills" / "best-in-code" / "SKILL.md"
	if not path.is_file():
		return
	content = path.read_text(encoding="utf-8")
	if len(content.splitlines()) > 500:
		errors.append("SKILL.md exceeds 500 lines")
	match = re.match(r"^---\n(.*?)\n---\n", content, re.DOTALL)
	if not match:
		errors.append("SKILL.md frontmatter is missing or malformed")
		return
	frontmatter = match.group(1)
	if not re.search(r"^name:[ \t]*best-in-code[ \t]*$", frontmatter, re.MULTILINE):
		errors.append("SKILL.md name must be best-in-code")
	description = re.search(r"^description:[ \t]*(.+)$", frontmatter, re.MULTILINE)
	if not description or len(description.group(1).strip()) < 80:
		errors.append("SKILL.md description must include specific trigger guidance")
	if "flowchart " in content:
		errors.append("SKILL.md must not duplicate the canonical graph")


def check_openai_yaml(root: Path, errors: list[str]) -> None:
	path = root / "skills" / "best-in-code" / "agents" / "openai.yaml"
	if not path.is_file():
		return
	content = path.read_text(encoding="utf-8")
	if any(line.startswith("\t") for line in content.splitlines()):
		errors.append("openai.yaml must use spaces because YAML forbids tab indentation")
	match = re.search(r'^\s*short_description:\s*"([^"]+)"', content, re.MULTILINE)
	if not match or not 25 <= len(match.group(1)) <= 64:
		errors.append("openai.yaml short_description must be 25-64 characters")


def check_links(root: Path, errors: list[str]) -> None:
	link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
	for path in root.rglob("*.md"):
		content = path.read_text(encoding="utf-8")
		for target in link_pattern.findall(content):
			clean = target.strip().strip("<>").split("#", 1)[0]
			if not clean or re.match(r"^[a-z][a-z0-9+.-]*:", clean, re.IGNORECASE):
				continue
			if not (path.parent / clean).resolve().exists():
				errors.append(f"Broken relative link in {path.relative_to(root)}: {target}")


def check_no_personal_paths(root: Path, errors: list[str]) -> None:
	pattern = re.compile(r"(?i)([a-z]:[\\/](?:users|documents and settings)[\\/]|/(?:users|home)/[^/\s]+/)")
	for path in root.rglob("*"):
		if not path.is_file() or path.suffix.lower() not in {".md", ".json", ".yaml", ".yml", ".py", ".fragment"}:
			continue
		if pattern.search(path.read_text(encoding="utf-8")):
			errors.append(f"Personal absolute path found in {path.relative_to(root)}")


def check_one_graph(root: Path, errors: list[str]) -> None:
	owners = [path.relative_to(root).as_posix() for path in root.rglob("*.md") if re.search(r"^flowchart\s", path.read_text(encoding="utf-8"), re.MULTILINE)]
	expected = ["skills/best-in-code/references/workflow-graph.md"]
	if owners != expected:
		errors.append(f"Canonical graph must exist only in workflow-graph.md; found {owners}")


def check_templates(root: Path, errors: list[str]) -> None:
	template_root = root / "skills" / "best-in-code" / "assets" / "templates"
	for name, expected in SCHEMA_EXPECTATIONS.items():
		path = template_root / name
		if not path.is_file():
			continue
		match = re.search(r"^- Schema version:[ \t]*(\d+)[ \t]*$", path.read_text(encoding="utf-8"), re.MULTILINE)
		if not match or int(match.group(1)) != expected:
			errors.append(f"{name} must declare schema version {expected}")
	state = load_json(template_root / "STATE.json", errors)
	if isinstance(state, dict):
		if state.get("schema_version") != 2:
			errors.append("STATE.json schema_version must be 2")
		for field in ("state_revision", "memory_revision_seen"):
			if not isinstance(state.get(field), int) or state.get(field, -1) < 0:
				errors.append(f"STATE.json {field} must be a non-negative integer")
		if state.get("operation") not in ALLOWED_OPERATIONS:
			errors.append("STATE.json has invalid operation")
		if state.get("requested_scale") not in ALLOWED_SCALES:
			errors.append("STATE.json has invalid requested_scale")
		if state.get("selected_scale") is not None and state.get("selected_scale") not in ALLOWED_SCALES - {"auto"}:
			errors.append("STATE.json has invalid selected_scale")
		if state.get("state") not in ALLOWED_STATES or not isinstance(state.get("next_action"), str):
			errors.append("STATE.json has invalid state or next_action")
	identity = load_json(template_root / "IDENTITY.json", errors)
	if isinstance(identity, dict) and identity.get("schema_version") != 1:
		errors.append("IDENTITY.json schema_version must be 1")
	memory = load_json(template_root / "MEMORY.json", errors)
	if isinstance(memory, dict):
		if memory.get("schema_version") != 1 or memory.get("revision") != 0:
			errors.append("MEMORY.json must start at schema 1 revision 0")
		if memory.get("records") != [] or memory.get("tombstones") != []:
			errors.append("MEMORY.json template must start empty")


def check_adapters(root: Path, errors: list[str]) -> None:
	adapter_root = root / "adapters" / "project"
	checks = {
		"AGENTS.md.fragment": ".harness/runtime/SKILL.md",
		"CLAUDE.md.fragment": "@AGENTS.md",
		"GEMINI.md.fragment": "@./AGENTS.md",
		"GENERIC.md": ".harness/runtime/SKILL.md",
	}
	for name, marker in checks.items():
		path = adapter_root / name
		if not path.is_file() or marker not in path.read_text(encoding="utf-8"):
			errors.append(f"Adapter missing required canonical pointer: {name}")


def check_fixtures(root: Path, errors: list[str]) -> None:
	eval_root = root / "skills" / "best-in-code" / "assets" / "evals"
	router = load_json(eval_root / "router-cases.json", errors)
	if isinstance(router, dict):
		cases = router.get("cases", [])
		ids = [case.get("id") for case in cases if isinstance(case, dict)]
		if len(ids) < 10 or len(ids) != len(set(ids)):
			errors.append("Router fixtures need at least 10 unique cases")
		for case in cases:
			if case.get("expected_operation") not in ALLOWED_OPERATIONS:
				errors.append(f"Invalid router operation in {case.get('id')}")
			scale = case.get("expected_scale")
			if scale is not None and scale not in ALLOWED_SCALES - {"auto"}:
				errors.append(f"Invalid router scale in {case.get('id')}")
	memory = load_json(eval_root / "memory-cases.json", errors)
	if isinstance(memory, dict):
		cases = memory.get("cases", [])
		ids = [case.get("id") for case in cases if isinstance(case, dict)]
		if ids != [f"M{number:02d}" for number in range(1, 42)]:
			errors.append("Memory fixtures must contain ordered unique M01-M41 cases")
		for case in cases:
			if not all(field in case for field in ("setup", "operation", "expected", "prohibited")):
				errors.append(f"Memory fixture {case.get('id')} lacks executable input/oracle fields")


def check_manifests(root: Path, errors: list[str]) -> None:
	codex = load_json(root / ".codex-plugin" / "plugin.json", errors)
	claude = load_json(root / ".claude-plugin" / "plugin.json", errors)
	gemini = load_json(root / "gemini-extension.json", errors)
	for label, data in (("Codex", codex), ("Claude", claude), ("Gemini", gemini)):
		if isinstance(data, dict) and data.get("name") != "harness":
			errors.append(f"{label} manifest name must be harness")
	if isinstance(claude, dict) and claude.get("skills") != "./skills/":
		errors.append("Claude manifest must point to the shared ./skills/ tree")
	versions = []
	for data in (codex, claude, gemini):
		if isinstance(data, dict) and isinstance(data.get("version"), str):
			versions.append(data["version"].split("+", 1)[0])
	if len(versions) != 3 or len(set(versions)) != 1:
		errors.append(f"Codex, Claude, and Gemini manifest base versions must match: {versions}")


def collect_project_ids(harness_dir: Path, errors: list[str]) -> set[str]:
	ids: set[str] = set()
	for path in harness_dir.glob("*"):
		if not path.is_file() or path_is_link_or_junction(path):
			continue
		if path.suffix.lower() == ".json":
			data = load_json(path, errors)
			value = data.get("project_id") if isinstance(data, dict) else None
			if value:
				if not isinstance(value, str) or not PROJECT_ID_PATTERN.fullmatch(value):
					errors.append(f"Invalid Project ID in {path.name}: {value}")
				else:
					ids.add(value)
		elif path.suffix.lower() == ".md":
			content = load_text(path, errors)
			if content is None:
				continue
			for match in re.finditer(r"^- Project ID(?: or GLOBAL)?:[ \t]*([^\r\n]*)$", content, re.MULTILINE):
				value = match.group(1).strip()
				if value and value != "GLOBAL":
					if not PROJECT_ID_PATTERN.fullmatch(value):
						errors.append(f"Invalid Project ID in {path.name}: {value}")
					else:
						ids.add(value)
	return ids


def runtime_digest(runtime_skill: Path) -> str:
	links = sorted(path for path in runtime_skill.rglob("*") if path_is_link_or_junction(path))
	if links:
		raise ValueError(f"runtime contains symlink: {links[0]}")
	generated = sorted(path for path in runtime_skill.rglob("*") if path.name == "__pycache__" or path.suffix.lower() == ".pyc")
	if generated:
		raise ValueError(f"runtime contains generated Python cache: {generated[0]}")
	digest = hashlib.sha256()
	files = sorted((path for path in runtime_skill.rglob("*") if path.is_file() and path.name != "HARNESS-RUNTIME.json"), key=lambda path: path.relative_to(runtime_skill).as_posix())
	for path in files:
		relative = path.relative_to(runtime_skill).as_posix().encode("utf-8")
		digest.update(len(relative).to_bytes(4, "big"))
		digest.update(relative)
		data = path.read_bytes()
		digest.update(len(data).to_bytes(8, "big"))
		digest.update(data)
	return f"sha256:{digest.hexdigest()}"


def check_project(project: Path, require_adapters: bool, errors: list[str]) -> None:
	try:
		root = project.expanduser().resolve(strict=True)
	except OSError as exc:
		errors.append(f"Invalid project path: {exc}")
		return
	harness_dir = root / ".harness"
	if not harness_dir.is_dir() or path_is_link_or_junction(harness_dir):
		errors.append("Project .harness directory is missing or symlinked")
		return
	for name in ("IDENTITY.json", "MEMORY.json", "INDEX.md", "CONFIG.md", "CONTEXT.md", "PREFERENCES.md", "DECISIONS.md", "STATE.json", "WORKFLOW.md"):
		path = harness_dir / name
		if not path.is_file() or path_is_link_or_junction(path):
			errors.append(f"Initialized project missing or symlinked .harness/{name}")
	ids = collect_project_ids(harness_dir, errors)
	if len(ids) != 1:
		errors.append(f"Initialized project must have exactly one non-empty Project ID; found {sorted(ids)}")
	try:
		memory_result = validate_project_memory(argparse.Namespace(project=str(root), logical_scope="."))
	except (OSError, UnicodeDecodeError, MemoryErrorWithCode) as exc:
		errors.append(f"Memory validation failed: {exc}")
	else:
		errors.extend(f"Memory validation: {error}" for error in memory_result.get("errors", []))
	state = load_json(harness_dir / "STATE.json", errors)
	if isinstance(state, dict):
		if ids and state.get("project_id") != next(iter(ids)):
			errors.append("STATE.json Project ID differs from identity")
		if state.get("run_id") == "" and state.get("state") != "INTAKE":
			errors.append("Blank Run ID must remain in INTAKE state")
		if not isinstance(state.get("state_revision"), int) or not isinstance(state.get("memory_revision_seen"), int):
			errors.append("STATE.json revisions must be integers")
	index_path = harness_dir / "INDEX.md"
	index = load_text(index_path, errors) if index_path.is_file() else ""
	index = index or ""
	if isinstance(state, dict):
		run_match = re.search(r"^- Active run ID:[ \t]*([^\r\n]*)$", index, re.MULTILINE)
		state_match = re.search(r"^- Active state:[ \t]*([^\r\n]*)$", index, re.MULTILINE)
		if not run_match or run_match.group(1).strip() != str(state.get("run_id", "")):
			errors.append("INDEX active run differs from STATE.json")
		if not state_match or state_match.group(1).strip() != str(state.get("state", "")):
			errors.append("INDEX active state differs from STATE.json")
	runtime_root = harness_dir / "runtime"
	runtime_manifest = load_json(runtime_root / "HARNESS-RUNTIME.json", errors)
	if not runtime_root.is_dir() or path_is_link_or_junction(runtime_root) or not (runtime_root / "SKILL.md").is_file() or path_is_link_or_junction(runtime_root / "SKILL.md"):
		errors.append("Project-pinned Harness runtime is missing or symlinked")
	elif not isinstance(runtime_manifest, dict):
		errors.append("Project-pinned Harness runtime manifest must be an object")
	else:
		required_manifest = {"schema_version", "source_version", "source_digest", "created_at", "update_policy"}
		created_at_valid = isinstance(runtime_manifest.get("created_at"), str)
		if created_at_valid:
			try:
				parse_time(runtime_manifest["created_at"])
			except MemoryErrorWithCode:
				created_at_valid = False
		if set(runtime_manifest) != required_manifest or runtime_manifest.get("schema_version") != 1 or not isinstance(runtime_manifest.get("source_version"), str) or not runtime_manifest.get("source_version") or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(runtime_manifest.get("source_digest", ""))) or not created_at_valid or runtime_manifest.get("update_policy") != "pinned; replace only after human-reviewed package update":
			errors.append("Project-pinned Harness runtime manifest schema is invalid")
		try:
			actual_runtime_digest = runtime_digest(runtime_root)
		except ValueError as exc:
			errors.append(f"Project-pinned Harness runtime is invalid: {exc}")
		else:
			if runtime_manifest.get("source_digest") != actual_runtime_digest:
				errors.append("Project-pinned Harness runtime digest mismatch")
	if require_adapters:
		plugin_root = Path(__file__).resolve().parents[3]
		checks = {
			"AGENTS.md": plugin_root / "adapters" / "project" / "AGENTS.md.fragment",
			"CLAUDE.md": plugin_root / "adapters" / "project" / "CLAUDE.md.fragment",
			"GEMINI.md": plugin_root / "adapters" / "project" / "GEMINI.md.fragment",
			"AI-HARNESS.md": plugin_root / "adapters" / "project" / "GENERIC.md",
		}
		for name, expected_path in checks.items():
			path = root / name
			content = load_text(path, errors) if path.is_file() and not path_is_link_or_junction(path) else None
			expected = load_text(expected_path, errors)
			if content is None or expected is None or not exact_managed_block(content, expected):
				errors.append(f"Project adapter missing or invalid: {name}")


def main() -> int:
	configure_utf8_stdio()
	args = parse_args()
	if args.project_only and not args.project:
		print(json.dumps({"ok":False,"errors":["--project-only requires --project"]},ensure_ascii=False,indent=2) if args.json else "--project-only requires --project", file=sys.stderr)
		return 2
	root = Path(args.root).expanduser().resolve() if args.root else Path(__file__).resolve().parents[3]
	errors: list[str] = []
	if not args.project_only:
		check_required(root, errors)
		check_tree_hygiene(root, errors)
		check_json_files(root, errors)
		check_skill(root, errors)
		check_openai_yaml(root, errors)
		check_links(root, errors)
		check_no_personal_paths(root, errors)
		check_one_graph(root, errors)
		check_templates(root, errors)
		check_adapters(root, errors)
		check_fixtures(root, errors)
		check_manifests(root, errors)
	if args.project:
		check_project(Path(args.project), args.require_adapters, errors)
	result = {"ok": not errors, "root": str(root), "errors": errors, "checks": (0 if args.project_only else 12) + int(bool(args.project))}
	if args.json:
		print(json.dumps(result, ensure_ascii=False, indent=2))
	elif errors:
		print("Harness portability validation failed:", file=sys.stderr)
		for error in errors:
			print(f"- {error}", file=sys.stderr)
	else:
		print(f"Harness portability validation passed ({result['checks']} check groups).")
	return 0 if not errors else 1


if __name__ == "__main__":
	raise SystemExit(main())
