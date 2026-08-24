#!/usr/bin/env python3
"""Deterministic, provider-neutral operations for Harness canonical memory."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


STORE_SCHEMA = 1
IDENTITY_SCHEMA = 1
RECORD_KINDS = {"fact", "preference", "decision", "command", "contract", "risk"}
SCOPES = {"task", "project", "global"}
STATUSES = {"Active", "Stale", "Conflict", "Superseded"}
VERIFICATION_POLICIES = {"manual", "on-read", "on-source-change"}
ACTIVE_RUN_STATES = {
	"INTAKE", "DISCOVERY", "PLAN", "WAITING_PLAN", "DESIGN", "WAITING_DESIGN",
	"BUILD", "INTEGRATE", "VERIFY", "REWORK", "WAITING_DECISION",
	"WAITING_ACCEPTANCE", "BLOCKED",
}
ACTIVE_RUN_OPERATIONS = {"start", "resume"}
AUTHORITIES = {
	"repository": 0,
	"human-project": 1,
	"human-global": 2,
	"verified-external": 3,
}
VERIFICATION_RANK = {"VERIFIED_CURRENT": 0, "VALID_UNTIL_TRIGGER": 1}
ID_PATTERN = re.compile(r"^(?:FACT|PREF|DEC|CMD|CONTRACT|RISK)-(?:T|P|G)-[0-9a-f]{16}$")
PROJECT_ID_PATTERN = re.compile(r"^project-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
TTL_PATTERN = re.compile(r"^ttl:(\d+)([smhd])$")
SHA256_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
TRANSACTION_ID_PATTERN = re.compile(r"^TX-[0-9]{8}-[0-9a-f]{12}$")
MAX_ADAPTER_RESULT_BYTES = 256 * 1024
MAX_ADAPTER_SELECTED_IDS = 100
MAX_CACHE_EXPORT_RECORDS = 1000
MAX_CACHE_EXPORT_BYTES = 1024 * 1024
MAX_CANONICAL_JSON_BYTES = 8 * 1024 * 1024
MAX_STORE_RECORDS = 1000
MAX_STORE_TOMBSTONES = 2000
MAX_RECORD_TAGS = 50
MAX_RECALL_RECORDS = 100
MAX_RECALL_BYTES = 128 * 1024
MAX_RECALL_MANIFEST_ENTRIES = 100
MAX_RECALL_MANIFEST_BYTES = 32 * 1024
MAX_DERIVED_VIEW_BYTES = 2 * 1024 * 1024
MAX_TTL_SECONDS = 365 * 24 * 60 * 60
MAX_VERIFICATION_SOURCE_BYTES = 64 * 1024 * 1024
MAX_CLOCK_SKEW_SECONDS = 5 * 60
STORE_FIELDS = {"schema_version", "project_id", "revision", "records", "tombstones", "adapter", "last_transaction"}
RECORD_FIELDS = {
	"id", "kind", "key", "value", "scope", "applies_when", "tags", "authority", "source",
	"source_fingerprint", "verification_policy", "last_verified", "confidence", "status", "supersedes",
	"replaced_by", "review_trigger", "run_id", "created_at", "updated_at",
}
ADAPTER_FIELDS = {"kind", "state", "scope", "source_revision", "export_digest"}
TRANSACTION_FIELDS = {"id", "operation", "record_id", "before_revision", "after_revision", "committed_at"}
ADAPTER_RESULT_FIELDS = {"schema_version", "project_id", "source_revision", "selected_ids"}
IDENTITY_FIELDS = {"schema_version", "project_id", "logical_scope", "repository", "created_at", "last_verified_at"}
REPOSITORY_IDENTITY_FIELDS = {"kind", "remote_fingerprint", "root_commit"}
TRANSACTION_OPERATIONS = {"remember", "correct", "forget", "export-cache", "close-run", "close-run-cache-invalidate", "migrate-v1"}
GIT_COMMIT_PATTERN = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
SECRET_PATTERNS = (
	re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE),
	re.compile(r"\b(?:sk|ghp|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{12,}\b"),
	re.compile(r"\b(?:glpat-|npm_)[A-Za-z0-9_-]{20,}\b"),
	re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
	re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
	re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
	re.compile(r"https?://[^/\s:@]+:[^@\s/]+@", re.IGNORECASE),
	re.compile(r"\b(?:password|passwd|secret|api[_ -]?key|access[_ -]?token|bearer)\s*[:=]\s*\S+", re.IGNORECASE),
)
PII_PATTERNS = (
	re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
	re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
	re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
)
PHONE_PATTERN = re.compile(r"\+?\d[\d .()-]{8,}\d")
INJECTION_PATTERNS = (
	re.compile(r"ignore (?:all |any )?(?:previous|prior|above) instructions", re.IGNORECASE),
	re.compile(r"\b(?:ignore|disregard|override|forget|bypass)\b.{0,80}\b(?:instructions?|directives?|rules?|polic(?:y|ies)|guardrails?|constraints?)\b", re.IGNORECASE),
	re.compile(r"(?:system|developer) (?:prompt|message|instructions?)", re.IGNORECASE),
	re.compile(r"reveal (?:the )?(?:prompt|secret|credentials?)", re.IGNORECASE),
	re.compile(r"(?:execute|run) (?:this|the following) (?:command|tool)", re.IGNORECASE),
	re.compile(r"\b(?:invoke|launch|execute|run|call|open)\b.{0,60}\b(?:shell|powershell|cmd(?:\.exe)?|terminal|tool|command)\b", re.IGNORECASE),
	re.compile(r"\b(?:exfiltrat(?:e|ion)|upload|send|transmit|post)\b.{0,80}\b(?:secrets?|credentials?|tokens?|\.env|project files?|source code|private data)\b", re.IGNORECASE),
	re.compile(r"<\s*(?:script|tool_call|system)\b", re.IGNORECASE),
)

_LOCAL_LOCKS: dict[str, threading.RLock] = {}
_LOCAL_LOCKS_GUARD = threading.Lock()
_LOCK_DEPTH = threading.local()


class MemoryErrorWithCode(RuntimeError):
	def __init__(self, code: str, message: str):
		super().__init__(message)
		self.code = code


def configure_utf8_stdio() -> None:
	for stream in (sys.stdout, sys.stderr):
		if hasattr(stream, "reconfigure"):
			stream.reconfigure(encoding="utf-8", errors="replace")


def utc_now() -> str:
	fixed = os.environ.get("HARNESS_FIXED_TIME", "").strip()
	if fixed:
		parse_time(fixed)
		return fixed.replace("+00:00", "Z")
	return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
	try:
		parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
	except ValueError as exc:
		raise MemoryErrorWithCode("INVALID_TIME", f"Invalid ISO-8601 timestamp: {value}") from exc
	if parsed.tzinfo is None:
		parsed = parsed.replace(tzinfo=timezone.utc)
	return parsed.astimezone(timezone.utc)


def normalize_text(value: str, field: str, max_bytes: int = 1000) -> str:
	if not isinstance(value, str):
		raise MemoryErrorWithCode("INVALID_FIELD", f"{field} must be a string")
	normalized = unicodedata.normalize("NFKC", value).strip()
	if not normalized:
		raise MemoryErrorWithCode("EMPTY_FIELD", f"{field} must not be empty")
	if "\n" in normalized or "\r" in normalized:
		raise MemoryErrorWithCode("NON_ATOMIC", f"{field} must be one atomic line")
	if len(normalized.encode("utf-8")) > max_bytes:
		raise MemoryErrorWithCode("FIELD_TOO_LARGE", f"{field} exceeds {max_bytes} UTF-8 bytes")
	return normalized


def normalize_optional_text(value: str | None, field: str, max_bytes: int) -> str:
	if value is None or value == "":
		return ""
	return normalize_text(value, field, max_bytes)


def normalize_key(value: str) -> str:
	raw = normalize_text(value, "key", 300).casefold()
	pieces: list[str] = []
	previous_dash = False
	for char in raw:
		if char.isalnum() or char in "._/":
			pieces.append(char)
			previous_dash = False
		elif not previous_dash:
			pieces.append("-")
			previous_dash = True
	normalized = "".join(pieces).strip("-")
	if not normalized:
		raise MemoryErrorWithCode("INVALID_KEY", "key has no stable alphanumeric content")
	return normalized[:120].rstrip("-")


def normalize_applies(value: str | None) -> str:
	if not value:
		return "always"
	return " ".join(normalize_text(value, "applies_when", 300).casefold().split())


def normalize_tags(values: Iterable[str]) -> list[str]:
	return sorted({normalize_key(value) for value in values if value.strip()})


def ttl_seconds(value: str) -> int | None:
	if not isinstance(value, str):
		return None
	match = TTL_PATTERN.fullmatch(value)
	if not match or len(match.group(1)) > 8:
		return None
	try:
		amount = int(match.group(1))
	except ValueError:
		return None
	seconds = amount * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
	return seconds if 1 <= seconds <= MAX_TTL_SECONDS else None


def unsafe_reason(*values: str) -> str | None:
	text = "\n".join(values)
	for pattern in SECRET_PATTERNS:
		if pattern.search(text):
			return "secret-like content"
	for pattern in PII_PATTERNS:
		if pattern.search(text):
			return "raw personal data"
	for match in PHONE_PATTERN.finditer(text):
		digit_count = sum(char.isdigit() for char in match.group(0))
		if 10 <= digit_count <= 15:
			return "raw personal data"
	for pattern in INJECTION_PATTERNS:
		if pattern.search(text):
			return "prompt-injection-like content"
	return None


def record_unsafe_reason(record: dict[str, Any]) -> str | None:
	values = [
		str(record.get(field, ""))
		for field in (
			"key", "value", "applies_when", "source", "confidence", "review_trigger", "run_id",
		)
	]
	tags = record.get("tags", [])
	if isinstance(tags, list):
		values.extend(str(tag) for tag in tags)
	return unsafe_reason(*values)


def canonical_json(data: Any) -> bytes:
	return (json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def pretty_json(data: Any) -> bytes:
	return (json.dumps(data, ensure_ascii=False, indent="\t") + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
	return hashlib.sha256(data).hexdigest()


def sha256_file_bounded(path: Path, max_bytes: int = MAX_VERIFICATION_SOURCE_BYTES) -> str | None:
	if path_is_link_or_junction(path):
		return None
	flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0) | getattr(os, "O_NOFOLLOW", 0)
	file_descriptor: int | None = None
	try:
		file_descriptor = os.open(path, flags)
		metadata = os.fstat(file_descriptor)
		if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink > 1 or metadata.st_size > max_bytes:
			return None
		digest = hashlib.sha256()
		read_bytes = 0
		while True:
			chunk = os.read(file_descriptor, min(1024 * 1024, max_bytes + 1 - read_bytes))
			if not chunk:
				break
			read_bytes += len(chunk)
			if read_bytes > max_bytes:
				return None
			digest.update(chunk)
		return digest.hexdigest()
	except OSError:
		return None
	finally:
		if file_descriptor is not None:
			os.close(file_descriptor)


def path_is_link_or_junction(path: Path) -> bool:
	try:
		return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())
	except OSError:
		return True


def ensure_within(path: Path, root: Path, field: str) -> Path:
	root_resolved = root.resolve(strict=True)
	parent_resolved = path.parent.resolve(strict=False)
	try:
		common = Path(os.path.commonpath((str(root_resolved), str(parent_resolved))))
	except ValueError as exc:
		raise MemoryErrorWithCode("PATH_ESCAPE", f"{field} escapes the allowed root") from exc
	if common != root_resolved:
		raise MemoryErrorWithCode("PATH_ESCAPE", f"{field} escapes the allowed root: {path}")
	if path_is_link_or_junction(path):
		raise MemoryErrorWithCode("SYMLINK_REJECTED", f"{field} is a symlink or junction: {path}")
	if path.exists():
		resolved = path.resolve(strict=True)
		try:
			resolved.relative_to(root_resolved)
		except ValueError as exc:
			raise MemoryErrorWithCode("PATH_ESCAPE", f"{field} resolves outside the allowed root: {path}") from exc
	return path


def read_regular_file_bounded(path: Path, max_bytes: int, field: str) -> bytes:
	if path_is_link_or_junction(path):
		raise MemoryErrorWithCode("SYMLINK_REJECTED", f"{field} is a symlink or junction: {path}")
	flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0) | getattr(os, "O_NOFOLLOW", 0)
	file_descriptor: int | None = None
	try:
		file_descriptor = os.open(path, flags)
		metadata = os.fstat(file_descriptor)
		if not stat.S_ISREG(metadata.st_mode):
			raise MemoryErrorWithCode("INVALID_TARGET", f"{field} is not a regular file: {path}")
		if metadata.st_nlink > 1:
			raise MemoryErrorWithCode("HARDLINK_REJECTED", f"{field} is hard-linked: {path}")
		if metadata.st_size > max_bytes:
			raise MemoryErrorWithCode("FILE_TOO_LARGE", f"{field} exceeds {max_bytes} bytes: {path}")
		chunks: list[bytes] = []
		read_bytes = 0
		while True:
			chunk = os.read(file_descriptor, min(1024 * 1024, max_bytes + 1 - read_bytes))
			if not chunk:
				break
			read_bytes += len(chunk)
			if read_bytes > max_bytes:
				raise MemoryErrorWithCode("FILE_TOO_LARGE", f"{field} exceeds {max_bytes} bytes: {path}")
			chunks.append(chunk)
		return b"".join(chunks)
	finally:
		if file_descriptor is not None:
			os.close(file_descriptor)


@contextlib.contextmanager
def target_file_lock(path: Path, timeout_seconds: float = 10.0):
	absolute_target = path.expanduser().absolute()
	harness_ancestor = next((parent for parent in (absolute_target.parent, *absolute_target.parents) if parent.name == ".harness"), None)
	sibling_harness = absolute_target.parent / ".harness"
	if (
		harness_ancestor is None and sibling_harness.is_dir() and not path_is_link_or_junction(sibling_harness)
		and sibling_harness.resolve(strict=True).parent == absolute_target.parent.resolve(strict=True)
	):
		harness_ancestor = sibling_harness
	if harness_ancestor is not None and path_is_link_or_junction(harness_ancestor):
		raise MemoryErrorWithCode("LOCK_UNAVAILABLE", f"Harness lock boundary is a symlink or junction: {harness_ancestor}")
	lock_root = (harness_ancestor / ".cache" / "locks") if harness_ancestor is not None else (absolute_target.parent / ".harness-locks")
	lock_boundary = harness_ancestor if harness_ancestor is not None else absolute_target.parent
	lock_root.mkdir(parents=True, exist_ok=True)
	if not lock_root.is_dir() or path_is_link_or_junction(lock_root):
		raise MemoryErrorWithCode("LOCK_UNAVAILABLE", f"Harness lock root is invalid: {lock_root}")
	ensure_within(lock_root, lock_boundary, "writer lock root")
	canonical_target = os.path.normcase(os.path.realpath(str(absolute_target)))
	lock_name = "writer.lock" if harness_ancestor is not None else hashlib.sha256(canonical_target.encode("utf-8")).hexdigest() + ".lock"
	lock_path = lock_root / lock_name
	if path_is_link_or_junction(lock_path):
		raise MemoryErrorWithCode("LOCK_UNAVAILABLE", f"Harness lock target is a symlink or junction: {lock_path}")
	lock_key = str(lock_path)
	with _LOCAL_LOCKS_GUARD:
		local_lock = _LOCAL_LOCKS.setdefault(lock_key, threading.RLock())
	with local_lock:
		depths = getattr(_LOCK_DEPTH, "keys", set())
		if lock_key in depths:
			yield
			return
		flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0) | getattr(os, "O_NOFOLLOW", 0)
		try:
			file_descriptor = os.open(lock_path, flags, 0o600)
		except PermissionError as exc:
			raise MemoryErrorWithCode("LOCK_UNAVAILABLE", f"Writer lock file cannot be opened: {lock_path}") from exc
		locked = False
		try:
			lock_metadata = os.fstat(file_descriptor)
			if not stat.S_ISREG(lock_metadata.st_mode) or lock_metadata.st_nlink > 1:
				raise MemoryErrorWithCode("LOCK_UNAVAILABLE", f"Harness lock target is not a regular file: {lock_path}")
			if lock_metadata.st_size < 1:
				os.write(file_descriptor, b"\0")
				os.fsync(file_descriptor)
			deadline = time.monotonic() + timeout_seconds
			while not locked:
				try:
					os.lseek(file_descriptor, 0, os.SEEK_SET)
					if os.name == "nt":
						import msvcrt
						msvcrt.locking(file_descriptor, msvcrt.LK_NBLCK, 1)
					else:
						import fcntl
						fcntl.flock(file_descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
					locked = True
				except OSError as exc:
					if time.monotonic() >= deadline:
						raise MemoryErrorWithCode("LOCK_TIMEOUT", f"Timed out waiting for concurrent writer lock: {path}") from exc
					time.sleep(0.05)
			depths.add(lock_key)
			_LOCK_DEPTH.keys = depths
			yield
		finally:
			depths.discard(lock_key)
			if locked:
				try:
					os.lseek(file_descriptor, 0, os.SEEK_SET)
					if os.name == "nt":
						import msvcrt
						msvcrt.locking(file_descriptor, msvcrt.LK_UNLCK, 1)
					else:
						import fcntl
						fcntl.flock(file_descriptor, fcntl.LOCK_UN)
				except OSError:
					pass
			os.close(file_descriptor)


WINDOWS_SHARE_RETRY_ERRORS = {5, 32, 33}


def retry_windows_share_conflict(operation):
	delay_seconds = 0.02
	for attempt in range(10):
		try:
			return operation()
		except PermissionError:
			if attempt == 9:
				raise
		except OSError as exc:
			if attempt == 9 or getattr(exc, "winerror", None) not in WINDOWS_SHARE_RETRY_ERRORS:
				raise
		time.sleep(delay_seconds)
		delay_seconds = min(delay_seconds * 2, 0.25)


def atomic_replace(path: Path, data: bytes, expected: bytes | None = None) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	with target_file_lock(path):
		if path_is_link_or_junction(path):
			raise MemoryErrorWithCode("SYMLINK_REJECTED", f"Refusing symlink target: {path}")
		fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
		temporary = Path(temporary_name)
		try:
			with os.fdopen(fd, "wb") as handle:
				handle.write(data)
				handle.flush()
				os.fsync(handle.fileno())
			try:
				current = read_regular_file_bounded(path, len(expected), "atomic target") if expected is not None and path.exists() else None
			except MemoryErrorWithCode as exc:
				if exc.code == "FILE_TOO_LARGE":
					raise MemoryErrorWithCode("REVISION_CONFLICT", f"Concurrent change detected for {path}") from exc
				raise
			if expected is not None and current != expected:
				raise MemoryErrorWithCode("REVISION_CONFLICT", f"Concurrent change detected for {path}")
			if expected is None and path.exists():
				raise MemoryErrorWithCode("TARGET_EXISTS", f"Target appeared concurrently: {path}")
			retry_windows_share_conflict(lambda: os.replace(temporary, path))
		finally:
			if temporary.exists():
				temporary.unlink()


def atomic_delete(path: Path, expected: bytes) -> None:
	with target_file_lock(path):
		if not path.exists() or path_is_link_or_junction(path):
			raise MemoryErrorWithCode("ROLLBACK_CONFLICT", f"Delete target changed type: {path}")
		current = read_regular_file_bounded(path, len(expected), "delete target")
		if current != expected:
			raise MemoryErrorWithCode("ROLLBACK_CONFLICT", f"Delete target changed concurrently: {path}")
		retry_windows_share_conflict(path.unlink)


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
	result: dict[str, Any] = {}
	for key, value in pairs:
		if key in result:
			raise ValueError(f"duplicate JSON key: {key}")
		result[key] = value
	return result


def read_json_bytes(path: Path) -> tuple[dict[str, Any], bytes]:
	try:
		raw = read_regular_file_bounded(path, MAX_CANONICAL_JSON_BYTES, "canonical JSON")
	except OSError as exc:
		raise MemoryErrorWithCode("STORE_UNAVAILABLE", f"Cannot read {path}: {exc}") from exc
	except MemoryErrorWithCode as exc:
		if exc.code == "FILE_TOO_LARGE":
			raise MemoryErrorWithCode("STORE_TOO_LARGE", str(exc)) from exc
		raise
	try:
		data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_json_object)
	except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError, MemoryError) as exc:
		raise MemoryErrorWithCode("STORE_INVALID", f"Invalid UTF-8 JSON store {path}: {exc}") from exc
	if not isinstance(data, dict):
		raise MemoryErrorWithCode("STORE_INVALID", f"Store root must be an object: {path}")
	return data, raw


def project_paths(project_arg: str) -> tuple[Path, Path, Path]:
	try:
		project = Path(project_arg).expanduser().resolve(strict=True)
	except OSError as exc:
		raise MemoryErrorWithCode("PROJECT_UNAVAILABLE", f"Invalid project path: {exc}") from exc
	if not project.is_dir():
		raise MemoryErrorWithCode("PROJECT_UNAVAILABLE", f"Project is not a directory: {project}")
	harness = project / ".harness"
	if not harness.is_dir() or path_is_link_or_junction(harness):
		raise MemoryErrorWithCode("HARNESS_UNINITIALIZED", "Run Harness init before project memory operations")
	return project, harness / "IDENTITY.json", harness / "MEMORY.json"


def normalized_active_run_id(state: dict[str, Any], project_id: str) -> str:
	state_value = state.get("state")
	operation_value = state.get("operation")
	if (
		state.get("project_id") != project_id or not isinstance(state_value, str) or state_value not in ACTIVE_RUN_STATES
		or not isinstance(operation_value, str) or operation_value not in ACTIVE_RUN_OPERATIONS
	):
		return ""
	current = state.get("run_id")
	if not isinstance(current, str) or not current:
		return ""
	try:
		normalized = normalize_text(current, "run_id", 200)
	except MemoryErrorWithCode:
		return ""
	if normalized != current or unsafe_reason(current):
		return ""
	return current


def assert_current_run(project: Path, project_id: str, run_id: str | None, allow_done: bool = False) -> None:
	state, _ = read_json_bytes(project / ".harness" / "STATE.json")
	current = state.get("run_id")
	if state.get("project_id") != project_id or not isinstance(current, str) or not current:
		raise MemoryErrorWithCode("RUN_UNAVAILABLE", "Task memory requires a non-empty current run in STATE.json")
	try:
		normalized_current = normalize_text(current, "run_id", 200)
		normalized_requested = normalize_optional_text(run_id, "run_id", 200)
	except MemoryErrorWithCode as exc:
		raise MemoryErrorWithCode("RUN_UNAVAILABLE", "Task memory requires a valid one-line Run ID") from exc
	if normalized_current != current or normalized_requested != run_id or unsafe_reason(current, normalized_requested):
		raise MemoryErrorWithCode("RUN_UNAVAILABLE", "Task memory requires a safe normalized Run ID")
	if normalized_requested != current:
		raise MemoryErrorWithCode("RUN_ID_MISMATCH", "Task memory Run ID must exactly match the current STATE.json run_id")
	allowed_states = ACTIVE_RUN_STATES | ({"DONE"} if allow_done else set())
	state_value = state.get("state")
	operation_value = state.get("operation")
	if (
		not isinstance(state_value, str) or state_value not in allowed_states
		or not isinstance(operation_value, str) or operation_value not in ACTIVE_RUN_OPERATIONS
	):
		raise MemoryErrorWithCode("RUN_NOT_ACTIVE", "Task memory writes require an unfinished active run")


def default_global_store() -> Path:
	base = os.environ.get("HARNESS_HOME", "").strip()
	return (Path(base).expanduser() if base else Path.home() / ".harness") / "MEMORY.json"


def git_value(project: Path, *arguments: str) -> str:
	try:
		result = subprocess.run(
			["git", "-C", str(project), *arguments],
			capture_output=True,
			text=True,
			encoding="utf-8",
			errors="replace",
			timeout=5,
			check=False,
		)
	except (OSError, subprocess.SubprocessError):
		return ""
	return result.stdout.strip() if result.returncode == 0 else ""


def repository_identity(project: Path, project_id: str, logical_scope: str = ".") -> dict[str, Any]:
	remote = git_value(project, "config", "--get", "remote.origin.url")
	root_commits = sorted(set(git_value(project, "rev-list", "--max-parents=0", "HEAD").splitlines()))
	if len(root_commits) == 1:
		root_fingerprint = root_commits[0]
	elif root_commits:
		root_fingerprint = f"sha256:{sha256_bytes(canonical_json(root_commits))}"
	else:
		root_fingerprint = ""
	return {
		"schema_version": IDENTITY_SCHEMA,
		"project_id": project_id,
		"logical_scope": normalize_applies(logical_scope),
		"repository": {
			"kind": "git" if git_value(project, "rev-parse", "--is-inside-work-tree") == "true" else "directory",
			"remote_fingerprint": f"sha256:{sha256_bytes(remote.encode('utf-8'))}" if remote else "",
			"root_commit": root_fingerprint,
		},
		"created_at": utc_now(),
		"last_verified_at": utc_now(),
	}


def validate_identity(data: dict[str, Any]) -> list[str]:
	if not isinstance(data, dict):
		return ["identity must be an object"]
	errors: list[str] = []
	if set(data) != IDENTITY_FIELDS:
		errors.append("identity must contain the exact canonical fields")
	if data.get("schema_version") != IDENTITY_SCHEMA:
		errors.append("identity schema_version must be 1")
	project_id = data.get("project_id")
	if not isinstance(project_id, str) or not PROJECT_ID_PATTERN.fullmatch(project_id):
		errors.append("identity project_id is invalid")
	if not isinstance(data.get("logical_scope"), str) or not data.get("logical_scope"):
		errors.append("identity logical_scope is invalid")
	else:
		try:
			if normalize_applies(data["logical_scope"]) != data["logical_scope"]:
				errors.append("identity logical_scope is not normalized")
		except MemoryErrorWithCode:
			errors.append("identity logical_scope is invalid")
	repository = data.get("repository")
	repository_kind = repository.get("kind") if isinstance(repository, dict) else None
	if (
		not isinstance(repository, dict) or set(repository) != REPOSITORY_IDENTITY_FIELDS
		or not isinstance(repository_kind, str) or repository_kind not in {"git", "directory", "unknown"}
	):
		errors.append("identity repository is invalid")
	elif not isinstance(repository.get("remote_fingerprint"), str) or not isinstance(repository.get("root_commit"), str):
		errors.append("identity repository fingerprints must be strings")
	elif repository.get("remote_fingerprint") and not SHA256_PATTERN.fullmatch(repository["remote_fingerprint"]):
		errors.append("identity remote_fingerprint is invalid")
	elif repository.get("root_commit") and not (GIT_COMMIT_PATTERN.fullmatch(repository["root_commit"]) or SHA256_PATTERN.fullmatch(repository["root_commit"])):
		errors.append("identity root_commit is invalid")
	elif repository.get("kind") != "git" and (repository.get("remote_fingerprint") or repository.get("root_commit")):
		errors.append("non-Git identity cannot carry Git fingerprints")
	for field in ("created_at", "last_verified_at"):
		try:
			parse_time(str(data.get(field, "")))
		except MemoryErrorWithCode:
			errors.append(f"identity {field} is invalid")
	return errors


def assert_current_identity(project: Path, identity: dict[str, Any], logical_scope: str = ".") -> None:
	errors = validate_identity(identity)
	if errors:
		raise MemoryErrorWithCode("IDENTITY_INVALID", "; ".join(errors))
	if identity.get("logical_scope") != normalize_applies(logical_scope):
		raise MemoryErrorWithCode("IDENTITY_MISMATCH", "Logical monorepo scope changed; confirm identity before memory write")
	stored = identity.get("repository", {})
	current = repository_identity(project, identity["project_id"], logical_scope)["repository"]
	for field in ("kind", "remote_fingerprint", "root_commit"):
		if stored.get(field, "") != current.get(field, ""):
			raise MemoryErrorWithCode("IDENTITY_MISMATCH", f"Repository {field} changed; confirm clone/fork/scope before memory write")


def empty_store(project_id: str) -> dict[str, Any]:
	return {
		"schema_version": STORE_SCHEMA,
		"project_id": project_id,
		"revision": 0,
		"records": [],
		"tombstones": [],
		"adapter": {"kind": "none", "state": "UNAVAILABLE", "scope": "", "source_revision": 0, "export_digest": ""},
		"last_transaction": None,
	}


def record_tuple(record: dict[str, Any]) -> tuple[str, str, str, str]:
	scope = str(record.get("scope", ""))
	run_id = str(record.get("run_id", "")) if scope == "task" else ""
	return scope, str(record.get("key", "")), str(record.get("applies_when", "")), run_id


def validate_store(store: dict[str, Any], expected_project_id: str | None = None) -> list[str]:
	if not isinstance(store, dict):
		return ["memory store must be an object"]
	errors: list[str] = []
	if set(store) != STORE_FIELDS:
		errors.append("memory store must contain the exact canonical fields")
	if store.get("schema_version") != STORE_SCHEMA:
		errors.append("memory schema_version must be 1")
	project_id = store.get("project_id")
	if project_id != "GLOBAL" and (not isinstance(project_id, str) or not PROJECT_ID_PATTERN.fullmatch(project_id)):
		errors.append("memory project_id is invalid")
	if expected_project_id is not None and project_id != expected_project_id:
		errors.append("memory project_id does not match identity")
	revision_value = store.get("revision")
	revision_valid = isinstance(revision_value, int) and not isinstance(revision_value, bool) and revision_value >= 0
	if not revision_valid:
		errors.append("memory revision must be a non-negative integer")
	records = store.get("records")
	tombstones = store.get("tombstones")
	if not isinstance(records, list):
		errors.append("memory records must be an array")
		records = []
	elif len(records) > MAX_STORE_RECORDS:
		errors.append(f"memory records exceed the limit of {MAX_STORE_RECORDS}")
		records = records[:MAX_STORE_RECORDS]
	if not isinstance(tombstones, list):
		errors.append("memory tombstones must be an array")
		tombstones = []
	elif len(tombstones) > MAX_STORE_TOMBSTONES:
		errors.append(f"memory tombstones exceed the limit of {MAX_STORE_TOMBSTONES}")
		tombstones = tombstones[:MAX_STORE_TOMBSTONES]
	ids: set[str] = set()
	active_tuples: dict[tuple[str, str, str, str], str] = {}
	record_by_id: dict[str, dict[str, Any]] = {}
	for index, record in enumerate(records):
		if not isinstance(record, dict):
			errors.append(f"record {index} must be an object")
			continue
		if set(record) != RECORD_FIELDS:
			errors.append(f"record {index} must contain the exact canonical fields")
		record_id = record.get("id")
		if not isinstance(record_id, str) or not ID_PATTERN.fullmatch(record_id):
			errors.append(f"record {index} has invalid ID")
			continue
		if record_id in ids:
			errors.append(f"duplicate record ID {record_id}")
		ids.add(record_id)
		record_by_id[record_id] = record
		kind = record.get("kind")
		scope = record.get("scope")
		status = record.get("status")
		authority = record.get("authority")
		verification_policy = record.get("verification_policy")
		if not isinstance(kind, str) or kind not in RECORD_KINDS:
			errors.append(f"record {record_id} has invalid kind")
		if not isinstance(scope, str) or scope not in SCOPES:
			errors.append(f"record {record_id} has invalid scope")
		if not isinstance(status, str) or status not in STATUSES:
			errors.append(f"record {record_id} has invalid status")
		if not isinstance(authority, str) or authority not in AUTHORITIES:
			errors.append(f"record {record_id} has invalid authority")
		if not isinstance(verification_policy, str) or (verification_policy not in VERIFICATION_POLICIES and ttl_seconds(verification_policy) is None):
			errors.append(f"record {record_id} has invalid verification policy")
		for field in ("key", "value", "applies_when", "source"):
			if not isinstance(record.get(field), str):
				errors.append(f"record {record_id} has invalid {field}")
		for field in ("source_fingerprint", "confidence", "supersedes", "replaced_by", "review_trigger", "run_id"):
			if not isinstance(record.get(field), str):
				errors.append(f"record {record_id} has invalid {field}")
		tags = record.get("tags")
		if not isinstance(tags, list) or len(tags) > MAX_RECORD_TAGS or any(not isinstance(tag, str) for tag in tags):
			errors.append(f"record {record_id} has invalid tags")
		else:
			try:
				if tags != normalize_tags(tags):
					errors.append(f"record {record_id} tags are not normalized")
			except MemoryErrorWithCode:
				errors.append(f"record {record_id} has invalid tags")
		fingerprint = record.get("source_fingerprint")
		if isinstance(fingerprint, str) and fingerprint and not SHA256_PATTERN.fullmatch(fingerprint):
			errors.append(f"record {record_id} has invalid source_fingerprint")
		if record.get("verification_policy") == "on-source-change" and (not str(record.get("source", "")).startswith("file:") or not isinstance(fingerprint, str) or not SHA256_PATTERN.fullmatch(fingerprint)):
			errors.append(f"record {record_id} on-source-change requires a file source and SHA-256 fingerprint")
		for field in ("last_verified", "created_at", "updated_at"):
			try:
				parse_time(str(record.get(field, "")))
			except MemoryErrorWithCode:
				errors.append(f"record {record_id} has invalid {field}")
		if project_id == "GLOBAL" and record.get("scope") != "global":
			errors.append(f"record {record_id} has non-global scope in global store")
		if project_id == "GLOBAL" and record.get("kind") != "preference":
			errors.append(f"record {record_id} has non-preference kind in global store")
		if project_id != "GLOBAL" and record.get("scope") == "global":
			errors.append(f"record {record_id} has global scope in project store")
		if record.get("scope") == "global" and record.get("authority") != "human-global":
			errors.append(f"record {record_id} has invalid global authority")
		if record.get("scope") != "global" and record.get("authority") == "human-global":
			errors.append(f"record {record_id} has out-of-scope human-global authority")
		if record.get("authority") == "repository" and (not str(record.get("source", "")).startswith("file:") or record.get("verification_policy") != "on-source-change" or not SHA256_PATTERN.fullmatch(str(record.get("source_fingerprint", "")))):
			errors.append(f"record {record_id} has unverified repository authority")
		if record.get("authority") == "verified-external" and (record.get("source") == "human-command" or record.get("verification_policy") == "manual"):
			errors.append(f"record {record_id} has unverified external authority")
		if record.get("scope") == "task" and not record.get("run_id"):
			errors.append(f"task record {record_id} lacks run_id")
		if record.get("scope") != "task" and record.get("run_id"):
			errors.append(f"non-task record {record_id} has run_id")
		for field in ("supersedes", "replaced_by"):
			linked_id = record.get(field)
			if isinstance(linked_id, str) and linked_id and not ID_PATTERN.fullmatch(linked_id):
				errors.append(f"record {record_id} has invalid {field}")
		try:
			normalized_key = normalize_key(str(record.get("key", "")))
			normalized_value = normalize_text(str(record.get("value", "")), "value")
			normalized_applies = normalize_applies(str(record.get("applies_when", "")))
			normalized_source = normalize_text(str(record.get("source", "")), "source", 500)
			normalized_confidence = normalize_text(str(record.get("confidence", "")), "confidence", 50).casefold()
			normalized_review_trigger = normalize_optional_text(record.get("review_trigger"), "review_trigger", 500)
			normalized_run_id = normalize_optional_text(record.get("run_id"), "run_id", 200)
			if (
				normalized_key != record.get("key") or normalized_value != record.get("value")
				or normalized_applies != record.get("applies_when") or normalized_source != record.get("source")
				or normalized_confidence != record.get("confidence") or normalized_review_trigger != record.get("review_trigger")
				or normalized_run_id != record.get("run_id")
			):
				errors.append(f"record {record_id} contains non-normalized canonical fields")
			if isinstance(kind, str) and kind in RECORD_KINDS and isinstance(scope, str) and scope in SCOPES:
				expected_id = record_id_for_validation(record)
				legacy_task_id = legacy_record_id_for_validation(record) if record.get("scope") == "task" else ""
				if record_id not in {expected_id, legacy_task_id}:
					errors.append(f"record {record_id} content-derived ID mismatch")
		except MemoryErrorWithCode:
			errors.append(f"record {record_id} has invalid canonical fields")
		unsafe = record_unsafe_reason(record)
		if unsafe:
			errors.append(f"record {record_id} contains {unsafe}")
		if record.get("status") == "Active":
			key = record_tuple(record)
			if key in active_tuples:
				errors.append(f"duplicate active tuple {key}: {active_tuples[key]} and {record_id}")
			active_tuples[key] = record_id
	tombstone_ids: set[str] = set()
	tombstone_scopes: dict[str, str] = {}
	for index, tombstone in enumerate(tombstones):
		if not isinstance(tombstone, dict) or set(tombstone) != {"id", "scope", "revoked_at", "cache_sync"}:
			errors.append(f"tombstone {index} must be content-free with exact fields")
			continue
		tombstone_id = tombstone.get("id")
		if not isinstance(tombstone_id, str) or not ID_PATTERN.fullmatch(tombstone_id):
			errors.append(f"tombstone {index} has invalid ID")
		else:
			if tombstone_id in tombstone_ids or tombstone_id in ids:
				errors.append(f"tombstone ID is duplicated or still active: {tombstone_id}")
			tombstone_ids.add(tombstone_id)
		tombstone_scope = tombstone.get("scope")
		if not isinstance(tombstone_scope, str) or tombstone_scope not in SCOPES:
			errors.append(f"tombstone {index} has invalid scope")
		elif isinstance(tombstone_id, str) and ID_PATTERN.fullmatch(tombstone_id):
			tombstone_scopes[tombstone_id] = tombstone_scope
		try:
			parse_time(str(tombstone.get("revoked_at", "")))
		except MemoryErrorWithCode:
			errors.append(f"tombstone {index} has invalid revoked_at")
		cache_sync = tombstone.get("cache_sync")
		if not isinstance(cache_sync, str) or cache_sync not in {"NOT_CONFIGURED", "DIRTY", "SYNCED"}:
			errors.append(f"tombstone {index} has invalid cache_sync")
	for record_id, record in record_by_id.items():
		replacement = record.get("replaced_by")
		supersedes = record.get("supersedes")
		if isinstance(replacement, str) and replacement and replacement not in record_by_id and replacement not in tombstone_ids:
			errors.append(f"record {record_id} points to missing replacement {replacement}")
		if isinstance(supersedes, str) and supersedes and supersedes not in record_by_id and supersedes not in tombstone_ids:
			errors.append(f"record {record_id} points to missing superseded record {supersedes}")
		if record.get("status") == "Superseded" and not replacement:
			errors.append(f"superseded record {record_id} lacks replaced_by")
		if record.get("status") != "Superseded" and replacement:
			errors.append(f"non-superseded record {record_id} has replaced_by")
		if replacement == record_id or supersedes == record_id:
			errors.append(f"record {record_id} has a self-referential history link")
		if isinstance(replacement, str) and replacement in record_by_id:
			replacement_record = record_by_id[replacement]
			if replacement_record.get("supersedes") != record_id:
				errors.append(f"record {record_id} replacement link is not reciprocal with {replacement}")
			if record_tuple(replacement_record) != record_tuple(record) or replacement_record.get("kind") != record.get("kind"):
				errors.append(f"record {record_id} replacement {replacement} changes the logical history tuple")
		elif isinstance(replacement, str) and replacement in tombstone_scopes and tombstone_scopes[replacement] != record.get("scope"):
			errors.append(f"record {record_id} replacement tombstone has a different scope")
		if isinstance(supersedes, str) and supersedes in record_by_id:
			superseded_record = record_by_id[supersedes]
			if superseded_record.get("replaced_by") != record_id:
				errors.append(f"record {record_id} supersedes link is not reciprocal with {supersedes}")
			if record_tuple(superseded_record) != record_tuple(record) or superseded_record.get("kind") != record.get("kind"):
				errors.append(f"record {record_id} supersedes {supersedes} from a different logical history tuple")
		elif isinstance(supersedes, str) and supersedes in tombstone_scopes and tombstone_scopes[supersedes] != record.get("scope"):
			errors.append(f"record {record_id} superseded tombstone has a different scope")
	for start_id in record_by_id:
		seen: set[str] = set()
		current_id = start_id
		while current_id in record_by_id:
			if current_id in seen:
				errors.append(f"record history contains a cycle reachable from {start_id}")
				break
			seen.add(current_id)
			next_id = record_by_id[current_id].get("supersedes")
			if not isinstance(next_id, str) or not next_id:
				break
			current_id = next_id
	adapter = store.get("adapter")
	adapter_state = adapter.get("state") if isinstance(adapter, dict) else None
	if (
		not isinstance(adapter, dict) or set(adapter) != ADAPTER_FIELDS
		or not isinstance(adapter_state, str) or adapter_state not in {"UNAVAILABLE", "DIRTY", "EXPORT_READY", "READY"}
	):
		errors.append("memory adapter state is invalid")
	elif (
		not isinstance(adapter.get("kind"), str) or not isinstance(adapter.get("scope"), str)
		or not isinstance(adapter.get("source_revision"), int) or isinstance(adapter.get("source_revision"), bool)
		or not isinstance(adapter.get("export_digest"), str)
	):
		errors.append("memory adapter fields are invalid")
	else:
		kind = adapter["kind"]
		state = adapter["state"]
		try:
			if kind != "none" and (normalize_key(kind) != kind or unsafe_reason(kind)):
				errors.append("memory adapter kind is invalid")
		except MemoryErrorWithCode:
			errors.append("memory adapter kind is invalid")
		revision_ceiling = revision_value if revision_valid else -1
		if adapter["source_revision"] < 0 or adapter["source_revision"] > revision_ceiling:
			errors.append("memory adapter source_revision is invalid")
		if kind == "none":
			if adapter != {"kind": "none", "state": "UNAVAILABLE", "scope": "", "source_revision": 0, "export_digest": ""}:
				errors.append("unconfigured memory adapter metadata is incoherent")
		elif state == "UNAVAILABLE" or adapter["scope"] != project_id:
			errors.append("configured memory adapter metadata is incoherent")
		elif state == "DIRTY" and adapter["export_digest"] != "":
			errors.append("dirty memory adapter must not retain an export digest")
		elif state in {"EXPORT_READY", "READY"} and (adapter["source_revision"] != store.get("revision") or not SHA256_PATTERN.fullmatch(adapter["export_digest"])):
			errors.append("ready memory adapter metadata is incoherent")
	transaction = store.get("last_transaction")
	if store.get("revision") == 0 and transaction is not None:
		errors.append("revision 0 memory must not have a transaction")
	elif isinstance(store.get("revision"), int) and store.get("revision", 0) > 0:
		if not isinstance(transaction, dict) or set(transaction) != TRANSACTION_FIELDS:
			errors.append("revised memory lacks last_transaction")
		else:
			if not TRANSACTION_ID_PATTERN.fullmatch(str(transaction.get("id", ""))):
				errors.append("last_transaction ID is invalid")
			if (
				not isinstance(transaction.get("before_revision"), int) or isinstance(transaction.get("before_revision"), bool)
				or not isinstance(transaction.get("after_revision"), int) or isinstance(transaction.get("after_revision"), bool)
				or transaction.get("before_revision") != store["revision"] - 1 or transaction.get("after_revision") != store["revision"]
			):
				errors.append("last_transaction revision does not match memory revision")
			operation = transaction.get("operation")
			record_id_value = transaction.get("record_id")
			if not isinstance(operation, str) or operation not in TRANSACTION_OPERATIONS or not isinstance(record_id_value, str):
				errors.append("last_transaction operation is invalid")
			elif operation in {"remember", "correct", "forget"} and not ID_PATTERN.fullmatch(record_id_value):
				errors.append("last_transaction record_id is invalid")
			elif operation == "export-cache" and record_id_value != "CACHE":
				errors.append("last_transaction cache reference is invalid")
			elif operation == "migrate-v1" and record_id_value != "MIGRATION":
				errors.append("last_transaction migration reference is invalid")
			elif operation in {"close-run", "close-run-cache-invalidate"}:
				try:
					if normalize_text(record_id_value, "transaction run_id", 200) != record_id_value or unsafe_reason(record_id_value):
						errors.append("last_transaction Run ID is invalid")
				except MemoryErrorWithCode:
					errors.append("last_transaction Run ID is invalid")
			try:
				parse_time(str(transaction.get("committed_at", "")))
			except MemoryErrorWithCode:
				errors.append("last_transaction committed_at is invalid")
	return errors


def record_id_for_validation(record: dict[str, Any]) -> str:
	return record_id(
		str(record["kind"]),
		str(record["scope"]),
		str(record["key"]),
		str(record["applies_when"]),
		str(record["value"]),
		str(record.get("supersedes", "")),
		str(record.get("run_id", "")),
	)


def legacy_record_id_for_validation(record: dict[str, Any]) -> str:
	return record_id(
		str(record["kind"]),
		str(record["scope"]),
		str(record["key"]),
		str(record["applies_when"]),
		str(record["value"]),
		str(record.get("supersedes", "")),
		"",
	)


def load_project_store(project_arg: str, for_write: bool = False, logical_scope: str = ".") -> tuple[Path, Path, dict[str, Any], bytes, dict[str, Any]]:
	project, identity_path, store_path = project_paths(project_arg)
	identity, _ = read_json_bytes(identity_path)
	if for_write:
		assert_current_identity(project, identity, logical_scope)
	store, raw = read_json_bytes(store_path)
	errors = validate_store(store, identity.get("project_id")) + validate_identity(identity)
	if errors:
		raise MemoryErrorWithCode("STORE_INVALID", "; ".join(errors))
	return project, store_path, store, raw, identity


def load_global_store(path: Path, create: bool = False) -> tuple[Path, dict[str, Any], bytes | None]:
	path = path.expanduser().absolute()
	if path_is_link_or_junction(path):
		raise MemoryErrorWithCode("SYMLINK_REJECTED", f"Global store is a symlink or junction: {path}")
	path = path.parent.resolve(strict=False) / path.name
	if not path.exists():
		if not create:
			raise MemoryErrorWithCode("GLOBAL_UNAVAILABLE", f"Global store does not exist: {path}")
		return path, empty_store("GLOBAL"), None
	store, raw = read_json_bytes(path)
	errors = validate_store(store, "GLOBAL")
	if errors:
		raise MemoryErrorWithCode("STORE_INVALID", "; ".join(errors))
	return path, store, raw


def record_id(kind: str, scope: str, key: str, applies: str, value: str, supersedes: str = "", run_id: str = "") -> str:
	prefix = {"fact": "FACT", "preference": "PREF", "decision": "DEC", "command": "CMD", "contract": "CONTRACT", "risk": "RISK"}[kind]
	scope_code = {"task": "T", "project": "P", "global": "G"}[scope]
	payload_fields = {"kind": kind, "scope": scope, "key": key, "applies": applies, "value": value, "supersedes": supersedes}
	if scope == "task" and run_id:
		payload_fields["run_id"] = run_id
	payload = canonical_json(payload_fields)
	return f"{prefix}-{scope_code}-{sha256_bytes(payload)[:16]}"


def prepare_transaction(store: dict[str, Any], operation: str, record_id_value: str) -> tuple[dict[str, Any], int, int, str]:
	before = int(store["revision"])
	after = before + 1
	transaction_id = f"TX-{after:08d}-{sha256_bytes(f'{operation}:{record_id_value}:{after}'.encode('utf-8'))[:12]}"
	updated = json.loads(json.dumps(store, ensure_ascii=False))
	updated["revision"] = after
	updated["last_transaction"] = {
		"id": transaction_id,
		"operation": operation,
		"record_id": record_id_value,
		"before_revision": before,
		"after_revision": after,
		"committed_at": utc_now(),
	}
	return updated, before, after, transaction_id


def mark_adapter_dirty(store: dict[str, Any]) -> None:
	adapter = store["adapter"]
	if adapter.get("kind") != "none":
		adapter["state"] = "DIRTY"
		adapter["export_digest"] = ""


def commit_store(path: Path, original: bytes | None, store: dict[str, Any]) -> None:
	errors = validate_store(store, store.get("project_id"))
	if errors:
		raise MemoryErrorWithCode("MUTATION_INVALID", "; ".join(errors))
	atomic_replace(path, pretty_json(store), expected=original)


def markdown_cell(value: Any) -> str:
	return str(value if value is not None else "").replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def project_view_payloads(store: dict[str, Any]) -> dict[str, bytes]:
	project_id = store["project_id"]
	revision = store["revision"]
	records = sorted(store["records"], key=lambda record: record["id"])
	context_rows = []
	preference_rows = []
	decision_rows = []
	for record in records:
		if record["kind"] == "preference":
			preference_rows.append("| " + " | ".join(markdown_cell(record.get(field, "")) for field in ("id", "key", "value", "scope", "applies_when", "authority", "status", "supersedes", "replaced_by", "last_verified", "review_trigger")) + " |")
		elif record["kind"] == "decision":
			decision_rows.append("| " + " | ".join(markdown_cell(record.get(field, "")) for field in ("id", "created_at", "value", "source", "authority", "review_trigger", "status", "supersedes", "replaced_by")) + " |")
		else:
			context_rows.append("| " + " | ".join(markdown_cell(record.get(field, "")) for field in ("id", "kind", "key", "value", "source", "verification_policy", "last_verified", "status", "replaced_by")) + " |")
	tombstone_rows = ["| " + " | ".join(markdown_cell(item.get(field, "")) for field in ("id", "scope", "revoked_at", "cache_sync")) + " |" for item in store["tombstones"]]
	context = f"""# Harness Project Context

Generated readable view of non-preference, non-decision records in `MEMORY.json`. Do not edit generated rows directly; use `memory_ops.py`.

- Schema version: 4
- Project ID: {project_id}
- Source memory revision: {revision}
- Generated view: yes

## Durable records

| ID | Kind | Key | Statement | Source | Verification | Last verified | Status | Replaced by |
|---|---|---|---|---|---|---|---|---|
{chr(10).join(context_rows)}

## Tombstones

Deleted payloads are intentionally absent.

| ID | Scope | Revoked at | Cache sync |
|---|---|---|---|
{chr(10).join(tombstone_rows)}
"""
	preferences = f"""# Harness Preferences

Generated readable view of explicit preference records in `MEMORY.json`. Do not edit generated rows directly; use `memory_ops.py`.

- Schema version: 2
- Project ID: {project_id}
- Source memory revision: {revision}
- Generated view: yes

| ID | Key | Value | Scope | Applies when | Authority | Status | Supersedes | Replaced by | Last confirmed | Review trigger |
|---|---|---|---|---|---|---|---|---|---|---|
{chr(10).join(preference_rows)}
"""
	decisions = f"""# Harness Human Decisions

Generated readable view of durable decision records in `MEMORY.json`. Do not edit generated rows directly; use `memory_ops.py`.

- Schema version: 3
- Project ID: {project_id}
- Source memory revision: {revision}
- Generated view: yes

| ID | Date | Decision | Evidence/source | Authority | Revisit condition | Status | Supersedes | Replaced by |
|---|---|---|---|---|---|---|---|---|
{chr(10).join(decision_rows)}
"""
	return {"CONTEXT.md": context.encode("utf-8"), "PREFERENCES.md": preferences.encode("utf-8"), "DECISIONS.md": decisions.encode("utf-8")}


def render_project_views(project: Path, store: dict[str, Any]) -> list[str]:
	harness = project / ".harness"
	outputs = project_view_payloads(store)
	for name, content in outputs.items():
		path = ensure_within(harness / name, project, name)
		existing = read_regular_file_bounded(path, MAX_DERIVED_VIEW_BYTES, name) if path.exists() else None
		atomic_replace(path, content, expected=existing)
	return sorted(outputs)


def make_record(args: argparse.Namespace, scope: str, supersedes: str = "") -> dict[str, Any]:
	kind = args.kind
	if kind not in RECORD_KINDS:
		raise MemoryErrorWithCode("INVALID_KIND", f"Unsupported kind: {kind}")
	raw_tags = [str(tag) for tag in (args.tag or [])]
	raw_metadata = [
		str(value or "")
		for value in (
			args.key, args.value, args.applies, args.source, args.confidence, args.review_trigger, args.run_id,
		)
	]
	reason = unsafe_reason(*raw_metadata, *raw_tags)
	if reason:
		raise MemoryErrorWithCode("UNSAFE_MEMORY", f"Refusing to persist {reason}; use a sanitized abstraction")
	key = normalize_key(args.key)
	value = normalize_text(args.value, "value")
	applies = normalize_applies(args.applies)
	source = normalize_text(args.source or "human-command", "source", 500)
	source_fingerprint = normalize_optional_text(args.source_fingerprint, "source_fingerprint", 71).casefold()
	confidence = normalize_text(args.confidence or "confirmed", "confidence", 50).casefold()
	review_trigger = normalize_optional_text(args.review_trigger, "review_trigger", 500)
	run_id = normalize_optional_text(args.run_id, "run_id", 200)
	if scope == "task" and not run_id:
		raise MemoryErrorWithCode("RUN_ID_REQUIRED", "Task memory requires --run-id")
	if scope != "task" and run_id:
		raise MemoryErrorWithCode("INVALID_RUN_SCOPE", "Only task memory may carry a Run ID")
	verification = args.verification or ("manual" if kind in {"preference", "decision"} else "on-read")
	if verification not in VERIFICATION_POLICIES and ttl_seconds(verification) is None:
		raise MemoryErrorWithCode("INVALID_VERIFICATION", f"Unsupported verification policy: {verification}")
	if scope == "global" and kind != "preference":
		raise MemoryErrorWithCode("GLOBAL_PREFERENCE_ONLY", "Global durable memory accepts explicit preferences only")
	requested_authority = getattr(args, "authority", None)
	authority = requested_authority or ("human-global" if scope == "global" else "repository" if source.startswith("file:") and verification == "on-source-change" else "human-project")
	if authority not in AUTHORITIES:
		raise MemoryErrorWithCode("INVALID_AUTHORITY", f"Unsupported authority: {authority}")
	if scope == "global" and authority != "human-global":
		raise MemoryErrorWithCode("INVALID_AUTHORITY", "Global memory requires human-global authority")
	if scope != "global" and authority == "human-global":
		raise MemoryErrorWithCode("INVALID_AUTHORITY", "Project/task memory cannot claim human-global authority")
	if authority == "repository" and (not source.startswith("file:") or verification != "on-source-change" or not SHA256_PATTERN.fullmatch(source_fingerprint)):
		raise MemoryErrorWithCode("INVALID_AUTHORITY", "Repository authority requires file source, on-source-change verification, and SHA-256 fingerprint")
	if authority == "verified-external" and (source == "human-command" or verification == "manual"):
		raise MemoryErrorWithCode("INVALID_AUTHORITY", "Verified-external authority requires a named source and re-verification policy")
	created = utc_now()
	last_verified = args.last_verified or created
	if parse_time(last_verified) > parse_time(created) + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
		raise MemoryErrorWithCode("INVALID_TIME", "last_verified is too far in the future")
	return {
		"id": record_id(kind, scope, key, applies, value, supersedes, run_id),
		"kind": kind,
		"key": key,
		"value": value,
		"scope": scope,
		"applies_when": applies,
		"tags": normalize_tags(raw_tags),
		"authority": authority,
		"source": source,
		"source_fingerprint": source_fingerprint,
		"verification_policy": verification,
		"last_verified": last_verified,
		"confidence": confidence,
		"status": "Active",
		"supersedes": supersedes,
		"replaced_by": "",
		"review_trigger": review_trigger,
		"run_id": run_id,
		"created_at": created,
		"updated_at": created,
	}


def mutate_remember(args: argparse.Namespace) -> dict[str, Any]:
	if args.scope == "global":
		path, store, original = load_global_store(Path(args.global_store) if args.global_store else default_global_store(), create=True)
		project = None
	else:
		project, path, store, original, identity = load_project_store(args.project, for_write=True, logical_scope=args.logical_scope)
		if args.scope == "task":
			assert_current_run(project, identity["project_id"], args.run_id)
	record = make_record(args, args.scope)
	active = [item for item in store["records"] if item["status"] == "Active" and record_tuple(item) == record_tuple(record)]
	if active:
		if len(active) == 1 and active[0]["kind"] == record["kind"] and active[0]["value"] == record["value"]:
			return {"ok": True, "operation": "remember", "result": "NO_OP_DUPLICATE", "record_id": active[0]["id"], "revision": store["revision"]}
		raise MemoryErrorWithCode("MEMORY_CONFLICT", f"Active tuple already exists; use correct {active[0]['id']} or a human decision")
	occupied_ids = {item["id"] for item in store["records"]} | {item["id"] for item in store["tombstones"]}
	restored_from = ""
	while record["id"] in occupied_ids:
		restored_from = record["id"]
		record = make_record(args, args.scope, supersedes=restored_from)
	updated, before, after, transaction_id = prepare_transaction(store, "remember", record["id"])
	updated["records"].append(record)
	mark_adapter_dirty(updated)
	commit_store(path, original, updated)
	view_state = "DIRTY"
	if project is not None:
		try:
			render_project_views(project, updated)
			view_state = "CURRENT"
		except (OSError, MemoryErrorWithCode):
			view_state = "DIRTY"
	return {"ok": True, "operation": "remember", "result": "COMMITTED", "record_id": record["id"], "restored_from": restored_from, "transaction_id": transaction_id, "before_revision": before, "after_revision": after, "adapter_state": updated["adapter"]["state"], "view_state": view_state}


def find_record(store: dict[str, Any], record_id_value: str) -> dict[str, Any]:
	matches = [record for record in store["records"] if record.get("id") == record_id_value]
	if len(matches) != 1:
		raise MemoryErrorWithCode("ID_NOT_FOUND", f"Exact active/history record ID not found: {record_id_value}")
	return matches[0]


def load_store_for_id(args: argparse.Namespace, record_id_value: str, for_write: bool) -> tuple[Path | None, Path, dict[str, Any], bytes | None]:
	if "-G-" in record_id_value:
		path, store, raw = load_global_store(Path(args.global_store) if args.global_store else default_global_store(), create=False)
		return None, path, store, raw
	project, path, store, raw, _ = load_project_store(args.project, for_write=for_write, logical_scope=args.logical_scope)
	return project, path, store, raw


def mutate_correct(args: argparse.Namespace) -> dict[str, Any]:
	project, path, store, original = load_store_for_id(args, args.record_id, True)
	old = find_record(store, args.record_id)
	if old["status"] != "Active":
		raise MemoryErrorWithCode("NOT_ACTIVE", f"Only an Active record can be corrected: {args.record_id}")
	if old["scope"] == "task" and project is not None:
		assert_current_run(project, store["project_id"], args.run_id)
		if old.get("run_id") != args.run_id:
			raise MemoryErrorWithCode("RUN_ID_MISMATCH", "Task memory target belongs to a different run")
	for field in ("kind", "key", "applies", "source", "verification", "authority", "source_fingerprint", "last_verified", "confidence", "review_trigger", "run_id"):
		if not hasattr(args, field):
			setattr(args, field, None)
	args.kind = old["kind"]
	args.key = old["key"]
	args.applies = old["applies_when"]
	args.source = args.source or old["source"]
	args.verification = args.verification or old["verification_policy"]
	args.authority = args.authority or old["authority"]
	args.source_fingerprint = args.source_fingerprint or old["source_fingerprint"]
	args.last_verified = args.last_verified or utc_now()
	args.confidence = args.confidence or old["confidence"]
	args.review_trigger = args.review_trigger if args.review_trigger is not None else old["review_trigger"]
	args.run_id = args.run_id or old.get("run_id", "")
	args.tag = args.tag or old.get("tags", [])
	new = make_record(args, old["scope"], supersedes=old["id"])
	updated, before, after, transaction_id = prepare_transaction(store, "correct", new["id"])
	updated_old = find_record(updated, old["id"])
	updated_old["status"] = "Superseded"
	updated_old["replaced_by"] = new["id"]
	updated_old["updated_at"] = utc_now()
	updated["records"].append(new)
	mark_adapter_dirty(updated)
	commit_store(path, original, updated)
	view_state = "NOT_APPLICABLE"
	if project is not None:
		try:
			render_project_views(project, updated)
			view_state = "CURRENT"
		except (OSError, MemoryErrorWithCode):
			view_state = "DIRTY"
	return {"ok": True, "operation": "correct", "result": "COMMITTED", "old_record_id": old["id"], "record_id": new["id"], "transaction_id": transaction_id, "before_revision": before, "after_revision": after, "adapter_state": updated["adapter"]["state"], "view_state": view_state}


def mutate_forget(args: argparse.Namespace) -> dict[str, Any]:
	project, path, store, original = load_store_for_id(args, args.record_id, True)
	old = find_record(store, args.record_id)
	if old["scope"] == "task" and project is not None:
		if not args.run_id:
			raise MemoryErrorWithCode("RUN_ID_REQUIRED", "Forgetting task memory requires --run-id")
		assert_current_run(project, store["project_id"], args.run_id)
		if old.get("run_id") != args.run_id:
			raise MemoryErrorWithCode("RUN_ID_MISMATCH", "Task memory target belongs to a different run")
	updated, before, after, transaction_id = prepare_transaction(store, "forget", old["id"])
	updated["records"] = [record for record in updated["records"] if record["id"] != old["id"]]
	updated["tombstones"].append({"id": old["id"], "scope": old["scope"], "revoked_at": utc_now(), "cache_sync": "DIRTY" if updated["adapter"].get("kind") != "none" else "NOT_CONFIGURED"})
	mark_adapter_dirty(updated)
	commit_store(path, original, updated)
	view_state = "NOT_APPLICABLE"
	if project is not None:
		try:
			render_project_views(project, updated)
			view_state = "CURRENT"
		except (OSError, MemoryErrorWithCode):
			view_state = "DIRTY"
	adapter_configured = updated["adapter"].get("kind") != "none"
	return {
		"ok": True, "operation": "forget", "result": "CANONICAL_COMMITTED", "record_id": old["id"],
		"transaction_id": transaction_id, "before_revision": before, "after_revision": after, "canonical_recall": False,
		"adapter_state": updated["adapter"]["state"], "semantic_deletion_state": "PENDING" if adapter_configured else "NOT_APPLICABLE",
		"semantic_deletion_applicable": adapter_configured, "semantic_deletion_verified": False, "view_state": view_state,
		"limitations": ["Git history", "backups", "chat exports", "provider memory"],
	}


def verification_state(record: dict[str, Any], project: Path | None) -> str:
	if record.get("status") == "Stale":
		return "STALE"
	if record.get("status") == "Conflict":
		return "CONFLICTED"
	if record.get("status") != "Active":
		return "UNAVAILABLE"
	if unsafe_reason(str(record.get("key", "")), str(record.get("value", "")), str(record.get("source", ""))):
		return "UNAVAILABLE"
	policy = str(record.get("verification_policy", ""))
	if policy == "manual":
		return "VALID_UNTIL_TRIGGER"
	ttl = ttl_seconds(policy)
	if ttl is not None:
		try:
			age = parse_time(utc_now()) - parse_time(record["last_verified"])
			if age < -timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
				return "UNAVAILABLE"
			return "VERIFIED_CURRENT" if age <= timedelta(seconds=ttl) else "STALE"
		except (MemoryErrorWithCode, KeyError, OverflowError, ValueError):
			return "UNAVAILABLE"
	source = str(record.get("source", ""))
	fingerprint = str(record.get("source_fingerprint", ""))
	if source.startswith("file:") and project is not None:
		relative = source[5:]
		candidate = project / relative
		try:
			ensure_within(candidate, project, "record source")
		except MemoryErrorWithCode:
			return "UNAVAILABLE"
		if not candidate.is_file():
			return "UNAVAILABLE"
		actual_digest = sha256_file_bounded(candidate)
		if actual_digest is None:
			return "UNAVAILABLE"
		actual = f"sha256:{actual_digest}"
		return "VERIFIED_CURRENT" if actual == fingerprint else "STALE"
	return "UNAVAILABLE"


def query_tokens(value: str) -> set[str]:
	normalized = unicodedata.normalize("NFKC", value).casefold()
	return {token for token in re.split(r"[^\w./-]+", normalized) if token}


def match_rank(record: dict[str, Any], query: str, semantic_ids: set[str]) -> int | None:
	normalized_query = normalize_key(query)
	if record["key"] == normalized_query:
		return 0
	if normalized_query in record.get("tags", []):
		return 1
	query_set = query_tokens(query)
	record_set = query_tokens(record["key"] + " " + record["value"] + " " + " ".join(record.get("tags", [])))
	if query_set and query_set & record_set:
		return 2
	if record["id"] in semantic_ids:
		return 3
	return None


def read_adapter_ids(path: Path, project: Path, store: dict[str, Any]) -> tuple[set[str], str]:
	adapter = store["adapter"]
	if adapter.get("state") != "READY" or adapter.get("source_revision") != store["revision"]:
		return set(), "NOT_READY"
	cache_root = project / ".harness" / ".cache" / "memory"
	try:
		ensure_within(cache_root, project, "adapter cache root")
		if not cache_root.is_dir() or path_is_link_or_junction(cache_root):
			return set(), "INVALID"
		ensure_within(path, cache_root, "adapter results")
	except (OSError, MemoryErrorWithCode):
		return set(), "INVALID"
	try:
		if not path.is_file() or path.stat().st_size > MAX_ADAPTER_RESULT_BYTES:
			return set(), "INVALID"
		raw = path.read_bytes()
	except OSError:
		return set(), "INVALID"
	if len(raw) > MAX_ADAPTER_RESULT_BYTES:
		return set(), "INVALID"
	if adapter.get("export_digest") and f"sha256:{sha256_bytes(raw)}" != adapter["export_digest"]:
		return set(), "INVALID"
	try:
		data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_json_object)
	except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError, MemoryError):
		return set(), "INVALID"
	if not isinstance(data, dict):
		return set(), "INVALID"
	selected_ids = data.get("selected_ids")
	if (
		set(data) != ADAPTER_RESULT_FIELDS or data.get("schema_version") != 1 or data.get("project_id") != store["project_id"]
		or not isinstance(data.get("source_revision"), int) or isinstance(data.get("source_revision"), bool)
		or data.get("source_revision") != store["revision"] or not isinstance(selected_ids, list)
		or len(selected_ids) > MAX_ADAPTER_SELECTED_IDS
		or any(not isinstance(item, str) or not ID_PATTERN.fullmatch(item) for item in selected_ids)
		or len(set(selected_ids)) != len(selected_ids)
	):
		return set(), "INVALID"
	eligible_ids = {
		record["id"] for record in store["records"]
		if record.get("status") == "Active" and record.get("scope") == "project"
	}
	if not set(selected_ids).issubset(eligible_ids):
		return set(), "INVALID"
	return set(selected_ids), "READY"


def recall(args: argparse.Namespace) -> dict[str, Any]:
	project, _, project_store, _, _ = load_project_store(args.project, for_write=False, logical_scope=args.logical_scope)
	try:
		state, _ = read_json_bytes(project / ".harness" / "STATE.json")
		current_task_run = normalized_active_run_id(state, project_store["project_id"])
	except MemoryErrorWithCode:
		current_task_run = ""
	stores: list[tuple[str, dict[str, Any], Path | None]] = []
	if args.scope in {"project", "all"}:
		stores.append(("project", project_store, project))
	if args.scope in {"global", "all"}:
		try:
			_, global_store, _ = load_global_store(Path(args.global_store) if args.global_store else default_global_store())
			stores.append(("global", global_store, None))
		except MemoryErrorWithCode as exc:
			if exc.code != "GLOBAL_UNAVAILABLE":
				raise
	semantic_ids: set[str] = set()
	adapter_result_state = "NOT_REQUESTED"
	if args.adapter_results:
		semantic_ids, adapter_result_state = read_adapter_ids(Path(args.adapter_results).expanduser(), project, project_store)
	manifest: list[dict[str, Any]] = []
	manifest_by_id: dict[str, dict[str, Any]] = {}
	candidates: list[tuple[tuple[Any, ...], dict[str, Any], str]] = []
	active_tuples: dict[tuple[str, str, str], list[str]] = {}
	for _, store, _ in stores:
		for record in store["records"]:
			if record.get("scope") == "task" and record.get("run_id") != current_task_run:
				continue
			if record.get("status") == "Active":
				active_tuples.setdefault(record_tuple(record), []).append(record["id"])
	for store_scope, store, source_project in stores:
		for record in store["records"]:
			if record.get("scope") == "task" and record.get("run_id") != current_task_run:
				continue
			match = match_rank(record, args.query, semantic_ids)
			if match is None:
				continue
			state = "CONFLICTED" if len(active_tuples.get(record_tuple(record), [])) > 1 else verification_state(record, source_project)
			entry = {"id": record["id"], "scope": record["scope"], "verification_state": state, "selected": False, "reason": "not eligible"}
			manifest.append(entry)
			manifest_by_id[record["id"]] = entry
			if state not in VERIFICATION_RANK:
				continue
			scope_rank = {"task": 0, "project": 1, "global": 2}[record["scope"]]
			authority_rank = AUTHORITIES.get(record["authority"], 99)
			try:
				last_verified_rank = -int(parse_time(record.get("last_verified", "")).timestamp())
			except MemoryErrorWithCode:
				last_verified_rank = 0
			rank = (match, scope_rank, authority_rank, VERIFICATION_RANK[state], last_verified_rank, record["id"])
			candidates.append((rank, record, state))
	best_scope = {}
	for _, record, state in candidates:
		if state in VERIFICATION_RANK:
			key = (record["key"], record["applies_when"])
			best_scope[key] = min(best_scope.get(key, 99), {"task": 0, "project": 1, "global": 2}[record["scope"]])
	selected: list[dict[str, Any]] = []
	used_bytes = 0
	for _, record, state in sorted(candidates, key=lambda item: item[0]):
		key = (record["key"], record["applies_when"])
		if {"task": 0, "project": 1, "global": 2}[record["scope"]] > best_scope.get(key, 99):
			manifest_by_id[record["id"]]["reason"] = "shadowed by a valid narrower-scope record"
			continue
		payload = {"id": record["id"], "kind": record["kind"], "key": record["key"], "value": record["value"], "scope": record["scope"], "applies_when": record["applies_when"], "verification_state": state}
		size = len(canonical_json(payload))
		if len(selected) >= args.max_records or used_bytes + size > args.max_bytes:
			continue
		selected.append(payload)
		used_bytes += size
		manifest_by_id[record["id"]]["selected"] = True
		manifest_by_id[record["id"]]["reason"] = "selected by deterministic rank"
	digest_input = [{"id": item["id"], "state": item["verification_state"]} for item in selected]
	full_manifest = sorted(manifest, key=lambda item: item["id"])
	manifest_digest = f"sha256:{sha256_bytes(canonical_json(full_manifest))}"
	bounded_manifest: list[dict[str, Any]] = []
	manifest_bytes = 0
	for item in sorted(full_manifest, key=lambda entry: (not entry["selected"], entry["id"])):
		item_size = len(canonical_json(item))
		if len(bounded_manifest) >= MAX_RECALL_MANIFEST_ENTRIES or manifest_bytes + item_size > MAX_RECALL_MANIFEST_BYTES:
			continue
		bounded_manifest.append(item)
		manifest_bytes += item_size
	return {
		"ok": True, "operation": "recall", "query": args.query, "selected": selected, "manifest": bounded_manifest,
		"manifest_total": len(full_manifest), "manifest_omitted": len(full_manifest) - len(bounded_manifest), "manifest_digest": manifest_digest,
		"manifest_utf8_bytes": manifest_bytes, "selected_digest": f"sha256:{sha256_bytes(canonical_json(digest_input))}",
		"used_utf8_bytes": used_bytes, "max_utf8_bytes": args.max_bytes, "max_records": args.max_records,
		"adapter_candidates_used": bool(semantic_ids), "adapter_result_state": adapter_result_state,
	}


def memory_status(args: argparse.Namespace) -> dict[str, Any]:
	project, _, store, _, identity = load_project_store(args.project, for_write=False, logical_scope=args.logical_scope)
	active = [record for record in store["records"] if record["status"] == "Active"]
	counts: dict[str, int] = {}
	for record in active:
		counts[record["kind"]] = counts.get(record["kind"], 0) + 1
	return {"ok": True, "operation": "status", "project": str(project), "project_id": identity["project_id"], "revision": store["revision"], "active_counts": counts, "tombstones": len(store["tombstones"]), "adapter": store["adapter"], "last_transaction": store["last_transaction"]}


def purge_memory_cache(project: Path) -> tuple[str, int]:
	cache_root = project / ".harness" / ".cache" / "memory"
	ensure_within(cache_root, project, "memory cache root")
	if not cache_root.exists():
		return "EMPTY", 0
	if path_is_link_or_junction(cache_root) or not cache_root.is_dir():
		raise MemoryErrorWithCode("SYMLINK_REJECTED", f"Memory cache root is not a safe directory: {cache_root}")
	root_resolved = cache_root.resolve(strict=True)
	removed = 0

	def purge_directory(directory: Path) -> None:
		nonlocal removed
		resolved = directory.resolve(strict=True)
		try:
			resolved.relative_to(root_resolved)
		except ValueError as exc:
			raise MemoryErrorWithCode("PATH_ESCAPE", f"Cache directory escapes the project cache: {directory}") from exc
		with os.scandir(directory) as iterator:
			entries = list(iterator)
		for entry in entries:
			candidate = Path(entry.path)
			if path_is_link_or_junction(candidate):
				raise MemoryErrorWithCode("SYMLINK_REJECTED", f"Cache entry is a symlink or junction: {candidate}")
			elif entry.is_dir(follow_symlinks=False):
				purge_directory(candidate)
				candidate.rmdir()
			else:
				candidate.unlink()
				removed += 1

	purge_directory(cache_root)
	return ("PURGED" if removed else "EMPTY"), removed


def close_run_memory(args: argparse.Namespace) -> dict[str, Any]:
	project, path, store, original, identity = load_project_store(args.project, for_write=True, logical_scope=args.logical_scope)
	assert_current_run(project, identity["project_id"], args.run_id, allow_done=True)
	args.run_id = normalize_text(args.run_id, "run_id", 200)
	removed = [record for record in store["records"] if record.get("scope") == "task" and record.get("run_id") == args.run_id]
	needs_adapter_invalidation = store["adapter"].get("kind") != "none" and store["adapter"].get("state") != "DIRTY"
	committed = bool(removed or needs_adapter_invalidation)
	result = "NO_OP"
	view_state = "NOT_APPLICABLE"
	transaction_id = ""
	before = store["revision"]
	after = store["revision"]
	if committed:
		operation = "close-run" if removed else "close-run-cache-invalidate"
		updated, before, after, transaction_id = prepare_transaction(store, operation, args.run_id)
		removed_ids = {record["id"] for record in removed}
		updated["records"] = [record for record in updated["records"] if record["id"] not in removed_ids]
		cache_sync = "DIRTY" if updated["adapter"].get("kind") != "none" else "NOT_CONFIGURED"
		updated["tombstones"].extend({"id": record["id"], "scope": "task", "revoked_at": utc_now(), "cache_sync": cache_sync} for record in removed)
		mark_adapter_dirty(updated)
		commit_store(path, original, updated)
		store = updated
		result = "COMMITTED" if removed else "CACHE_INVALIDATED"
	try:
		render_project_views(project, store)
		view_state = "CURRENT"
	except (OSError, MemoryErrorWithCode):
		view_state = "DIRTY"
	try:
		cache_cleanup_state, cache_payloads_removed = purge_memory_cache(project)
		cache_cleanup_error = ""
	except (OSError, MemoryErrorWithCode) as exc:
		cache_cleanup_state = "DIRTY"
		cache_payloads_removed = 0
		cache_cleanup_error = type(exc).__name__
	cache_deletion_verified = cache_cleanup_state != "DIRTY"
	derived_cleanup_verified = view_state == "CURRENT" and cache_deletion_verified
	canonical_result = result
	if not derived_cleanup_verified:
		if committed and view_state == "DIRTY" and not cache_deletion_verified:
			result = "CANONICAL_COMMITTED_DERIVED_DIRTY"
		elif committed and view_state == "DIRTY":
			result = "CANONICAL_COMMITTED_VIEWS_DIRTY"
		elif committed:
			result = "CANONICAL_COMMITTED_CACHE_DIRTY"
		else:
			result = "DERIVED_CLEANUP_FAILED"
	payload = {
		"ok": derived_cleanup_verified, "operation": "close-run", "result": result, "canonical_result": canonical_result, "run_id": args.run_id,
		"removed": len(removed), "revision": store["revision"], "adapter_state": store["adapter"]["state"],
		"view_state": view_state, "cache_cleanup_state": cache_cleanup_state,
		"cache_payloads_removed": cache_payloads_removed, "cache_cleanup_error": cache_cleanup_error,
		"cache_deletion_verified": cache_deletion_verified, "derived_cleanup_verified": derived_cleanup_verified,
	}
	if committed:
		payload.update({"transaction_id": transaction_id, "before_revision": before, "after_revision": after})
	return payload


def validate_project_memory(args: argparse.Namespace) -> dict[str, Any]:
	project, identity_path, store_path = project_paths(args.project)
	identity, _ = read_json_bytes(identity_path)
	store, _ = read_json_bytes(store_path)
	errors = validate_identity(identity) + validate_store(store, identity.get("project_id"))
	try:
		assert_current_identity(project, identity, args.logical_scope)
	except MemoryErrorWithCode as exc:
		errors.append(str(exc))
	try:
		state, _ = read_json_bytes(project / ".harness" / "STATE.json")
		current_run = normalized_active_run_id(state, str(identity.get("project_id", "")))
		for record in store.get("records", []):
			if isinstance(record, dict) and record.get("scope") == "task" and (not current_run or record.get("run_id") != current_run):
				errors.append(f"task record belongs to a non-current run: {record.get('id')}")
	except MemoryErrorWithCode as exc:
		errors.append(str(exc))
	view_revisions: dict[str, int | None] = {}
	for name in ("CONTEXT.md", "PREFERENCES.md", "DECISIONS.md"):
		path = project / ".harness" / name
		if not path.is_file() or path_is_link_or_junction(path):
			errors.append(f"missing or symlinked derived view {name}")
			view_revisions[name] = None
			continue
		try:
			if path.stat().st_size > MAX_DERIVED_VIEW_BYTES:
				raise ValueError(f"view exceeds {MAX_DERIVED_VIEW_BYTES} bytes")
			raw_view = path.read_bytes()
			if len(raw_view) > MAX_DERIVED_VIEW_BYTES:
				raise ValueError(f"view exceeds {MAX_DERIVED_VIEW_BYTES} bytes")
			view_text = raw_view.decode("utf-8")
		except (OSError, UnicodeDecodeError, ValueError) as exc:
			errors.append(f"invalid derived view {name}: {exc}")
			view_revisions[name] = None
			continue
		match = re.search(r"^- Source memory revision:[ \t]*(\d+)[ \t]*$", view_text, re.MULTILINE)
		view_revisions[name] = int(match.group(1)) if match else None
		if view_revisions[name] != store.get("revision"):
			errors.append(f"stale or invalid derived view {name}")
	return {"ok": not errors, "operation": "validate", "project_id": identity.get("project_id"), "revision": store.get("revision"), "view_revisions": view_revisions, "errors": errors}


def render_command(args: argparse.Namespace) -> dict[str, Any]:
	project, _, store, _, _ = load_project_store(args.project, for_write=False, logical_scope=args.logical_scope)
	files = render_project_views(project, store)
	return {"ok": True, "operation": "render", "revision": store["revision"], "files": files}


def export_cache(args: argparse.Namespace) -> dict[str, Any]:
	project, store_path, store, original, _ = load_project_store(args.project, for_write=True, logical_scope=args.logical_scope)
	if unsafe_reason(args.kind):
		raise MemoryErrorWithCode("UNSAFE_MEMORY", "Refusing unsafe adapter kind")
	adapter_kind = normalize_key(args.kind)
	if adapter_kind == "none":
		raise MemoryErrorWithCode("INVALID_ADAPTER_KIND", "Adapter kind 'none' is reserved for an unconfigured adapter")
	cache_root = project / ".harness" / ".cache" / "memory"
	ensure_within(cache_root, project, "cache root")
	cache_root.mkdir(parents=True, exist_ok=True)
	if path_is_link_or_junction(cache_root):
		raise MemoryErrorWithCode("SYMLINK_REJECTED", f"Cache root is a symlink: {cache_root}")
	requested_output = Path(args.output).expanduser()
	if not requested_output.is_absolute():
		requested_output = project / requested_output
	output = ensure_within(requested_output.absolute(), cache_root, "cache export")
	updated, before, after, transaction_id = prepare_transaction(store, "export-cache", "CACHE")
	active = [{"id": record["id"], "project_id": store["project_id"], "scope": record["scope"], "kind": record["kind"], "key": record["key"], "value": record["value"], "applies_when": record["applies_when"], "source": record["source"], "verification_policy": record["verification_policy"]} for record in store["records"] if record["status"] == "Active" and record["scope"] == "project"]
	if len(active) > MAX_CACHE_EXPORT_RECORDS:
		raise MemoryErrorWithCode("CACHE_EXPORT_TOO_LARGE", f"Cache export exceeds {MAX_CACHE_EXPORT_RECORDS} records")
	payload = {"schema_version": 1, "project_id": store["project_id"], "source_revision": after, "records": active, "selected_ids": []}
	raw = pretty_json(payload)
	if len(raw) > MAX_CACHE_EXPORT_BYTES:
		raise MemoryErrorWithCode("CACHE_EXPORT_TOO_LARGE", f"Cache export exceeds {MAX_CACHE_EXPORT_BYTES} UTF-8 bytes")
	existing = read_regular_file_bounded(output, MAX_CACHE_EXPORT_BYTES, "cache export target") if output.exists() else None
	atomic_replace(output, raw, expected=existing)
	updated["adapter"] = {"kind": adapter_kind, "state": "EXPORT_READY", "scope": store["project_id"], "source_revision": after, "export_digest": f"sha256:{sha256_bytes(raw)}"}
	commit_store(store_path, original, updated)
	return {"ok": True, "operation": "export-cache", "output": str(output), "record_count": len(active), "export_digest": updated["adapter"]["export_digest"], "source_revision": after, "store_revision": after, "transaction_id": transaction_id, "adapter_state": "EXPORT_READY"}


def add_common_record_args(parser: argparse.ArgumentParser, include_kind: bool = True) -> None:
	if include_kind:
		parser.add_argument("--kind", required=True, choices=sorted(RECORD_KINDS))
	parser.add_argument("--key", required=include_kind)
	parser.add_argument("--value", required=True)
	parser.add_argument("--applies", default="always")
	parser.add_argument("--tag", action="append", default=[])
	parser.add_argument("--source")
	parser.add_argument("--source-fingerprint")
	parser.add_argument("--verification")
	parser.add_argument("--last-verified")
	parser.add_argument("--confidence")
	parser.add_argument("--review-trigger")
	parser.add_argument("--run-id")


def doctor_command(args: argparse.Namespace) -> dict[str, Any]:
	DOCTOR_KNOWN_OPERATIONS = {"start", "resume", "review", "init", "memory", "done"}
	DOCTOR_PARSE_ERRORS = (MemoryErrorWithCode, OSError, KeyError, TypeError, AttributeError, ValueError)
	checks: list[dict[str, Any]] = []

	def record(name: str, ok: bool, detail: str = "", **extra: Any) -> None:
		entry: dict[str, Any] = {"check": name, "ok": ok, "detail": detail}
		entry.update(extra)
		checks.append(entry)

	project_id = ""
	store: dict[str, Any] = {}
	try:
		project, identity_path, store_path = project_paths(args.project)
		record("project-initialized", True, str(project))
	except MemoryErrorWithCode as exc:
		record("project-initialized", False, str(exc))
		return {"ok": False, "operation": "doctor", "checks": checks, "verdict": "UNINITIALIZED"}
	except OSError as exc:
		record("project-initialized", False, f"IO_ERROR {exc}")
		return {"ok": False, "operation": "doctor", "checks": checks, "verdict": "UNAVAILABLE"}

	try:
		identity, _ = read_json_bytes(identity_path)
		identity_errors = validate_identity(identity)
		current_repository = repository_identity(project, str(identity.get("project_id", "")), str(identity.get("logical_scope", ".")))["repository"]
		drifted = [field for field in ("kind", "remote_fingerprint", "root_commit") if identity.get("repository", {}).get(field, "") != current_repository.get(field, "")]
		if identity_errors:
			record("identity-valid", False, "; ".join(identity_errors))
		elif drifted:
			record("identity-current", False, f"repository drifted: {', '.join(drifted)}")
		else:
			record("identity-valid", True, str(identity.get("project_id", "")))
			project_id = str(identity.get("project_id", ""))
	except DOCTOR_PARSE_ERRORS as exc:
		record("identity-valid", False, str(exc))

	try:
		store, _ = read_json_bytes(store_path)
		store_errors = validate_store(store, project_id or None)
		scopes: dict[str, int] = {}
		statuses: dict[str, int] = {}
		for item in store.get("records", []):
			scopes[item.get("scope", "?")] = scopes.get(item.get("scope", "?"), 0) + 1
			statuses[item.get("status", "?")] = statuses.get(item.get("status", "?"), 0) + 1
		active_tuples: dict[tuple, int] = {}
		for item in store.get("records", []):
			if item.get("status") == "Active":
				key = tuple(item.get(field, "") for field in ("kind", "key", "applies_when"))
				active_tuples[key] = active_tuples.get(key, 0) + 1
		conflicted = sum(1 for count in active_tuples.values() if count > 1)
		record(
			"store-valid",
			not store_errors and conflicted == 0,
			"; ".join(store_errors) if store_errors else ("duplicate active tuples: use correct" if conflicted else ""),
			revision=store.get("revision"),
			records=scopes,
			statuses=statuses,
			conflicted_tuples=conflicted,
			tombstones=len(store.get("tombstones", [])),
		)
	except DOCTOR_PARSE_ERRORS as exc:
		record("store-valid", False, str(exc))

	state_path = project / ".harness" / "STATE.json"
	try:
		state, _ = read_json_bytes(state_path)
		run_state = state.get("state")
		run_operation = state.get("operation")
		run_id_value = state.get("run_id")
		known_state = isinstance(run_state, str) and (run_state in ACTIVE_RUN_STATES or run_state == "DONE")
		idle_intake = run_state == "INTAKE" and run_id_value in ("", None)
		if idle_intake:
			safe_run = True
			valid_operation = isinstance(run_operation, str) and run_operation != ""
		else:
			safe_run = isinstance(run_id_value, str) and run_id_value != "" and normalize_text(run_id_value, "run_id", 200) == run_id_value and not unsafe_reason(run_id_value)
			valid_operation = isinstance(run_operation, str) and (run_operation in DOCTOR_KNOWN_OPERATIONS or run_state == "DONE")
		matches_project = project_id == "" or state.get("project_id") == project_id
		ok = known_state and safe_run and valid_operation and matches_project
		record(
			"state-readable",
			ok,
			"no active run yet (INTAKE)" if idle_intake else f"state={run_state} operation={run_operation}",
			run_id=run_id_value if isinstance(run_id_value, str) else "",
			project_id_match=matches_project,
		)
	except DOCTOR_PARSE_ERRORS as exc:
		record("state-readable", False, str(exc))

	try:
		expected_views = project_view_payloads(store) if store else {}
		view_states: dict[str, str] = {}
		for name, content in sorted(expected_views.items()):
			path = ensure_within(project / ".harness" / name, project, name)
			if not path.exists():
				view_states[name] = "MISSING"
				continue
			existing = read_regular_file_bounded(path, MAX_DERIVED_VIEW_BYTES, name)
			view_states[name] = "CURRENT" if existing == content else "DRIFTED"
		bad = [name for name, value in view_states.items() if value != "CURRENT"]
		record("views-fresh", not bad, ", ".join(f"{name}:{view_states[name]}" for name in bad) or "all derived views match canonical memory", views=view_states)
	except DOCTOR_PARSE_ERRORS as exc:
		record("views-fresh", False, str(exc))

	runtime_manifest = project / ".harness" / "runtime" / "HARNESS-RUNTIME.json"
	try:
		if runtime_manifest.is_file():
			pin, _ = read_json_bytes(runtime_manifest)
			version = str(pin.get("source_version", ""))
			digest_ok = SHA256_PATTERN.fullmatch(str(pin.get("source_digest", ""))) is not None
			skill_present = (runtime_manifest.parent / "SKILL.md").is_file()
			record("runtime-pinned", digest_ok and skill_present, f"version={version}", manifest_complete=digest_ok, skill_present=skill_present)
		else:
			record("runtime-pinned", False, "no pinned runtime under .harness/runtime; run init_project.py")
	except DOCTOR_PARSE_ERRORS as exc:
		record("runtime-pinned", False, str(exc))

	lock_probe = "UNKNOWN"
	try:
		with target_file_lock(store_path, timeout_seconds=1.5):
			lock_probe = "AVAILABLE"
	except MemoryErrorWithCode as exc:
		lock_probe = exc.code
	except OSError as exc:
		lock_probe = f"IO_ERROR {exc}"
	record("writer-lock-probe", lock_probe in {"AVAILABLE"}, str(lock_probe))

	cache_root = project / ".harness" / ".cache" / "memory"
	record("cache-dir", not cache_root.exists() or cache_root.is_dir(), "present" if cache_root.exists() else "empty")

	failed = [entry["check"] for entry in checks if not entry["ok"]]
	return {
		"ok": not failed,
		"operation": "doctor",
		"project": str(project),
		"verdict": "HEALTHY" if not failed else "DEGRADED",
		"failed_checks": failed,
		"checks": checks,
	}


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Deterministic Harness memory operations")
	parser.add_argument("--json", action="store_true", help="Retained for CLI compatibility; output is always JSON")
	subparsers = parser.add_subparsers(dest="command", required=True)
	remember_parser = subparsers.add_parser("remember")
	remember_parser.add_argument("--project", default=".")
	remember_parser.add_argument("--logical-scope", default=".")
	remember_parser.add_argument("--global-store")
	remember_parser.add_argument("--scope", required=True, choices=sorted(SCOPES))
	add_common_record_args(remember_parser)
	correct_parser = subparsers.add_parser("correct")
	correct_parser.add_argument("record_id")
	correct_parser.add_argument("--project", default=".")
	correct_parser.add_argument("--logical-scope", default=".")
	correct_parser.add_argument("--global-store")
	add_common_record_args(correct_parser, include_kind=False)
	forget_parser = subparsers.add_parser("forget")
	forget_parser.add_argument("record_id")
	forget_parser.add_argument("--project", default=".")
	forget_parser.add_argument("--logical-scope", default=".")
	forget_parser.add_argument("--global-store")
	forget_parser.add_argument("--run-id")
	close_parser = subparsers.add_parser("close-run")
	close_parser.add_argument("--project", default=".")
	close_parser.add_argument("--logical-scope", default=".")
	close_parser.add_argument("--run-id", required=True)
	recall_parser = subparsers.add_parser("recall")
	recall_parser.add_argument("--project", default=".")
	recall_parser.add_argument("--logical-scope", default=".")
	recall_parser.add_argument("--global-store")
	recall_parser.add_argument("--scope", choices=("project", "global", "all"), default="all")
	recall_parser.add_argument("--query", required=True)
	recall_parser.add_argument("--max-records", type=int, default=20)
	recall_parser.add_argument("--max-bytes", type=int, default=12000)
	recall_parser.add_argument("--adapter-results")
	status_parser = subparsers.add_parser("status")
	status_parser.add_argument("--project", default=".")
	status_parser.add_argument("--logical-scope", default=".")
	doctor_parser = subparsers.add_parser("doctor")
	doctor_parser.add_argument("--project", default=".")
	doctor_parser.add_argument("--logical-scope", default=".")
	validate_parser = subparsers.add_parser("validate")
	validate_parser.add_argument("--project", default=".")
	validate_parser.add_argument("--logical-scope", default=".")
	render_parser = subparsers.add_parser("render")
	render_parser.add_argument("--project", default=".")
	render_parser.add_argument("--logical-scope", default=".")
	export_parser = subparsers.add_parser("export-cache")
	export_parser.add_argument("--project", default=".")
	export_parser.add_argument("--logical-scope", default=".")
	export_parser.add_argument("--output", required=True)
	export_parser.add_argument("--kind", default="generic")
	return parser.parse_args()


def run_without_operation_lock(args: argparse.Namespace) -> dict[str, Any]:
	if args.command == "remember":
		if args.scope == "task" and not args.run_id:
			raise MemoryErrorWithCode("RUN_ID_REQUIRED", "Task memory requires --run-id")
		return mutate_remember(args)
	if args.command == "correct":
		return mutate_correct(args)
	if args.command == "forget":
		return mutate_forget(args)
	if args.command == "close-run":
		return close_run_memory(args)
	if args.command == "recall":
		if args.max_records < 1 or args.max_records > MAX_RECALL_RECORDS or args.max_bytes < 256 or args.max_bytes > MAX_RECALL_BYTES:
			raise MemoryErrorWithCode("INVALID_BUDGET", f"Recall requires max-records 1..{MAX_RECALL_RECORDS} and max-bytes 256..{MAX_RECALL_BYTES}")
		return recall(args)
	if args.command == "status":
		return memory_status(args)
	if args.command == "doctor":
		return doctor_command(args)
	if args.command == "validate":
		return validate_project_memory(args)
	if args.command == "render":
		return render_command(args)
	if args.command == "export-cache":
		return export_cache(args)
	raise MemoryErrorWithCode("UNKNOWN_COMMAND", str(args.command))


def run(args: argparse.Namespace) -> dict[str, Any]:
	global_only = (args.command == "remember" and args.scope == "global") or (args.command in {"correct", "forget"} and "-G-" in args.record_id)
	mutating_project_command = args.command in {"remember", "correct", "forget", "close-run", "render", "export-cache"} and not global_only
	if not mutating_project_command:
		return run_without_operation_lock(args)
	project_argument = getattr(args, "project", ".")
	try:
		project = Path(project_argument).expanduser().resolve(strict=True)
	except OSError:
		return run_without_operation_lock(args)
	harness = project / ".harness"
	if not harness.is_dir() or path_is_link_or_junction(harness):
		return run_without_operation_lock(args)
	with target_file_lock(harness / "MEMORY.json"):
		return run_without_operation_lock(args)


def main() -> int:
	configure_utf8_stdio()
	args = parse_args()
	try:
		result = run(args)
		print(json.dumps(result, ensure_ascii=False, indent=2))
		return 0 if result.get("ok") else 1
	except MemoryErrorWithCode as exc:
		print(json.dumps({"ok": False, "code": exc.code, "error": str(exc)}, ensure_ascii=False, indent=2))
		return 2
	except OSError as exc:
		print(json.dumps({"ok": False, "code": "IO_ERROR", "error": str(exc)}, ensure_ascii=False, indent=2))
		return 2
	except (TypeError, ValueError) as exc:
		print(json.dumps({"ok": False, "code": "INVALID_DATA", "error": f"Malformed structured data: {exc}"}, ensure_ascii=False, indent=2))
		return 2


if __name__ == "__main__":
	raise SystemExit(main())
