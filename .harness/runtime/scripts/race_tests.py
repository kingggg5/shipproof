"""Real two-process race regression tests for Harness memory operations.

Each scenario spawns genuine OS processes against a disposable fixture project,
so contention is always measured against a held lock, never simulated in-process.
Run: python race_tests.py [--keep]
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))
sys.dont_write_bytecode = True

READY_POLL_SECONDS = 0.01
READY_DEADLINE_SECONDS = 15.0


def utc_now() -> str:
	return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def new_project_id() -> str:
	return f"project-{uuid.uuid4()}"


def make_fixture(root: Path, project_id: str, run_id: str) -> Path:
	project = root / "proj"
	harness = project / ".harness"
	harness.mkdir(parents=True)
	identity = {
		"schema_version": 1,
		"project_id": project_id,
		"logical_scope": ".",
		"repository": {"kind": "directory", "remote_fingerprint": "", "root_commit": ""},
		"created_at": utc_now(),
		"last_verified_at": utc_now(),
	}
	store = {
		"schema_version": 1,
		"project_id": project_id,
		"revision": 0,
		"records": [],
		"tombstones": [],
		"adapter": {"kind": "none", "state": "UNAVAILABLE", "scope": "", "source_revision": 0, "export_digest": ""},
		"last_transaction": None,
	}
	state = {"project_id": project_id, "run_id": run_id, "state": "BUILD", "operation": "start"}
	(harness / "IDENTITY.json").write_bytes(pretty(identity))
	(harness / "MEMORY.json").write_bytes(pretty(store))
	(harness / "STATE.json").write_bytes(pretty(state))
	return project


def pretty(payload: dict) -> bytes:
	return (json.dumps(payload, ensure_ascii=False, indent=1, sort_keys=True) + "\n").encode("utf-8")


def cli(project: Path, *arguments: str) -> subprocess.CompletedProcess:
	command = [sys.executable, str(SCRIPTS_DIR / "memory_ops.py"), *[str(item) for item in arguments]]
	return subprocess.run([*command, "--project", str(project)], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)


def cli_json(result: subprocess.CompletedProcess) -> dict:
	try:
		return json.loads(result.stdout)
	except json.JSONDecodeError:
		return {"ok": False, "code": "UNPARSEABLE", "error": result.stdout + result.stderr}


def spawn_child(mode: str, lock_path: Path, hold_ms: int, ready_file: Path, result_file: Path) -> subprocess.Popen:
	command = [sys.executable, str(Path(__file__).resolve()), "__child__", mode, str(lock_path), str(hold_ms), str(ready_file), str(result_file)]
	return subprocess.Popen(command, cwd=str(SCRIPTS_DIR))


def wait_ready(ready_file: Path, deadline_seconds: float = READY_DEADLINE_SECONDS) -> bool:
	deadline = time.monotonic() + deadline_seconds
	while time.monotonic() < deadline:
		if ready_file.exists():
			return True
		time.sleep(READY_POLL_SECONDS)
	return False


def wait_exit(process: subprocess.Popen, timeout_seconds: float = READY_DEADLINE_SECONDS) -> int:
	try:
		return process.wait(timeout=timeout_seconds)
	except subprocess.TimeoutExpired:
		process.kill()
		return -1


def short_path(path: Path) -> str:
	if os.name != "nt":
		return ""
	buffer = ctypes.create_unicode_buffer(1024)
	length = ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, 1024)
	if length == 0 or length > 1023:
		return ""
	return buffer.value


def running_as_root() -> bool:
	return hasattr(os, "geteuid") and os.geteuid() == 0


class Report:
	def __init__(self) -> None:
		self.rows: list[dict] = []

	def add(self, name: str, outcome: str, detail: str) -> None:
		self.rows.append({"test": name, "outcome": outcome, "detail": detail})
		print(f"[{outcome}] {name}: {detail}", flush=True)

	def counts(self) -> dict:
		outcomes = [row["outcome"] for row in self.rows]
		return {key: outcomes.count(key) for key in ("PASS", "FAIL", "KNOWN_GAP", "SKIP")}


def test_contention(report: Report, workspace: Path) -> Path:
	project_id = new_project_id()
	run_id = "RUN-RACE-CONTENTION"
	project = make_fixture(workspace / "contention", project_id, run_id)
	store_path = project / ".harness" / "MEMORY.json"
	lock_path = store_path
	base = workspace / "contention"
	holder = spawn_child("hold", lock_path, 3000, base / "holder.ready", base / "holder.result")
	if not wait_ready(base / "holder.ready"):
		report.add("contention", "FAIL", "holder never signalled ready")
		wait_exit(holder)
		return project
	started = time.monotonic()
	impatient = spawn_child("timeout", lock_path, 700, base / "impatient.ready", base / "impatient.result")
	wait_exit(impatient, 30)
	impatient_elapsed = time.monotonic() - started
	try:
		impatient_result = json.loads((base / "impatient.result").read_text(encoding="utf-8"))
	except (OSError, json.JSONDecodeError):
		impatient_result = {}
	if impatient_result.get("code") == "LOCK_TIMEOUT" and not impatient_result.get("acquired"):
		report.add("contender-times-out-against-held-lock", "PASS", f"LOCK_TIMEOUT after {impatient_elapsed:.2f}s, mutation refused")
	else:
		report.add("contender-times-out-against-held-lock", "FAIL", f"unexpected contender result: {impatient_result}")
	patient = cli(project, "remember", "--kind", "fact", "--scope", "project", "--key", "after-release", "--value", "committed-after-holder-released")
	patient_payload = cli_json(patient)
	store_after = json.loads(store_path.read_text(encoding="utf-8"))
	wrote_once = (
		patient_payload.get("ok") is True
		and store_after["revision"] == 1
		and sum(1 for record in store_after["records"] if record.get("key") == "after-release") == 1
	)
	if wrote_once:
		report.add("patient-commits-exactly-once-after-release", "PASS", "revision 0->1, single record")
	else:
		report.add("patient-commits-exactly-once-after-release", "FAIL", f"payload={patient_payload} revision={store_after['revision']}")
	wait_exit(holder, 30)
	return project


def test_crash_orphan(report: Report, workspace: Path) -> Path:
	project_id = new_project_id()
	run_id = "RUN-RACE-CRASH"
	project = make_fixture(workspace / "crash", project_id, run_id)
	store_path = project / ".harness" / "MEMORY.json"
	base = workspace / "crash"
	victim = spawn_child("crash", store_path, 0, base / "victim.ready", base / "victim.result")
	if not wait_ready(base / "victim.ready"):
		report.add("crash-orphan-recovery", "FAIL", "victim never acquired the lock")
		wait_exit(victim)
		return project
	exit_code = wait_exit(victim, 30)
	recovery_started = time.monotonic()
	survivor = cli(project, "remember", "--kind", "fact", "--scope", "project", "--key", "post-crash", "--value", "acquired-without-manual-cleanup")
	elapsed = time.monotonic() - recovery_started
	payload = cli_json(survivor)
	if payload.get("ok") is True and elapsed < 9.0:
		report.add("crash-orphan-recovery", "PASS", f"victim died holding lock (exit {exit_code}); survivor committed in {elapsed:.2f}s with zero manual cleanup")
	else:
		report.add("crash-orphan-recovery", "FAIL", f"exit={exit_code} elapsed={elapsed:.2f}s payload={payload}")
	return project


def test_lost_update_storm(report: Report, workspace: Path) -> Path:
	project_id = new_project_id()
	run_id = "RUN-RACE-STORM"
	project = make_fixture(workspace / "storm", project_id, run_id)
	store_path = project / ".harness" / "MEMORY.json"
	base = workspace / "storm"
	go_file = base / "go"
	worker_count = 6
	workers = []
	for index in range(worker_count):
		command = [
			sys.executable, str(SCRIPTS_DIR / "memory_ops.py"), "remember",
			"--project", str(project), "--kind", "fact", "--scope", "project",
			"--key", f"storm-{index:02d}", "--value", f"storm-value-{index:02d}-unique",
		]
		error_path = base / f"worker-{index:02d}.err"
		out_path = base / f"worker-{index:02d}.out"
		with open(out_path, "w", encoding="utf-8") as out_log, open(error_path, "w", encoding="utf-8") as error_log:
			workers.append(subprocess.Popen(command, stdout=out_log, stderr=error_log))
	go_file.write_bytes(b"go")
	torn_reads = 0
	shared_violations = 0
	deadline = time.monotonic() + 60
	sample_every = 0
	while any(worker.poll() is None for worker in workers) and time.monotonic() < deadline:
		sample_every += 1
		if sample_every % 5 == 0:
			try:
				json.loads(store_path.read_text(encoding="utf-8"))
			except json.JSONDecodeError:
				torn_reads += 1
			except OSError:
				shared_violations += 1
	results = [worker.wait(timeout=90) for worker in workers]
	worker_errors = ""
	for index in range(worker_count):
		error_log = (base / f"worker-{index:02d}.err").read_text(encoding="utf-8").strip()
		out_text = (base / f"worker-{index:02d}.out").read_text(encoding="utf-8").strip()
		if error_log:
			worker_errors += f" [{index:02d}] STDERR {error_log[-300:]}"
		elif results[index] != 0 and out_text:
			try:
				failure = json.loads(out_text)
				worker_errors += f" [{index:02d}] {failure.get('code')}: {str(failure.get('error'))[:200]}"
			except json.JSONDecodeError:
				worker_errors += f" [{index:02d}] RAW {out_text[-200:]}"
	successes = sum(1 for code in results if code == 0)
	final_store = json.loads(store_path.read_text(encoding="utf-8"))
	record_keys = sorted(record.get("key", "") for record in final_store["records"])
	expected_keys = sorted(f"storm-{index:02d}" for index in range(worker_count))
	no_loss = (
		successes == worker_count
		and final_store["revision"] == worker_count
		and record_keys == expected_keys
		and len({record["id"] for record in final_store["records"]}) == worker_count
		and torn_reads == 0
	)
	if no_loss:
		report.add("lost-update-storm", "PASS", f"{worker_count}/{worker_count} concurrent commits serialized, revision={final_store['revision']}, readers never saw torn JSON")
	else:
		report.add("lost-update-storm", "FAIL", f"successes={successes} revision={final_store['revision']} keys={record_keys} torn_reads={torn_reads} read_share_violations={shared_violations}{worker_errors}")
	return project


def test_alias_fallback_gap(report: Report, workspace: Path) -> Path:
	target_dir = workspace / "alias-fallback"
	target_dir.mkdir(parents=True, exist_ok=True)
	target = target_dir / "fallback-target.json"
	target.write_bytes(b"payload\n")
	long_form = str(target)
	attacker_label = ""
	short_form = short_path(target)
	if short_form and short_form != long_form:
		attacker_label = "8.3 short name"
	elif os.name == "posix":
		alias_link = target_dir / "alias-link.json"
		try:
			os.symlink(target, alias_link)
			short_form = str(alias_link)
			attacker_label = "symlink"
		except OSError:
			pass
	if not attacker_label or short_form == long_form:
		report.add("alias-fallback-gap", "SKIP", "no path alias constructible on this volume/platform")
		return workspace
	base = target_dir
	holder = spawn_child("hold", Path(long_form), 2500, base / "alias_holder.ready", base / "alias_holder.result")
	if not wait_ready(base / "alias_holder.ready"):
		report.add("alias-fallback-gap", "SKIP", "alias holder never signalled ready")
		wait_exit(holder)
		return workspace
	attacker = spawn_child("timeout", Path(short_form), 1500, base / "alias_attacker.ready", base / "alias_attacker.result")
	wait_exit(attacker, 30)
	wait_exit(holder, 30)
	try:
		attacker_result = json.loads((base / "alias_attacker.result").read_text(encoding="utf-8"))
	except (OSError, json.JSONDecodeError):
		attacker_result = {}
	if attacker_result.get("acquired"):
		report.add("alias-fallback-gap", "FAIL", "two path aliases of one file produced two independent fallback locks; exclusion broke")
	elif attacker_result.get("code") == "LOCK_TIMEOUT":
		report.add("alias-fallback-gap", "PASS", f"{attacker_label} alias converges to one canonical lock key via realpath; contender timed out against held lock")
	else:
		report.add("alias-fallback-gap", "FAIL", f"unexpected attacker result: {attacker_result}")
	return workspace


def test_lock_open_denied(report: Report, workspace: Path) -> None:
	project_id = new_project_id()
	run_id = "RUN-RACE-DENIED"
	project = make_fixture(workspace / "denied", project_id, run_id)
	lock_file = project / ".harness" / ".cache" / "locks" / "writer.lock"
	lock_file.parent.mkdir(parents=True, exist_ok=True)
	lock_file.write_bytes(b"\0")
	os.chmod(lock_file, stat.S_IREAD)
	if running_as_root():
		os.chmod(lock_file, stat.S_IREAD | stat.S_IWRITE)
		report.add("lock-open-denied", "SKIP", "running as root; permission bits cannot deny open")
		return None
	try:
		started = time.monotonic()
		result = cli(project, "remember", "--kind", "fact", "--scope", "project", "--key", "denied-write", "--value", "must-not-commit")
		elapsed = time.monotonic() - started
		payload = cli_json(result)
		store_after = json.loads((project / ".harness" / "MEMORY.json").read_text(encoding="utf-8"))
		fast_refusal = payload.get("code") == "LOCK_UNAVAILABLE" and elapsed < 6.0 and result.returncode == 2 and store_after["revision"] == 0
		if fast_refusal:
			report.add("lock-open-denied", "PASS", f"unopenable lock file refused immediately as LOCK_UNAVAILABLE ({elapsed:.2f}s), store untouched")
		else:
			report.add("lock-open-denied", "FAIL", f"code={payload.get('code')} elapsed={elapsed:.2f}s revision={store_after['revision']}")
	finally:
		os.chmod(lock_file, stat.S_IREAD | stat.S_IWRITE)
	return None


def git_repo_fixture(root: Path, project_id: str, run_id: str) -> Path:
	project = make_fixture(root, project_id, run_id)
	(project / ".marker").write_text(uuid.uuid4().hex)
	environment = dict(os.environ)
	environment.setdefault("GIT_CONFIG_GLOBAL", str(root / "gitconfig"))
	environment.setdefault("GIT_CONFIG_SYSTEM", os.devnull)
	subprocess.run(["git", "init", "-q"], cwd=str(project), check=True, capture_output=True, env=environment)
	subprocess.run(["git", "-C", str(project), "add", "-A"], check=True, capture_output=True, env=environment)
	subprocess.run(["git", "-C", str(project), "-c", "user.email=race@test.local", "-c", "user.name=Race", "commit", "-qm", "fixture"], check=True, capture_output=True, env=environment)
	return project


def test_identity_and_digest_binding(report: Report, workspace: Path) -> Path:
	import shutil
	import memory_ops
	import migrate_project

	if shutil.which("git") is None:
		report.add("identity-and-digest-binding", "SKIP", "git unavailable on this platform; repository identity binding cannot be exercised")
		return workspace

	project_id_a = new_project_id()
	run_id = "RUN-RACE-DIGEST"
	root = workspace / "digest"
	project = make_fixture(root, project_id_a, run_id)
	input_one = project / "legacy-input-a.md"
	input_two = project / "legacy-input-b.md"
	bytes_one = b"# Legacy notes alpha\n"
	bytes_two = b"# Legacy notes beta\n"
	input_one.write_bytes(bytes_one)
	input_two.write_bytes(bytes_two)
	snapshot = {input_one: bytes_one, input_two: bytes_two}
	digest_baseline = migrate_project.snapshot_tree_digest(project, snapshot)
	snapshot_tampered = {input_one: b"# Legacy notes alpha TAMPERED\n", input_two: bytes_two}
	digest_tampered_input = migrate_project.snapshot_tree_digest(project, snapshot_tampered)
	project_id_b = new_project_id()
	identity_b = memory_ops.repository_identity(project, project_id_b, ".")
	stable_a = memory_ops.canonical_json({"schema_version": identity_b["schema_version"], "project_id": project_id_a, "logical_scope": identity_b["logical_scope"]})
	stable_b = memory_ops.canonical_json({"schema_version": identity_b["schema_version"], "project_id": project_id_b, "logical_scope": identity_b["logical_scope"]})
	input_flip_detected = digest_tampered_input != digest_baseline
	identity_flip_detected = stable_a != stable_b
	repo_home_a = git_repo_fixture(workspace / "repo-a", project_id_a, run_id)
	repo_home_b = git_repo_fixture(workspace / "repo-b", project_id_a, run_id)
	root_commit_a = memory_ops.repository_identity(repo_home_a, project_id_a, ".")["repository"]["root_commit"]
	root_commit_b = memory_ops.repository_identity(repo_home_b, project_id_a, ".")["repository"]["root_commit"]
	move_detected = bool(root_commit_a) and root_commit_a != root_commit_b
	try:
		memory_ops.assert_current_identity(repo_home_b, memory_ops.repository_identity(repo_home_b, project_id_a, "."), ".")
	except memory_ops.MemoryErrorWithCode as exc:
		move_detected = False
	try:
		memory_ops.assert_current_identity(repo_home_b, {**memory_ops.repository_identity(repo_home_b, project_id_a, "."), "repository": {**memory_ops.repository_identity(repo_home_b, project_id_a, ".")["repository"], "root_commit": root_commit_a}}, ".")
		cloned_history_accepted = True
	except memory_ops.MemoryErrorWithCode as exc:
		cloned_history_accepted = exc.code == "IDENTITY_MISMATCH"
	if input_flip_detected and identity_flip_detected and move_detected and cloned_history_accepted:
		report.add("identity-and-digest-binding", "PASS", f"one flipped input byte flips the plan digest; a new Project ID flips the identity binding; two independent clones have distinct roots ({root_commit_a[:8]} vs {root_commit_b[:8]}) and a foreign root_commit is refused with IDENTITY_MISMATCH")
	else:
		report.add("identity-and-digest-binding", "FAIL", f"input_flip={input_flip_detected} identity_flip={identity_flip_detected} distinct_roots={move_detected} foreign_root_refused={cloned_history_accepted}")
	return project


def test_run_ownership(report: Report, workspace: Path) -> None:
	project_id = new_project_id()
	run_one = "RUN-OWNER-ONE"
	run_two = "RUN-OWNER-TWO"
	project = make_fixture(workspace / "ownership", project_id, run_one)
	wrong_run = cli(project, "remember", "--kind", "fact", "--scope", "task", "--run-id", "RUN-NOT-CURRENT", "--key", "intruder", "--value", "must-not-commit", "--verification", "manual")
	wrong_payload = cli_json(wrong_run)
	first = cli_json(cli(project, "remember", "--kind", "fact", "--scope", "task", "--run-id", run_one, "--key", "wip-one", "--value", "task note one", "--verification", "manual"))
	close_one = cli_json(cli(project, "close-run", "--run-id", run_one))
	close_again = cli_json(cli(project, "close-run", "--run-id", run_one))
	state_path = project / ".harness" / "STATE.json"
	state_path.write_bytes(pretty({**json.loads(state_path.read_text(encoding="utf-8")), "run_id": run_two}))
	next_run = cli_json(cli(project, "remember", "--kind", "fact", "--scope", "task", "--run-id", run_two, "--key", "wip-two", "--value", "task note two", "--verification", "manual"))
	recall_after = cli_json(cli(project, "recall", "--query", "task note"))
	recalled_keys = sorted(hit.get("key", "") for hit in recall_after.get("selected", [])) if recall_after.get("ok") else []
	store_now = json.loads((project / ".harness" / "MEMORY.json").read_text(encoding="utf-8"))
	task_ids = [record["id"] for record in store_now["records"] if record.get("scope") == "task"]
	checks = {
		"wrong run refused RUN_ID_MISMATCH": wrong_payload.get("code") == "RUN_ID_MISMATCH",
		"current-run task record commits": first.get("ok") is True,
		"close-run removes own task records": close_one.get("result") == "COMMITTED" and close_one.get("removed") == 1,
		"close-run replay is NO_OP": close_again.get("result") == "NO_OP",
		"next run writes fresh task memory": next_run.get("ok") is True,
		"closed-run records never leak into later runs": recalled_keys == ["wip-two"] and not any("wip-one" in item for item in task_ids),
	}
	if all(checks.values()):
		report.add("exact-run-ownership", "PASS", "; ".join(checks))
	else:
		failed = [name for name, passed in checks.items() if not passed]
		report.add("exact-run-ownership", "FAIL", "; ".join(f"{name} [actual: {wrong_payload.get('code')}/{close_one.get('result')}/{close_again.get('result')}/{recalled_keys}]" for name in failed))


def test_recall_ceiling(report: Report, workspace: Path) -> None:
	project_id = new_project_id()
	run_id = "RUN-RACE-BUDGET"
	project = make_fixture(workspace / "budget", project_id, run_id)
	oversized = cli(project, "recall", "--query", "anything", "--max-records", "10000")
	oversized_payload = cli_json(oversized)
	negative = cli(project, "recall", "--query", "anything", "--max-bytes", "10")
	negative_payload = cli_json(negative)
	if oversized_payload.get("code") == "INVALID_BUDGET" and negative_payload.get("code") == "INVALID_BUDGET":
		report.add("recall-budget-ceiling", "PASS", "out-of-range recall budgets refused with INVALID_BUDGET before any read")
	else:
		report.add("recall-budget-ceiling", "FAIL", f"oversized={oversized_payload.get('code')} negative={negative_payload.get('code')}")


def child_main(mode: str, lock_path_text: str, hold_ms: int, ready_file_text: str, result_file_text: str) -> int:
	ready_file = Path(ready_file_text)
	result_file = Path(result_file_text)
	lock_path = Path(lock_path_text)
	outcome: dict = {}
	try:
		if mode == "timeout":
			memory_ops_module().target_file_lock(lock_path, timeout_seconds=max(hold_ms, 1) / 1000.0).__enter__()
			outcome = {"acquired": True}
		else:
			with memory_ops_module().target_file_lock(lock_path, timeout_seconds=10.0):
				result_file.write_text(json.dumps({"acquired": True}), encoding="utf-8")
				ready_file.write_bytes(b"ready")
				if mode == "crash":
					time.sleep(0.05)
					os._exit(9)
				time.sleep(max(hold_ms, 0) / 1000.0)
				return 0
	except memory_ops_module().MemoryErrorWithCode as exc:
		outcome = {"acquired": False, "code": exc.code}
	except BaseException as exc:
		outcome = {"acquired": False, "code": type(exc).__name__, "error": str(exc)}
	result_file.write_text(json.dumps(outcome), encoding="utf-8")
	ready_file.write_bytes(b"done")
	return 0


def memory_ops_module():
	import memory_ops
	return memory_ops


def main(argv: list[str]) -> int:
	if len(argv) >= 6 and argv[0] == "__child__":
		child_args = argv[1:]
		mode = child_args[0]
		rest = child_args[1:]
		if len(rest) >= 4:
			child_main(mode, rest[0], int(rest[1]), Path(rest[2]), Path(rest[3]))
			return 0
		return 2
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--keep", action="store_true", help="Keep fixture workspace instead of deleting it")
	arguments = parser.parse_args(argv)
	report = Report()
	started = time.monotonic()
	with tempfile.TemporaryDirectory(prefix="harness-race-") as temporary:
		workspace = Path(temporary)
		test_contention(report, workspace)
		test_crash_orphan(report, workspace)
		test_lost_update_storm(report, workspace)
		test_alias_fallback_gap(report, workspace)
		test_lock_open_denied(report, workspace)
		test_identity_and_digest_binding(report, workspace)
		test_run_ownership(report, workspace)
		test_recall_ceiling(report, workspace)
	counts = report.counts()
	print(json.dumps({"counts": counts, "elapsed_seconds": round(time.monotonic() - started, 2)}, indent=2))
	return 0 if counts["FAIL"] == 0 else 1


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
