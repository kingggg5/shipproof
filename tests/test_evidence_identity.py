"""Q01 acceptance: snapshot identity stability and mismatch detection."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import snapshot_identity as identity  # noqa: E402

IMPORTER_SPEC = importlib.util.spec_from_file_location(
    "import_external_evidence_q01", ROOT / "scripts" / "import_external_evidence.py"
)
if IMPORTER_SPEC is None or IMPORTER_SPEC.loader is None:
    raise RuntimeError("could not load external evidence importer")
importer = importlib.util.module_from_spec(IMPORTER_SPEC)
sys.modules[IMPORTER_SPEC.name] = importer
IMPORTER_SPEC.loader.exec_module(importer)


def make_repo(files: dict[str, str]) -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return tmp


def snapshot(root: Path, **kwargs):
    paths = [p for p in root.rglob("*") if p.is_file()]
    return identity.snapshot_identity(
        root,
        files=paths,
        policy={"fail_on": "high"},
        scanner_version="shipproof-test/1.0",
        rules_identity="executable-rules/test",
        **kwargs,
    )


class SnapshotIdentityTests(unittest.TestCase):
    def test_runtime_identity_binds_each_detector_and_packet_module(self):
        manifest = json.loads((ROOT / "packaging/approved-files.json").read_text(encoding="utf-8"))
        unrelated_tools = {
            "capacity_model.py",
            "cost_model.py",
            "invariants.py",
            "worktree_manager.py",
        }
        filenames = [
            Path(name).name
            for name in manifest["files"]
            if name.startswith("skills/audit-production-readiness/scripts/")
            and name.endswith(".py")
            and Path(name).name not in unrelated_tools
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in filenames:
                (root / name).write_bytes(b"pass\n")
            with mock.patch.object(identity, "__file__", str(root / "snapshot_identity.py")):
                before = identity.scanner_code_identity()
                for name in filenames:
                    with self.subTest(module=name):
                        (root / name).write_bytes(b"fail\n")
                        self.assertNotEqual(identity.scanner_code_identity(), before)
                        (root / name).write_bytes(b"pass\n")
                self.assertEqual(identity.scanner_code_identity(), before)

    def test_git_identity_uses_bounded_trusted_runner(self):
        with make_repo({"app.py": "value = 1\n", ".git/HEAD": "ref: refs/heads/main\n"}) as tmp:
            with (
                mock.patch(
                    "scan_repo._run_git_bounded", side_effect=ValueError("untrusted git")
                ) as runner,
                self.assertRaisesRegex(ValueError, "untrusted git"),
            ):
                identity.resolved_commit(Path(tmp))
            runner.assert_called_once()

    def test_stable_identity_when_unchanged(self):
        with make_repo({"app.py": "value = 1\n"}) as tmp:
            first = snapshot(Path(tmp))
            second = snapshot(Path(tmp))
        self.assertEqual(first["target_digest"], second["target_digest"])
        self.assertEqual(first["config_digest"], second["config_digest"])
        self.assertEqual(first["identity_version"], "snapshot-identity/1.0")

    def test_same_size_same_mtime_edit_is_detected(self):
        with make_repo({"app.py": "value = 1\n"}) as tmp:
            root = Path(tmp)
            before = snapshot(root)
            target = root / "app.py"
            stat = target.stat()
            target.write_text("value = 2\n", encoding="utf-8")
            # Restore size (same) and mtime to simulate a stealthy edit.
            import os

            os.utime(target, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            after = snapshot(root)
        self.assertEqual(len("value = 1\n"), len("value = 2\n"))
        self.assertNotEqual(before["target_digest"], after["target_digest"])

    def test_deleted_context_is_detected(self):
        with make_repo({"app.py": "value = 1\n", "other.py": "value = 2\n"}) as tmp:
            root = Path(tmp)
            before = snapshot(root)
            (root / "other.py").unlink()
            after = snapshot(root)
        self.assertNotEqual(before["target_digest"], after["target_digest"])
        self.assertNotEqual(before["selection_digest"], after["selection_digest"])

    def test_moved_refs_are_detected(self):
        with make_repo({"app.py": "value = 1\n"}) as tmp:
            root = Path(tmp)
            before = snapshot(root)
            (root / "app.py").rename(root / "renamed.py")
            after = snapshot(root)
        self.assertNotEqual(before["target_digest"], after["target_digest"])

    def test_changed_policy_and_rules_are_detected(self):
        with make_repo({"app.py": "value = 1\n"}) as tmp:
            root = Path(tmp)
            paths = [p for p in root.rglob("*") if p.is_file()]
            base = identity.snapshot_identity(
                root,
                files=paths,
                policy={"fail_on": "high"},
                scanner_version="s/1",
                rules_identity="r/1",
            )
            other_policy = identity.snapshot_identity(
                root,
                files=paths,
                policy={"fail_on": "medium"},
                scanner_version="s/1",
                rules_identity="r/1",
            )
            other_rules = identity.snapshot_identity(
                root,
                files=paths,
                policy={"fail_on": "high"},
                scanner_version="s/1",
                rules_identity="r/2",
            )
        self.assertNotEqual(base["config_digest"], other_policy["config_digest"])
        self.assertNotEqual(base["target_digest"], other_policy["target_digest"])
        self.assertNotEqual(base["target_digest"], other_rules["target_digest"])

    def test_secrets_do_not_affect_config_identity(self):
        first = identity.config_digest_for({"fail_on": "high", "api_key": "sk-secret123"})
        second = identity.config_digest_for({"fail_on": "high", "api_key": "sk-other999"})
        third = identity.config_digest_for({"fail_on": "medium", "api_key": "sk-secret123"})
        self.assertEqual(first, second)
        self.assertNotEqual(first, third)

    def test_absolute_paths_are_not_part_of_identity(self):
        with (
            make_repo({"app.py": "value = 1\n"}) as tmp_a,
            make_repo({"app.py": "value = 1\n"}) as tmp_b,
        ):
            digest_a = snapshot(Path(tmp_a))["target_digest"]
            digest_b = snapshot(Path(tmp_b))["target_digest"]
        # Same bytes + same policy => same identity regardless of checkout location.
        self.assertEqual(digest_a, digest_b)


def write_envelope(directory: Path, name: str, payload: dict) -> Path:
    path = directory / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def base_payload() -> dict:
    return {
        "schema_version": "1.0",
        "tool": {"name": "example-linter", "version": "1.2.3", "command": "lint"},
        "verdict": "REVIEW",
        "limitations": ["synthetic"],
        "target_digest": "a" * 64,
        "config_digest": "b" * 64,
        "captured_at": "2026-09-15T00:00:00Z",
        "findings": [],
    }


class ImporterIdentityTests(unittest.TestCase):
    def test_partial_identity_never_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_envelope(Path(tmp), "ok.json", base_payload())
            for kwargs in ({"expect_target": "a" * 64}, {"expect_config": "b" * 64}):
                report = importer.load_envelope(path, **kwargs)
                self.assertFalse(report["identity_matches"])
                self.assertFalse(report["gate_eligible"])
                self.assertFalse(report["resume_eligible"])

    def test_nonfinite_and_negative_freshness_policies_are_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_envelope(Path(tmp), "ok.json", base_payload())
            for value in (float("nan"), float("inf"), -1, True):
                for name in ("max_age_hours", "clock_skew_minutes"):
                    with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                        importer.load_envelope(path, **{name: value})

    def test_identity_match_does_not_attest_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_envelope(Path(tmp), "ok.json", base_payload())
            report = importer.load_envelope(
                path,
                expect_target="a" * 64,
                expect_config="b" * 64,
                now=datetime(2026, 9, 15, 12, tzinfo=timezone.utc),
            )
        self.assertEqual(report["verification"]["status"], "verified")
        self.assertFalse(report["gate_eligible"])
        self.assertTrue(report["resume_eligible"])
        self.assertFalse(report["authorship_verified"])

    def test_wrong_root_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_envelope(Path(tmp), "ok.json", base_payload())
            with self.assertRaisesRegex(ValueError, "target_digest does not match"):
                importer.load_envelope(path, expect_target="c" * 64)
            report = importer.load_envelope(path, expect_target="c" * 64, allow_unverified=True)
        self.assertEqual(report["verification"]["status"], "unverified")
        self.assertFalse(report["gate_eligible"])
        self.assertFalse(report["resume_eligible"])

    def test_old_evidence_without_expiry_still_verifies_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_envelope(Path(tmp), "ok.json", base_payload())
            report = importer.load_envelope(
                path,
                expect_target="a" * 64,
                expect_config="b" * 64,
                now=datetime(2028, 1, 1, tzinfo=timezone.utc),
            )
        self.assertEqual(report["verification"]["status"], "verified")

    def test_stale_evidence_with_max_age_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_envelope(Path(tmp), "ok.json", base_payload())
            now = datetime(2026, 9, 15, 12, tzinfo=timezone.utc)
            with self.assertRaisesRegex(ValueError, "max-age"):
                importer.load_envelope(
                    path,
                    expect_target="a" * 64,
                    expect_config="b" * 64,
                    max_age_hours=1,
                    now=now,
                )

    def test_future_timestamp_beyond_skew_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = base_payload()
            payload["captured_at"] = "2026-09-16T00:00:00Z"
            path = write_envelope(Path(tmp), "future.json", payload)
            with self.assertRaisesRegex(ValueError, "future"):
                importer.load_envelope(path, now=datetime(2026, 9, 15, 12, tzinfo=timezone.utc))

    def test_malformed_envelopes_never_crash_nor_pass(self):
        cases = []
        unknown = base_payload()
        unknown["extra"] = 1
        cases.append(("unknown top field", json.dumps(unknown)))
        dup = (
            '{"schema_version":"1.0","schema_version":"1.0",'
            '"tool":{"name":"x","version":"1.2.3","command":"lint"},'
            '"verdict":"REVIEW","limitations":["s"],'
            '"target_digest":"' + "a" * 64 + '","config_digest":"' + "b" * 64 + '",'
            '"captured_at":"2026-09-15T00:00:00Z","findings":[]}'
        )
        cases.append(("duplicate field", dup))
        nulled = base_payload()
        nulled["tool"] = None
        cases.append(("null tool", json.dumps(nulled)))
        absolute = base_payload()
        absolute["findings"] = [
            {"original_rule_id": "X", "severity": "high", "path": "/etc/passwd", "message": "m"}
        ]
        cases.append(("absolute path", json.dumps(absolute)))
        escape = base_payload()
        escape["findings"] = [
            {"original_rule_id": "X", "severity": "high", "path": "../outside.py", "message": "m"}
        ]
        cases.append(("escaping path", json.dumps(escape)))
        coerced = base_payload()
        coerced["findings"] = [
            {
                "original_rule_id": "X",
                "severity": "high",
                "path": "a.py",
                "line": True,
                "message": "m",
            }
        ]
        cases.append(("coerced line bool", json.dumps(coerced)))
        with tempfile.TemporaryDirectory() as tmp:
            for label, raw in cases:
                with self.subTest(label=label):
                    path = Path(tmp) / f"{label.replace(' ', '_')}.json"
                    path.write_text(raw, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        importer.load_envelope(path)

    def test_snapshot_mismatch_end_to_end(self):
        # Envelope computed for repo A must not verify against repo B bytes.
        with (
            make_repo({"app.py": "value = 1\n"}) as tmp_a,
            make_repo({"app.py": "value = 2\n"}) as tmp_b,
        ):
            digest_a = snapshot(Path(tmp_a))["target_digest"]
            digest_b = snapshot(Path(tmp_b))["target_digest"]
        self.assertNotEqual(digest_a, digest_b)
        with tempfile.TemporaryDirectory() as tmp:
            payload = base_payload()
            payload["target_digest"] = digest_a
            path = write_envelope(Path(tmp), "foreign.json", payload)
            with self.assertRaisesRegex(ValueError, "target_digest does not match"):
                importer.load_envelope(path, expect_target=digest_b)


if __name__ == "__main__":
    unittest.main()
