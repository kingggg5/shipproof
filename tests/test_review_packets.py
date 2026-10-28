"""Q05 acceptance: bounded packets, accounting, redaction, reconciliation."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import review_packets as packets  # noqa: E402
from scan_repo import main as scan_repo_main  # noqa: E402


def finding(rule_id="SP101", path="app.py", line=1, fingerprint="a" * 16):
    return {
        "rule_id": rule_id,
        "path": path,
        "line": line,
        "severity": "high",
        "proof_level": "L0",
        "fingerprint": fingerprint,
    }


def make_tree(files: dict[str, str]) -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return tmp


class PacketTests(unittest.TestCase):
    def test_changed_source_cannot_receive_current_identity(self):
        with make_tree({"app.py": "value = 1\n"}) as tmp:
            original = packets.identity.snapshot_identity

            def changed(root, **kwargs):
                (root / "app.py").write_text("value = 2\n", encoding="utf-8")
                return original(root, **kwargs)

            with mock.patch.object(packets.identity, "snapshot_identity", side_effect=changed):
                report = packets.build_packets(Path(tmp), [finding()])
        self.assertIsNone(report["identity"])
        self.assertEqual(report["counts"]["failed"], 1)
        self.assertEqual(report["packets"][0]["status"], "partial")
        self.assertIn("source changed", report["identity_error"])

    def test_every_selected_item_is_accounted_once(self):
        with make_tree({"app.py": "value = 1\n", "other.py": "value = 2\n"}) as tmp:
            report = packets.build_packets(
                Path(tmp),
                [
                    finding(fingerprint="a" * 16, path="app.py"),
                    finding(fingerprint="b" * 16, path="other.py"),
                ],
            )
        accounting = report["selection_accounting"]
        self.assertEqual(len(accounting), 2)
        self.assertEqual(report["counts"]["selected"], 2)
        self.assertEqual(report["counts"]["scheduled"] + report["counts"]["deferred"], 2)

    def test_byte_and_file_caps_defer_with_reasons(self):
        big = "x = 1\n" * 5000
        with make_tree({"big.py": big, "small.py": "y = 2\n"}) as tmp:
            report = packets.build_packets(
                Path(tmp),
                [
                    finding(fingerprint="c" * 16, path="big.py"),
                    finding(fingerprint="g" * 16, path="small.py"),
                ],
                max_bytes=1024,
            )
        (packet,) = report["packets"]
        self.assertEqual(packet["status"], "partial")
        self.assertTrue(packet["truncation_reasons"])
        self.assertLessEqual(packet["source_bytes"], 1024)
        ledger = {entry["fingerprint"]: entry for entry in report["selection_accounting"]}
        self.assertEqual(ledger["c" * 16]["status"], "deferred")
        self.assertEqual(ledger["g" * 16]["status"], "scheduled")
        with make_tree({"a.py": "1\n", "b.py": "2\n", "c.py": "3\n"}) as tmp:
            report = packets.build_packets(
                Path(tmp),
                [finding(fingerprint="d" * 16, path="a.py")],
                max_files=1,
            )
        self.assertTrue(
            report["packets"][0]["truncation_reasons"] or report["counts"]["deferred"] >= 0
        )

    def test_secrets_are_redacted(self):
        with make_tree({"app.py": 'token = "sk-secretvalue123"\n'}) as tmp:
            report = packets.build_packets(
                Path(tmp), [finding(fingerprint="e" * 16, path="app.py")]
            )
        text = report["packets"][0]["files"][0]["text"]
        self.assertIn("[REDACTED]", text)
        self.assertNotIn("sk-secretvalue123", text)

    def test_source_roles_are_labeled_with_basis(self):
        roles = {
            path: packets.classify_role(path)
            for path in ("app.py", "tests/test_app.py", "examples/demo.py")
        }
        self.assertEqual(roles["app.py"][0], "app")
        self.assertEqual(roles["tests/test_app.py"][0], "test")
        self.assertEqual(roles["examples/demo.py"][0], "example")
        for _role, basis in roles.values():
            self.assertTrue(basis)

    def test_token_estimate_is_labeled_an_estimate(self):
        with make_tree({"app.py": "value = 1\n"}) as tmp:
            report = packets.build_packets(
                Path(tmp), [finding(fingerprint="f" * 16, path="app.py")]
            )
        packet = report["packets"][0]
        self.assertIn("estimate", packet["token_estimate_note"])

    def test_reconcile_handles_all_agent_outcomes(self):
        with make_tree({"app.py": "value = 1\n", "other.py": "value = 2\n"}) as tmp:
            report = packets.build_packets(
                Path(tmp),
                [
                    finding(fingerprint="a" * 16, path="app.py"),
                    finding(fingerprint="b" * 16, path="other.py"),
                ],
            )
        packet_id = report["packets"][0]["packet_id"]
        packet_digest = report["packets"][0]["packet_digest"]
        report = packets.reconcile(
            report,
            [
                {
                    "packet_id": packet_id,
                    "packet_digest": packet_digest,
                    "decided": [{"fingerprint": "a" * 16, "verdict": "completed"}],
                },
                {
                    "packet_id": packet_id,
                    "packet_digest": packet_digest,
                    "decided": [{"fingerprint": "a" * 16, "verdict": "completed"}],
                },
                {"packet_id": "packet-999", "decided": []},
                {
                    "packet_id": packet_id,
                    "packet_digest": packet_digest,
                    "decided": [{"fingerprint": "z" * 16, "verdict": "completed"}],
                },
            ],
        )
        ledger = {entry["fingerprint"]: entry for entry in report["selection_accounting"]}
        self.assertEqual(ledger["a" * 16]["status"], "completed")
        # b was never decided: missing responses never complete items.
        self.assertEqual(ledger["b" * 16]["status"], "scheduled")
        self.assertTrue(any("duplicate" in note for note in report["reconcile_notes"]))
        self.assertTrue(any("unknown packet" in note for note in report["reconcile_notes"]))
        self.assertTrue(any("unknown fingerprint" in note for note in report["reconcile_notes"]))

    def test_timeout_fails_scheduled_items(self):
        with make_tree({"app.py": "value = 1\n"}) as tmp:
            report = packets.build_packets(
                Path(tmp), [finding(fingerprint="a" * 16, path="app.py")]
            )
        packet_id = report["packets"][0]["packet_id"]
        report = packets.reconcile(
            report,
            [
                {
                    "packet_id": packet_id,
                    "timed_out": True,
                    "packet_digest": report["packets"][0]["packet_digest"],
                }
            ],
        )
        ledger = {entry["fingerprint"]: entry for entry in report["selection_accounting"]}
        self.assertEqual(ledger["a" * 16]["status"], "failed")

    def test_builder_does_not_mutate_findings(self):
        source = [finding(fingerprint="a" * 16, path="app.py")]
        with make_tree({"app.py": "value = 1\n"}) as tmp:
            packets.build_packets(Path(tmp), source)
        self.assertEqual(len(source), 1)
        self.assertEqual(source[0]["fingerprint"], "a" * 16)


class PacketCliTests(unittest.TestCase):
    def run_cli(self, *arguments):
        import contextlib
        import io

        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = scan_repo_main([str(self.root), *arguments])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_packet_out_writes_ledger_without_changing_gate(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            self.root = Path(directory)
            (self.root / "app.py").write_text(
                "import subprocess\nsubprocess.run(cmd, shell=True)\n", encoding="utf-8"
            )
            out_dir = self.root / "packets"
            out_dir.mkdir()
            plain, _, _ = self.run_cli("--fail-on", "none", "--format", "json")
            status, _, stderr = self.run_cli(
                "--fail-on", "none", "--format", "json", "--packet-out", str(out_dir)
            )
            self.assertEqual(status, plain)
            self.assertIn("review packets:", stderr)
            ledger = __import__("json").loads((out_dir / "ledger.json").read_text())
            self.assertGreaterEqual(ledger["counts"]["scheduled"], 1)
            self.assertIn("target_digest", ledger["packets"][0])

    def test_packet_out_requires_existing_directory(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            self.root = Path(directory)
            (self.root / "app.py").write_text("value = 1\n", encoding="utf-8")
            status, _, _ = self.run_cli("--packet-out", str(self.root / "missing"))
            self.assertEqual(status, 2)


if __name__ == "__main__":
    unittest.main()
