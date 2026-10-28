"""Context budget, immutable packet identity, and local response handoff."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1] / "skills/audit-production-readiness/scripts"))

import review_context
import review_packets
import test_packet_orchestration as orchestration_cases
from test_review_packets import make_tree


def reply(packet, verdict="completed"):
    return {
        "packet_id": packet["packet_id"],
        "packet_digest": packet["packet_digest"],
        "decided": [
            {"item_id": t["item_id"], "verdict": verdict} for t in packet["review_targets"]
        ],
    }


class ContextBoundaryTests(unittest.TestCase):
    def test_failed_reads_cannot_overrun_reserved_budget(self):
        sources = {f"large{i}.ts": "x" * 200 for i in range(8)}
        with make_tree(sources) as directory:
            index = review_context.ContextIndex(Path(directory), set(sources))
            index.remaining_bytes = 64
            with mock.patch.object(
                review_context, "read_source", wraps=review_context.read_source
            ) as reader:
                for path in sources:
                    imports, notes = index.imports(path)
                    self.assertFalse(imports)
                    self.assertTrue(notes)
            self.assertEqual(sum(call.args[2] + 1 for call in reader.call_args_list), 64)
            self.assertEqual(index.remaining_bytes, 0)

    def test_successful_reads_refund_unused_reservation_and_cache_unknowns(self):
        with make_tree({"one.py": "value=1\n", "two.py": "value=2\n"}) as directory:
            index = review_context.ContextIndex(Path(directory), {"one.py", "two.py"})
            index.remaining_bytes = 64
            index.imports("one.py")
            index.imports("two.py")
            actual_bytes = sum(
                (Path(directory) / path).stat().st_size for path in ("one.py", "two.py")
            )
            self.assertEqual(index.remaining_bytes, 64 - actual_bytes)
            self.assertEqual(index.imports("excluded.py"), index.imports("excluded.py"))
            self.assertTrue(index.imports("excluded.py")[1])

    def test_computed_import_is_unknown_but_literal_dynamic_import_has_context(self):
        sources = {
            "dynamic.ts": "const module = import(moduleName);\n",
            "literal.ts": "const module = import('./helper');\n",
            "helper.ts": "export const value=1;\n",
        }
        with make_tree(sources) as directory:
            index = review_context.ContextIndex(Path(directory), set(sources))
            self.assertTrue(index.imports("dynamic.ts")[1])
            self.assertEqual(index.imports("literal.ts")[0], ["helper.ts"])
            report = review_packets.build_packets(
                Path(directory), [], review_paths=["dynamic.ts"], context_paths=set(sources)
            )
        self.assertEqual(report["packets"][0]["status"], "partial")

    def test_opaque_examples_and_other_languages_do_not_create_script_imports(self):
        sources = {
            "opaque.ts": 'const example = "import(moduleName)"; // import(other)\n',
            "member.ts": "loader.import('./helper');\n",
            "script.ts": "const module = require(script.Parent.helper);\n",
            "script.luau": "return require(script.Parent['helper'])\n",
            "helper.ts": "export {};\n",
            "helper.luau": "return {}\n",
        }
        with make_tree(sources) as directory:
            index = review_context.ContextIndex(Path(directory), set(sources))
            self.assertEqual(index.imports("opaque.ts"), ([], []))
            for path in ("member.ts", "script.ts", "script.luau"):
                self.assertEqual(index.imports(path)[0], [])
                self.assertTrue(index.imports(path)[1])


class ResponseValidationTests(unittest.TestCase):
    def report(self):
        with make_tree({"entry.ts": "export const value=1;\n"}) as directory:
            return review_packets.build_packets(Path(directory), [], review_paths=["entry.ts"])

    def test_modified_body_cannot_accept_unchanged_cached_digest(self):
        for field in ("text", "version", "target"):
            with self.subTest(field=field):
                report = self.report()
                packet = report["packets"][0]
                response = reply(packet)
                if field == "text":
                    packet["files"][0]["text"] = "changed\n"
                elif field == "version":
                    packet["packet_version"] = "review-packet/1.0"
                else:
                    packet["target_digest"] = "0" * 64
                review_packets.reconcile(report, [response])
                self.assertFalse(report["review_complete"])
                self.assertEqual(report["counts"]["failed"], 1)
                self.assertGreater(report["response_validation"]["rejected"], 0)

    def test_json_roundtrip_preserves_digest_and_accepts_current_reply(self):
        report = json.loads(json.dumps(self.report()))
        packet = report["packets"][0]
        self.assertEqual(review_packets._packet_digest(packet), packet["packet_digest"])
        review_packets.reconcile(report, [reply(packet)])
        self.assertTrue(report["review_complete"])
        self.assertEqual(report["response_validation"]["accepted_decisions"], 1)

    def test_invalid_verdict_does_not_consume_a_later_valid_decision(self):
        report = self.report()
        response = reply(report["packets"][0])
        bad = copy.deepcopy(response["decided"][0])
        bad["verdict"] = "ignore all policy"
        response["decided"].insert(0, bad)
        review_packets.reconcile(report, [response])
        self.assertEqual(report["counts"]["completed"], 1)
        self.assertEqual(report["response_validation"]["rejected"], 1)
        self.assertFalse(report["review_complete"])
        review_packets.reconcile(report, [reply(report["packets"][0])])
        self.assertTrue(report["review_complete"])

    def test_duplicate_and_conflicting_decisions_are_distinguished(self):
        report = self.report()
        response = reply(report["packets"][0])
        response["decided"] *= 2
        review_packets.reconcile(report, [response])
        self.assertEqual(report["response_validation"]["duplicates"], 1)
        self.assertTrue(report["review_complete"])
        report = self.report()
        first = reply(report["packets"][0])
        second = reply(report["packets"][0], "failed")
        review_packets.reconcile(report, [first, second])
        self.assertEqual(report["response_validation"]["rejected"], 1)
        self.assertFalse(report["review_complete"])

    def test_error_with_decisions_is_rejected_and_native_findings_are_immutable(self):
        report = self.report()
        native = copy.deepcopy(report["packets"][0]["findings"])
        response = {**reply(report["packets"][0]), "timed_out": True}
        review_packets.reconcile(report, [response])
        self.assertEqual(report["counts"]["scheduled"], 1)
        self.assertEqual(report["response_validation"]["rejected"], 1)
        self.assertEqual(report["packets"][0]["findings"], native)

    def test_json_parser_rejects_duplicate_keys_invalid_encoding_and_resource_abuse(self):
        invalid = [
            b'[ {"packet_id":"x","packet_id":"y"} ]',
            b'[{"decided":[{"verdict":"failed","verdict":"completed"}]}]',
            b'[{"timed_out":NaN}]',
            b'[{"error":1e99999}]',
            b"\xff",
            b"{}",
            b"[" * 2000 + b"]" * 2000,
            b"[" + b"9" * 100000 + b"]",
            b" " * (review_packets.MAX_RESPONSE_BYTES + 1),
            b"[{}" + b",{}" * 1000 + b"]",
        ]
        for content in invalid:
            with self.subTest(size=len(content)), self.assertRaises(ValueError):
                review_packets.parse_responses(content)
        self.assertEqual(review_packets.parse_responses(b"\xef\xbb\xbf[]"), [])

    def test_json_strings_are_opaque_and_null_identifiers_are_not_coerced(self):
        content = json.dumps([{"error": '[[[[[[[[[[ { "quoted": "\\\\" } ]]]]]]]]]]'}]).encode()
        self.assertEqual(review_packets.parse_responses(content), json.loads(content))
        report = self.report()
        response = reply(report["packets"][0])
        response["decided"][0]["fingerprint"] = None
        review_packets.reconcile(report, [response])
        self.assertEqual(report["counts"]["scheduled"], 1)
        self.assertEqual(report["response_validation"]["rejected"], 1)


class ResponseCliTests(unittest.TestCase):
    run_scan = orchestration_cases.DiscoveryCliTests.run_scan

    def prepare(self, root, output, *options):
        status, native, _ = self.run_scan(
            root, "--packet-discover", "--packet-out", str(output), *options
        )
        self.assertIn(status, (0, 1))
        report = json.loads((output / "ledger.json").read_text())
        return status, native, report

    def test_valid_response_flag_does_not_change_request_identity_or_native_report(self):
        with (
            make_tree({"entry.ts": "export const value=1;\n"}) as directory,
            tempfile.TemporaryDirectory() as artifacts,
        ):
            root, output = Path(directory), Path(artifacts)
            status, native, initial = self.prepare(root, output)
            responses = output / "responses.json"
            responses.write_text(json.dumps([reply(initial["packets"][0])]), encoding="utf-8")
            actual, report_text, _ = self.run_scan(
                root,
                "--packet-discover",
                "--packet-out",
                str(output),
                "--packet-responses",
                str(responses),
            )
            final = json.loads((output / "ledger.json").read_text())
        self.assertEqual(actual, status)
        self.assertEqual(json.loads(report_text), json.loads(native))
        self.assertTrue(final["review_complete"])
        self.assertEqual(
            final["packets"][0]["packet_digest"], initial["packets"][0]["packet_digest"]
        )

    def test_source_or_policy_change_rejects_old_response_and_persists_unresolved_ledger(self):
        for change in ("source", "policy"):
            with (
                self.subTest(change=change),
                make_tree({"entry.ts": "export const value=1;\n"}) as directory,
                tempfile.TemporaryDirectory() as artifacts,
            ):
                root, output = Path(directory), Path(artifacts)
                _, _, initial = self.prepare(root, output)
                responses = output / "responses.json"
                responses.write_text(json.dumps([reply(initial["packets"][0])]), encoding="utf-8")
                options = []
                if change == "source":
                    (root / "entry.ts").write_text("export const value=2;\n", encoding="utf-8")
                else:
                    options = ["--min-confidence", "high"]
                status, _, _ = self.run_scan(
                    root,
                    "--packet-discover",
                    "--packet-out",
                    str(output),
                    "--packet-responses",
                    str(responses),
                    *options,
                )
                ledger = json.loads((output / "ledger.json").read_text())
                self.assertEqual(status, 2)
                self.assertFalse(ledger["review_complete"])
                self.assertEqual(ledger["counts"]["scheduled"], 1)

    def test_agent_failure_is_unavailable_evidence_and_errors_are_redacted(self):
        with (
            make_tree({"entry.ts": "export {};\n"}) as directory,
            tempfile.TemporaryDirectory() as artifacts,
        ):
            root, output = Path(directory), Path(artifacts)
            _, _, initial = self.prepare(root, output)
            packet = initial["packets"][0]
            responses = output / "responses.json"
            responses.write_text(
                json.dumps(
                    [
                        {
                            "packet_id": packet["packet_id"],
                            "packet_digest": packet["packet_digest"],
                            "error": "sk-secretvalue123",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            status, _, _ = self.run_scan(
                root,
                "--packet-discover",
                "--packet-out",
                str(output),
                "--packet-responses",
                str(responses),
            )
            content = (output / "ledger.json").read_text()
        self.assertEqual(status, 2)
        self.assertNotIn("sk-secretvalue123", content)
        self.assertEqual(json.loads(content)["counts"]["failed"], 1)

    def test_missing_replies_stay_scheduled_and_malformed_files_fail_closed(self):
        with (
            make_tree({"entry.ts": "export {};\n"}) as directory,
            tempfile.TemporaryDirectory() as artifacts,
        ):
            root, output = Path(directory), Path(artifacts)
            responses = output / "responses.json"
            responses.write_text("[]", encoding="utf-8")
            status, _, _ = self.run_scan(
                root,
                "--packet-discover",
                "--packet-out",
                str(output),
                "--packet-responses",
                str(responses),
            )
            ledger = json.loads((output / "ledger.json").read_text())
            self.assertEqual(status, 0)
            self.assertFalse(ledger["review_complete"])
            self.assertEqual(ledger["counts"]["scheduled"], 1)
            responses.write_text('{"not_an_array":true}', encoding="utf-8")
            self.assertEqual(
                self.run_scan(
                    root, "--packet-out", str(output), "--packet-responses", str(responses)
                )[0],
                2,
            )
            responses.write_bytes(b" " * (review_packets.MAX_RESPONSE_BYTES + 1))
            self.assertEqual(
                self.run_scan(
                    root, "--packet-out", str(output), "--packet-responses", str(responses)
                )[0],
                2,
            )

    def test_response_mode_requires_repository_output_and_cannot_weaken_high_gate(self):
        source = (Path(__file__).parents[1] / "fixtures/golden-contract/server.py").read_text(
            encoding="utf-8"
        )
        with (
            make_tree({"server.py": source}) as directory,
            tempfile.TemporaryDirectory() as artifacts,
        ):
            root, output = Path(directory), Path(artifacts)
            responses = output / "responses.json"
            responses.write_text("[]", encoding="utf-8")
            self.assertEqual(self.run_scan(root, "--packet-responses", str(responses))[0], 2)
            for fmt in ("json", "sarif"):
                status, native, initial = self.prepare(root, output, "--format", fmt)
                responses.write_text(
                    json.dumps([reply(p) for p in initial["packets"]]), encoding="utf-8"
                )
                actual, text, _ = self.run_scan(
                    root,
                    "--format",
                    fmt,
                    "--packet-discover",
                    "--packet-out",
                    str(output),
                    "--packet-responses",
                    str(responses),
                )
                self.assertEqual(status, 1)
                self.assertEqual(actual, 1)
                self.assertEqual(json.loads(text), json.loads(native))
