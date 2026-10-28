"""Cross-file coverage must not silently become a clean or unreachable result."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1] / "skills/audit-production-readiness/scripts"))

import impact_graph
import review_packets
import scan_repo
import test_packet_orchestration as orchestration_cases
from test_packet_responses import reply
from test_review_packets import make_tree


def query_route():
    return (
        "function queryUser(value) { return db." + "query(value); }\n"
        "app.get('/user', (req, res) => { const value=req.query.id; return res.send(queryUser(value)); });\n"
    )


class CrossFileCoverageTests(unittest.TestCase):
    def test_file_truncation_is_incomplete_not_a_vulnerability(self):
        with make_tree({"server.js": query_route()}) as directory:
            root = Path(directory)
            small, complete = scan_repo.scan_repository(root, cross_file=True)
            self.assertTrue(any(f.rule_id == "SP103" and f.proof_level == "L2" for f in small))
            self.assertTrue(complete["completeness"]["is_complete"])
            (root / "server.js").write_text(
                "// bounded padding\n" * 24000 + query_route(), encoding="utf-8", newline="\n"
            )
            omitted, stats = scan_repo.scan_repository(root, cross_file=True)
            self.assertFalse(stats["completeness"]["is_complete"])
            self.assertEqual(stats["completeness"]["parser_limit"], 1)
            self.assertFalse(any(f.proof_level == "L2" for f in omitted))
            with self.assertRaisesRegex(ValueError, "incomplete"):
                scan_repo.collect_cross_file_taint(root)

    def test_exact_selected_source_under_pruned_directory_is_analyzed(self):
        with make_tree(
            {"vendor/selected.js": query_route(), "private/other.js": query_route()}
        ) as directory:
            root = Path(directory)
            selected = frozenset({"vendor/selected.js"})
            with mock.patch.object(
                impact_graph.os,
                "walk",
                side_effect=AssertionError("scope must not be rediscovered"),
            ):
                graph = impact_graph.ImpactGraph(root, allowed_paths=selected)
                graph.build()
            self.assertTrue(graph.completeness["is_complete"])
            self.assertEqual(graph.analyzed_paths, set(selected))
            self.assertTrue(graph.taint_flows)
            findings, stats = scan_repo.scan_repository(
                root, include_paths=selected, cross_file=True, scan_profile="application"
            )
            self.assertTrue(stats["completeness"]["is_complete"])
            self.assertTrue(
                any(
                    f.rule_id == "SP103"
                    and f.path == "vendor/selected.js"
                    and f.proof_level == "L2"
                    for f in findings
                )
            )

    def test_changed_size_cannot_bypass_bounded_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source.py"
            source.write_bytes(b"def helper(value):\n    return value\n" + b"# padding\n" * 50)
            actual_stat = Path.stat

            def short_stat(path, *args, **kwargs):
                meta = actual_stat(path, *args, **kwargs)
                if path == source:

                    class SizeProxy:
                        st_size = 1

                        def __getattr__(self, name):
                            return getattr(meta, name)

                    return SizeProxy()
                return meta

            with (
                mock.patch.object(Path, "stat", short_stat),
                mock.patch.object(
                    impact_graph, "read_source", wraps=impact_graph.read_source
                ) as reader,
            ):
                graph = impact_graph.ImpactGraph(root, max_file_bytes=32)
                graph.build()
            self.assertEqual(reader.call_count, 1)
            self.assertEqual(reader.call_args.args[2], 32)
            self.assertEqual(graph.files_scanned_count, 0)
            self.assertFalse(graph.completeness["is_complete"])
            self.assertEqual(graph.completeness["oversized"], 1)

    def test_guarded_reads_preserve_universal_newlines_and_coordinates(self):
        for separator in ("\r", "\r\n"):
            with self.subTest(separator=separator), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = "const marker=0;\n" + query_route()
                (root / "entry.js").write_bytes(source.replace("\n", separator).encode())
                graph = impact_graph.ImpactGraph(root)
                graph.build()
                self.assertTrue(graph.completeness["is_complete"])
                self.assertTrue(
                    any(f.sink_rule_id == "SP103" and f.sink_line == 2 for f in graph.taint_flows)
                )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = "//x\n" * 95000 + query_route()
            (root / "entry.js").write_bytes(source.replace("\n", "\r\n").encode())
            graph = impact_graph.ImpactGraph(root)
            graph.build()
            self.assertTrue(graph.completeness["is_complete"])
            self.assertTrue(graph.taint_flows)

    def test_invalid_encoding_syntax_and_reader_failures_remain_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "encoding.py").write_bytes(b"\xff\xfe")
            (root / "syntax.py").write_text("def broken(\n", encoding="utf-8")
            graph = impact_graph.ImpactGraph(root)
            graph.build()
            self.assertEqual(graph.completeness["unreadable"], 1)
            self.assertEqual(graph.completeness["parser_limit"], 1)
            report = graph.analyze_impact("encoding.py")
            self.assertEqual(report.blast_radius_score, "UNKNOWN")
            self.assertIn("UNKNOWN", report.reachability_status)
            self.assertIn("incomplete", impact_graph.render_impact_markdown(report))

    def test_walk_failure_and_parser_fallback_are_not_complete(self):
        with make_tree({"entry.js": "function entry() { return 1; }\n"}) as directory:
            root = Path(directory)

            def failed_walk(*_args, **kwargs):
                kwargs["onerror"](OSError("controlled traversal failure"))
                return iter(())

            with mock.patch.object(impact_graph.os, "walk", failed_walk):
                graph = impact_graph.ImpactGraph(root)
                graph.build()
            self.assertIn("walk_error", graph.completeness["reasons"])
            with mock.patch.object(
                impact_graph.JsTsAnalyzer,
                "analyze",
                side_effect=ValueError("controlled parser failure"),
            ):
                graph = impact_graph.ImpactGraph(root)
                graph.build()
            self.assertIn("js_parser", graph.completeness["reasons"])

    def test_missing_unsupported_and_invalid_line_targets_fail(self):
        with make_tree({"entry.py": "value=1\n", "README.md": "text\n"}) as directory:
            graph = impact_graph.ImpactGraph(Path(directory))
            graph.build()
            for target, line in (("missing.py", None), ("README.md", None), ("entry.py", 0)):
                with self.subTest(target=target, line=line), self.assertRaises(ValueError):
                    graph.analyze_impact(target, line)

    def test_out_of_scope_target_does_not_poison_subsequent_analysis(self):
        with make_tree(
            {"entry.py": "def helper():\n    return 1\n", "vendor/other.py": "value=1\n"}
        ) as directory:
            graph = impact_graph.ImpactGraph(Path(directory))
            graph.build()
            with self.assertRaisesRegex(ValueError, "outside the analyzed"):
                graph.analyze_impact("vendor/other.py")
            self.assertTrue(graph.completeness["is_complete"])
            self.assertNotEqual(graph.analyze_impact("entry.py").blast_radius_score, "UNKNOWN")

    def test_omission_accounting_is_bounded_and_idempotent(self):
        with make_tree({"entry.py": "value=1\n"}) as directory:
            graph = impact_graph.ImpactGraph(Path(directory))
            for index in range(5000):
                graph._omit(f"f{index}.js", "functions")
            graph._omit("f0.js", "functions")
            self.assertEqual(graph.completeness["affected_inputs"], 5000)
            with self.assertRaisesRegex(ValueError, "5000"):
                graph._omit("overflow.js", "functions")

    def test_hop_budget_and_repeated_propagation_keep_incompleteness(self):
        code = "@app.get('/item')\ndef route(value):\n    return hop0(value)\n"
        for index in range(7):
            code += f"def hop{index}(value):\n    return hop{index + 1}(value)\n"
        code += "def hop7(value):\n    return cursor." + "execute(value)\n"
        with make_tree({"route.py": code}) as directory:
            graph = impact_graph.ImpactGraph(Path(directory))
            graph.build()
            first = graph.completeness
            graph.propagate_interprocedural_taint()
            self.assertEqual(graph.completeness, first)
            self.assertIn("call_depth", first["reasons"])


class JsBudgetTests(unittest.TestCase):
    def test_function_body_and_parameter_limits_have_boundary_negatives(self):
        analyzer = impact_graph.JsTsAnalyzer()
        with mock.patch.object(analyzer, "MAX_FUNCTIONS_PER_FILE", 2):
            analyzer.analyze("entry.js", "function a() {}\nfunction b() {}\n")
            self.assertNotIn("functions", analyzer.omissions)
            analyzer.analyze("entry.js", "function a() {}\nfunction b() {}\nfunction c() {}\n")
            self.assertIn("functions", analyzer.omissions)
        with mock.patch.object(analyzer, "MAX_BODY_CHARS", 20):
            analyzer.analyze("entry.js", "function a() { return 1; }\n")
            self.assertNotIn("body_chars", analyzer.omissions)
            analyzer.analyze("entry.js", "function a() {" + " " * 21 + "}\n")
            self.assertIn("body_chars", analyzer.omissions)
        analyzer.analyze(
            "entry.js", "function a(" + ",".join(f"p{i}" for i in range(12)) + ") {}\n"
        )
        self.assertNotIn("parameters", analyzer.omissions)
        analyzer.analyze(
            "entry.js", "function a(" + ",".join(f"p{i}" for i in range(13)) + ") {}\n"
        )
        self.assertIn("parameters", analyzer.omissions)

    def test_sink_and_callee_caps_report_only_unprocessed_candidates(self):
        analyzer = impact_graph.JsTsAnalyzer()
        with mock.patch.object(analyzer, "MAX_SINKS_PER_FUNCTION", 2):
            analyzer.analyze(
                "entry.js",
                "function query(value) {\n"
                + "db."
                + "query(value);\n"
                + "db."
                + "query(value);\n}\n",
            )
            self.assertNotIn("sinks", analyzer.omissions)
            analyzer.analyze(
                "entry.js", "function query(value) {\n" + ("db." + "query(value);\n") * 3 + "}\n"
            )
            self.assertIn("sinks", analyzer.omissions)
        with mock.patch.object(analyzer, "MAX_CALLEES_PER_FUNCTION", 2):
            analyzer.analyze("entry.js", "function query(value) {\na(value);\nb(value);\n}\n")
            self.assertNotIn("callees", analyzer.omissions)
            analyzer.analyze(
                "entry.js", "function query(value) {\na(value);\nb(value);\nc(value);\n}\n"
            )
            self.assertIn("callees", analyzer.omissions)

    def test_call_position_and_argument_limits_remain_explicit(self):
        analyzer = impact_graph.JsTsAnalyzer()
        analyzer.analyze(
            "entry.js",
            "function a(req) {\nconst {a,b,c,d,e,f,g,h,i}=req.body;\nreturn db." + "query(i);\n}\n",
        )
        self.assertIn("binding_targets", analyzer.omissions)
        analyzer.analyze(
            "entry.js", "function a(value) {\nhelper(" + ",".join(["0"] * 8 + ["value"]) + ");\n}\n"
        )
        self.assertIn("callee_positions", analyzer.omissions)
        with mock.patch.object(analyzer, "MAX_ARG_CHARS", 20):
            analyzer.analyze(
                "entry.js", "function a(value) {\nreturn db." + "query(" + " " * 30 + "value);\n}\n"
            )
            self.assertIn("sink_args", analyzer.omissions)


class CoverageCliTests(unittest.TestCase):
    run_scan = orchestration_cases.DiscoveryCliTests.run_scan

    def test_strict_and_exploratory_modes_and_sarif_report_graph_coverage(self):
        with make_tree({"server.js": "// bounded padding\n" * 24000 + query_route()}) as directory:
            status, native, _ = self.run_scan(directory)
            strict, text, _ = self.run_scan(directory, "--cross-file")
            exploratory, preview, _ = self.run_scan(directory, "--cross-file", "--allow-incomplete")
            sarif_status, sarif, _ = self.run_scan(directory, "--cross-file", "--format", "sarif")
        self.assertEqual(status, 0)
        self.assertTrue(json.loads(native)["summary"]["completeness"]["is_complete"])
        self.assertEqual(strict, 1)
        self.assertEqual(exploratory, 0)
        self.assertEqual(json.loads(text)["verdict"], "CONDITIONAL")
        self.assertEqual(json.loads(preview)["verdict"], "CONDITIONAL")
        self.assertEqual(sarif_status, 1)
        self.assertFalse(json.loads(sarif)["runs"][0]["properties"]["completeness"]["is_complete"])

    def test_impact_cli_reports_unknown_and_invalid_evidence_exit(self):
        with make_tree({"server.js": "// bounded padding\n" * 24000 + query_route()}) as directory:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = impact_graph.main(["server.js", "--root", directory, "--format", "json"])
        result = json.loads(stdout.getvalue())
        self.assertEqual(status, 2)
        self.assertFalse(result["completeness"]["is_complete"])
        self.assertEqual(result["blast_radius_score"], "UNKNOWN")

    def test_late_packet_failure_cannot_complete_review_or_pass_response_mode(self):
        for failure in ({"timed_out": True}, {"error": "controlled model failure"}):
            with (
                self.subTest(failure=failure),
                make_tree({"entry.ts": "export {};\n"}) as directory,
                tempfile.TemporaryDirectory() as artifacts,
            ):
                output = Path(artifacts)
                self.assertEqual(
                    self.run_scan(directory, "--packet-discover", "--packet-out", artifacts)[0], 0
                )
                initial = json.loads((output / "ledger.json").read_text())
                packet = initial["packets"][0]
                done = reply(packet)
                error = {
                    "packet_id": packet["packet_id"],
                    "packet_digest": packet["packet_digest"],
                    **failure,
                }
                report = json.loads(json.dumps(initial))
                review_packets.reconcile(report, [done, error])
                self.assertFalse(report["review_complete"])
                self.assertEqual(report["counts"]["completed"], 1)
                response_file = output / "responses.json"
                response_file.write_text(json.dumps([done, error]), encoding="utf-8")
                status, _native, _message = self.run_scan(
                    directory,
                    "--packet-discover",
                    "--packet-out",
                    artifacts,
                    "--packet-responses",
                    str(response_file),
                )
                self.assertEqual(status, 2)
