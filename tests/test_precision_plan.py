"""Precision-plan engine: proof gate, library mode, test scope, and context filters."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

import precision as precision_policy  # noqa: E402
import scan_repo  # noqa: E402
from scan_repo import (  # noqa: E402
    build_json_report,
    determine_scope,
    determine_verdict,
    find_python_ast_issues,
    find_regex_issues,
    gate_failed,
    lint_source_snippet,
    scan_repository,
)

NEGATIVES = json.loads(
    (ROOT / "tests" / "precision_plan_negatives.json").read_text(encoding="utf-8")
)


class PrecisionPlanTests(unittest.TestCase):
    def test_test_scope_includes_filename_suffixes(self):
        self.assertEqual(determine_scope("src/anthropic_adapter_tests.py"), "test")
        self.assertEqual(determine_scope("widget_test.py"), "test")
        self.assertEqual(determine_scope("conftest.py"), "test")
        self.assertEqual(determine_scope("widget.test.ts"), "test")
        self.assertEqual(determine_scope("widget.spec.jsx"), "test")
        self.assertEqual(determine_scope("src/service.py"), "app")

    def test_sp019_does_not_fire_in_docstrings(self):
        source = (
            "def describe():\n"
            '    """Example DSN: postgres://app:secret@db.example.test:5432/app."""\n'
            "    return 1\n"
        )
        findings = find_regex_issues(
            Path("models.py"),
            "models.py",
            source,
            docstring_lines=precision_policy.docstring_lines(scan_repo.parse_python_source(source)),
        )
        self.assertFalse(any(item.rule_id == "SP019" for item in findings))

    def test_fnmatch_filter_in_a_loop_is_not_an_n_plus_one_query(self):
        source = "import fnmatch\nfor name in names:\n    fnmatch.filter(names, '*.py')\n"
        findings = find_python_ast_issues("routing.py", source)
        self.assertFalse(any(item.rule_id == "SP307" for item in findings))

    def test_while_true_with_recv_is_not_a_spin_loop(self):
        source = "while True:\n    data = sock.recv(4096)\n    if not data:\n        break\n"
        findings = find_python_ast_issues("connection.py", source)
        self.assertFalse(any(item.rule_id == "SP310" for item in findings))

    def test_l0_high_findings_are_review_not_block_unless_allowlisted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            routes = root / "routes"
            routes.mkdir()
            (routes / "auth.py").write_text(
                "import hashlib\n"
                "def store(password):\n"
                "    return hashlib.sha1(password.encode()).hexdigest()\n",
                encoding="utf-8",
            )
            findings, stats = scan_repository(root)
            report = build_json_report(root, findings, stats)
            self.assertEqual(report["verdict"], "REVIEW")
            self.assertFalse(gate_failed(findings, "high"))
            self.assertTrue(any(item.rule_id == "SP140" for item in findings))

    def test_demo_allowlisted_debug_true_still_blocks_with_ast_findings(self):
        demo = ROOT / "examples" / "demo-api" / "fixtures" / "before"
        findings, stats = scan_repository(demo)
        report = build_json_report(demo, findings, stats)
        self.assertEqual(report["verdict"], "BLOCK")
        self.assertTrue(gate_failed(findings, "high"))

    def test_library_profile_downranks_application_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "compiler.py").write_text(
                "def render(template):\n    return eval(template)\n",
                encoding="utf-8",
            )
            findings, stats = scan_repository(root)
            self.assertEqual(stats["scan_profile"], "library")
            sp101 = [item for item in findings if item.rule_id == "SP101"]
            self.assertTrue(sp101)
            self.assertTrue(all(item.severity == "medium" for item in sp101))
            self.assertTrue(all(item.scan_profile == "library" for item in sp101))

    def test_advisory_bare_except_does_not_change_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "util.py").write_text(
                "try:\n    call()\nexcept Exception:\n    pass\n",
                encoding="utf-8",
            )
            findings, stats = scan_repository(root)
            self.assertTrue(
                any(item.rule_id == "SP061" and item.tier == "advisory" for item in findings)
            )
            self.assertTrue(
                all(item.confidence == "low" for item in findings if item.rule_id == "SP061")
            )
            self.assertEqual(
                determine_verdict(findings, completeness=stats["completeness"]),
                "PASS_WITH_EVIDENCE",
            )

    def test_sse_mime_string_without_stream_construction_is_silent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "openapi.py").write_text(
                'schema = {"content": {"text/event-stream": {"schema": {"type": "string"}}}}\n',
                encoding="utf-8",
            )
            findings, _ = scan_repository(root)
            self.assertFalse(any(item.rule_id == "SP636" for item in findings))

    def test_json_keeps_every_finding_when_terminal_collapses(self):
        findings = []
        for index in range(6):
            findings.extend(
                find_regex_issues(
                    Path("util.py"),
                    "util.py",
                    f"try:\n    call{index}()\nexcept Exception:\n    pass\n",
                )
            )
        visible, notes = precision_policy.collapse_for_display(findings)
        self.assertLess(len(visible), len(findings))
        self.assertTrue(notes)
        payload = build_json_report(Path("."), findings, {"files_scanned": 1, "suppressed": 0})
        self.assertEqual(len(payload["findings"]), len(findings))

    def test_nested_wsgi_and_asgi_modules_do_not_make_a_library_an_application(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "wsgi.py").write_text(
                "def get_host(environ):\n    return environ['HOST']\n", encoding="utf-8"
            )
            transports = root / "_transports"
            transports.mkdir()
            (transports / "asgi.py").write_text(
                "async def send(message):\n    return message\n",
                encoding="utf-8",
            )
            middleware = root / "middleware"
            middleware.mkdir()
            (middleware / "wsgi.py").write_text(
                "def wrap(app):\n    return app\n",
                encoding="utf-8",
            )
            _, stats = scan_repository(root)
            self.assertEqual(stats["scan_profile"], "library")

    def test_manage_py_and_server_py_still_mark_an_application(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "manage.py").write_text("def main():\n    return 0\n", encoding="utf-8")
            _, stats = scan_repository(root)
            self.assertEqual(stats["scan_profile"], "application")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server.py").write_text("def listen():\n    return 0\n", encoding="utf-8")
            _, stats = scan_repository(root)
            self.assertEqual(stats["scan_profile"], "application")

    def test_exec_compile_config_loader_is_not_rce(self):
        source = (
            "import types\n"
            "def from_pyfile(filename):\n"
            "    module = types.ModuleType('config')\n"
            "    with open(filename, 'rb') as handle:\n"
            "        exec(compile(handle.read(), filename, 'exec'), module.__dict__)\n"
            "    return module\n"
        )
        findings = lint_source_snippet(source, "config.py")
        self.assertFalse(any(item.rule_id == "SP101" for item in findings))

    def test_debug_repl_exec_without_request_input_is_silent(self):
        source = (
            "import code\n"
            "class Console(code.InteractiveInterpreter):\n"
            "    def runcode(self, compiled):\n"
            "        exec(compiled, self.locals)\n"
        )
        findings = lint_source_snippet(source, "debug/console.py")
        self.assertFalse(any(item.rule_id == "SP101" for item in findings))

    def test_framework_sse_implementation_is_not_a_missing_disconnect(self):
        source = (
            "from starlette.responses import StreamingResponse\n"
            "class APIRouter:\n"
            "    def stream(self):\n"
            "        return StreamingResponse(body, media_type='text/event-stream')\n"
        )
        findings = lint_source_snippet(source, "routing.py")
        self.assertFalse(any(item.rule_id == "SP636" for item in findings))

    def test_request_inflate_pipe_ownership_is_not_inferred(self):
        source = (
            "function contentstream(req) {\n"
            "  const stream = createDecompressionStream(encoding);\n"
            "  req.pipe(stream);\n"
            "  return stream;\n"
            "}\n"
        )
        findings = lint_source_snippet(source, "lib/read.js")
        self.assertFalse(any(item.rule_id in {"SP336", "SP367"} for item in findings))

    def test_precision_plan_negatives_stay_silent_on_the_full_scan_path(self):
        for case in NEGATIVES["rules"]:
            with self.subTest(rule_id=case["rule_id"]):
                findings = lint_source_snippet(case["source"], case["path"])
                self.assertFalse(
                    any(item.rule_id == case["rule_id"] for item in findings),
                    [item.rule_id for item in findings],
                )


if __name__ == "__main__":
    unittest.main()
