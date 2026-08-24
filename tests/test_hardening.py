"""Tests for scanner hardening: gates, suppression, proof ranking, columns, cross-file."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

import scan_repo  # noqa: E402
from scan_repo import (  # noqa: E402
    LiteralGate,
    build_sarif_report,
    comment_line_prefixes,
    deduplicate_and_suppress_findings,
    extract_inline_ignore_ids,
    find_regex_issues,
    lint_source_snippet,
    main,
    multiline_string_lines,
    parse_python_source,
    scan_repository,
)


def scan_snippet(source: str, filename: str = "app.py"):
    return lint_source_snippet(source, filename)


class LiteralGateTests(unittest.TestCase):
    def test_alternation_branch_requires_one_member(self):
        gate = LiteralGate((), ((frozenset({"Counter"}), frozenset({"Gauge"})),))
        self.assertTrue(gate.allows("x = new Counter()"))
        self.assertTrue(gate.allows("x = new Gauge()"))
        self.assertFalse(gate.allows("x = new Registry()"))

    def test_case_insensitive_literals(self):
        gate = LiteralGate(("password",), ())
        self.assertTrue(gate.allows('PASSWORD = "x"'))
        self.assertTrue(gate.allows('Password = "x"'))
        self.assertFalse(gate.allows("secret = xyz"))

    def test_gate_soundness_on_sample_corpus(self):
        """Every regex match must pass its gate: gates may only skip non-matches."""
        corpus_roots = [
            ROOT / "tests",
            ROOT / "fixtures" / "golden-contract",
            ROOT / "examples",
        ]
        checked = 0
        for corpus_root in corpus_roots:
            for path in sorted(corpus_root.rglob("*")):
                if not path.is_file() or path.suffix.lower() not in {".py", ".js", ".ts", ".mjs"}:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
                gates = scan_repo.rule_gates()
                for line in text.splitlines():
                    for rule in scan_repo.RULES:
                        gate = gates.get(rule.rule_id)
                        if gate is None:
                            continue
                        if rule.pattern.search(line):
                            checked += 1
                            self.assertTrue(
                                gate.allows(line),
                                f"{rule.rule_id} gate rejected a matching line in {path}",
                            )
        self.assertGreater(checked, 100)


class InlineIgnoreTests(unittest.TestCase):
    def test_marker_inside_string_literal_is_not_honored(self):
        source = 'hint = "shipproof-ignore: SP101"\nresult = ev' + "al(user)\n"
        findings = scan_snippet(source)
        self.assertTrue(any(item.rule_id == "SP101" for item in findings))

    def test_marker_accepts_multiple_rule_ids(self):
        marker = "# shipproof-ignore SP101 SP102\n"
        source = marker + "result = ev" + "al(user)\n"
        findings = scan_snippet(source)
        self.assertFalse(any(item.rule_id == "SP101" for item in findings))

    def test_trailing_comment_marker_is_honored(self):
        source = "result = ev" + "al(user)  # shipproof-ignore SP101\n"
        findings = scan_snippet(source)
        self.assertFalse(any(item.rule_id == "SP101" for item in findings))

    def test_marker_in_json_string_value_is_not_honored(self):
        ids = extract_inline_ignore_ids('  "note": "shipproof-ignore: SP518",', ())
        self.assertEqual(ids, ())

    def test_line_start_marker_is_honored_without_comment_syntax(self):
        line = "shipproof-ignore SP003 then a leaked value follows"
        self.assertEqual(extract_inline_ignore_ids(line, ()), ("SP003",))

    def test_comment_prefix_mapping_is_stable(self):
        self.assertEqual(comment_line_prefixes(Path("app.py")), ("#",))
        self.assertEqual(comment_line_prefixes(Path("app.js")), ("//", "/*"))
        self.assertEqual(comment_line_prefixes(Path("query.sql")), ("--", "/*"))


class SecretRuleSetTests(unittest.TestCase):
    def test_provider_token_rules_are_treated_as_secrets(self):
        for rule_id in ("SP026", "SP035", "SP050", "SP404", "SP509"):
            self.assertIn(rule_id, scan_repo.SECRET_RULE_IDS)
        for rule in scan_repo.RULES:
            self.assertEqual(rule.rule_id in scan_repo.SECRET_RULE_IDS, rule.redact)

    def test_document_files_scan_provider_token_rules(self):
        prefix = "".join(("sk-", "ant-", "api03-"))
        payload = "A1b2C3d4E5f6G7h8I9j0" * 4
        token = prefix + payload
        findings = scan_snippet(f"token = `{token}`\n", "README.md")
        self.assertTrue(any(item.rule_id == "SP026" for item in findings))

    def test_placeholder_provider_token_is_filtered(self):
        prefix = "".join(("sk-", "ant-", "api03-"))
        token = prefix + ("example" * 7) + "12345"
        findings = scan_snippet(f"token = '{token}'\n", "README.md")
        self.assertFalse(any(item.rule_id == "SP026" for item in findings))


class ProofRankingTests(unittest.TestCase):
    def test_ast_taint_finding_is_preferred_over_pattern_hit(self):
        source = 'user = request.args["q"]\nresult = ev' + "al(user)\n"
        findings = scan_snippet(source)
        eval_findings = [item for item in findings if item.rule_id == "SP101"]
        self.assertTrue(eval_findings)
        self.assertTrue(
            any(item.detection == "taint" and item.proof_level == "L2" for item in eval_findings),
            [item.detection for item in eval_findings],
        )

    def test_dedup_keeps_higher_proof_level(self):
        pattern = scan_repo.find_rule("SP101")
        low = scan_repo.make_finding(pattern, "a.py", 1, "line", "pattern")
        high = scan_repo.make_finding(pattern, "a.py", 1, "line", "taint")
        active, _ = deduplicate_and_suppress_findings([low, high])
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].detection, "taint")


class DocstringTests(unittest.TestCase):
    def test_multiline_docstring_example_is_not_flagged(self):
        source = (
            "def helper():\n"
            '    """Usage:\n'
            "    result = ev" + "al(user_input)\n"
            '    """\n'
            "    return 1\n"
        )
        findings = scan_snippet(source)
        self.assertFalse(any(item.rule_id == "SP101" for item in findings))

    def test_secret_inside_docstring_is_still_flagged(self):
        key = "".join(("AK", "IA", "B2C3D4E5F6G7H8I9"))
        source = f'def helper():\n    """Docs: access key {key} here"""\n    return 1\n'
        findings = scan_snippet(source)
        self.assertTrue(any(item.rule_id == "SP002" for item in findings))

    def test_multiline_string_lines_tracks_interior_only(self):
        tree = parse_python_source('x = """start\nmiddle\nend"""\ny = 1\n')
        self.assertEqual(multiline_string_lines(tree), {2})


class EntropyConfidenceTests(unittest.TestCase):
    def test_low_entropy_fallback_default_is_downgraded(self):
        filler = "a" * 20
        getenv = "os.environ." + "get"
        source = f'token = {getenv}("API_SECRET", "{filler}")\n'
        findings = scan_snippet(source)
        fallback = [item for item in findings if item.rule_id == "SP004"]
        self.assertTrue(fallback)
        self.assertEqual(fallback[0].confidence, "low")

    def test_high_entropy_fallback_default_stays_confident(self):
        value = "f9Zq2xK7mQ4vT8bN3wL6pR1yJ5hD" + "0c"
        self.assertGreaterEqual(scan_repo.shannon_entropy(value), 4.0)
        getenv = "os.environ." + "get"
        source = f'token = {getenv}("API_SECRET", "{value}")\n'
        findings = scan_snippet(source)
        fallback = [item for item in findings if item.rule_id == "SP004"]
        self.assertTrue(fallback)
        self.assertNotEqual(fallback[0].confidence, "low")


class AssembledCredentialTests(unittest.TestCase):
    def test_concatenated_credential_is_detected(self):
        source = 'api_key = "sk-live-" + "a1b2c3d4e5f6g7h9"\n'
        findings = scan_snippet(source)
        assembled = [item for item in findings if item.rule_id == "SP003"]
        self.assertTrue(assembled)
        self.assertEqual(assembled[0].detection, "ast")

    def test_base64_encoded_credential_is_detected_with_low_confidence(self):
        encoded = "c2VjcmV0LWhhcmRjb2RlZC12YWx1ZS0xMjM0NTY3OA=="
        source = f'password = base64.b64decode("{encoded}")\n'
        findings = scan_snippet(source)
        encoded_findings = [item for item in findings if item.rule_id == "SP003"]
        self.assertTrue(encoded_findings)
        self.assertEqual(encoded_findings[0].confidence, "low")

    def test_non_credential_concatenation_is_ignored(self):
        source = 'title = "Hello" + " " + "World of Widgets"\n'
        findings = scan_snippet(source)
        self.assertFalse(any(item.rule_id == "SP003" for item in findings))


class ColumnAttributionTests(unittest.TestCase):
    def test_line_findings_carry_columns_into_sarif(self):
        source = "result = ev" + "al(user)\n"
        findings = scan_snippet(source)
        item = next(finding for finding in findings if finding.rule_id == "SP101")
        self.assertIsNotNone(item.column)
        sarif = build_sarif_report([item])
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        self.assertEqual(region["startLine"], item.line)
        self.assertEqual(region["startColumn"], item.column)
        self.assertEqual(region.get("endColumn"), item.end_column)


class FrameworkConfidenceTests(unittest.TestCase):
    def scan_express_repo(self, package_json: str):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(package_json, encoding="utf-8")
            (root / "server.js").write_text(
                "const express = require('express');\nconst app = express();\napp.listen(3000);\n",
                encoding="utf-8",
            )
            findings, _ = scan_repository(root)
            return next((f for f in findings if f.rule_id == "SP401"), None)

    def test_declared_framework_keeps_confidence(self):
        finding = self.scan_express_repo('{"dependencies": {"express": "^4.18.0"}}')
        self.assertIsNotNone(finding)
        self.assertEqual(finding.confidence, scan_repo.find_rule("SP401").confidence)

    def test_undeclared_framework_downgrades_confidence(self):
        finding = self.scan_express_repo('{"dependencies": {"fastify": "^4.0.0"}}')
        self.assertIsNotNone(finding)
        expected = scan_repo.DOWNRANK_CONFIDENCE[scan_repo.find_rule("SP401").confidence]
        self.assertEqual(finding.confidence, expected)
        self.assertGreater(
            scan_repo.CONFIDENCE[finding.confidence],
            scan_repo.CONFIDENCE[scan_repo.find_rule("SP401").confidence],
        )


class ExitCodeContractTests(unittest.TestCase):
    def test_unexpected_crash_exits_two_not_one(self):
        with (
            mock.patch.object(scan_repo, "scan_repository", side_effect=RuntimeError("boom")),
            tempfile.TemporaryDirectory() as tmp,
        ):
            exit_code = main(["--format", "json", tmp])
        self.assertEqual(exit_code, 2)

    def test_pathological_nesting_is_skipped_not_fatal(self):
        deep_source = "(" * 60000 + "1" + ")" * 60000
        self.assertIsNone(parse_python_source(deep_source))
        self.assertEqual(scan_repo.find_python_ast_issues("deep.py", deep_source), [])


class CrossFileScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        (self.root / "routes").mkdir()
        (self.root / "repos").mkdir()
        (self.root / "routes" / "user.py").write_text(
            "from repos.user_repo import query_user\n\n"
            "@app.get('/users/{user_id}')\n"
            "def get_user(user_id: str):\n"
            "    return query_user(user_id)\n",
            encoding="utf-8",
        )
        (self.root / "repos" / "user_repo.py").write_text(
            "import sqlite3\n\n"
            "def query_user(raw_id: str):\n"
            "    conn = sqlite3.connect('db.sqlite')\n"
            "    cursor = conn.cursor()\n"
            "    cursor.execute(raw_id)\n"
            "    return cursor.fetchall()\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_cross_file_flow_becomes_l2_finding(self):
        findings, stats = scan_repository(self.root, cross_file=True)
        self.assertEqual(stats.get("cross_file_flows"), 1)
        taint = [item for item in findings if item.detection == "taint"]
        self.assertEqual(len(taint), 1)
        self.assertEqual(taint[0].rule_id, "SP103")
        self.assertEqual(taint[0].proof_level, "L2")
        self.assertEqual(taint[0].path, "repos/user_repo.py")
        self.assertIn("routes/user.py", taint[0].evidence)

    def test_cross_file_is_opt_in(self):
        findings, stats = scan_repository(self.root)
        self.assertNotIn("cross_file_flows", stats)
        self.assertFalse(any(item.detection == "taint" for item in findings))

    def test_report_serializes_taint_finding(self):
        findings, _ = scan_repository(self.root, cross_file=True)
        report = scan_repo.build_json_report(self.root, findings, {"files_scanned": 2})
        self.assertIn("SP103", json.dumps(report))

    def test_cross_file_respects_include_paths(self):
        findings, stats = scan_repository(
            self.root,
            include_paths=frozenset(),
            cross_file=True,
        )
        self.assertEqual(stats["files_scanned"], 0)
        self.assertEqual(stats["cross_file_flows"], 0)
        self.assertFalse(any(item.detection == "taint" for item in findings))

    def test_cross_file_respects_excludes(self):
        findings, stats = scan_repository(
            self.root,
            exclude_patterns=["repos/**"],
            cross_file=True,
        )
        self.assertEqual(stats["files_scanned"], 1)
        self.assertEqual(stats["cross_file_flows"], 0)
        self.assertFalse(any(item.detection == "taint" for item in findings))

    def test_cross_file_respects_max_file_bytes(self):
        findings, stats = scan_repository(
            self.root,
            max_file_bytes=100,
            cross_file=True,
        )
        self.assertEqual(stats["files_scanned"], 0)
        self.assertEqual(stats["cross_file_flows"], 0)
        self.assertFalse(any(item.detection == "taint" for item in findings))


class BoundedMultilineRulesTests(unittest.TestCase):
    def test_prometheus_counter_in_handler_is_detected(self):
        source = (
            "async def handle():\n    counter = new Coun" + "ter('requests')\n    return counter\n"
        )
        findings = find_regex_issues(Path("app.py"), "app.py", source)
        self.assertTrue(any(item.rule_id == "SP577" for item in findings))

    def test_prometheus_counter_far_from_handler_is_not_detected(self):
        source = (
            "async def handle():\n"
            "    return 1\n" + "# padding line\n" * 300 + "counter = new Coun" + "ter('requests')\n"
        )
        findings = find_regex_issues(Path("app.py"), "app.py", source)
        self.assertFalse(any(item.rule_id == "SP577" for item in findings))


class ParallelJobsTests(unittest.TestCase):
    def scan_via_cli(self, jobs: int) -> str:
        import subprocess

        result = subprocess.run(  # noqa: S603 - fixed argv in a test fixture
            [
                sys.executable,
                str(ROOT / "skills" / "audit-production-readiness" / "scripts" / "scan_repo.py"),
                str(ROOT),
                "--format",
                "json",
                "--fail-on",
                "none",
                "--exclude",
                "node_modules/**",
                "--jobs",
                str(jobs),
            ],
            capture_output=True,
            text=True,
            shell=False,
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return result.stdout

    def test_parallel_scan_matches_sequential_output(self):
        # The repository itself has well over the parallel threshold of files.
        sequential = self.scan_via_cli(1)
        parallel = self.scan_via_cli(4)
        self.assertEqual(sequential, parallel)

    def test_jobs_flag_rejects_zero(self):
        exit_code = main([".", "--format", "json", "--jobs", "0"])
        self.assertEqual(exit_code, 2)


if __name__ == "__main__":
    unittest.main()


class FalsePositiveRegressionTests(unittest.TestCase):
    """Guard the precision fixes measured against the five OSS corpora."""

    def test_flask_dict_session_is_not_an_outbound_request(self):
        source = 'from flask import session\nflashes = session.get("_flashes", [])\n'
        findings = scan_snippet(source)
        self.assertFalse(any(item.rule_id == "SP304" for item in findings))

    def test_untracked_client_receiver_is_not_an_outbound_request(self):
        source = 'client.get("/things")\n'
        findings = scan_snippet(source)
        self.assertFalse(any(item.rule_id == "SP304" for item in findings))

    def test_requests_session_binding_still_flags_missing_timeout(self):
        source = (
            "import requests\n"
            "session = requests.Session()\n"
            "response = session.get('https://example.test')\n"
        )
        findings = scan_snippet(source)
        self.assertTrue(any(item.rule_id == "SP304" for item in findings))

    def test_rxjs_operator_pipe_is_not_a_node_stream(self):
        source = (
            "return this.http.get(this.host).pipe(\n"
            "  map((response) => response.data),\n"
            "  catchError((error) => throwError(error)),\n"
            ");\n"
        )
        findings = scan_snippet(source, "service.ts")
        self.assertFalse(any(item.rule_id == "SP367" for item in findings))

    def test_node_stream_pipe_without_handler_still_flagged(self):
        source = "readStream.pipe(res);\n"
        findings = scan_snippet(source, "server.js")
        self.assertTrue(any(item.rule_id == "SP367" for item in findings))

    def test_ignore_scripts_install_is_not_unsafe(self):
        source = "run: npm install --ignore-scripts --include=dev\n"
        findings = scan_snippet(source, "ci.yml")
        self.assertFalse(any(item.rule_id == "SP213" for item in findings))

    def test_unsafe_perm_install_still_flagged(self):
        flag = "--unsafe-" + "perm"
        source = f"npm install {flag}\n"
        findings = scan_snippet(source, "script.sh")
        self.assertTrue(any(item.rule_id == "SP213" for item in findings))

    def test_node_env_fallback_is_not_a_secret(self):
        source = "var env = process.env.NODE_ENV || 'development';\n"
        findings = scan_snippet(source, "app.js")
        self.assertFalse(any(item.rule_id == "SP004" for item in findings))

    def test_debug_kwarg_required_for_sp201(self):
        findings = scan_snippet("self.debug = True\n", "cli.py")
        self.assertFalse(any(item.rule_id == "SP201" for item in findings))
        findings = scan_snippet("app = FastAPI(de" + "bug=True)\n", "app.py")
        self.assertTrue(any(item.rule_id == "SP201" for item in findings))

    def test_express_call_in_comment_does_not_trigger_sp401(self):
        source = "/*\n *      , app = express();\n */\nmodule.exports = {};\n"
        findings = scan_snippet(source, "lib.js")
        self.assertFalse(any(item.rule_id == "SP401" for item in findings))

    def test_hash_helper_name_is_not_md5_call(self):
        findings = scan_snippet('def _lazy_sha1(string: bytes = b"") -> t.Any:\n', "sessions.py")
        self.assertFalse(any(item.rule_id == "SP140" for item in findings))

    def test_plain_while_true_is_not_an_agent_loop(self):
        source = "while True:\n    command = input('> ')\n"
        findings = scan_snippet(source, "repl.py")
        self.assertFalse(any(item.rule_id == "SP527" for item in findings))

    def test_agent_while_true_still_flagged(self):
        source = "while " + "True:\n    response = llm.chat(messages)\n"
        findings = scan_snippet(source, "agent.py")
        self.assertTrue(any(item.rule_id == "SP527" for item in findings))
        guard = "response." + "tool_calls"
        direct = scan_snippet(f"while {guard}:\n    run_tool(response)\n", "agent.py")
        self.assertTrue(any(item.rule_id == "SP527" for item in direct))

    def test_generic_url_variable_is_not_ssrf(self):
        source = "response = requests.get(url)\n"
        findings = scan_snippet(source, "fetcher.py")
        self.assertFalse(any(item.rule_id == "SP109" for item in findings))

    def test_express_req_params_access_is_not_nextjs(self):
        source = "router.get('/x', (req, res) => res.send(req.params.id));\n"
        findings = scan_snippet(source, "routes.js")
        self.assertFalse(any(item.rule_id == "SP593" for item in findings))

    def test_js_template_prose_does_not_trigger_non_secret_rules(self):
        source = "const guide = `Usage:\nRun ev" + "al(user_input) only in local docs.\n`;\n"
        findings = scan_snippet(source, "guide.js")
        self.assertFalse(any(item.rule_id == "SP101" for item in findings))

    def test_minified_line_downgrades_confidence(self):
        long_line = "var a=1;" + "x" * 1100 + ";shell" + "=true;"
        findings = scan_snippet(long_line, "bundle.js")
        sp = [f for f in findings if f.rule_id == "SP102"]
        self.assertTrue(sp)
        self.assertEqual(
            sp[0].confidence,
            scan_repo.DOWNRANK_CONFIDENCE[scan_repo.find_rule("SP102").confidence],
        )
