from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).parents[1] / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from scan_repo import (  # noqa: E402
    VERSION,
    build_decision_trace,
    build_sarif_report,
    changed_files,
    deduplicate_and_suppress_findings,
    find_python_ast_issues,
    find_regex_issues,
    is_excluded,
    iter_scannable_files,
    main,
    normalize_exclude_patterns,
    render_explain,
    render_fix_prompts,
    render_github_annotations,
    render_markdown_report,
    scan_repository,
)


class ScanRepoTests(unittest.TestCase):
    def findings(self, name: str, source: str):
        path = Path(name)
        candidates = find_regex_issues(path, name, source)
        if path.suffix == ".py":
            candidates.extend(find_python_ast_issues(name, source))
        return deduplicate_and_suppress_findings(candidates)[0]

    def test_secret_is_redacted(self):
        secret = "AKIA" + "A" * 16
        findings = self.findings("settings.py", f'cloud_key = "{secret}"\n')
        aws = next(item for item in findings if item.rule_id == "SP002")
        self.assertEqual(aws.severity, "critical")
        self.assertNotIn(secret, aws.evidence)

    def test_placeholder_secret_is_ignored(self):
        placeholder = "replace_me" + "_with_your_key"
        findings = self.findings(".env", f'API_KEY="{placeholder}"\n')
        self.assertFalse(any(item.rule_id == "SP003" for item in findings))

    def test_quoted_json_credential_key_is_detected(self):
        secret = "".join(("N7vK", "2mQ9", "xR4p", "T8wZ", "6cB3"))
        findings = self.findings("settings.json", f'{{"password": "{secret}"}}\n')
        match = next(item for item in findings if item.rule_id == "SP003")
        self.assertNotIn(secret, match.evidence)

    def test_placeholder_elsewhere_on_line_does_not_hide_real_secret(self):
        secret = "AKIA" + "D" * 16
        findings = self.findings("settings.py", f'key = "{secret}"  # replace_me in docs\n')
        self.assertTrue(any(item.rule_id == "SP002" for item in findings))

    def test_request_timeout_is_ast_checked(self):
        findings = self.findings(
            "client.py",
            "import requests\nrequests.get('https://api.test')\nrequests.post('https://api.test', timeout=2)\n",
        )
        timeout_lines = [item.line for item in findings if item.rule_id == "SP304"]
        self.assertEqual(timeout_lines, [2])

    def test_multiline_interpolated_sql_is_ast_checked(self):
        findings = self.findings(
            "repository.py",
            'database.execute(\n    f"SELECT id FROM users WHERE email = {email}"\n)\n',
        )
        self.assertEqual([item.rule_id for item in findings], ["SP103"])

    def test_bound_sql_parameters_are_not_flagged(self):
        findings = self.findings(
            "repository.py",
            'database.execute("SELECT id FROM users WHERE email = ?", (email,))\n',
        )
        self.assertFalse(any(item.rule_id == "SP103" for item in findings))

    def test_sensitive_fastapi_route_requires_visible_authorization(self):
        findings = self.findings(
            "app.py",
            """from fastapi import Depends, FastAPI
app = FastAPI()
def require_admin(): ...
@app.get('/admin/users')
def unsafe(): ...
@app.get('/admin/audit', dependencies=[Depends(require_admin)])
def safe(): ...
""",
        )
        auth_lines = [item.line for item in findings if item.rule_id == "SP108"]
        self.assertEqual(auth_lines, [4])

    def test_route_page_size_requires_request_boundary_maximum(self):
        findings = self.findings(
            "app.py",
            """from fastapi import FastAPI, Query
app = FastAPI()
@app.get('/items')
def unsafe(limit: int = 50): ...
@app.get('/bounded')
def safe(page_size: int = Query(50, ge=1, le=100)): ...
""",
        )
        pagination_lines = [item.line for item in findings if item.rule_id == "SP305"]
        self.assertEqual(pagination_lines, [4])

    def test_blocking_sleep_only_flags_async_context(self):
        source = "import time\ndef sync():\n    time.sleep(1)\nasync def async_job():\n    time.sleep(1)\n"
        findings = self.findings("jobs.py", source)
        sleep_lines = [item.line for item in findings if item.rule_id == "SP303"]
        self.assertEqual(sleep_lines, [5])

    def test_nested_sync_function_is_not_treated_as_async(self):
        source = "import time\nasync def outer():\n    def sync():\n        time.sleep(1)\n"
        findings = self.findings("jobs.py", source)
        self.assertFalse(any(item.rule_id == "SP303" for item in findings))

    def test_combined_cors_risk(self):
        source = "allow_" + 'origins=["*"]\nallow_' + "credentials=True\n"
        findings = self.findings("api.py", source)
        self.assertTrue(any(item.rule_id == "SP107" for item in findings))

    def test_baseline_suppresses_exact_fingerprint(self):
        source = "result = " + "ev" + "al(value)\n"
        candidates = find_regex_issues(Path("app.py"), "app.py", source)
        target_fps = {
            finding.fingerprint
            for finding in candidates
            if finding.rule_id == candidates[0].rule_id
        }
        active, suppressed = deduplicate_and_suppress_findings(candidates, target_fps)
        self.assertEqual(active, [])
        self.assertEqual(suppressed, 1)

    def test_fingerprint_survives_line_movement(self):
        source = "result = " + "ev" + "al(value)\n"
        first = self.findings("app.py", source)[0]
        moved = self.findings("app.py", "\n\n" + source)[0]
        self.assertEqual(first.fingerprint, moved.fingerprint)

    def test_sarif_uses_supported_version(self):
        source = "result = " + "ev" + "al(value)\n"
        findings = self.findings("app.py", source)
        payload = build_sarif_report(findings)
        self.assertEqual(payload["version"], "2.1.0")
        result_rule_ids = [result["ruleId"] for result in payload["runs"][0]["results"]]
        self.assertIn("SP101", result_rule_ids)
        self.assertEqual(payload["runs"][0]["tool"]["driver"]["version"], VERSION)
        json.dumps(payload)

    def test_markdown_report_renders_finding_evidence_and_conditional_verdict(self):
        findings = self.findings("query.sql", "SELECT * FROM users\n")
        report = render_markdown_report(
            Path("."),
            findings,
            {"files_scanned": 1, "suppressed": 0},
        )
        self.assertIn("**Verdict:** CONDITIONAL", report)
        self.assertIn("SP302", report)
        self.assertIn("**Fix:**", report)
        self.assertIn("## Limitations", report)

    def test_container_base_rule_only_applies_to_dockerfiles(self):
        sql_findings = self.findings("query.sql", "SELECT * FROM audit_events;\n")
        docker_findings = self.findings("Dockerfile", "FROM node:20\n")
        self.assertFalse(any(item.rule_id == "SP202" for item in sql_findings))
        self.assertIn("SP202", [item.rule_id for item in docker_findings])
        self.assertIn("SP226", [item.rule_id for item in docker_findings])
        self.assertIn("SP227", [item.rule_id for item in docker_findings])

    def test_unpinned_git_dependency_excludes_repository_metadata(self):
        dependency = self.findings(
            "package.json",
            '"dependencies": {"widget": "git+https://github.com/example/widget.git#main"}\n',
        )
        metadata = self.findings(
            "package.json",
            '"repository": {"type": "git", "url": "git+https://github.com/example/app.git"}\n',
        )
        pinned = self.findings(
            "package.json",
            '"dependencies": {"widget": "git+https://github.com/example/widget.git#0123456789abcdef0123456789abcdef01234567"}\n',
        )
        self.assertIn("SP221", [item.rule_id for item in dependency])
        self.assertNotIn("SP221", [item.rule_id for item in metadata])
        self.assertNotIn("SP221", [item.rule_id for item in pinned])

    def test_previously_unwalked_language_suffixes_are_scanned(self):
        svelte = self.findings("Component.svelte", "<div>{@html user.bio}</div>\n")
        swift = self.findings(
            "Session.swift", "let credential = URLCredential(trust: serverTrust)\n"
        )
        self.assertIn("SP644", [item.rule_id for item in svelte])
        self.assertIn("SP646", [item.rule_id for item in swift])

    def test_multiline_systemd_rule_runs_against_whole_source(self):
        findings = self.findings(
            "shipproof.service", "[Unit]\nDescription=demo\n[Service]\nExecStart=/opt/demo\n"
        )
        self.assertIn("SP269", [item.rule_id for item in findings])

    def test_multiline_kubernetes_privileged_rule_has_both_polarities(self):
        unsafe = self.findings("deployment.yaml", "securityContext:\n  privileged: true\n")
        safe = self.findings("deployment.yaml", "securityContext:\n  privileged: false\n")
        self.assertIn("SP236", [item.rule_id for item in unsafe])
        self.assertNotIn("SP236", [item.rule_id for item in safe])

    def test_server_action_auth_guard_suppresses_multiline_false_positive(self):
        unsafe = self.findings(
            "actions.ts",
            "'use server';\nexport async function removeAccount() {\n  await deleteAccount();\n}\n",
        )
        safe = self.findings(
            "actions.ts",
            "'use server';\nexport async function removeAccount() {\n  const user = await auth();\n  await deleteAccount(user.id);\n}\n",
        )
        self.assertIn("SP420", [item.rule_id for item in unsafe])
        self.assertNotIn("SP420", [item.rule_id for item in safe])

    def test_agent_shell_tool_requires_an_explicit_approval_gate(self):
        unsafe = self.findings(
            "agent.py",
            "@tool\ndef execute_command(command):\n    return subprocess."
            + "run(command, shell="
            + "True)\n",
        )
        safe = self.findings(
            "agent.py",
            "@tool\ndef execute_command(command):\n    require_human_approval(command)\n"
            + "    return subprocess."
            + "run(command, shell="
            + "True)\n",
        )
        self.assertIn("SP518", [item.rule_id for item in unsafe])
        self.assertNotIn("SP518", [item.rule_id for item in safe])

    def test_temporal_global_rule_requires_mutation_not_a_read(self):
        unsafe = self.findings(
            "workflow.py",
            "counter = 0\n@workflow."
            + "defn\nclass Job:\n    async def run(self):\n        global counter\n"
            + "        counter += 1\n",
        )
        safe = self.findings(
            "workflow.py",
            "counter = 0\n@workflow."
            + "defn\nclass Job:\n    async def run(self):\n        global counter\n"
            + "        return counter\n",
        )
        self.assertIn("SP585", [item.rule_id for item in unsafe])
        self.assertNotIn("SP585", [item.rule_id for item in safe])

    def test_identical_text_multiple_lines_reported(self):
        source = (
            "def a():\n    result = ev" + "al(value)\n\n\ndef b():\n    result = ev" + "al(value)\n"
        )
        findings = self.findings("app.py", source)
        eval_lines = [item.line for item in findings if item.rule_id == "SP101"]
        self.assertEqual(eval_lines, [2, 6])

    def test_baseline_suppresses_multiple_identical_findings(self):
        source = (
            "def a():\n    result = ev" + "al(value)\n\n\ndef b():\n    result = ev" + "al(value)\n"
        )
        candidates = find_regex_issues(Path("app.py"), "app.py", source)
        target_fps = {
            finding.fingerprint
            for finding in candidates
            if finding.rule_id == candidates[0].rule_id
        }
        active, suppressed = deduplicate_and_suppress_findings(candidates, target_fps)
        self.assertEqual(active, [])
        self.assertEqual(suppressed, 2)

    def test_pure_comments_are_ignored_for_code_rules(self):
        source = "# never call ev" + "al(value) here\nresult = ev" + "al(value)\n"
        findings = self.findings("app.py", source)
        eval_lines = [item.line for item in findings if item.rule_id == "SP101"]
        self.assertEqual(eval_lines, [2])

    def test_javascript_regexp_exec_is_not_dynamic_code_execution(self):
        findings = self.findings("cli.mjs", "const match = /Python (\\d+)/.exec(version);\n")
        self.assertFalse(any(item.rule_id == "SP101" for item in findings))

    def test_secrets_in_comments_are_still_flagged(self):
        secret = "AKIA" + "B" * 16
        source = f'# old_key = "{secret}"\n'
        findings = self.findings("app.py", source)
        self.assertTrue(any(item.rule_id == "SP002" for item in findings))

    def test_documentation_is_scanned_only_for_secrets(self):
        secret = "AKIA" + "C" * 16
        findings = self.findings("notes.md", f"Never call eval here. Leaked key: {secret}\n")
        self.assertEqual([item.rule_id for item in findings], ["SP002"])

    def test_ignored_directories_are_pruned_before_traversal(self):
        subdirectories = ["node_modules", "src", "bin", ".git"]
        with patch("scan_repo.os.walk", return_value=[("/repo", subdirectories, [])]):
            self.assertEqual(list(iter_scannable_files(Path("/repo"), 1_000)), [])
        self.assertEqual(subdirectories, ["bin", "src"])

    def test_exclude_patterns_prune_a_directory_tree(self):
        patterns = normalize_exclude_patterns(["generated/**", "reports/*.json"])
        self.assertTrue(is_excluded("generated", patterns))
        self.assertTrue(is_excluded("generated/api/client.py", patterns))
        self.assertTrue(is_excluded("reports/scan.json", patterns))
        self.assertFalse(is_excluded("src/api.py", patterns))

    def test_exclude_patterns_reject_parent_traversal(self):
        with self.assertRaisesRegex(ValueError, "unsafe exclude pattern"):
            normalize_exclude_patterns(["../secrets/**"])

    def test_express_without_helmet_is_flagged(self):
        source = "const express = require('express');\nconst app = express();\napp.listen(3000);\n"
        findings = self.findings("server.js", source)
        self.assertTrue(any(item.rule_id == "SP401" for item in findings))

    def test_express_with_helmet_is_not_flagged(self):
        source = "const express = require('express');\nconst helmet = require('helmet');\nconst app = express();\napp.use(helmet());\n"
        findings = self.findings("server.js", source)
        self.assertFalse(any(item.rule_id == "SP401" for item in findings))

    def test_express_auth_route_without_rate_limiting_is_flagged(self):
        source = "const app = express();\napp.post('/api/auth/login', signIn);\n"
        findings = self.findings("server.js", source)
        rate_limit = next(item for item in findings if item.rule_id == "SP402")
        self.assertEqual(rate_limit.line, 2)

    def test_express_auth_route_with_rate_limiting_is_not_flagged(self):
        source = (
            "const app = express();\n"
            "const limiter = require('express-rate-limit');\n"
            "app.use('/api/auth/login', limiter);\n"
            "app.post('/api/auth/login', signIn);\n"
        )
        findings = self.findings("server.js", source)
        self.assertFalse(any(item.rule_id == "SP402" for item in findings))

    def test_express_non_auth_route_is_not_flagged_for_rate_limiting(self):
        source = "const app = express();\napp.post('/items', createItem);\n"
        findings = self.findings("server.js", source)
        self.assertFalse(any(item.rule_id == "SP402" for item in findings))

    def test_cookie_session_routes_without_csrf_are_flagged(self):
        source = "const app = express();\napp.use(cookieParser());\napp.post('/profile', updateProfile);\n"
        findings = self.findings("server.js", source)
        csrf = next(item for item in findings if item.rule_id == "SP407")
        self.assertEqual(csrf.line, 3)

    def test_cookie_session_routes_with_csrf_are_not_flagged(self):
        source = (
            "const app = express();\n"
            "app.use(cookieParser());\n"
            "app.use(require('csurf')({ cookie: true }));\n"
            "app.post('/profile', updateProfile);\n"
        )
        findings = self.findings("server.js", source)
        self.assertFalse(any(item.rule_id == "SP407" for item in findings))

    def test_token_routes_without_cookies_are_not_flagged_for_csrf(self):
        source = "const app = express();\napp.post('/profile', updateProfile);\n"
        findings = self.findings("server.js", source)
        self.assertFalse(any(item.rule_id == "SP407" for item in findings))

    def test_next_config_without_csp_is_flagged(self):
        source = "const nextConfig = { reactStrictMode: true };\nmodule.exports = nextConfig;\n"
        findings = self.findings("next.config.js", source)
        csp = next(item for item in findings if item.rule_id == "SP408")
        self.assertEqual(csp.line, 1)

    def test_next_config_with_csp_is_not_flagged(self):
        source = (
            "const nextConfig = {\n"
            "  async headers() {\n"
            "    return [{ key: 'Content-Security-Policy', value: 'default-src self' }];\n"
            "  },\n"
            "};\n"
            "module.exports = nextConfig;\n"
        )
        findings = self.findings("next.config.js", source)
        self.assertFalse(any(item.rule_id == "SP408" for item in findings))

    def test_unrelated_config_without_csp_is_not_flagged(self):
        source = "export default {};\n"
        findings = self.findings("vite.config.js", source)
        self.assertFalse(any(item.rule_id == "SP408" for item in findings))

    def test_next_public_secret_is_flagged(self):
        source = "NEXT_PUBLIC_" + "STRIPE_" + "SECRET_" + 'KEY="sk_live_1234567890123456"\n'
        findings = self.findings(".env.local", source)
        self.assertTrue(any(item.rule_id == "SP403" for item in findings))

    def test_django_hardcoded_secret_key_is_flagged(self):
        source = (
            "SECRET_" + "KEY" + ' = "' + "django-" + 'insecure-abcdefghijklmnopqrstuvwxyz123456"\n'
        )
        findings = self.findings("settings.py", source)
        self.assertTrue(any(item.rule_id == "SP404" for item in findings))

    def test_django_wildcard_allowed_hosts_is_flagged(self):
        source = "ALLOWED_" + "HOSTS = ['*']\n"
        findings = self.findings("settings.py", source)
        self.assertTrue(any(item.rule_id == "SP405" for item in findings))

    def test_inline_ignore_suppresses_specific_rule(self):
        source = "const app = express(); // shipproof-ignore SP401\n"
        findings = self.findings("server.js", source)
        self.assertFalse(any(item.rule_id == "SP401" for item in findings))

    def test_inline_ignore_suppresses_file_level_rule(self):
        source = "// shipproof-ignore SP408\nconst nextConfig = {};\nmodule.exports = nextConfig;\n"
        findings = self.findings("next.config.js", source)
        self.assertFalse(any(item.rule_id == "SP408" for item in findings))

    def test_insecure_secret_fallback_default_is_flagged(self):
        source = (
            "JWT_"
            + "SECRET = "
            + "os."
            + "getenv("
            + '"JWT_'
            + 'SECRET", "dev_secret_key_12345")\n'
        )
        findings = self.findings("app.py", source)
        self.assertTrue(any(item.rule_id == "SP004" for item in findings))

    def test_ssrf_metadata_is_flagged(self):
        source = 'response = requests.get("http://' + '169.254.169.254/latest/meta-data")\n'
        findings = self.findings("app.py", source)
        self.assertTrue(any(item.rule_id == "SP109" for item in findings))

    def test_path_traversal_is_flagged(self):
        source = 'with open(f"/uploads/' + '{user_filename}", "rb") as f:\n    data = f.read()\n'
        findings = self.findings("app.py", source)
        self.assertTrue(any(item.rule_id == "SP110" for item in findings))

    def test_secret_logging_is_flagged(self):
        source = "logger." + 'info(f"User login attempt: ' + '{user.password}")\n'
        findings = self.findings("app.py", source)
        self.assertTrue(any(item.rule_id == "SP204" for item in findings))

    def test_unbounded_concurrency_is_flagged(self):
        source = (
            "const results = await Promise." + "all(items.map(async item => fetch(item.url)));\n"
        )
        findings = self.findings("service.js", source)
        self.assertTrue(any(item.rule_id == "SP306" for item in findings))

    def test_express_cors_wildcard_with_credentials_is_flagged(self):
        source = "app.use(cors({ origin: true, credentials: true }));\n"
        findings = self.findings("server.js", source)
        self.assertTrue(any(item.rule_id == "SP107" for item in findings))

    def test_authorized_router_inherits_authorization(self):
        source = (
            "from fastapi import APIRouter, Depends\n"
            "def require_admin(): pass\n"
            "admin_router = APIRouter(prefix='/admin', dependencies=[Depends(require_admin)])\n"
            "@admin_router.get('/users')\n"
            "def list_users(): return []\n"
        )
        findings = self.findings("admin.py", source)
        self.assertFalse(any(item.rule_id == "SP108" for item in findings))

    def test_session_instance_without_timeout_is_flagged(self):
        source = (
            "import requests\n"
            "session = requests.Session()\n"
            "response = session.get('https://example.test')\n"
        )
        findings = self.findings("client.py", source)
        self.assertTrue(any(item.rule_id == "SP304" for item in findings))

    def test_lint_source_snippet_works(self):
        from scan_repo import lint_source_snippet

        findings = lint_source_snippet("const a = 1;\n", "test.js")
        self.assertEqual(findings, [])

    def test_snippet_stdin_is_bounded_and_uses_requested_root(self):
        import contextlib
        import io
        import json
        import tempfile
        from unittest.mock import patch

        from scan_repo import MAX_SNIPPET_BYTES, main

        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with (
                patch("sys.stdin", io.StringIO("const value = 1;")),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(
                    main([directory, "--snippet-stdin", "--snippet-file", "snippet.js"]),
                    0,
                )
            self.assertEqual(Path(json.loads(output.getvalue())["root"]), Path(directory).resolve())

            with (
                patch("sys.stdin", io.StringIO("x" * (MAX_SNIPPET_BYTES + 1))),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(main([directory, "--snippet-stdin"]), 2)

            with self.assertRaises(SystemExit) as invalid:
                main([directory, "--snippet", "value", "--snippet-stdin"])
            self.assertEqual(invalid.exception.code, 2)

    def test_unmetered_ai_route_is_flagged(self):
        source = (
            "const res = await openai.chat."
            + "completions.create({ model: 'gpt-4o', messages: [] });\n"
        )
        findings = self.findings("route.js", source)
        self.assertTrue(any(item.rule_id == "SP501" for item in findings))

    def test_insecure_stripe_webhook_is_flagged(self):
        source = "const event = stripe.webhooks." + "constructEvent(req.body, sig, secret);\n"
        findings = self.findings("webhook.js", source)
        self.assertTrue(any(item.rule_id == "SP502" for item in findings))

    def test_supabase_service_role_key_leak_is_flagged(self):
        source = "const key = process.env.NEXT_PUBLIC_" + "SUPABASE_SERVICE_ROLE_KEY;\n"
        findings = self.findings("supabaseClient.ts", source)
        self.assertTrue(any(item.rule_id == "SP503" for item in findings))

    def test_serverless_prisma_non_singleton_is_flagged(self):
        source = "const prisma = new " + "PrismaClient();\n"
        findings = self.findings("route.ts", source)
        self.assertTrue(any(item.rule_id == "SP313" for item in findings))

    def test_n_plus_one_query_in_loop_is_flagged(self):
        source = (
            "for user in users:\n"
            "    profile = db.query(Profile).filter_by(user_id=user.id).first()\n"
        )
        findings = self.findings("service.py", source)
        self.assertTrue(any(item.rule_id == "SP307" for item in findings))

    def test_svg_upload_acceptance_is_flagged(self):
        source = (
            "const uploader = multer({ allowed" + 'Extensions: [".png", ".jpg", "' + '.svg"] });\n'
        )
        findings = self.findings("upload.js", source)
        self.assertTrue(any(item.rule_id == "SP112" for item in findings))

    def test_render_terminal_report_and_fix_prompts(self):
        from scan_repo import (
            detect_frameworks,
            read_source_context,
            render_explain,
            render_fix_prompts,
            render_terminal_report,
        )

        findings = self.findings("app.py", "ev" + "al('1')\n")
        stats = {"files_scanned": 1, "suppressed": 0}
        term_report = render_terminal_report(Path("."), findings, stats)
        self.assertIn("SP101", term_report)
        prompts = render_fix_prompts(Path("."), findings)
        self.assertIn("Fix SP101", prompts)
        self.assertEqual(render_fix_prompts(Path("."), []), "No findings to fix.\n")
        explain_known = render_explain("SP108")
        self.assertIn("What it detects", explain_known)
        explain_unknown = render_explain("UNKNOWN")
        self.assertIn("Unknown rule", explain_unknown)
        frameworks = detect_frameworks(Path("."))
        self.assertIsInstance(frameworks, set)
        ctx = read_source_context(Path("."), "nonexistent.py", 1)
        self.assertEqual(ctx, [])

    def test_secret_renderers_never_rehydrate_redacted_source(self):
        from scan_repo import render_terminal_report

        secret = "AKIA" + "E" * 16
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "settings.py").write_text(f'key = "{secret}"\n', encoding="utf-8")
            findings, stats = scan_repository(root)
            rendered = "\n".join(
                (
                    render_terminal_report(root, findings, stats),
                    render_fix_prompts(root, findings),
                    render_fix_prompts(root, findings, as_json=True),
                )
            )
        self.assertNotIn(secret, rendered)
        self.assertIn("REDACTED", rendered)

    def test_main_cli_execution_branches(self):
        import contextlib
        import io
        import tempfile

        from scan_repo import main

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--explain", "SP108"]), 0)
            self.assertEqual(main(["--snippet", "const a = 1;", "--snippet-file", "test.js"]), 0)
            self.assertEqual(main(["--snippet", "ev" + "al('1')", "--snippet-file", "test.js"]), 1)
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
                baseline_out = Path(f.name)
            try:
                self.assertEqual(
                    main(
                        [
                            ".",
                            "--format",
                            "json",
                            "--baseline-out",
                            str(baseline_out),
                            "--min-confidence",
                            "high",
                        ]
                    ),
                    0,
                )
                self.assertTrue(baseline_out.exists())
            finally:
                if baseline_out.exists():
                    baseline_out.unlink()

    def test_detect_frameworks_across_manifests(self):
        import tempfile

        from scan_repo import detect_frameworks

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            pkg = {
                "dependencies": {
                    "next": "14.0.0",
                    "nuxt": "3.0.0",
                    "@sveltejs/kit": "2.0.0",
                    "@remix-run/react": "2.0.0",
                    "astro": "4.0.0",
                    "vue": "3.0.0",
                    "@angular/core": "17.0.0",
                    "solid-js": "1.8.0",
                    "express": "4.18.0",
                    "fastify": "4.0.0",
                    "@nestjs/core": "10.0.0",
                    "koa": "2.0.0",
                    "hono": "3.0.0",
                    "elysia": "0.8.0",
                    "@prisma/client": "5.0.0",
                    "drizzle-orm": "0.29.0",
                    "typeorm": "0.3.0",
                    "mongoose": "8.0.0",
                    "@supabase/supabase-js": "2.0.0",
                }
            }
            (root / "package.json").write_text(json.dumps(pkg), encoding="utf-8")
            (root / "pyproject.toml").write_text(
                "dependencies = ['fastapi', 'django', 'flask', 'starlette', 'tornado', 'litestar', 'sanic', 'sqlalchemy', 'supabase']\n",
                encoding="utf-8",
            )
            (root / "go.mod").write_text(
                "module test\nrequire github.com/gin-gonic/gin v1.9.0\nrequire github.com/labstack/echo v4.0.0\nrequire github.com/gofiber/fiber v2.0.0\nrequire github.com/go-chi/chi v5.0.0\n",
                encoding="utf-8",
            )
            (root / "Cargo.toml").write_text(
                "[dependencies]\nactix-web = '4'\naxum = '0.7'\nrocket = '0.5'\n",
                encoding="utf-8",
            )
            (root / "composer.json").write_text(
                '{"require": {"laravel/framework": "^10.0", "symfony/framework-bundle": "^6.0"}}',
                encoding="utf-8",
            )
            (root / "Gemfile").write_text("gem 'rails'\ngem 'sinatra'\n", encoding="utf-8")
            (root / "pom.xml").write_text(
                "<project><dependencies><dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot</artifactId></dependency></dependencies></project>",
                encoding="utf-8",
            )
            (root / "build.gradle").write_text("plugins { id 'io.quarkus' }\n", encoding="utf-8")
            (root / "build.gradle.kts").write_text(
                "plugins { id('io.micronaut') }\n", encoding="utf-8"
            )
            (root / "Dockerfile").write_text("FROM node:20\n", encoding="utf-8")
            (root / "serverless.yml").write_text("service: test\n", encoding="utf-8")
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / "App.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk.Web"><ItemGroup><PackageReference Include="Microsoft.AspNetCore.App" /><PackageReference Include="Microsoft.EntityFrameworkCore" /></ItemGroup></Project>',
                encoding="utf-8",
            )
            (root / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.20)\n", encoding="utf-8"
            )
            (root / "Makefile").write_text("all:\n\tgcc main.c\n", encoding="utf-8")

            fw = detect_frameworks(root)
            self.assertIn("nextjs", fw)
            self.assertIn("fastapi", fw)
            self.assertIn("gin", fw)
            self.assertIn("actix", fw)
            self.assertIn("laravel", fw)
            self.assertIn("rails", fw)
            self.assertIn("springboot", fw)
            self.assertIn("dotnet", fw)
            self.assertIn("aspnetcore", fw)
            self.assertIn("entityframework", fw)
            self.assertIn("cmake", fw)
            self.assertIn("make", fw)
            self.assertIn("docker", fw)
            self.assertIn("github-actions", fw)

    def test_php_unserialize_is_flagged(self):
        findings = self.findings("handler.php", "$data = " + "un" + "serialize($_POST['data']);\n")
        self.assertEqual([f.rule_id for f in findings], ["SP113"])

    def test_redos_nested_quantifier_is_flagged(self):
        findings = self.findings("validator.js", "const regex = /(" + "a+" + ")+$/;\n")
        self.assertEqual([f.rule_id for f in findings], ["SP114"])

    def test_sqlite_database_file_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            db_path = root / "app.db"
            db_path.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)
            findings, _stats = scan_repository(root)
            self.assertIn("SP314", [f.rule_id for f in findings])

    def test_go_http_request_missing_close_is_flagged(self):
        findings = self.findings(
            "client.go", "resp, err := " + "http." + 'Get("https://example.com")\n'
        )
        self.assertEqual([f.rule_id for f in findings], ["SP315"])

    def test_http_call_inside_transaction_is_flagged(self):
        code = (
            "with "
            + "db.trans"
            + "action():\n"
            + "    "
            + "requests."
            + "post('https://api.stripe.com', timeout=5)\n"
        )
        findings = self.findings("billing.py", code)
        self.assertIn("SP316", [f.rule_id for f in findings])

    def test_blocking_call_in_async_def_is_flagged(self):
        code = (
            "async def get_data():\n"
            + "    return "
            + "requests."
            + "get('https://api.example.com', timeout=5)\n"
        )
        findings = self.findings("api.py", code)
        self.assertIn("SP317", [f.rule_id for f in findings])

    def run_git(self, root: Path, *arguments: str) -> None:
        completed = subprocess.run(  # noqa: S603 (fixed argv, PATH lookup is intended)
            ["git", "-C", str(root), *arguments],  # noqa: S607 (git resolved from PATH by design)
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            completed.returncode,
            0,
            f"git {' '.join(arguments)} failed: {completed.stderr}",
        )

    def test_changed_since_limits_scan_to_changed_and_untracked_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "committed.py").write_text("app = FastAPI(de" + "bug=True)\n", encoding="utf-8")
            self.run_git(root, "init", "-q")
            self.run_git(root, "config", "user.email", "shipproof@example.test")
            self.run_git(root, "config", "user.name", "ShipProof Test")
            self.run_git(root, "add", "-A")
            self.run_git(root, "commit", "-q", "-m", "base")
            (root / "modified.py").write_text(
                'import requests\nrequests.get("https://api.invalid")\n',
                encoding="utf-8",
            )
            include_paths = changed_files(root, "HEAD")
            self.assertEqual(include_paths, frozenset({"modified.py"}))
            findings, stats = scan_repository(root, include_paths=include_paths)
            self.assertEqual(stats["files_scanned"], 1)
            self.assertTrue(any(item.rule_id == "SP304" for item in findings))
            self.assertFalse(any(item.rule_id == "SP201" for item in findings))

    def test_changed_since_handles_unicode_paths_and_subdirectory_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "pkg"
            package.mkdir()
            unicode_file = package / "ทดสอบ.py"
            unicode_file.write_text("value = 1\n", encoding="utf-8")
            self.run_git(root, "init", "-q")
            self.run_git(root, "config", "user.email", "shipproof@example.test")
            self.run_git(root, "config", "user.name", "ShipProof Test")
            self.run_git(root, "add", "-A")
            self.run_git(root, "commit", "-q", "-m", "base")
            unicode_file.write_text("app = FastAPI(debug=" + "True)\n", encoding="utf-8")

            include_paths = changed_files(package, "HEAD")
            self.assertEqual(include_paths, frozenset({"ทดสอบ.py"}))
            findings, stats = scan_repository(package, include_paths=include_paths)
            self.assertEqual(stats["files_scanned"], 1)
            self.assertIn("SP201", [item.rule_id for item in findings])

    def test_changed_since_reports_renamed_and_copied_destinations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rename_source = root / "rename_source.py"
            copy_source = root / "copy_source.py"
            rename_source.write_text("def renamed_fixture():\n    return 1\n", encoding="utf-8")
            copy_source.write_text("def copied_fixture():\n    return 2\n", encoding="utf-8")
            self.run_git(root, "init", "-q")
            self.run_git(root, "config", "user.email", "shipproof@example.test")
            self.run_git(root, "config", "user.name", "ShipProof Test")
            self.run_git(root, "add", "-A")
            self.run_git(root, "commit", "-q", "-m", "base")

            rename_source.rename(root / "renamed.py")
            (root / "copied.py").write_text(
                copy_source.read_text(encoding="utf-8"), encoding="utf-8"
            )

            self.assertEqual(changed_files(root, "HEAD"), frozenset({"renamed.py", "copied.py"}))

    def test_changed_since_reports_the_ref_in_stats(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            self.run_git(root, "init", "-q")
            self.run_git(root, "config", "user.email", "shipproof@example.test")
            self.run_git(root, "config", "user.name", "ShipProof Test")
            self.run_git(root, "add", "-A")
            self.run_git(root, "commit", "-q", "-m", "base")
            with (
                patch(
                    "sys.argv",
                    ["scan_repo.py", str(root), "--changed-since", "HEAD", "--format", "json"],
                ),
                patch("sys.stdout") as mock_stdout,
            ):
                self.assertEqual(main(), 0)
            printed = "".join(call.args[0] for call in mock_stdout.write.call_args_list)
            self.assertIn('"changed_since": "HEAD"', printed.replace("'", '"'))

    def test_changed_since_fails_closed_outside_git_repository(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("sys.argv", ["scan_repo.py", directory, "--changed-since", "HEAD"]),
            patch("sys.stderr"),
        ):
            self.assertEqual(main(), 2)

    def test_changed_since_rejects_option_shaped_refs(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            self.assertRaisesRegex(ValueError, "invalid git ref"),
        ):
            changed_files(Path(directory), "--upload-pack=malicious")

    # --- Rule Factory corpus: each detector ships positive, negative, and
    # --- adversarial cases. Adversarial cases record the evasions the current
    # --- engine cannot see yet, so future engine work has a fixed target.

    def test_lxml_without_hardened_parser_is_flagged(self):
        source = (
            "from lxml import " + "etree\n" + "root = " + "etree.from" + "string(xml_payload)\n"
        )
        findings = self.findings("parser.py", source)
        self.assertIn("SP115", [f.rule_id for f in findings])

    def test_lxml_with_hardened_parser_is_not_flagged(self):
        source = (
            "from lxml import etree\n"
            "parser = etree.XMLParser(resolve_entities=False)\n"
            "root = etree.fromstring(xml_payload, parser)\n"
        )
        findings = self.findings("parser.py", source)
        self.assertNotIn("SP115", [f.rule_id for f in findings])

    def test_lxml_alias_import_evades_detection(self):
        # Known limitation: resolving `import ... as` aliases needs import tracking.
        source = "from lxml import etree as ET\nroot = ET.fromstring(xml_payload)\n"
        findings = self.findings("parser.py", source)
        self.assertNotIn("SP115", [f.rule_id for f in findings])

    def test_dynamic_dangerously_set_inner_html_is_flagged(self):
        source = "const el = { dangerously" + "SetInnerHTML: { __html: userBio } };\n"
        findings = self.findings("profile.jsx", source)
        self.assertIn("SP116", [f.rule_id for f in findings])

    def test_static_dangerously_set_inner_html_is_not_flagged(self):
        source = 'const el = { dangerouslySetInnerHTML: { __html: "<b>ok</b>" } };\n'
        findings = self.findings("profile.jsx", source)
        self.assertNotIn("SP116", [f.rule_id for f in findings])

    def test_sanitized_wrapper_still_flagged_for_review(self):
        source = "const el = { dangerouslySetInnerHTML: { __html: sanitize(userBio) } };\n"
        findings = self.findings("profile.jsx", source)
        self.assertIn("SP116", [f.rule_id for f in findings])

    def test_new_function_is_flagged(self):
        source = "const fn = new " + "Function('return 1')\n"
        findings = self.findings("plugin.js", source)
        self.assertIn("SP117", [f.rule_id for f in findings])

    def test_new_function_alias_evades_detection(self):
        # Known limitation: `const F = Function; F(...)` needs call-graph analysis.
        source = "const F = Function;\nconst fn = F('return 1');\n"
        findings = self.findings("plugin.js", source)
        self.assertNotIn("SP117", [f.rule_id for f in findings])

    def test_timer_string_is_flagged(self):
        source = "set" + 'Timeout("refresh()", 500);\n'
        findings = self.findings("widget.js", source)
        self.assertIn("SP118", [f.rule_id for f in findings])

    def test_timer_function_callback_is_not_flagged(self):
        source = "setTimeout(refresh, 500);\n"
        findings = self.findings("widget.js", source)
        self.assertNotIn("SP118", [f.rule_id for f in findings])

    def test_path_join_from_request_is_flagged(self):
        source = "const full = path" + ".join(uploadDir, re" + "q.params.filename);\n"
        findings = self.findings("files.js", source)
        self.assertIn("SP119", [f.rule_id for f in findings])

    def test_path_join_from_config_is_not_flagged(self):
        source = "const full = path.join(uploadDir, config.defaultName);\n"
        findings = self.findings("files.js", source)
        self.assertNotIn("SP119", [f.rule_id for f in findings])

    def test_multiline_path_join_evades_detection(self):
        # Known limitation: request data flows in on the next line; needs data flow.
        source = (
            "const parts = req.params.name.split('/');\n"
            "const full = path.join(uploadDir,\n"
            "  ...parts);\n"
        )
        findings = self.findings("files.js", source)
        self.assertNotIn("SP119", [f.rule_id for f in findings])

    def test_node_serialize_unserialize_is_flagged(self):
        source = (
            "const ser = require('node-"
            + "serialize');\n"
            + "const obj = ser.unseri"
            + "alize(payload);\n"
        )
        findings = self.findings("legacy.js", source)
        self.assertIn("SP120", [f.rule_id for f in findings])

    def test_json_parse_is_not_flagged_as_deserialization(self):
        source = "const obj = JSON.parse(payload);\n"
        findings = self.findings("legacy.js", source)
        self.assertNotIn("SP120", [f.rule_id for f in findings])

    def test_dynamic_require_of_node_serialize_evades_detection(self):
        # Known limitation: computed require expressions need constant analysis.
        source = "const ser = require('node-' + 'serialize');\n"
        findings = self.findings("legacy.js", source)
        self.assertNotIn("SP120", [f.rule_id for f in findings])

    def test_redirect_from_request_is_flagged(self):
        js = "res.redi" + "rect(re" + "q.query.next);\n"
        py = "return redi" + "rect(request.args.get('next'))\n"
        self.assertIn("SP121", [f.rule_id for f in self.findings("auth.js", js)])
        self.assertIn("SP121", [f.rule_id for f in self.findings("auth.py", py)])

    def test_static_redirect_is_not_flagged(self):
        source = 'res.redirect("/dashboard");\n'
        findings = self.findings("auth.js", source)
        self.assertNotIn("SP121", [f.rule_id for f in findings])

    def test_indirect_redirect_target_evades_detection(self):
        # Known limitation: the request value is assigned on an earlier line.
        source = "const target = req.query.next;\nres.redirect(target);\n"
        findings = self.findings("auth.js", source)
        self.assertNotIn("SP121", [f.rule_id for f in findings])

    def test_security_value_from_insecure_randomness_is_flagged(self):
        js = "const apiToken = Math" + ".random().toString(36);\n"
        py = "session_token = random" + ".random()\n"
        self.assertIn("SP122", [f.rule_id for f in self.findings("token.js", js)])
        self.assertIn("SP122", [f.rule_id for f in self.findings("token.py", py)])

    def test_security_value_from_secrets_module_is_not_flagged(self):
        source = "session_token = secrets.token_hex(32)\n"
        findings = self.findings("token.py", source)
        self.assertNotIn("SP122", [f.rule_id for f in findings])

    def test_randomness_behind_helper_evades_detection(self):
        # Known limitation: the security-named variable never shares a line with
        # the PRNG call; needs data flow.
        source = (
            "const t = makeToken();\nfunction makeToken() { return Math.random().toString(36); }\n"
        )
        findings = self.findings("token.js", source)
        self.assertNotIn("SP122", [f.rule_id for f in findings])

    def test_hardcoded_cipher_iv_is_flagged(self):
        js = "const cipher = crypto.createCipher" + "iv('aes-256-cbc', key, '1234567890123456');\n"
        py = "cipher = AES" + ".new(key, AES.MODE_CBC, iv=b'1234567890123456')\n"
        self.assertIn("SP123", [f.rule_id for f in self.findings("vault.js", js)])
        self.assertIn("SP123", [f.rule_id for f in self.findings("vault.py", py)])

    def test_random_cipher_iv_is_not_flagged(self):
        source = (
            "const iv = crypto.randomBytes(16);\n"
            "const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);\n"
        )
        findings = self.findings("vault.js", source)
        self.assertNotIn("SP123", [f.rule_id for f in findings])

    def test_iv_from_constant_evades_detection(self):
        # Known limitation: the literal moved into a constant; needs constant tracking.
        source = (
            "const FIXED_IV = '1234567890123456';\n"
            "const cipher = crypto.createCipheriv('aes-256-cbc', key, FIXED_IV);\n"
        )
        findings = self.findings("vault.js", source)
        self.assertNotIn("SP123", [f.rule_id for f in findings])

    def test_fetch_of_request_url_is_flagged(self):
        source = "const response = await fe" + "tch(`https://${re" + "q.query.host}/api`);\n"
        findings = self.findings("proxy.js", source)
        self.assertIn("SP124", [f.rule_id for f in findings])

    def test_fetch_of_configured_url_is_not_flagged(self):
        source = 'const response = await fetch(config.apiUrl + "/health");\n'
        findings = self.findings("proxy.js", source)
        self.assertNotIn("SP124", [f.rule_id for f in findings])

    def test_indirect_fetch_url_evades_detection(self):
        # Known limitation: the URL is assigned on an earlier line.
        source = "const target = req.query.url;\nconst response = await fetch(target);\n"
        findings = self.findings("proxy.js", source)
        self.assertNotIn("SP124", [f.rule_id for f in findings])

    def test_unbounded_tenacity_retry_is_flagged(self):
        source = (
            "from tenacity import retry, wait_fixed\n"
            "\n"
            "@retry(wait=wait_fixed(1))\n"
            "def call_upstream(): ...\n"
        )
        findings = self.findings("client.py", source)
        self.assertIn("SP318", [f.rule_id for f in findings])

    def test_bounded_tenacity_retry_is_not_flagged(self):
        source = (
            "from tenacity import retry, stop_after_attempt\n"
            "\n"
            "@retry(stop=stop_after_attempt(3))\n"
            "def call_upstream(): ...\n"
        )
        findings = self.findings("client.py", source)
        self.assertNotIn("SP318", [f.rule_id for f in findings])

    def test_infinite_js_retries_are_flagged(self):
        source = "axiosRetry(axios, { retries: " + "Infinity });\n"
        findings = self.findings("client.js", source)
        self.assertIn("SP318", [f.rule_id for f in findings])

    def test_manual_infinite_retry_loop_evades_detection(self):
        # Known limitation: hand-rolled while-true retry needs loop analysis.
        source = "while (true) {\n  try { return doCall(); } catch (e) { await sleep(10); }\n}\n"
        findings = self.findings("client.js", source)
        self.assertNotIn("SP318", [f.rule_id for f in findings])

    # --- Wave 3: language-focused detectors (SP125-SP136) ---

    def test_angular_sanitizer_bypass_is_flagged(self):
        source = "this.trusted = sanitizer.by" + "passSecurityTrustHtml(userBio);\n"
        findings = self.findings("profile.component.ts", source)
        self.assertIn("SP125", [f.rule_id for f in findings])

    def test_angular_sanitized_rendering_is_not_flagged(self):
        source = "this.safe = sanitizer.sanitize(SecurityContext.HTML, userBio);\n"
        findings = self.findings("profile.component.ts", source)
        self.assertNotIn("SP125", [f.rule_id for f in findings])

    def test_angular_method_alias_evades_detection(self):
        # Known limitation: computed member access needs constant folding; a
        # direct reference to the bypass method is always caught by name.
        source = 'const kind = "Html";\nthis.trusted = sanitizer["bypassSecurityTrust" + kind](userBio);\n'
        findings = self.findings("profile.component.ts", source)
        self.assertNotIn("SP125", [f.rule_id for f in findings])

    def test_token_in_web_storage_is_flagged(self):
        source = "local" + "Storage.setItem('authToken', jwt);\n"
        findings = self.findings("auth.ts", source)
        self.assertIn("SP126", [f.rule_id for f in findings])

    def test_ui_preference_in_web_storage_is_not_flagged(self):
        source = "localStorage.setItem('theme', mode);\n"
        findings = self.findings("prefs.ts", source)
        self.assertNotIn("SP126", [f.rule_id for f in findings])

    def test_dynamic_storage_key_evades_detection(self):
        # Known limitation: key computed at runtime needs data flow.
        source = "storage.setItem(keyName, value);\n"
        findings = self.findings("prefs.ts", source)
        self.assertNotIn("SP126", [f.rule_id for f in findings])

    def test_php_loose_credential_comparison_is_flagged(self):
        source = "<?php\nif ($password " + "== $input) { }\n"
        findings = self.findings("login.php", source)
        self.assertIn("SP127", [f.rule_id for f in findings])

    def test_php_strict_credential_comparison_is_not_flagged(self):
        source = "<?php\nif ($password === $hash) { }\n"
        findings = self.findings("login.php", source)
        self.assertNotIn("SP127", [f.rule_id for f in findings])

    def test_php_interpolated_sql_is_flagged(self):
        source = '<?php\nmysqli_query($db, "SEL' + "ECT * FROM users WHERE id = " + '$user_id");\n'
        findings = self.findings("users.php", source)
        self.assertIn("SP128", [f.rule_id for f in findings])

    def test_php_prepared_statement_is_not_flagged(self):
        source = "<?php\n$stmt = $db->prepare('SELECT * FROM users WHERE id = ?');\n"
        findings = self.findings("users.php", source)
        self.assertNotIn("SP128", [f.rule_id for f in findings])

    def test_php_indirect_query_build_evades_detection(self):
        # Known limitation: SQL assembled into a variable first needs data flow.
        source = (
            "<?php\n$q = 'SEL"
            + "ECT * FROM t WHERE x=' . $_G"
            + "ET['x'];\nmysqli_query($db, $q);\n"
        )
        findings = self.findings("users.php", source)
        self.assertNotIn("SP128", [f.rule_id for f in findings])

    def test_php_echoed_superglobal_is_flagged(self):
        source = "<?php\necho $_G" + "ET['name'];\n"
        findings = self.findings("greet.php", source)
        self.assertIn("SP129", [f.rule_id for f in findings])

    def test_php_escaped_output_is_not_flagged(self):
        source = "<?php\necho htmlspecialchars($_GET['name']);\n"
        findings = self.findings("greet.php", source)
        self.assertNotIn("SP129", [f.rule_id for f in findings])

    def test_php_location_redirect_from_request_is_flagged(self):
        source = "<?php\nheader('Location: ' . $_G" + "ET['next']);\n"
        findings = self.findings("redirect.php", source)
        self.assertIn("SP130", [f.rule_id for f in findings])

    def test_php_static_location_header_is_not_flagged(self):
        source = "<?php\nheader('Location: /dashboard');\n"
        findings = self.findings("redirect.php", source)
        self.assertNotIn("SP130", [f.rule_id for f in findings])

    def test_go_http_server_without_timeouts_is_flagged(self):
        source = "srv := &http.Ser" + "ver{Addr: ':8080'}\n"
        findings = self.findings("server.go", source)
        self.assertIn("SP131", [f.rule_id for f in findings])

    def test_go_http_server_with_timeouts_is_not_flagged(self):
        source = "srv := &http.Server{Addr: ':8080', ReadTimeout: 5 * time.Second}\n"
        findings = self.findings("server.go", source)
        self.assertNotIn("SP131", [f.rule_id for f in findings])

    def test_dotnet_sync_over_async_is_flagged(self):
        source = "var result = GetDataAsync().GetA" + "waiter().GetResult();\n"
        findings = self.findings("api.cs", source)
        self.assertIn("SP132", [f.rule_id for f in findings])

    def test_dotnet_await_is_not_flagged(self):
        source = "var result = await GetDataAsync();\n"
        findings = self.findings("api.cs", source)
        self.assertNotIn("SP132", [f.rule_id for f in findings])

    def test_aspnet_debug_true_is_flagged(self):
        source = "<compilation debug=" + '"true" />\n'
        findings = self.findings("web.config", source)
        self.assertIn("SP133", [f.rule_id for f in findings])

    def test_aspnet_debug_false_is_not_flagged(self):
        source = '<compilation debug="false" />\n'
        findings = self.findings("web.config", source)
        self.assertNotIn("SP133", [f.rule_id for f in findings])

    def test_assert_as_authorization_is_flagged(self):
        source = "assert user.is_ad" + "min\n"
        findings = self.findings("admin.py", source)
        self.assertIn("SP134", [f.rule_id for f in findings])

    def test_explicit_authorization_check_is_not_flagged(self):
        source = "if not user.is_admin:\n    raise HTTPException(403)\n"
        findings = self.findings("admin.py", source)
        self.assertNotIn("SP134", [f.rule_id for f in findings])

    def test_unbounded_c_string_function_is_flagged(self):
        source = "str" + "cpy(dst, user_input);\n"
        findings = self.findings("legacy.c", source)
        self.assertIn("SP135", [f.rule_id for f in findings])

    def test_bounded_c_string_function_is_not_flagged(self):
        source = 'snprintf(dst, sizeof(dst), "%s", user_input);\n'
        findings = self.findings("legacy.c", source)
        self.assertNotIn("SP135", [f.rule_id for f in findings])

    def test_go_discarded_error_is_flagged(self):
        source = "result, err := doThing()\n" + "_, _ " + "= result, err\n"
        findings = self.findings("store.go", source)
        self.assertIn("SP136", [f.rule_id for f in findings])

    def test_go_handled_error_is_not_flagged(self):
        source = "result, err := doThing()\nif err != nil {\n    return err\n}\n"
        findings = self.findings("store.go", source)
        self.assertNotIn("SP136", [f.rule_id for f in findings])

    def test_scope_determination_and_downranking_for_test_paths(self):
        source = "app = FastAPI(de" + "bug=True)\n"
        test_finding = self.findings("tests/test_api.py", source)[0]
        self.assertEqual(test_finding.scope, "test")
        self.assertEqual(test_finding.confidence, "medium")

        app_finding = self.findings("src/api.py", source)[0]
        self.assertEqual(app_finding.scope, "app")
        self.assertEqual(app_finding.confidence, "high")

    def test_ruby_deserialization_is_flagged(self):
        marshal_source = "data = Marshal." + "load(user_input)\n"
        yaml_source = "config = YAML." + "unsafe_load(raw_yaml)\n"
        self.assertIn("SP106", [f.rule_id for f in self.findings("app.rb", marshal_source)])
        self.assertIn("SP106", [f.rule_id for f in self.findings("app.rb", yaml_source)])

    def test_intraprocedural_python_taint_is_flagged_with_l2(self):
        code = (
            "def handle_query(user_id):\n"
            '    sql = f"SELECT * FROM users WHERE id = {user_id}"\n'
            "    cursor.execute(sql)\n"
        )
        findings = self.findings("service.py", code)
        sp103 = next(f for f in findings if f.rule_id == "SP103")
        self.assertEqual(sp103.detection, "taint")
        self.assertEqual(sp103.proof_level, "L2")

    def test_github_annotations_formatting(self):
        finding = self.findings("server.py", "app = FastAPI(de" + "bug=True)\n")[0]
        annotations = render_github_annotations([finding])
        self.assertIn("::error file=server.py,line=1,title=SP201", annotations)

    def test_explain_and_fix_prompt_json_formats(self):
        explain_json = json.loads(render_explain("SP106", as_json=True))
        self.assertEqual(explain_json["rule_id"], "SP106")
        self.assertIn("why", explain_json)
        self.assertIn("attack", explain_json)

        finding = self.findings("server.py", "app = FastAPI(de" + "bug=True)\n")[0]
        fix_prompts_json = json.loads(render_fix_prompts(Path("."), [finding], as_json=True))
        self.assertEqual(len(fix_prompts_json), 1)
        self.assertEqual(fix_prompts_json[0]["rule_id"], "SP201")
        self.assertIn("Fix SP201 in server.py", fix_prompts_json[0]["prompt"])

    def test_progressive_context_is_bounded_and_monotonic(self):
        explain = {
            level: json.loads(render_explain("SP106", as_json=True, context_level=level))
            for level in ("summary", "overview", "full")
        }
        self.assertNotIn("why", explain["summary"])
        self.assertIn("why", explain["overview"])
        self.assertNotIn("attack", explain["overview"])
        self.assertIn("attack", explain["full"])
        self.assertLess(len(json.dumps(explain["summary"])), len(json.dumps(explain["overview"])))
        self.assertLess(len(json.dumps(explain["overview"])), len(json.dumps(explain["full"])))

        finding = self.findings("server.py", "app = FastAPI(de" + "bug=True)\n")[0]
        prompts = {
            level: json.loads(
                render_fix_prompts(Path("."), [finding], as_json=True, context_level=level)
            )[0]
            for level in ("summary", "overview", "full")
        }
        self.assertNotIn("evidence", prompts["summary"])
        self.assertIn("implicit_requirements", prompts["overview"])
        self.assertNotIn("failure_scenarios", prompts["overview"])
        self.assertIn("failure_scenarios", prompts["full"])

    def test_decision_trace_is_content_free_and_matches_gate(self):
        finding = self.findings("server.py", "app = FastAPI(de" + "bug=True)\n")[0]
        trace = build_decision_trace(
            [finding],
            {"files_scanned": 1, "suppressed": 2, "frameworks": ["fastapi"]},
            fail_on="high",
            include_tests=False,
            max_file_bytes=1_000_000,
            min_confidence="medium",
            exclude_patterns=["vendor/**", "vendor/**"],
            baseline_fingerprints=2,
            changed_candidates=None,
            findings_before_confidence_filter=1,
        )
        encoded = json.dumps(trace)
        self.assertTrue(trace["gate"]["failed"])
        self.assertEqual(trace["selection"]["exclude_patterns"], 1)
        self.assertNotIn("server.py", encoded)
        self.assertNotIn("SP201", encoded)

    def test_trace_cli_contract_and_invalid_combinations(self):
        import contextlib
        import io

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "safe.js").write_text("const value = 1;\n", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(
                    main([str(root), "--format", "json", "--fail-on", "none", "--trace"]),
                    0,
                )
            report = json.loads(output.getvalue())
            self.assertEqual(report["decision_trace"]["selection"]["files_scanned"], 1)

        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            self.assertEqual(main(["--context-level", "summary"]), 2)
            self.assertEqual(main(["--trace", "--format", "sarif"]), 2)
        self.assertIn("--context-level requires", errors.getvalue())
        self.assertIn("--trace is supported only", errors.getvalue())

    def test_gcp_service_account_private_key_is_flagged(self):
        source = (
            '{"type": "service_account", "project_id": "demo", "private_key": "-----BEGIN '
            + "PRIVATE KEY-----"
            + '\\nMIIEvgIBADANBgk..."}'
        )
        findings = self.findings("gcp-key.json", source)
        self.assertIn("SP005", [f.rule_id for f in findings])

    def test_safe_json_config_is_not_flagged_as_gcp_key(self):
        source = '{"type": "service_account", "project_id": "demo", "client_email": "sa@demo.iam.gserviceaccount.com"}'
        findings = self.findings("config.json", source)
        self.assertNotIn("SP005", [f.rule_id for f in findings])

    def test_github_pat_token_is_flagged(self):
        source = "token = 'gh" + "p_123456789012345678901234567890123456'\n"
        findings = self.findings("deploy.py", source)
        self.assertIn("SP006", [f.rule_id for f in findings])

    def test_normal_github_repo_slug_is_not_flagged_as_pat(self):
        source = "const repo = 'github/ghp_action_repo';\n"
        findings = self.findings("deploy.js", source)
        self.assertNotIn("SP006", [f.rule_id for f in findings])

    def test_zip_slip_extractall_is_flagged(self):
        source = (
            "with zipfile.ZipFile('archive.zip') as zip_ref:\n    zip_ref."
            + "extractall('/tmp/dest')\n"
        )
        findings = self.findings("extractor.py", source)
        self.assertIn("SP111", [f.rule_id for f in findings])

    def test_safe_archive_member_extraction_is_not_flagged(self):
        source = "for member in zip_file.infolist():\n    if not member.filename.startswith('/'):\n        zip_file.extract(member, '/tmp/dest')\n"
        findings = self.findings("safe_extractor.py", source)
        self.assertNotIn("SP111", [f.rule_id for f in findings])

    def test_ssti_dynamic_render_template_string_is_flagged(self):
        source = "return render_template_" + "string(f'Hello {username}')\n"
        findings = self.findings("views.py", source)
        self.assertIn("SP137", [f.rule_id for f in findings])

    def test_safe_template_render_with_context_is_not_flagged(self):
        source = "return render_template('hello.html', username=username)\n"
        findings = self.findings("views.py", source)
        self.assertNotIn("SP137", [f.rule_id for f in findings])

    def test_timing_attack_signature_comparison_is_flagged(self):
        source = "if received_" + "signature == " + "expected_sig:\n    proceed()\n"
        findings = self.findings("auth.py", source)
        self.assertIn("SP138", [f.rule_id for f in findings])

    def test_constant_time_signature_comparison_is_not_flagged(self):
        source = "if hmac.compare_digest(received_signature, expected_sig):\n    proceed()\n"
        findings = self.findings("auth.py", source)
        self.assertNotIn("SP138", [f.rule_id for f in findings])

    def test_insecure_tempfile_mktemp_is_flagged(self):
        source = "temp_path = tempfile." + "mktemp()\n"
        findings = self.findings("utils.py", source)
        self.assertIn("SP139", [f.rule_id for f in findings])

    def test_secure_named_temporary_file_is_not_flagged(self):
        source = "with tempfile.NamedTemporaryFile() as tmp:\n    tmp.write(b'data')\n"
        findings = self.findings("utils.py", source)
        self.assertNotIn("SP139", [f.rule_id for f in findings])

    def test_unbounded_global_cache_is_flagged(self):
        source = "global " + "USER_CACHE\nUSER_CACHE = {}\n"
        findings = self.findings("cache.py", source)
        self.assertIn("SP308", [f.rule_id for f in findings])

    def test_bounded_lru_cache_decorator_is_not_flagged(self):
        source = "@functools.lru_cache(maxsize=128)\ndef get_user(uid):\n    return db.get(uid)\n"
        findings = self.findings("cache.py", source)
        self.assertNotIn("SP308", [f.rule_id for f in findings])

    def test_goroutine_without_context_is_flagged(self):
        source = "go " + "func() {\n    doBackgroundWork()\n}()\n"
        findings = self.findings("worker.go", source)
        self.assertIn("SP309", [f.rule_id for f in findings])

    def test_goroutine_with_explicit_function_and_context_is_not_flagged(self):
        source = "go runWorkerWithContext(ctx, jobQueue)\n"
        findings = self.findings("worker.go", source)
        self.assertNotIn("SP309", [f.rule_id for f in findings])

    def test_busy_wait_spin_loop_is_flagged(self):
        source = "while " + "True:\n    pass\n"
        findings = self.findings("poller.py", source)
        self.assertIn("SP310", [f.rule_id for f in findings])

    def test_loop_with_sleep_backoff_is_not_flagged(self):
        source = "while True:\n    time.sleep(1)\n    check_status()\n"
        findings = self.findings("poller.py", source)
        self.assertNotIn("SP310", [f.rule_id for f in findings])

    def test_event_emitter_in_request_scope_is_flagged(self):
        source = "app.get('/stream', (req, res) => {\n    req." + "on('data', chunk => {});\n});\n"
        findings = self.findings("routes.js", source)
        self.assertIn("SP311", [f.rule_id for f in findings])

    def test_event_emitter_top_level_listener_is_not_flagged(self):
        source = "process.on('SIGTERM', () => { shutdown(); });\n"
        findings = self.findings("server.js", source)
        self.assertNotIn("SP311", [f.rule_id for f in findings])

    def test_retry_loop_without_backoff_is_flagged(self):
        source = "try:\n    call_api()\nexcept Exception:\n    time." + "sleep(0)\n"
        findings = self.findings("client.py", source)
        self.assertIn("SP312", [f.rule_id for f in findings])

    def test_retry_with_exponential_backoff_is_not_flagged(self):
        source = "try:\n    call_api()\nexcept Exception:\n    time.sleep(2 ** attempt)\n"
        findings = self.findings("client.py", source)
        self.assertNotIn("SP312", [f.rule_id for f in findings])

    def test_stripe_payment_missing_idempotency_is_flagged(self):
        source = "charge = stripe.charges." + "create(amount=2000, currency='usd')\n"
        findings = self.findings("billing.py", source)
        self.assertIn("SP504", [f.rule_id for f in findings])

    def test_stripe_payment_with_idempotency_key_is_not_flagged(self):
        source = "charge = stripe.charges.create(amount=2000, currency='usd', idempotency_key='order_123')\n"
        findings = self.findings("billing.py", source)
        self.assertNotIn("SP504", [f.rule_id for f in findings])

    def test_shannon_entropy_high_entropy_secret(self):
        source = 'token = "xoxb-' + '987654321012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"\n'
        findings = self.findings("config.py", source)
        self.assertTrue(any(f.rule_id == "SP008" and f.confidence == "high" for f in findings))

    def test_shannon_entropy_low_entropy_secret_downranked(self):
        source = "api_" + 'key = "' + "1" * 32 + '"\n'
        findings = self.findings("config.py", source)
        sp003_findings = [f for f in findings if f.rule_id == "SP003"]
        if sp003_findings:
            self.assertEqual(sp003_findings[0].confidence, "low")

    def test_taint_tracking_user_input_to_sql_execute(self):
        source = (
            "def handle(request):\n    user_id = request.args['id']\n    cursor.execute(user_id)\n"
        )
        findings = self.findings("views.py", source)
        taint_findings = [f for f in findings if f.rule_id == "SP103" and f.detection == "taint"]
        self.assertTrue(len(taint_findings) > 0)

    def test_taint_tracking_sanitized_input_not_flagged_as_taint(self):
        source = "def handle(request):\n    user_id = int(request.args['id'])\n    cursor.execute(user_id)\n"
        findings = self.findings("views.py", source)
        taint_findings = [f for f in findings if f.rule_id == "SP103" and f.detection == "taint"]
        self.assertEqual(len(taint_findings), 0)

    def test_import_alias_resolution_for_eval(self):
        source = "def run(code):\n    unsafe = eval\n    unsafe(code)\n"
        findings = self.findings("runner.py", source)
        self.assertTrue(any(f.rule_id == "SP101" for f in findings))

    def test_taint_tracking_command_injection_to_os_system(self):
        source = "def run_tool(request):\n    cmd = request.form['command']\n    os.system(cmd)\n"
        findings = self.findings("service.py", source)
        taint_findings = [f for f in findings if f.rule_id == "SP102" and f.detection == "taint"]
        self.assertTrue(len(taint_findings) > 0)

    def test_taint_tracking_shlex_quoted_command_clears_taint(self):
        source = "def run_tool(request):\n    cmd = shlex.quote(request.form['command'])\n    os.system(cmd)\n"
        findings = self.findings("service.py", source)
        taint_findings = [f for f in findings if f.rule_id == "SP102" and f.detection == "taint"]
        self.assertEqual(len(taint_findings), 0)

    def test_taint_tracking_uuid_sanitized_input_clears_taint(self):
        source = "def query_item(request):\n    item_id = uuid.UUID(request.args['id'])\n    cursor.execute(item_id)\n"
        findings = self.findings("db.py", source)
        taint_findings = [f for f in findings if f.rule_id == "SP103" and f.detection == "taint"]
        self.assertEqual(len(taint_findings), 0)

    def test_autofix_does_not_rewrite_calls_or_change_return_types(self):
        from scan_repo import apply_autofix_to_line

        self.assertIsNone(
            apply_autofix_to_line("SP304", "response = requests.get(build_url(user.id))")
        )
        self.assertIsNone(apply_autofix_to_line("SP122", "token = Math." + "random()"))
        self.assertIsNone(apply_autofix_to_line("SP139", "path = tempfile." + "mktemp()"))

    def test_autofix_sp104_verify_false_to_true(self):
        from scan_repo import apply_autofix_to_line

        orig = 'requests.get("https://api.example.com", verify=' + "False)"
        fixed = apply_autofix_to_line("SP104", orig)
        self.assertEqual(fixed, 'requests.get("https://api.example.com", verify=True)')

    def test_autofix_sp201_debug_true_to_false(self):
        from scan_repo import apply_autofix_to_line

        orig = "app = FastAPI(debug=" + "True)"
        fixed = apply_autofix_to_line("SP201", orig)
        self.assertEqual(fixed, "app = FastAPI(debug=False)")

    def test_autofix_exit_code_reflects_findings_that_remain(self):
        import contextlib
        import io

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "app.py"
            target.write_text(
                "import requests\n"
                "app = FastAPI(debug="
                "True)\n"
                'response = requests.get("https://api.example.invalid")\n',
                encoding="utf-8",
            )
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = main([str(root), "--fix", "--fail-on", "high"])
            self.assertEqual(exit_code, 1)
            self.assertIn("debug=False", target.read_text(encoding="utf-8"))

    def test_sp591_use_client_importing_database_client(self):
        source = '"use client";\nimport { prisma } from "@prisma/client";\nexport function Component() { return null; }'
        findings = self.findings("component.tsx", source)
        self.assertTrue(any(f.rule_id == "SP591" for f in findings))

    def test_sp592_route_handler_casting_body_to_any(self):
        source = "export async function POST(req: Request) {\n  const body = (await req.json()) as any;\n  return Response.json(body);\n}"
        findings = self.findings("route.ts", source)
        self.assertTrue(any(f.rule_id == "SP592" for f in findings))

    def test_sp593_next15_async_params_unawaited(self):
        source = "export default async function Page({ params }: { params: { id: string } }) {\n  const id = params.id;\n  return <div>{id}</div>;\n}"
        findings = self.findings("page.tsx", source)
        self.assertTrue(any(f.rule_id == "SP593" for f in findings))

    def test_sp594_authenticated_fetch_with_force_cache(self):
        source = 'export async function getUser() {\n  return fetch("https://api.internal/api/me", { cache: "force-cache" });\n}'
        findings = self.findings("api.ts", source)
        self.assertTrue(any(f.rule_id == "SP594" for f in findings))

    def test_sp595_server_action_mutation_without_revalidation(self):
        source = '"use server";\nexport async function updateItem() {\n  await prisma.user.update({ where: { id: "1" } });\n}'
        findings = self.findings("actions.ts", source)
        self.assertTrue(any(f.rule_id == "SP595" for f in findings))

    def test_sp596_client_hook_in_server_component(self):
        source = "export default function ServerPage() {\n  const [count, setCount] = useState(0);\n  return <div>{count}</div>;\n}"
        findings = self.findings("page.tsx", source)
        self.assertTrue(any(f.rule_id == "SP596" for f in findings))

    def test_sp597_server_component_waterfall_fetch(self):
        source = 'export default async function Page() {\n  const a = await fetch("https://a.com");\n  const b = await fetch("https://b.com");\n  return null;\n}'
        findings = self.findings("page.tsx", source)
        self.assertTrue(any(f.rule_id == "SP597" for f in findings))

    def test_sp598_mutating_route_handler_missing_origin_check(self):
        source = 'export async function POST(request: Request) {\n  const session = cookies().get("session");\n  return Response.json({ ok: true });\n}'
        findings = self.findings("route.ts", source)
        self.assertTrue(any(f.rule_id == "SP598" for f in findings))

    def test_sp599_typescript_non_null_assertion_on_dynamic_json(self):
        source = "async function getData() {\n  const res = await response.json();\n  const val = res.data!;\n  return val;\n}"
        findings = self.findings("client.ts", source)
        self.assertTrue(any(f.rule_id == "SP599" for f in findings))

    def test_sp600_server_action_accepting_raw_userid_for_mutation(self):
        source = '"use server";\nexport async function deleteAccount(userId: string) {\n  await prisma.user.delete({ where: { id: userId } });\n}'
        findings = self.findings("actions.ts", source)
        self.assertTrue(any(f.rule_id == "SP600" for f in findings))

    def test_sp601_llm_output_in_eval(self):
        source = "def run_ai(response):\n    " + "ex" + "ec(response.choices[0].message.content)\n"
        findings = self.findings("ai_runner.py", source)
        self.assertTrue(any(f.rule_id == "SP601" for f in findings))

    def test_sp602_llm_output_in_dangerously_set_inner_html(self):
        source = (
            "export function Output({ response }) {\n  return <div "
            + "dangerouslySetInnerHTML={{ __html: response.text }} />;\n}"
        )
        findings = self.findings("output.tsx", source)
        self.assertTrue(any(f.rule_id == "SP602" for f in findings))

    def test_sp603_unbounded_prompt_ingestion(self):
        source = (
            "export async function generate(req: Request) {\n  return "
            + "openai."
            + "chat.completions.create({ prompt: req.body });\n}"
        )
        findings = self.findings("generate.ts", source)
        self.assertTrue(any(f.rule_id == "SP603" for f in findings))

    def test_sp604_system_prompt_user_concatenation(self):
        source = (
            'const msg = { role: "system", content: "You are a helpful bot. " + ' + "req.body };"
        )
        findings = self.findings("prompt.ts", source)
        self.assertTrue(any(f.rule_id == "SP604" for f in findings))

    def test_sp605_destructive_ai_tool_definition(self):
        source = (
            'const shellTool = { name: "'
            + "execute_"
            + 'shell", description: "Runs shell commands" };'
        )
        findings = self.findings("tools.ts", source)
        self.assertTrue(any(f.rule_id == "SP605" for f in findings))

    def test_sp606_k8s_empty_resources(self):
        source = (
            "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    resources: {}\n"
        )
        findings = self.findings("pod.yaml", source)
        self.assertTrue(any(f.rule_id == "SP606" for f in findings))

    def test_sp607_k8s_privileged_true(self):
        source = (
            "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    securityContext:\n      "
            + "privileged: true\n"
        )
        findings = self.findings("pod.yaml", source)
        self.assertTrue(any(f.rule_id == "SP607" for f in findings))

    def test_sp608_k8s_readonly_rootfs_false(self):
        source = "securityContext:\n  " + "readOnlyRootFilesystem: false\n"
        findings = self.findings("deploy.yaml", source)
        self.assertTrue(any(f.rule_id == "SP608" for f in findings))

    def test_sp609_k8s_deployment_missing_probes(self):
        source = "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - name: web\n        image: nginx\n"
        findings = self.findings("deployment.yaml", source)
        self.assertTrue(any(f.rule_id == "SP609" for f in findings))

    def test_sp610_k8s_hostpath_volume(self):
        source = "volumes:\n- name: host-root\n  " + "hostPath:\n    path: /var/run/docker.sock\n"
        findings = self.findings("pod.yaml", source)
        self.assertTrue(any(f.rule_id == "SP610" for f in findings))

    def test_sp611_graphql_introspection_true(self):
        source = (
            "const server = new ApolloServer({ typeDefs, resolvers, "
            + "intro"
            + "spection: true });"
        )
        findings = self.findings("graphql.ts", source)
        self.assertTrue(any(f.rule_id == "SP611" for f in findings))

    def test_sp612_graphql_missing_depth_limit(self):
        source = "const server = new ApolloServer({ typeDefs, resolvers });"
        findings = self.findings("graphql.ts", source)
        self.assertTrue(any(f.rule_id == "SP612" for f in findings))

    def test_sp613_grpc_missing_context_timeout(self):
        source = (
            "func CallService(client pb.ServiceClient) {\n    client.NewClient("
            + "context.Background())\n}"
        )
        findings = self.findings("client.go", source)
        self.assertTrue(any(f.rule_id == "SP613" for f in findings))

    def test_sp614_grpc_insecure_credentials(self):
        source = "server := grpc.NewServer(" + "grpc." + "insecure_server_credentials())"
        findings = self.findings("server.py", source)
        self.assertTrue(any(f.rule_id == "SP614" for f in findings))

    def test_sp615_oauth_missing_state(self):
        source = (
            'const authUrl = "https://auth.provider.com/oauth/authorize?'
            + 'client_id=123&response_type=code";'
        )
        findings = self.findings("oauth.ts", source)
        self.assertTrue(any(f.rule_id == "SP615" for f in findings))

    def test_sp616_oauth_wildcard_redirect_uri(self):
        source = "if (redirect_uri.match(" + '"https://*.example.com")) { return true; }'
        findings = self.findings("auth.ts", source)
        self.assertTrue(any(f.rule_id == "SP616" for f in findings))

    def test_sp617_oauth_spa_missing_pkce(self):
        source = 'const url = "/oauth/authorize?' + 'response_type=code&client_id=spa123";'
        findings = self.findings("client.ts", source)
        self.assertTrue(any(f.rule_id == "SP617" for f in findings))

    def test_sp618_redis_set_without_ttl(self):
        source = "redisClient." + 'set("session:123", data);'
        findings = self.findings("session.ts", source)
        self.assertTrue(any(f.rule_id == "SP618" for f in findings))

    def test_sp619_kafka_auto_commit_true(self):
        source = 'const consumerConfig = { "' + "enable." + 'auto.commit": true };'
        findings = self.findings("kafka.ts", source)
        self.assertTrue(any(f.rule_id == "SP619" for f in findings))

    def test_sp620_postgres_migration_not_null_default_now(self):
        source = "ALTER TABLE users ADD COLUMN created_at TIMESTAMP NOT NULL " + "DEFAULT now();"
        findings = self.findings("migration.sql", source)
        self.assertTrue(any(f.rule_id == "SP620" for f in findings))

    def test_sp621_rust_unwrap_in_route_handler(self):
        source = (
            "async fn get_user(req: HttpRequest) -> HttpResponse {\n    let id = parse_id(&req)."
            + "unwrap();\n    HttpResponse::Ok().finish()\n}"
        )
        findings = self.findings("handler.rs", source)
        self.assertTrue(any(f.rule_id == "SP621" for f in findings))

    def test_sp622_go_defer_file_close_write(self):
        source = (
            "func SaveData(file *os.File) {\n    "
            + "defer file.Close()\n    file.WriteString('data')\n}"
        )
        findings = self.findings("writer.go", source)
        self.assertTrue(any(f.rule_id == "SP622" for f in findings))

    def test_sp623_java_jndi_dynamic_lookup(self):
        source = (
            "public void process(HttpServletRequest request) throws Exception {\n    ctx."
            + "lookup(request.getParameter('name'));\n}"
        )
        findings = self.findings("LookupService.java", source)
        self.assertTrue(any(f.rule_id == "SP623" for f in findings))

    def test_sp624_weak_prng_for_secret_token(self):
        source = "const reset_code = " + "Math.random().toString(36);"
        findings = self.findings("auth.ts", source)
        self.assertTrue(any(f.rule_id == "SP624" for f in findings))

    def test_sp625_csharp_unawaited_task_run(self):
        source = (
            "public async Task<IActionResult> PostHandler() {\n    "
            + "_ = Task.Run(() => BackgroundWork());\n    return Ok();\n}"
        )
        findings = self.findings("Controller.cs", source)
        self.assertTrue(any(f.rule_id == "SP625" for f in findings))

    def test_sp626_s3_public_wildcard_principal(self):
        source = '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}'
        findings = self.findings("policy.json", source)
        self.assertTrue(any(f.rule_id == "SP626" for f in findings))

    def test_sp627_storage_unencrypted(self):
        source = 'resource "aws_ebs_volume" "example" {\n  ' + "encrypted = " + "false\n}"
        findings = self.findings("main.tf", source)
        self.assertTrue(any(f.rule_id == "SP627" for f in findings))

    def test_sp628_security_group_open_ssh(self):
        source = (
            'resource "aws_security_group_rule" "ssh" {\n  from_port = 22\n  cidr_blocks = ["'
            + '0.0.0.0/0"]\n}'
        )
        findings = self.findings("main.tf", source)
        self.assertTrue(any(f.rule_id == "SP628" for f in findings))

    def test_sp629_iam_wildcard_action(self):
        source = '{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
        findings = self.findings("iam.json", source)
        self.assertTrue(any(f.rule_id == "SP629" for f in findings))

    def test_sp630_cloudfront_allow_all_http(self):
        source = 'viewer_protocol_policy = "' + 'allow-all"'
        findings = self.findings("cloudfront.tf", source)
        self.assertTrue(any(f.rule_id == "SP630" for f in findings))

    def test_sp631_edge_runtime_import_fs(self):
        source = 'export const runtime = "edge";\nimport fs from "node:fs";'
        findings = self.findings("route.ts", source)
        self.assertTrue(any(f.rule_id == "SP631" for f in findings))

    def test_sp632_edge_unbounded_fetch_loop(self):
        source = "for await (const k of keys) {\n  await env.KV.get(k);\n}"
        findings = self.findings("worker.ts", source)
        self.assertTrue(any(f.rule_id == "SP632" for f in findings))

    def test_sp633_edge_buffered_response(self):
        source = "const data = await response.arrayBuffer();\nreturn new Response(data);"
        findings = self.findings("worker.ts", source)
        self.assertTrue(any(f.rule_id == "SP633" for f in findings))

    def test_sp634_edge_cached_authenticated_response(self):
        source = (
            'headers.set("Cache-'
            + 'Control", "public, max-age=3600");\nconst token = cookies.get("auth");'
        )
        findings = self.findings("worker.ts", source)
        self.assertTrue(any(f.rule_id == "SP634" for f in findings))

    def test_sp635_websocket_missing_heartbeat(self):
        source = "const wss = new " + "WebSocketServer({ port: 8080 });"
        findings = self.findings("server.ts", source)
        self.assertTrue(any(f.rule_id == "SP635" for f in findings))

    def test_sp636_sse_missing_close_listener(self):
        source = (
            "res.set"
            + 'Header("Content-Type", "text/'
            + 'event-stream");\nsetInterval(() => res.write("data: 1"), 1000);'
        )
        findings = self.findings("stream.ts", source)
        self.assertTrue(any(f.rule_id == "SP636" for f in findings))

    def test_sp637_websocket_upgrade_missing_auth(self):
        source = (
            'server.on("upgrade", (req, socket, head) => {\n  wss.'
            + "handleUpgrade(req, socket, head, (ws) => {});\n});"
        )
        findings = self.findings("server.ts", source)
        self.assertTrue(any(f.rule_id == "SP637" for f in findings))

    def test_sp638_broadcast_channel_leaking(self):
        source = "const channel = new " + 'BroadcastChannel("app_events");'
        findings = self.findings("component.tsx", source)
        self.assertTrue(any(f.rule_id == "SP638" for f in findings))

    def test_sp639_symmetric_ecb_mode(self):
        source = 'const cipher = crypto.createCipheriv("' + 'des", key, null);'
        findings = self.findings("crypto.ts", source)
        self.assertTrue(any(f.rule_id == "SP639" for f in findings))

    def test_sp640_rsa_short_key(self):
        source = 'crypto.generateKeyPairSync("rsa", { ' + "modulusLength: " + "1024 });"
        findings = self.findings("keys.ts", source)
        self.assertTrue(any(f.rule_id == "SP640" for f in findings))

    def test_sp641_hardcoded_iv(self):
        source = "const " + "iv = Buffer.from('" + "0123456789abcdef0123456789abcdef', 'hex');"
        findings = self.findings("crypto.ts", source)
        self.assertTrue(any(f.rule_id == "SP641" for f in findings))

    def test_sp642_md5_hash_used(self):
        source = "const hash = crypto." + 'createHash("' + 'md5");'
        findings = self.findings("hash.ts", source)
        self.assertTrue(any(f.rule_id == "SP642" for f in findings))

    def test_sp643_timing_unsafe_signature_check(self):
        source = "if (signature =" + "== clientSig) { return true; }"
        findings = self.findings("auth.ts", source)
        self.assertTrue(any(f.rule_id == "SP643" for f in findings))

    def test_sp644_svelte_raw_html_unescaped(self):
        source = "<div>{@" + "html user_input}</div>"
        findings = self.findings("Component.svelte", source)
        self.assertTrue(any(f.rule_id == "SP644" for f in findings))

    def test_sp645_android_webview_file_url_access(self):
        source = "webSettings." + "setAllowFileAccessFromFileURLs(true);"
        findings = self.findings("MainActivity.java", source)
        self.assertTrue(any(f.rule_id == "SP645" for f in findings))

    def test_sp646_ios_urlsession_trust_all_certs(self):
        source = "completionHandler(." + "useCredential, URLCredential(trust: serverTrust))"
        findings = self.findings("APIClient.swift", source)
        self.assertTrue(any(f.rule_id == "SP646" for f in findings))

    def test_sp647_frontend_proxy_ssrf(self):
        source = "export async function POST(req) {\n  const res = await fet" + "ch(body.url);\n}"
        findings = self.findings("route.ts", source)
        self.assertTrue(any(f.rule_id == "SP647" for f in findings))

    def test_sp648_react_websocket_missing_cleanup(self):
        source = 'useEffect(() => {\n  const ws = new WebSocket("' + 'wss://api.com");\n}, []);'
        findings = self.findings("LiveFeed.tsx", source)
        self.assertTrue(any(f.rule_id == "SP648" for f in findings))

    def test_sp649_multitenant_missing_tenant_id(self):
        source = "SEL" + "ECT * FROM accounts WHERE id = :id;"
        findings = self.findings("query.sql", source)
        self.assertTrue(any(f.rule_id == "SP649" for f in findings))

    def test_sp650_recursive_json_parse(self):
        source = "function parse" + "Recursive(node) {\n  parseRecursive(node.child);\n}"
        findings = self.findings("parser.ts", source)
        self.assertTrue(any(f.rule_id == "SP650" for f in findings))


if __name__ == "__main__":
    unittest.main()
