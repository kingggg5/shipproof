from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).parents[1] / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from scan_repo import (  # noqa: E402
    VERSION,
    build_sarif_report,
    deduplicate_and_suppress_findings,
    find_python_ast_issues,
    find_regex_issues,
    is_excluded,
    iter_scannable_files,
    normalize_exclude_patterns,
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
        findings = self.findings(".env", 'API_KEY="replace_me_with_your_key"\n')
        self.assertFalse(any(item.rule_id == "SP003" for item in findings))

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
        findings = self.findings("app.py", source)
        active, suppressed = deduplicate_and_suppress_findings(findings, {findings[0].fingerprint})
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
        self.assertEqual(payload["runs"][0]["results"][0]["ruleId"], "SP101")
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
        self.assertEqual([item.rule_id for item in docker_findings], ["SP202"])

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
        fp = candidates[0].fingerprint
        active, suppressed = deduplicate_and_suppress_findings(candidates, {fp})
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

            fw = detect_frameworks(root)
            self.assertIn("nextjs", fw)
            self.assertIn("fastapi", fw)
            self.assertIn("gin", fw)
            self.assertIn("actix", fw)
            self.assertIn("laravel", fw)
            self.assertIn("rails", fw)
            self.assertIn("springboot", fw)
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


if __name__ == "__main__":
    unittest.main()
