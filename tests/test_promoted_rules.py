from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from scan_repo import (  # noqa: E402
    deduplicate_and_suppress_findings,
    find_regex_issues,
)


def detected(filename: str, source: str) -> set[str]:
    findings = find_regex_issues(Path(filename), filename, source)
    active, _ = deduplicate_and_suppress_findings(findings)
    return {finding.rule_id for finding in active}


class JwtHardcodedSecretTests(unittest.TestCase):
    def test_sign_with_string_literal_is_reported(self) -> None:
        self.assertIn(
            "SP052",
            detected("auth.ts", 'jwt.sign({ sub: user.id }, "super-secret-key-123");'),
        )

    def test_buffer_secret_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP052",
            detected("auth.ts", "jwt.sign(payload, process.env.JWT_SECRET);"),
        )


class WeakCipherTests(unittest.TestCase):
    def test_des_cipheriv_is_reported(self) -> None:
        self.assertIn(
            "SP053",
            detected("crypto.js", 'createCipheriv("des-ede3-cbc", key, iv);'),
        )

    def test_python_arc4_import_is_reported(self) -> None:
        self.assertIn("SP053", detected("legacy.py", "from Crypto.Cipher import ARC4\n"))

    def test_aes_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP053",
            detected("crypto.ts", 'createCipheriv("aes-256-gcm", key, iv);'),
        )


class ShellInterpolationTests(unittest.TestCase):
    def test_python_os_system_fstring_is_reported(self) -> None:
        self.assertIn("SP054", detected("tool.py", "os.system(f'git pull {repo}')"))

    def test_python_constant_command_is_not_reported(self) -> None:
        self.assertNotIn("SP054", detected("tool.py", "os.system('ls -la')"))

    def test_node_execsync_template_is_reported(self) -> None:
        self.assertIn("SP055", detected("deploy.js", "execSync(`git pull ${repo}`);"))

    def test_node_exec_array_is_not_reported(self) -> None:
        self.assertNotIn("SP055", detected("deploy.js", 'execFile("git", ["pull", repo]);'))


class SessionCookieFlagTests(unittest.TestCase):
    def test_missing_httponly_is_reported(self) -> None:
        source = "res.cookie('session', token, { secure: true });"
        self.assertIn("SP056", detected("login.ts", source))

    def test_httponly_present_is_not_reported(self) -> None:
        source = "res.cookie('session', token, { httpOnly: true, secure: true });"
        self.assertNotIn("SP056", detected("login.ts", source))

    def test_missing_samesite_is_reported(self) -> None:
        source = "res.cookie('session', token, { httpOnly: true });"
        self.assertIn("SP057", detected("login.ts", source))

    def test_samesite_present_is_not_reported(self) -> None:
        source = "res.cookie('session', token, { httpOnly: true, sameSite: 'lax' });"
        self.assertNotIn("SP057", detected("login.ts", source))

    def test_plain_cookie_name_is_ignored(self) -> None:
        source = "res.cookie('theme', 'dark', { maxAge: 86400000 });"
        self.assertNotIn("SP056", detected("ui.ts", source))
        self.assertNotIn("SP057", detected("ui.ts", source))


class QueryStringCredentialTests(unittest.TestCase):
    def test_url_with_api_key_is_reported(self) -> None:
        self.assertIn(
            "SP058",
            detected(
                "client.js",
                'const url = "https://api.example.com/v1/data?api_key=sk-live-123";',
            ),
        )

    def test_url_without_credential_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP058",
            detected("client.js", 'const url = "https://api.example.com/v1/data?page=2";'),
        )


class MongoOperatorInjectionTests(unittest.TestCase):
    def test_gt_from_body_is_reported(self) -> None:
        self.assertIn(
            "SP059",
            detected("login.js", "db.users.find({ user, password: { $gt: req.body.password } });"),
        )

    def test_constant_operator_is_not_reported(self) -> None:
        self.assertNotIn("SP059", detected("query.js", "db.metrics.find({ latency: { $gt: 0 } });"))


class ExpertCatalogPromotionsTests(unittest.TestCase):
    def test_php_dynamic_include_is_reported(self) -> None:
        self.assertIn("SP060", detected("page.php", "include($_GET['page']);"))
        self.assertIn("SP060", detected("page.php", "require $tpl . '.php';"))

    def test_static_include_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP060", detected("app.php", "require_once __DIR__ . '/vendor/autoload.php';")
        )

    def test_python_bare_except_is_reported(self) -> None:
        self.assertIn("SP061", detected("svc.py", "try:\n    run()\nexcept: pass"))

    def test_python_typed_except_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP061", detected("svc.py", "try:\n    run()\nexcept ValueError as e: log(e)")
        )

    def test_preg_replace_e_modifier_is_reported(self) -> None:
        self.assertIn(
            "SP062",
            detected("render.php", "preg_replace('/<b>(.*?)<\\/b>/e', $fn, $html);"),
        )

    def test_plain_preg_replace_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP062",
            detected("render.php", "preg_replace('/<b>(.*?)<\\/b>/', '<em>', $html);"),
        )

    def test_blank_target_without_noopener_is_reported(self) -> None:
        self.assertIn(
            "SP063",
            detected("index.html", '<a href="https://x.example" target="_blank">x</a>'),
        )

    def test_noopener_link_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP063",
            detected(
                "index.html",
                '<a href="https://x.example" target="_blank" rel="noopener noreferrer">x</a>',
            ),
        )

    def test_java_if_assignment_is_reported(self) -> None:
        self.assertIn("SP064", detected("Gate.java", "if (user.role = ADMIN) { grant(); }"))

    def test_java_if_equality_is_not_reported(self) -> None:
        self.assertNotIn("SP064", detected("Gate.java", "if (user.role == ADMIN) { grant(); }"))

    def test_java_el_evaluation_of_request_param_is_reported(self) -> None:
        source = 'factory.createValueExpression(ctx, "${" + request.getParameter("q") + "}");'
        self.assertIn("SP065", detected("Search.java", source))

    def test_java_el_with_literal_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP065",
            detected(
                "View.java",
                'factory.createValueExpression(elContext, "${user.name}", String.class);',
            ),
        )

    def test_php_shell_superglobal_is_reported_both_orders(self) -> None:
        self.assertIn("SP066", detected("tool.php", "system('id ' . $_GET['u']);"))
        self.assertIn("SP066", detected("tool.php", "$out = shell_exec($_POST['cmd']);"))

    def test_config_file_plaintext_credential_is_redacted(self) -> None:
        findings = find_regex_issues(
            Path("application.yml"),
            "config/application.yml",
            "spring.datasource.password=hunter2secret\n",
        )
        active, _ = deduplicate_and_suppress_findings(findings)
        sp067 = [f for f in active if f.rule_id == "SP067"]
        self.assertEqual(len(sp067), 1)
        self.assertEqual(sp067[0].evidence, "[REDACTED: credential-like material]")

    def test_config_placeholder_reference_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP067",
            detected("application.properties", "spring.datasource.password=${DB_PASSWORD}\n"),
        )


class LanguageExpansionPromotionsTests(unittest.TestCase):
    """Batch SP068-SP079 from the promotion shortlist (Go, Ruby, Java, Python,
    JavaScript, PHP coverage gaps verified against the executable catalog)."""

    def test_go_world_writable_mode_is_reported(self) -> None:
        self.assertIn(
            "SP068",
            detected("main.go", "ioutil.WriteFile(path, data, 0777)"),
        )
        self.assertIn("SP068", detected("main.go", "os.Chmod(cfgPath, 0o777)"))

    def test_go_normal_mode_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP068",
            detected("main.go", "os.WriteFile(path, data, 0o600)"),
        )

    def test_go_seeded_rand_is_reported(self) -> None:
        self.assertIn(
            "SP069",
            detected("token.go", "r := rand.New(rand.NewSource(time.Now().UnixNano()))"),
        )

    def test_go_crypto_rand_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP069",
            detected("token.go", "_, err := rand.Read(buf)"),
        )

    def test_go_checkorigin_allow_all_is_reported(self) -> None:
        source = (
            "var up = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}"
        )
        self.assertIn("SP070", detected("ws.go", source))

    def test_ruby_verify_none_is_reported(self) -> None:
        self.assertIn(
            "SP071",
            detected("net.rb", "http.verify_mode = OpenSSL::SSL::VERIFY_NONE"),
        )

    def test_ruby_eval_params_is_reported(self) -> None:
        self.assertIn("SP072", detected("calc_controller.rb", "result = eval(params[:expr])"))

    def test_ruby_safe_cast_is_not_reported(self) -> None:
        self.assertNotIn("SP072", detected("calc_controller.rb", "n = params[:n].to_i"))

    def test_java_bare_aes_is_reported(self) -> None:
        self.assertIn("SP073", detected("Crypto.java", 'Cipher c = Cipher.getInstance("AES");'))

    def test_java_gcm_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP073",
            detected("Crypto.java", 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");'),
        )

    def test_java_runtime_exec_concat_is_reported(self) -> None:
        self.assertIn(
            "SP074",
            detected("Run.java", 'Runtime.getRuntime().exec("ping " + host);'),
        )

    def test_java_processbuilder_array_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP074",
            detected("Run.java", 'new ProcessBuilder("ping", host).start();'),
        )

    def test_flask_send_file_from_request_is_reported(self) -> None:
        self.assertIn(
            "SP075",
            detected(
                "views.py",
                "return send_file(request.args.get('path'))",
            ),
        )

    def test_flask_static_send_file_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP075",
            detected("views.py", "return send_file('reports/weekly.pdf')"),
        )

    def test_express_sendfile_request_path_is_reported(self) -> None:
        self.assertIn(
            "SP076",
            detected("files.js", "res.sendFile(req.query.path);"),
        )

    def test_express_constant_sendfile_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP076",
            detected("files.js", "res.sendFile('/srv/app/public/index.html');"),
        )

    def test_stack_trace_to_client_is_reported(self) -> None:
        self.assertIn(
            "SP077",
            detected("server.js", "res.status(500).json({ error: err.stack });"),
        )

    def test_generic_error_body_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP077",
            detected("server.js", "res.status(500).json({ error: 'internal' });"),
        )

    def test_php_extract_superglobal_is_reported(self) -> None:
        self.assertIn("SP078", detected("legacy.php", "extract($_GET);"))

    def test_php_extract_with_extr_skip_is_not_reported(self) -> None:
        self.assertNotIn("SP078", detected("legacy.php", "extract($_GET, EXTR_SKIP);"))

    def test_java_unconstrained_request_mapping_is_reported(self) -> None:
        self.assertIn(
            "SP079",
            detected("UserController.java", '@RequestMapping("/users")'),
        )

    def test_java_get_mapping_shortcut_is_not_reported(self) -> None:
        self.assertNotIn(
            "SP079",
            detected("UserController.java", '@GetMapping("/users")'),
        )


if __name__ == "__main__":
    unittest.main()
