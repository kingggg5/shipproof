from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from impact_graph import ImpactGraph  # noqa: E402
from scan_repo import (  # noqa: E402
    deduplicate_and_suppress_findings,
    find_regex_issues,
)


def detected_rule_ids(filename: str, source: str) -> set[str]:
    path = Path(filename)
    findings = find_regex_issues(path, filename, source)
    active, _ = deduplicate_and_suppress_findings(findings)
    return {finding.rule_id for finding in active}


class JsCrossFileTaintTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _write(self, relative: str, content: str) -> None:
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def test_inline_route_handler_taints_helper_query_across_files(self) -> None:
        self._write(
            "routes/user.js",
            """
const { getUserById } = require("../services/userService");

router.get("/users/:id", async (req, res) => {
  const userId = req.params.id;
  res.json(await getUserById(userId));
});
""",
        )
        self._write(
            "services/userService.js",
            """
async function getUserById(uid) {
  return db.query(`SELECT * FROM users WHERE id = '${uid}'`);
}
""",
        )
        graph = ImpactGraph(self.root)
        graph.build()
        sql_flows = [flow for flow in graph.taint_flows if flow.sink_rule_id == "SP103"]
        self.assertEqual(len(sql_flows), 1)
        flow = sql_flows[0]
        self.assertEqual(flow.source_file, "routes/user.js")
        self.assertTrue(flow.source_entrypoint.startswith("inline:"))
        self.assertEqual(flow.sink_file, "services/userService.js")
        self.assertEqual(flow.sink_function, "getUserById")
        self.assertFalse(flow.is_sanitized)

    def test_named_handler_registration_becomes_entrypoint(self) -> None:
        self._write(
            "src/app.js",
            """
router.get("/report/:id", getReport);

function getReport(req, res) {
  runQuery(req.params.id);
}
""",
        )
        self._write(
            "src/db.js",
            """
function runQuery(rawId) {
  return pool.execute("SELECT * FROM reports WHERE id = " + rawId);
}
""",
        )
        graph = ImpactGraph(self.root)
        graph.build()
        sql_flows = [flow for flow in graph.taint_flows if flow.sink_rule_id == "SP103"]
        self.assertEqual(len(sql_flows), 1)
        self.assertEqual(sql_flows[0].source_entrypoint, "getReport")
        self.assertEqual(sql_flows[0].sink_function, "runQuery")

    def test_sanitized_chain_emits_no_flow(self) -> None:
        self._write(
            "routes/safe.js",
            """
router.get("/items/:id", async (req, res) => {
  const itemId = Number(req.params.id);
  res.json(await loadItem(itemId));
});
""",
        )
        self._write(
            "services/items.js",
            """
async function loadItem(cleanId) {
  return db.execute("SELECT * FROM items WHERE id = ?", [cleanId]);
}
""",
        )
        graph = ImpactGraph(self.root)
        graph.build()
        unsanitized = [
            flow
            for flow in graph.taint_flows
            if flow.sink_rule_id == "SP103" and not flow.is_sanitized
        ]
        self.assertEqual(unsanitized, [])

    def test_command_injection_sink_in_inline_handler(self) -> None:
        self._write(
            "routes/run.js",
            """
router.post("/run", (req, res) => {
  const command = req.body.command;
  cp.exec(`ls ${command}`);
});
""",
        )
        graph = ImpactGraph(self.root)
        graph.build()
        exec_flows = [
            flow
            for flow in graph.taint_flows
            if flow.sink_rule_id == "SP102" and flow.source_file == "routes/run.js"
        ]
        self.assertEqual(len(exec_flows), 1)
        self.assertFalse(exec_flows[0].is_sanitized)

    def test_path_traversal_reaches_fs_sink_through_alias(self) -> None:
        self._write(
            "routes/files.js",
            """
router.get("/files/:name", async (req, res) => {
  res.send(await readFileReport(req.params.name));
});
""",
        )
        self._write(
            "utils/storage.js",
            """
async function readFileReport(rawName) {
  const reportPath = path.join(__dirname, "../reports/" + rawName);
  return fs.readFile(reportPath, "utf8");
}
""",
        )
        graph = ImpactGraph(self.root)
        graph.build()
        traversal = [flow for flow in graph.taint_flows if flow.sink_rule_id == "SP110"]
        self.assertEqual(len(traversal), 1)
        self.assertEqual(traversal[0].sink_file, "utils/storage.js")
        self.assertFalse(traversal[0].is_sanitized)

    def test_basename_and_containment_guard_clear_traversal(self) -> None:
        self._write(
            "routes/files.js",
            """
router.get("/files/:name", async (req, res) => {
  res.send(await readFileReport(req.params.name));
});
""",
        )
        self._write(
            "utils/storage.js",
            """
async function readFileReport(rawName) {
  const fileName = path.basename(rawName);
  const reportPath = path.join(REPORTS_DIR, fileName);
  if (!reportPath.startsWith(REPORTS_DIR)) throw new Error("bad path");
  return fs.readFile(reportPath, "utf8");
}
""",
        )
        graph = ImpactGraph(self.root)
        graph.build()
        traversal = [
            flow
            for flow in graph.taint_flows
            if flow.sink_rule_id == "SP110" and not flow.is_sanitized
        ]
        self.assertEqual(traversal, [])

    def test_fetch_with_tainted_url_is_ssrf_sink(self) -> None:
        self._write(
            "routes/proxy.js",
            """
router.get("/proxy", async (req, res) => {
  const target = req.query.url;
  const upstream = await fetch(target);
  res.json(await upstream.json());
});
""",
        )
        graph = ImpactGraph(self.root)
        graph.build()
        ssrf = [
            flow
            for flow in graph.taint_flows
            if flow.sink_rule_id == "SP124" and flow.source_file == "routes/proxy.js"
        ]
        self.assertEqual(len(ssrf), 1)
        self.assertEqual(ssrf[0].sink_type, "ssrf")

    def test_route_registration_is_not_an_http_sink(self) -> None:
        self._write(
            "routes/plain.js",
            """
router.get("/users/:id", async (req, res) => {
  res.json({ id: req.params.id });
});
""",
        )
        graph = ImpactGraph(self.root)
        graph.build()
        ssrf = [flow for flow in graph.taint_flows if flow.sink_rule_id == "SP124"]
        self.assertEqual(ssrf, [])

    def test_client_side_location_hash_to_innerhtml_is_xss_flow(self) -> None:
        self._write(
            "public/app.js",
            """
function renderHash() {
  const payload = location.hash.slice(1);
  document.getElementById("out").innerHTML = payload;
}
""",
        )
        graph = ImpactGraph(self.root)
        graph.build()
        xss = [
            flow
            for flow in graph.taint_flows
            if flow.sink_rule_id == "SP147" and flow.source_file == "public/app.js"
        ]
        self.assertEqual(len(xss), 1)
        self.assertFalse(xss[0].is_sanitized)

    def test_html_response_with_request_data_is_reflected_xss(self) -> None:
        self._write(
            "routes/greet.js",
            """
router.get("/greet", (req, res) => {
  res.send(`<h1>Hello ${req.query.name}</h1>`);
});
""",
        )
        graph = ImpactGraph(self.root)
        graph.build()
        xss = [
            flow
            for flow in graph.taint_flows
            if flow.sink_rule_id == "SP080" and flow.source_file == "routes/greet.js"
        ]
        self.assertEqual(len(xss), 1)

    def test_json_response_is_not_html_xss(self) -> None:
        self._write(
            "routes/api.js",
            """
router.get("/api/user", (req, res) => {
  res.send({ name: req.query.name });
});
""",
        )
        graph = ImpactGraph(self.root)
        graph.build()
        xss = [flow for flow in graph.taint_flows if flow.sink_rule_id == "SP080"]
        self.assertEqual(xss, [])

    def test_document_write_with_cookie_is_xss_flow(self) -> None:
        self._write(
            "public/legacy.js",
            """
function echoCookie() {
  const raw = document.cookie;
  document.write(raw);
}
""",
        )
        graph = ImpactGraph(self.root)
        graph.build()
        xss = [
            flow
            for flow in graph.taint_flows
            if flow.sink_rule_id == "SP146" and flow.source_file == "public/legacy.js"
        ]
        self.assertEqual(len(xss), 1)


class HtmlResponseRuleTests(unittest.TestCase):
    def test_interpolated_html_send_is_reported(self) -> None:
        source = 'res.send(`<div class="msg">${req.query.msg}</div>`);'
        self.assertIn("SP080", detected_rule_ids("app.js", source))

    def test_plain_template_without_markup_is_not_reported(self) -> None:
        source = "res.send(`hello ${name}`);"
        self.assertNotIn("SP080", detected_rule_ids("app.js", source))

    def test_json_body_is_not_reported(self) -> None:
        source = "res.send(JSON.stringify(req.body));"
        self.assertNotIn("SP080", detected_rule_ids("app.js", source))


class PrototypePollutionRuleTests(unittest.TestCase):
    def detected(self, source: str) -> set[str]:
        return detected_rule_ids("app.js", source)

    def test_merge_of_request_body_is_reported(self) -> None:
        self.assertIn("SP051", self.detected("_.merge(config, req.body);"))
        self.assertIn(
            "SP051",
            self.detected("utils.deepMerge(options, JSON.parse(req.rawBody));"),
        )

    def test_merges_without_request_source_are_not_reported(self) -> None:
        self.assertNotIn("SP051", self.detected("_.merge(config, defaults);"))
        self.assertNotIn(
            "SP051",
            self.detected("merge(target, sanitize(req.body));"),
        )


class AdversarialHardeningTests(unittest.TestCase):
    """Traps from fixtures/adversarial-node: code-shaped rules must not fire
    inside string literals, method look-alikes, or without their required
    context — while taint probes still fire."""

    def detected(self, filename: str, source: str) -> set[str]:
        return detected_rule_ids(filename, source)

    def test_sql_inside_string_literal_is_not_code(self) -> None:
        source = "const exampleSql = \"db.execute('SELECT * FROM users WHERE id = ' + userId)\";"
        self.assertNotIn("SP103", self.detected("docs.js", source))

    def test_executable_concat_still_reported(self) -> None:
        source = "db.execute('SELECT * FROM users WHERE id = ' + userId);"
        self.assertIn("SP103", self.detected("app.js", source))

    def test_method_open_call_is_not_path_traversal(self) -> None:
        source = "snackBar.open(`Version ${version} is incompatible`, 'errorBar');"
        self.assertNotIn("SP110", self.detected("ui.js", source))

    def test_bare_open_with_fstring_still_traversal(self) -> None:
        findings = find_regex_issues(Path("upload.py"), "upload.py", 'open(f"/uploads/{name}")')
        active, _ = deduplicate_and_suppress_findings(findings)
        self.assertIn("SP110", {item.rule_id for item in active})

    def test_sync_fs_outside_loop_is_not_blocking(self) -> None:
        source = "const content = fs.readFileSync(target, 'utf8');"
        self.assertNotIn("SP321", self.detected("util.js", source))

    def test_sync_fs_in_loop_is_blocking(self) -> None:
        source = "for (const f of files) {\n  const c = fs.readFileSync(f);\n}"
        self.assertIn("SP321", self.detected("batch.js", source))

    def test_nextjs_params_rule_downgrades_off_next(self) -> None:
        source = "const id = params.id;"
        findings = find_regex_issues(
            Path("routes/x.ts"),
            "routes/x.ts",
            source,
            detected_frameworks=frozenset({"express"}),
        )
        sp593 = [f for f in findings if f.rule_id == "SP593"]
        if sp593:
            self.assertEqual(sp593[0].confidence, "medium")


class ExpressMissingAuthTests(unittest.TestCase):
    def test_admin_route_without_any_auth_signal_is_reported(self) -> None:
        source = "\n".join(
            [
                "const express = require('express');",
                "const app = express();",
                'app.delete("/admin/users/:id", removeUser);',
            ]
        )
        self.assertIn("SP108", detected_rule_ids("server.js", source))

    def test_global_auth_middleware_suppresses_finding(self) -> None:
        source = "\n".join(
            [
                "const express = require('express');",
                "const app = express();",
                "app.use(requireAuth);",
                'app.delete("/admin/users/:id", removeUser);',
            ]
        )
        self.assertNotIn("SP108", detected_rule_ids("server.js", source))

    def test_route_level_auth_middleware_suppresses_finding(self) -> None:
        source = "\n".join(
            [
                "const express = require('express');",
                "const router = express.Router();",
                'router.delete("/admin/users/:id", requireAdmin, removeUser);',
            ]
        )
        self.assertNotIn("SP108", detected_rule_ids("server.js", source))

    def test_non_admin_route_is_not_reported(self) -> None:
        source = "\n".join(
            [
                "const express = require('express');",
                "const app = express();",
                'app.get("/users/:id", getUser);',
            ]
        )
        self.assertNotIn("SP108", detected_rule_ids("server.js", source))

    def test_commented_admin_route_is_not_reported(self) -> None:
        source = "\n".join(
            [
                "// Example from docs:",
                '// app.delete("/admin/users/:id", removeUser);',
                "module.exports = {};",
            ]
        )
        self.assertNotIn("SP108", detected_rule_ids("server.js", source))


class SqlConcatDetectionTests(unittest.TestCase):
    def test_concatenated_sql_literal_is_reported(self) -> None:
        source = "db.execute('SELECT * FROM users WHERE id = ' + userId);"
        self.assertIn("SP103", detected_rule_ids("app.js", source))

    def test_parameterized_query_is_not_reported(self) -> None:
        source = 'db.execute("SELECT * FROM users WHERE id = ?", [userId]);'
        self.assertNotIn("SP103", detected_rule_ids("app.js", source))


if __name__ == "__main__":
    unittest.main()
