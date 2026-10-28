"""Context, provenance and adversarial regression cases for protection contracts."""

from __future__ import annotations

import ast
import html
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/audit-production-readiness/scripts"
sys.path.insert(0, str(SCRIPTS))

import taint_contracts as contracts  # noqa: E402
from impact_graph import ImpactGraph  # noqa: E402
from scan_repo import (  # noqa: E402
    collect_cross_file_taint,
    deduplicate_and_suppress_findings,
    find_python_ast_issues,
)


class SanitizerContractTests(unittest.TestCase):
    def native(self, body, imports="", definitions=""):
        source = (
            "from flask import request\n"
            + imports
            + "\n"
            + definitions
            + '\ndef handle():\n    raw = request.args.get("q")\n'
            + textwrap.indent(textwrap.dedent(body).strip(), "    ")
            + "\n"
        )
        findings, _ = deduplicate_and_suppress_findings(find_python_ast_issues("app.py", source))
        return findings

    def flows(self, files, rule="SP103"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, content in files.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(textwrap.dedent(content), encoding="utf-8")
            graph = ImpactGraph(root)
            graph.build()
            return [flow for flow in graph.taint_flows if flow.sink_rule_id == rule]

    def python_flows(self, expression, imports="", before="", sink="cursor.execute(value)"):
        return self.flows(
            {
                "app.py": imports
                + '\nfrom store import query\n@app.get("/q")\ndef route(raw):\n'
                + textwrap.indent(before, "    ")
                + f"    value = {expression}\n    return query(value)\n",
                "store.py": f"def query(value):\n    return {sink}\n",
            }
        )

    def js_flows(self, body, imports="", rule="SP103"):
        return self.flows(
            {"app.js": imports + '\nrouter.get("/q", (req, res) => {\n' + body + "\n});\n"},
            rule,
        )

    def test_html_escaping_is_not_a_sql_defense_in_native_python(self):
        for expression, imports in [
            ("html.escape(raw)", "import html"),
            ("e(raw)", "from html import escape as e"),
            ("h.escape(raw)", "import html as h"),
        ]:
            with self.subTest(expression=expression):
                matches = [
                    f
                    for f in self.native(f"value = {expression}\ncursor.execute(value)", imports)
                    if f.rule_id == "SP103"
                ]
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0].tier, "gate")

    def test_transparent_identity_names_do_not_clear_native_taint(self):
        for name in ("cleanIdentity", "hint", "validate", "escape"):
            with self.subTest(name=name):
                definitions = f"def {name}(x):\n    return x\n"
                self.assertTrue(
                    any(
                        f.rule_id == "SP103" and f.tier == "gate"
                        for f in self.native(
                            f"cursor.execute({name}(raw))", definitions=definitions
                        )
                    )
                )

    def test_unknown_protector_is_advisory_not_safe_or_blocking(self):
        for name in ("sanitize", "custom_escape", "validateSQL", "is_uuid"):
            with self.subTest(name=name):
                matches = [
                    f for f in self.native(f"cursor.execute({name}(raw))") if f.rule_id == "SP103"
                ]
                self.assertEqual(len(matches), 1)
                self.assertEqual(matches[0].tier, "advisory")
                flows = self.python_flows(f"{name}(raw)")
                self.assertTrue(flows)
                self.assertTrue(all(f.uncertain and not f.is_sanitized for f in flows))

    def test_known_scalar_conversions_keep_safe_sql_quiet(self):
        for expression, imports in [
            ("int(raw)", ""),
            ("float(raw)", ""),
            ("bool(raw)", ""),
            ("len(raw)", ""),
            ("UUID(raw)", "from uuid import UUID"),
            ("b.int(raw)", "import builtins as b"),
        ]:
            with self.subTest(expression=expression):
                self.assertFalse(
                    any(
                        f.rule_id == "SP103"
                        for f in self.native(
                            f'value = {expression}\ncursor.execute(f"SELECT {{value}}")', imports
                        )
                    )
                )
                flows = self.python_flows(expression, imports)
                self.assertTrue(flows)
                self.assertTrue(all(f.is_sanitized for f in flows))

    def test_scalar_is_not_ssrf_or_path_authorization(self):
        for rule in ("SP110", "SP124"):
            self.assertFalse(contracts.protected({"scalar"}, rule))
        for expression in ("Number(req.query.url)", "parseInt(req.query.url)"):
            with self.subTest(expression=expression):
                flows = self.js_flows(f"  fetch({expression});", rule="SP124")
                self.assertTrue(flows)
                self.assertTrue(all(not f.is_sanitized for f in flows))

    def test_native_protection_only_applies_to_derived_value(self):
        findings = self.native("safe = int(raw)\ncursor.execute(safe)\ncursor.execute(raw)")
        matches = [f for f in findings if f.rule_id == "SP103"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].line, 8)

    def test_native_overwrite_clears_only_the_written_value(self):
        for body in (
            'value = raw\nvalue = "SELECT 1"\ncursor.execute(value)',
            'raw = "SELECT 1"\ncursor.execute(raw)',
        ):
            with self.subTest(body=body):
                self.assertFalse(any(f.rule_id == "SP103" for f in self.native(body)))
        self.assertTrue(
            any(
                f.rule_id == "SP103"
                for f in self.native("safe = int(raw)\nsafe = raw\ncursor.execute(safe)")
            )
        )

    def test_safe_bind_parameters_are_not_sql_statement_construction(self):
        self.assertFalse(
            any(f.rule_id == "SP103" for f in self.native('cursor.execute("SELECT ?", [raw])'))
        )
        self.assertEqual(self.python_flows("raw", sink='cursor.execute("SELECT ?", [value])'), [])
        self.assertEqual(self.js_flows('  db.query("SELECT $1", [req.query.q]);'), [])

    def test_bound_imports_and_shadowing_are_required(self):
        for source, name in [
            ("", "html.escape"),
            ("int = other", "int"),
            ("import html\nhtml.escape = other", "html.escape"),
            ("def int(x):\n    return x", "int"),
            ("import builtins\nbuiltins.int = other", "builtins.int"),
            ("import html\nfrom custom import escape as html", "html.escape"),
            ("def clean(x):\n    return x\ndef clean(x):\n    return other(x)", "clean"),
        ]:
            with self.subTest(source=source):
                module = contracts.PythonContracts(ast.parse(source))
                self.assertNotIn(module.kind(name), {"scalar", "html", "shell"})
        module = ast.parse("def clean(x):\n    return x\ndef use(clean):\n    return clean(1)")
        parent = contracts.PythonContracts(module)
        child = contracts.PythonContracts(module.body[1], parent)
        self.assertNotEqual(child.kind("clean"), "identity")

    def test_multi_argument_wrapper_is_not_a_one_argument_identity(self):
        for source in (
            "def clean(other, /, value):\n    return value",
            "def clean(value, *args):\n    return value",
            "def clean(value, *, other):\n    return value",
        ):
            module = contracts.PythonContracts(ast.parse(source))
            self.assertEqual(module.kind("clean"), "unknown")

    def test_user_numeric_protocol_does_not_prove_primitive_output(self):
        module = contracts.PythonContracts(ast.parse(""))
        for name in ("abs", "round"):
            self.assertNotEqual(module.kind(name), "scalar")

    def test_shell_quote_requires_bound_posix_guard_and_correct_sink(self):
        source = "import os, shlex"
        guard = 'if os.name != "posix":\n    raise RuntimeError("POSIX required")\n'
        quoted = self.native(guard + "value = shlex.quote(raw)\nos.system(value)", source)
        self.assertFalse(any(f.rule_id == "SP102" for f in quoted))
        sql = self.native(guard + "cursor.execute(shlex.quote(raw))", source)
        self.assertTrue(any(f.rule_id == "SP103" for f in sql))
        unknown = self.native("os.system(shlex.quote(raw))", source)
        self.assertTrue(any(f.rule_id == "SP102" and f.tier == "advisory" for f in unknown))

    def test_python_argv_without_shell_is_not_shell_injection(self):
        for call in (
            'subprocess.check_call(["echo", raw])',
            'subprocess.check_output(("echo", raw), shell=False)',
        ):
            self.assertFalse(
                any(f.rule_id == "SP102" for f in self.native(call, "import subprocess"))
            )
        self.assertTrue(
            any(
                f.rule_id == "SP102"
                for f in self.native(
                    'subprocess.check_call(["echo", raw], shell=True)', "import subprocess"
                )
            )
        )

    def test_shell_quote_before_guard_or_inside_quotes_is_unresolved(self):
        imports = "import os, shlex"
        before = self.native(
            'os.system(shlex.quote(raw))\nif os.name != "posix":\n    raise RuntimeError()', imports
        )
        self.assertTrue(any(f.rule_id == "SP102" and f.tier == "advisory" for f in before))
        wrapped = self.native(
            "if os.name != \"posix\":\n    raise RuntimeError()\nvalue = 'echo \"' + shlex.quote(raw) + '\"'\nos.system(value)",
            imports,
        )
        self.assertTrue(any(f.rule_id == "SP102" and f.tier == "advisory" for f in wrapped))

    def test_conditional_constant_statements_remain_quiet(self):
        findings = self.native('cursor.execute("SELECT 1" if raw else "SELECT 2")')
        self.assertFalse(any(f.rule_id == "SP103" for f in findings))

    def test_lookup_result_does_not_inherit_numeric_index_protection(self):
        findings = self.native("value = statements[int(raw)]\ncursor.execute(value)")
        self.assertTrue(any(f.rule_id == "SP103" and f.tier == "advisory" for f in findings))

    def test_receiver_methods_preserve_unresolved_provenance(self):
        for expression in ("raw.strip()", "raw.lower().strip()", "raw.replace('x', 'y')"):
            with self.subTest(expression=expression):
                findings = self.native(f"cursor.execute({expression})")
                self.assertTrue(
                    any(f.rule_id == "SP103" and f.tier == "advisory" for f in findings)
                )
                flows = self.python_flows(expression)
                self.assertTrue(flows)
                self.assertTrue(all(not f.is_sanitized and f.uncertain for f in flows))

    def test_sqlmodel_exec_is_not_python_code_execution(self):
        self.assertFalse(any(f.rule_id == "SP101" for f in self.native("session.exec(raw)")))
        flows = self.flows(
            {"app.py": '@app.get("/q")\ndef route(raw):\n    return session.exec(raw)\n'}, "SP101"
        )
        self.assertEqual(flows, [])
        self.assertTrue(
            any(
                f.rule_id == "SP101"
                for f in self.native("ev(raw)", "from builtins import eval as ev")
            )
        )
        self.assertFalse(
            any(
                f.rule_id == "SP101"
                for f in self.native("eval(raw)", definitions="def eval(x):\n    return x\n")
            )
        )

    def test_query_builder_result_stays_advisory(self):
        flows = self.python_flows(
            "sa.select(Model).where(Model.id == raw)", "import sqlalchemy as sa"
        )
        self.assertTrue(flows)
        self.assertTrue(all(f.uncertain and not f.is_sanitized for f in flows))

    def test_conditional_protection_cannot_clear_other_python_path(self):
        findings = self.native("if condition:\n    raw = int(raw)\ncursor.execute(raw)")
        self.assertTrue(any(f.rule_id == "SP103" for f in findings))
        safe = self.native(
            "if condition:\n    raw = int(raw)\nelse:\n    raw = int(raw)\ncursor.execute(raw)"
        )
        self.assertFalse(any(f.rule_id == "SP103" for f in safe))
        flows = self.flows(
            {
                "app.py": 'from store import query\n@app.get("/q")\ndef route(raw):\n    if condition:\n        value = raw\n    else:\n        value = int(raw)\n    return query(value)\n',
                "store.py": "def query(value):\n    return cursor.execute(value)\n",
            }
        )
        self.assertTrue(flows)
        self.assertTrue(any(not f.is_sanitized for f in flows))

    def test_cross_file_wrong_context_and_identity_wrappers(self):
        for expression, imports in [
            ("html.escape(raw)", "import html"),
            ("hint(raw)", "def hint(x):\n    return x\n"),
            ("cleanIdentity(raw)", "def cleanIdentity(x):\n    return x\n"),
        ]:
            with self.subTest(expression=expression):
                flows = self.python_flows(expression, imports)
                self.assertTrue(flows)
                self.assertTrue(all(not f.is_sanitized and not f.uncertain for f in flows))

    def test_safe_and_raw_paths_to_same_helper_both_survive(self):
        flows = self.flows(
            {
                "app.py": 'from store import query\n@app.get("/q")\ndef route(raw):\n    query(int(raw))\n    return query(raw)\n',
                "store.py": "def query(value):\n    return cursor.execute(value)\n",
            }
        )
        self.assertEqual({f.is_sanitized for f in flows}, {True, False})

    def test_unknown_collector_flow_is_advisory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                '@app.get("/q")\ndef route(raw):\n    cursor.execute(sanitize(raw))\n',
                encoding="utf-8",
            )
            findings, _, _ = collect_cross_file_taint(root)
            self.assertTrue(findings)
            self.assertTrue(all(f.tier == "advisory" for f in findings))

    def test_js_numeric_conversion_does_not_clear_raw_alias(self):
        flows = self.js_flows(
            "  const raw = req.query.q;\n  const safe = Number(raw);\n  db.query(safe);\n  db.query(raw);"
        )
        self.assertEqual({f.is_sanitized for f in flows}, {True, False})

    def test_js_unknown_sanitizer_and_wrong_context(self):
        for imports, value, rule in [
            ("", "sanitize(req.query.q)", "SP103"),
            ('const d = require("dompurify");', "d.sanitize(req.query.q)", "SP103"),
            ('const p = require("node:path");', "p.basename(req.query.q)", "SP124"),
        ]:
            with self.subTest(value=value):
                sink = "fetch" if rule == "SP124" else "db.query"
                flows = self.js_flows(f"  {sink}({value});", imports, rule)
                self.assertTrue(flows)
                self.assertTrue(all(not f.is_sanitized for f in flows))
                self.assertEqual(all(f.uncertain for f in flows), not imports)

    def test_js_trusted_html_conversion_only_protects_html(self):
        flows = self.js_flows(
            "  document.write(d.sanitize(req.query.q));", 'import d from "dompurify";', "SP146"
        )
        self.assertTrue(flows)
        self.assertTrue(all(f.is_sanitized for f in flows))

    def test_dompurify_options_hooks_escapes_and_embedding_are_unresolved(self):
        for imports, body in [
            ('import d from "dompurify";', "  document.write(d.sanitize(req.query.q, options));"),
            (
                'import d from "dompurify";\nd.setConfig(options);',
                "  document.write(d.sanitize(req.query.q));",
            ),
            (
                'import d from "dompurify";\nd.addHook("afterSanitizeAttributes", hook);',
                "  document.write(d.sanitize(req.query.q));",
            ),
            (
                'import d from "dompurify";\nconfigure(d);',
                "  document.write(d.sanitize(req.query.q));",
            ),
            (
                'import d from "dompurify";',
                "  const safe = d.sanitize(req.query.q);\n  document.write('<a title=\"' + safe + '\">');",
            ),
        ]:
            with self.subTest(body=body, imports=imports):
                flows = self.js_flows(body, imports, "SP146")
                self.assertTrue(flows)
                self.assertTrue(all(not f.is_sanitized and f.uncertain for f in flows))

    def test_mixed_js_values_do_not_inherit_only_first_carrier_protection(self):
        prefix = "  const a = Number(req.query.a);\n  const z = req.query.z;\n"
        for suffix in (
            "  db.query(a + z);",
            "  const value = a + z;\n  db.query(value);",
        ):
            flows = self.js_flows(prefix + suffix)
            self.assertTrue(flows)
            self.assertTrue(all(not f.is_sanitized for f in flows))
        safe = self.js_flows(prefix + "  db.query(Number(a + z));")
        self.assertTrue(safe)
        self.assertTrue(all(f.is_sanitized for f in safe))

    def test_absent_carrier_does_not_create_a_constant_contract(self):
        chain = contracts.js_value_chain("location.search", [], {}, {}, set())
        proofs, _ = contracts.transfer((), chain)
        self.assertFalse(contracts.protected(proofs, "SP147"))

    def test_js_shadowed_conversion_cannot_prove_safety(self):
        for imports in ("const Number = identity;", "function Number(x) { return x; }"):
            flows = self.js_flows("  db.query(Number(req.query.q));", imports)
            self.assertTrue(flows)
            self.assertTrue(all(not f.is_sanitized and f.uncertain for f in flows))

    def test_template_literals_cannot_hide_conversion_rebinding(self):
        for imports in (
            "const Number = identity;\nconst text = `example ${1}`;",
            "const text = `${Number = identity}`;",
        ):
            with self.subTest(imports=imports):
                flows = self.js_flows("  db.query(Number(req.query.q));", imports)
                self.assertTrue(flows)
                self.assertTrue(all(f.uncertain and not f.is_sanitized for f in flows))

    def test_inert_template_text_does_not_shadow_real_builtin(self):
        flows = self.js_flows(
            "  db.query(Number(req.query.q));", "const text = `Number = identity ${1}`;"
        )
        self.assertTrue(flows)
        self.assertTrue(all(f.is_sanitized for f in flows))

    def test_template_expressions_do_not_erase_bound_module_identity(self):
        flows = self.js_flows(
            "  document.write(d.sanitize(req.query.q));",
            'import d from "dompurify";\nconst text = `example ${1}`;',
            "SP146",
        )
        self.assertTrue(flows)
        self.assertTrue(all(f.is_sanitized for f in flows))

    def test_binding_token_budget_cannot_claim_builtin_safety(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = (
                "const Number = identity;\n"
                + ";" * 60000
                + '\nrouter.get("/q", (req, res) => { db.query(Number(req.query.q)); });\n'
            )
            (root / "app.js").write_text(source, encoding="utf-8")
            graph = ImpactGraph(root)
            graph.build()
            self.assertFalse(graph.completeness["is_complete"])
            self.assertGreater(graph.completeness["parser_limit"], 0)
            self.assertTrue(graph.taint_flows)
            self.assertTrue(all(not flow.is_sanitized for flow in graph.taint_flows))

    def test_ambiguous_protection_view_defers_without_dropping_source_flow(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = 'const view = <Box value={item}/>;\nrouter.get("/q", (req, res) => { db.query(Number(req.query.q)); });\n'
            (root / "app.jsx").write_text(source, encoding="utf-8")
            graph = ImpactGraph(root)
            graph.build()
            self.assertTrue(graph.completeness["is_complete"])
            self.assertTrue(graph.taint_flows)
            self.assertTrue(
                all(flow.uncertain and not flow.is_sanitized for flow in graph.taint_flows)
            )

    def test_js_rebound_module_member_is_not_trusted(self):
        flows = self.js_flows(
            "  document.write(d.sanitize(req.query.q));",
            'const d = require("dompurify");\nd.sanitize = identity;',
            "SP146",
        )
        self.assertTrue(flows)
        self.assertTrue(all(not f.is_sanitized and f.uncertain for f in flows))

    def test_js_global_conversion_rebinding_is_unresolved(self):
        flows = self.js_flows("  db.query(Number(req.query.q));", "globalThis.Number = identity;")
        self.assertTrue(flows)
        self.assertTrue(all(f.uncertain and not f.is_sanitized for f in flows))

    def test_js_destructured_conversion_and_shadowed_require_are_unresolved(self):
        flows = self.js_flows("  db.query(Number(req.query.q));", "const { Number } = custom;")
        self.assertTrue(flows)
        self.assertTrue(all(f.uncertain and not f.is_sanitized for f in flows))
        for imports in (
            'function require(name) { return custom; }\nconst d = require("dompurify");',
            'const d = require("node:path");\nconst d = require("dompurify");',
        ):
            flows = self.js_flows("  document.write(d.sanitize(req.query.q));", imports, "SP146")
            self.assertTrue(flows)
            self.assertTrue(all(f.uncertain and not f.is_sanitized for f in flows))

    def test_js_conditional_conversion_or_overwrite_is_unresolved(self):
        for assignment in ("value = Number(value);", 'value = "SELECT 1";'):
            flows = self.js_flows(
                "  let value = req.query.q;\n  if (condition) {\n    "
                + assignment
                + "\n  }\n  db.query(value);"
            )
            self.assertTrue(flows)
            self.assertTrue(all(f.uncertain and not f.is_sanitized for f in flows))

    def test_js_comments_and_literal_names_do_not_create_flows(self):
        self.assertEqual(
            self.js_flows(
                '  // db.query(req.query.q);\n  const s = "db.query(req.query.q)";\n  db.query("SELECT 1");'
            ),
            [],
        )

    def test_dom_insert_adjacent_html_checks_payload_argument(self):
        imports = 'import d from "dompurify";'
        safe = self.js_flows(
            '  element.insertAdjacentHTML("beforeend", d.sanitize(req.query.q));', imports, "SP147"
        )
        unsafe = self.js_flows(
            '  element.insertAdjacentHTML("beforeend", req.query.q);', imports, "SP147"
        )
        self.assertTrue(safe)
        self.assertTrue(all(f.is_sanitized for f in safe))
        self.assertTrue(unsafe)
        self.assertTrue(all(not f.is_sanitized for f in unsafe))

    def test_js_nested_expression_is_not_mistaken_for_whole_conversion(self):
        for expression in (
            "Number(raw) + identity(raw)",
            "Number(raw) || identity(raw)",
            "Number(raw), identity(raw)",
        ):
            chain = contracts.js_chain(expression, "raw", (), {}, set())
            proofs, _ = contracts.transfer((), chain)
            self.assertFalse(contracts.protected(proofs, "SP103"), expression)
        proofs, _ = contracts.transfer(
            (), contracts.js_chain("Number(String(raw))", "raw", (), {}, set())
        )
        self.assertTrue(contracts.protected(proofs, "SP103"))

    def test_js_path_guard_needs_normalization_separator_rejection(self):
        imports = 'const p = require("node:path");\nconst ROOT = "/srv/files";'
        for guard, safe in [
            ("if (!value.startsWith(ROOT)) throw new Error();", False),
            ("if (value.startsWith(ROOT + p.sep)) console.log(value);", False),
            ("if (!value.startsWith(ROOT + p.sep)) throw new Error();", True),
        ]:
            with self.subTest(guard=guard):
                flows = self.js_flows(
                    "  const value = p.resolve(ROOT, req.query.q);\n  "
                    + guard
                    + "\n  fs.readFile(value);",
                    imports,
                    "SP110",
                )
                self.assertTrue(flows)
                self.assertEqual(all(f.is_sanitized for f in flows), safe)
                if not safe:
                    self.assertTrue(all(f.uncertain for f in flows))

    def test_js_guard_cannot_protect_reassigned_value_or_earlier_sink(self):
        imports = 'const p = require("node:path");'
        body = "  let value = p.resolve(ROOT, req.query.q);\n  fs.readFile(value);\n  if (!value.startsWith(ROOT + p.sep)) throw new Error();\n  value = p.resolve(ROOT, req.query.other);\n  fs.readFile(value);"
        flows = self.js_flows(body, imports, "SP110")
        self.assertEqual(len(flows), 2)
        self.assertTrue(all(not f.is_sanitized for f in flows))

    def test_path_concatenation_after_normalization_does_not_prove_containment(self):
        flows = self.js_flows(
            '  const value = p.resolve(ROOT, req.query.q) + "/../" + req.query.q;\n  if (!value.startsWith(ROOT + p.sep)) throw new Error();\n  fs.readFile(value);',
            'const p = require("node:path");',
            "SP110",
        )
        self.assertTrue(flows)
        self.assertTrue(all(f.uncertain and not f.is_sanitized for f in flows))

    def test_transform_bounds_fail_closed(self):
        expr = ast.parse("int(" * 28 + "raw" + ")" * 28, mode="eval").body
        with self.assertRaises(contracts.ContractLimitError):
            contracts.python_trace(
                expr,
                lambda name: contracts.Trace(name),
                lambda _: False,
                contracts.PythonContracts(ast.parse("")),
            )
        with self.assertRaises(contracts.ContractLimitError):
            contracts.js_chain("Number(" * 15 + "raw" + ")" * 15, "raw", (), {}, set())

    def test_expression_budget_is_visible_as_incomplete_graph(self):
        for filename, source in [
            (
                "app.py",
                '@app.get("/q")\ndef route(raw):\n    cursor.execute('
                + "int(" * 28
                + "raw"
                + ")" * 28
                + ")\n",
            ),
            (
                "app.js",
                'router.get("/q", (req, res) => {\n  db.query('
                + "Number(" * 15
                + "req.query.q"
                + ")" * 15
                + ");\n});\n",
            ),
        ]:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / filename).write_text(source, encoding="utf-8")
                graph = ImpactGraph(root)
                graph.build()
                self.assertFalse(graph.completeness["is_complete"])
                self.assertGreater(graph.completeness["parser_limit"], 0)

    def test_html_escape_vs_bound_sql_demonstrated_in_isolated_memory(self):
        # Own fixture only; no target application or external database executes.
        connection = sqlite3.connect(":memory:")
        try:
            raw = "0 OR 1=1"
            unsafe = connection.execute("SELECT 1 WHERE 0 = " + html.escape(raw)).fetchall()
            safe = connection.execute("SELECT 1 WHERE 0 = ?", [raw]).fetchall()
            self.assertEqual(unsafe, [(1,)])
            self.assertEqual(safe, [])
        finally:
            connection.close()

    @unittest.skipUnless(shutil.which("node"), "Node is required for cross-entrypoint parity")
    def test_python_node_sarif_parity_for_wrong_context(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text(
                'import html\nfrom flask import request\ndef route():\n    raw = request.args.get("q")\n    cursor.execute(html.escape(raw))\n',
                encoding="utf-8",
            )
            reports = []
            for command in (
                [sys.executable, str(SCRIPTS / "scan_repo.py")],
                [shutil.which("node"), str(ROOT / "bin/shipproof.mjs"), "scan"],
            ):
                run = subprocess.run(  # noqa: S603 - fixed local scanner and own temporary fixture
                    [*command, str(root), "--format", "json", "--fail-on", "none"],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    timeout=30,
                )
                self.assertEqual(run.returncode, 0, run.stderr)
                reports.append(json.loads(run.stdout))
            self.assertEqual(reports[0], reports[1])
            findings = [f for f in reports[0]["findings"] if f["rule_id"] == "SP103"]
            self.assertEqual(len(findings), 1)
            sarif = subprocess.run(  # noqa: S603 - fixed local scanner and own temporary fixture
                [
                    sys.executable,
                    str(SCRIPTS / "scan_repo.py"),
                    str(root),
                    "--format",
                    "sarif",
                    "--fail-on",
                    "none",
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
            )
            self.assertEqual(sarif.returncode, 0, sarif.stderr)
            results = [
                r for r in json.loads(sarif.stdout)["runs"][0]["results"] if r["ruleId"] == "SP103"
            ]
            self.assertEqual(len(results), 1)
            self.assertEqual(
                results[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
                findings[0]["line"],
            )


if __name__ == "__main__":
    unittest.main()
