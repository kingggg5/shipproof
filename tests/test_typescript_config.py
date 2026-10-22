from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))

from scan_repo import (  # noqa: E402
    JS_CONFIG_SUFFIXES,
    RULE_INDEX,
    build_json_report,
    build_sarif_report,
    find_regex_issues,
    find_rule,
    gate_failed,
    make_finding,
    scan_repository,
)

COHORT = {f"SP{number}" for number in range(674, 683)}


class TypeScriptConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        payload = json.loads((ROOT / "tests/rule_cases_v2.json").read_text(encoding="utf-8"))
        cls.records = [row for row in payload["rules"] if row["rule_id"] in COHORT]

    def findings(self, source: str, filename: str = "app.ts"):
        return find_regex_issues(Path(filename), filename, source)

    def ids(self, source: str, filename: str = "app.ts"):
        return {finding.rule_id for finding in self.findings(source, filename)}

    def test_every_authored_case_through_real_repository_walker(self):
        self.assertEqual(len(self.records), 9)
        for row in self.records:
            for polarity in ("positive", "negative", "adversarial"):
                for case in row[polarity]:
                    with self.subTest(
                        rule=row["rule_id"], polarity=polarity, source=case["source"]
                    ):
                        with tempfile.TemporaryDirectory(
                            prefix="shipproof-typescript-"
                        ) as directory:
                            root = Path(directory)
                            path = root / case["path"]
                            path.write_text(case["source"], encoding="utf-8")
                            findings, stats = scan_repository(root)
                        self.assertTrue(stats["completeness"]["is_complete"])
                        expected = (
                            case["expected"]
                            if polarity == "adversarial"
                            else polarity == "positive"
                        )
                        hits = [
                            finding for finding in findings if finding.rule_id == row["rule_id"]
                        ]
                        self.assertEqual(bool(hits), expected)
                        if expected:
                            self.assertEqual(len(hits), 1)
                            self.assertEqual(
                                (hits[0].tier, hits[0].proof_level), ("advisory", "L1")
                            )
                        # A safe counterpart for one API must not invent another cohort issue.
                        if not expected:
                            self.assertFalse(
                                COHORT.intersection(finding.rule_id for finding in findings)
                            )

    def test_supported_source_suffixes_and_commonjs(self):
        source = "const { verify: check } = require('jsonwebtoken');\ncheck(token, key, {ignoreExpiration:true});\n"
        for suffix in sorted(JS_CONFIG_SUFFIXES):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / ("auth" + suffix)).write_text(source, encoding="utf-8")
                findings, stats = scan_repository(root)
                self.assertIn("SP675", {finding.rule_id for finding in findings})
                self.assertTrue(stats["completeness"]["is_complete"])
        for suffix in (".txt", ".md", ".py", ".cs"):
            self.assertNotIn("SP675", self.ids(source, "notes" + suffix))

    def test_namespace_named_imports_and_rebinding_boundaries(self):
        source = "import {verify as validate} from 'jsonwebtoken';\nvalidate(token,key,{ignoreExpiration:true});\n"
        self.assertIn("SP675", self.ids(source))
        for safe in (
            source.replace("{verify as", "{type verify as"),
            source.replace("from 'jsonwebtoken'", "from './jsonwebtoken'"),
            source.replace("validate(token", "object.validate(token"),
            source.replace(
                "validate(token",
                "function run(validate: Verifier): unknown { return validate(token",
            )
            + "}",
            source.replace("validate(token", "validate = checkedVerify;\nvalidate(token"),
            source.replace("validate(token", "const alias = validate;\nalias(token"),
            source.replace("validate(token", "const { validate } = local;\nvalidate(token"),
        ):
            with self.subTest(source=safe):
                self.assertNotIn("SP675", self.ids(safe))
        default = (
            "import jwt from 'jsonwebtoken';\njwt.verify(token,key,{ignoreExpiration:true});\n"
        )
        self.assertNotIn(
            "SP675",
            self.ids(
                default.replace("jwt.verify(token", "jwt.verify = safeVerify; jwt.verify(token")
            ),
        )
        namespace = (
            "import * as jwt from 'jsonwebtoken';\njwt.verify(token,key,{ignoreExpiration:true});\n"
        )
        self.assertIn("SP675", self.ids(namespace))
        commonjs = (
            "const jwt = require('jsonwebtoken');\njwt.verify(token,key,{ignoreExpiration:true});\n"
        )
        self.assertNotIn("SP675", self.ids("const require = localLoader;\n" + commonjs))
        self.assertNotIn(
            "SP675",
            self.ids(commonjs.replace("require('jsonwebtoken')", "require('jsonwebtoken').safe")),
        )
        self.assertNotIn(
            "SP675",
            self.ids(
                commonjs.replace("require('jsonwebtoken')", "require('jsonwebtoken') && safeTokens")
            ),
        )
        self.assertNotIn("SP675", self.ids(source.replace("'jsonwebtoken'", "'node:jsonwebtoken'")))

    def test_ambiguous_object_shapes_do_not_override_a_safe_setting(self):
        prefix = "import jwt from 'jsonwebtoken';\n"
        for options in (
            "{ignoreExpiration:true, ignoreExpiration:false}",
            "{ignoreExpiration:true, ignoreExpiration:config}",
            "{ignoreExpiration:true, ...settings}",
            "{...settings, ignoreExpiration:true}",
            "{ignoreExpiration:true, [optionName]:false}",
            "{ignoreExpiration:true, 'ignore\\u0045xpiration':false}",
            "{ignoreExpiration:true, get ignoreExpiration(){return false}}",
            "{ignoreExpiration:true, ignoreExpiration}",
            "{metadata:{ignoreExpiration:true}}",
        ):
            with self.subTest(options=options):
                self.assertNotIn("SP675", self.ids(prefix + f"jwt.verify(token,key,{options});"))
        self.assertIn(
            "SP675",
            self.ids(
                prefix + "jwt.verify(token,key,{ignoreExpiration:false,ignoreExpiration:true});"
            ),
        )

    def test_comment_string_regex_and_unresolved_template_contexts(self):
        source = self.records[1]["positive"][0]["source"]
        for data in (
            "/*\n" + source + "*/",
            "const doc = " + json.dumps(source) + ";",
            "const doc = `" + source + "`;",
            "const doc = /jwt.verify(token,key,{ignoreExpiration:true})/;",
            "const doc = `example ${value}`;\n" + source,
            "/* unterminated\n" + source,
            source + "'unterminated",
        ):
            with self.subTest(source=data):
                self.assertFalse(COHORT.intersection(self.ids(data)))

    def test_config_requires_exported_unmodified_next_filename(self):
        source = "const config = {images:{dangerouslyAllowLocalIP:true}};\nexport default config;"
        self.assertIn("SP674", self.ids(source, "next.config.ts"))
        self.assertNotIn("SP674", self.ids(source, "sample.ts"))
        self.assertNotIn(
            "SP674",
            self.ids(
                source.replace("export default config", "export default wrap(config)"),
                "next.config.ts",
            ),
        )
        for source in (
            "export default {images:{dangerouslyAllowLocalIP:true}} && safeConfig;",
            "const config = {images:{dangerouslyAllowLocalIP:true}} && safeConfig; export default config;",
            "const config = {images:{dangerouslyAllowLocalIP:true}}; export default config && safeConfig;",
            "const module = localModule; module.exports = {images:{dangerouslyAllowLocalIP:true}};",
            "module.exports = {images:{dangerouslyAllowLocalIP:true}}; module.exports = {};",
            "module.exports = {images:{dangerouslyAllowLocalIP:true}}; module.exports.images = {};",
        ):
            self.assertNotIn("SP674", self.ids(source, "next.config.ts"))
        for extension in ("cjs", "cts"):
            self.assertNotIn(
                "SP674",
                self.ids(
                    "module.exports = {images:{dangerouslyAllowLocalIP:true}};",
                    "next.config." + extension,
                ),
            )
        self.assertNotIn(
            "SP674",
            self.ids(
                "module.exports = {images:{dangerouslyAllowLocalIP:true}};", "next.config.mjs"
            ),
        )
        self.assertIn(
            "SP674",
            self.ids("module.exports = {images:{dangerouslyAllowLocalIP:true}};", "next.config.js"),
        )
        self.assertIn(
            "SP674",
            self.ids("export default {images:{dangerouslyAllowLocalIP:true}};", "next.config.mjs"),
        )
        self.assertNotIn(
            "SP674",
            self.ids(
                source.replace("export default", "config.images = safeImages;\nexport default"),
                "next.config.ts",
            ),
        )

    def test_buffer_source_identity_and_read_boundaries(self):
        prefix = "import {Buffer} from 'node:buffer';\n"
        for expression in (
            "Buffer.allocUnsafe(0).toString()",
            "Buffer.allocUnsafe(16).toString('hex',0,0)",
            "Buffer.allocUnsafe(16).toString('not-an-encoding')",
            "Buffer.allocUnsafe(16).fill(0).toString()",
            "Buffer.allocUnsafe(size).toString()",
            "Buffer.allocUnsafe(-1).toString()",
        ):
            self.assertNotIn("SP678", self.ids(prefix + "const text = " + expression + ";"))
        self.assertNotIn(
            "SP678",
            self.ids("import Buffer from 'node:buffer'; Buffer.allocUnsafe(16).toString();"),
        )
        self.assertNotIn(
            "SP678", self.ids("import {allocUnsafe} from 'buffer'; allocUnsafe(16).toString();")
        )
        # A huge decimal token must not enter Python's integer conversion limit.
        self.assertNotIn(
            "SP678", self.ids(prefix + "Buffer.allocUnsafe(" + "9" * 5000 + ").toString();")
        )

    def test_existing_client_import_rule_excludes_erased_types_and_prose(self):
        for source in (
            "'use client';\nimport type { User } from '@prisma/client';\nexport const value = 1;",
            "'use client';\nimport { type User, type Post as Entry } from '@prisma/client';\nexport const value = 1;",
            "'use client';\nexport type { User } from '@prisma/client';",
            "const label = 'use client';\nimport { PrismaClient } from '@prisma/client';",
            "/* 'use client'; */\nimport { PrismaClient } from '@prisma/client';",
            "'use client';\n// import { PrismaClient } from '@prisma/client';\nexport const value = 1;",
            "'use client';\nconst example = \"import { PrismaClient } from '@prisma/client'\";",
        ):
            with self.subTest(source=source):
                self.assertNotIn("SP591", self.ids(source, "client.tsx"))
        for source in (
            "'use client';\nimport { type User, PrismaClient } from '@prisma/client';",
            "'use strict';\n'use client';\nimport 'server-only';",
            "'use client'\nimport database from 'pg';",
        ):
            self.assertIn("SP591", self.ids(source, "client.tsx"))

    def test_default_express_limit_is_not_reported_as_unbounded(self):
        self.assertNotIn("SP429", RULE_INDEX)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "server.ts").write_text(
                "import express from 'express';\nconst app = express();\napp.use(express.json());\n",
                encoding="utf-8",
            )
            findings, _ = scan_repository(root)
            self.assertNotIn("SP429", {finding.rule_id for finding in findings})

    def test_new_rules_and_client_boundary_are_advisory_at_all_gate_floors(self):
        for rule_id in COHORT | {"SP591"}:
            finding = make_finding(find_rule(rule_id), "app.ts", 1, "evidence", "structural")
            self.assertEqual(finding.tier, "advisory")
            for proof in ("L0", "L1", "L2"):
                for severity in ("critical", "high", "medium", "low"):
                    self.assertFalse(
                        gate_failed(
                            [replace(finding, proof_level=proof)], severity, block_min_proof="L0"
                        )
                    )

    def test_inline_ignore_and_fingerprint_line_movement(self):
        source = self.records[1]["positive"][0]["source"]
        before = next(finding for finding in self.findings(source) if finding.rule_id == "SP675")
        after = next(
            finding
            for finding in self.findings("// moved\n" + source)
            if finding.rule_id == "SP675"
        )
        self.assertEqual(after.line, before.line + 1)
        self.assertEqual(before.fingerprint, after.fingerprint)
        self.assertNotIn(
            "SP675",
            self.ids(
                source.replace(
                    "export const",
                    "// shipproof-ignore SP675 reviewed renewal endpoint\nexport const",
                )
            ),
        )

    def test_json_sarif_and_node_cli_parity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = self.records[1]
            (root / "auth.ts").write_text(row["positive"][0]["source"], encoding="utf-8")
            findings, stats = scan_repository(root)
            report = build_json_report(root, findings, stats)
            self.assertEqual(report["findings"][0]["proof_level"], "L1")
            sarif = build_sarif_report(findings, root)
            item = next(item for item in sarif["runs"][0]["results"] if item["ruleId"] == "SP675")
            self.assertEqual(item["locations"][0]["physicalLocation"]["region"]["startLine"], 2)
            outputs = []
            common = [str(root), "--format", "json", "--fail-on", "low", "--block-min-proof", "L0"]
            for command in (
                [
                    sys.executable,
                    str(ROOT / "skills/audit-production-readiness/scripts/scan_repo.py"),
                    *common,
                ],
                ["node", str(ROOT / "bin/shipproof.mjs"), "scan", *common],
            ):
                done = subprocess.run(  # noqa: S603 - fixed local test commands
                    command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", check=False
                )
                self.assertEqual(done.returncode, 0, done.stderr)
                rows = json.loads(done.stdout)["findings"]
                outputs.append(
                    [(item["rule_id"], item["tier"], item["fingerprint"]) for item in rows]
                )
            self.assertEqual(outputs[0], outputs[1])
            self.assertEqual(outputs[0][0][:2], ("SP675", "advisory"))

    def test_contract_generators_are_current_together(self):
        for script in ("build_typescript_contracts.py", "build_roblox_rust_contracts.py"):
            done = subprocess.run(  # noqa: S603 - fixed local generator
                [sys.executable, str(ROOT / "scripts" / script), "--check"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(done.returncode, 0, done.stderr or done.stdout)


if __name__ == "__main__":
    unittest.main()
