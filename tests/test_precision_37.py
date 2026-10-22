"""Issue #37 regressions through the real repository walker, not regex witnesses."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
import polyglot_checks  # noqa: E402
import scan_repo  # noqa: E402

CASES = json.loads((ROOT / "tests/precision_37_cases.json").read_text(encoding="utf-8"))["cases"]


class Precision37Tests(unittest.TestCase):
    def test_polarities_and_original_severity_are_preserved(self):
        counts = Counter((case["rule_id"], case["kind"]) for case in CASES)
        for rule_id in {case["rule_id"] for case in CASES}:
            for kind, minimum in (("positive", 3), ("negative", 5), ("adversarial", 2)):
                self.assertGreaterEqual(counts[rule_id, kind], minimum)
            rule = scan_repo.find_rule(rule_id)
            self.assertEqual(rule.severity, "medium" if rule_id == "SP136" else "high")

    def test_real_walker_context_boundaries(self):
        for case in CASES:
            with (
                self.subTest(rule=case["rule_id"], name=case["name"]),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                path = root / case["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(bytes.fromhex(case["source_hex"]))
                findings, stats = scan_repo.scan_repository(root)
                self.assertTrue(stats["completeness"]["is_complete"], stats["completeness"])
                matches = [item for item in findings if item.rule_id == case["rule_id"]]
                self.assertEqual(len(matches), 1 if case["kind"] == "positive" else 0)
                for finding in matches:
                    self.assertEqual(finding.path, case["path"])
                    self.assertEqual(
                        finding.proof_level,
                        "L1" if case["rule_id"] in {"SP212", "SP377", "SP378", "SP621"} else "L0",
                    )

    def test_parent_cache_directory_does_not_hide_deserialization(self):
        source = "import pickle\ndef decode(payload):\n    return pickle." + "loads(payload)\n"
        with tempfile.TemporaryDirectory() as directory:
            positions = []
            for parent in ("ordinary", ".cache"):
                root = Path(directory) / parent / "package"
                root.mkdir(parents=True)
                (root / "reader.py").write_text(source, encoding="utf-8")
                findings, stats = scan_repo.scan_repository(root)
                self.assertTrue(stats["completeness"]["is_complete"])
                positions.append(
                    [(f.rule_id, f.path, f.line) for f in findings if f.rule_id == "SP106"]
                )
            self.assertTrue(positions[0])
            self.assertEqual(positions[0], positions[1])

    def test_cache_name_does_not_override_visible_external_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "cache.py").write_text(
                "import pickle\ndef decode(request):\n    return pickle." + "loads(request.body)\n",
                encoding="utf-8",
            )
            findings, _ = scan_repo.scan_repository(root)
            self.assertTrue(any(f.rule_id == "SP106" for f in findings))

    def test_native_limits_are_unavailable_coverage_not_a_clean_pass(self):
        with self.assertRaises(polyglot_checks.LexicalLimitError):
            polyglot_checks.signature_spans(
                'import "net/http"\nvar s = http.Server{' + "{" * 129, "go"
            )
        with self.assertRaises(polyglot_checks.LexicalLimitError):
            polyglot_checks.signature_spans(
                "fn handler() { value.unwrap(); " + "x;" * 26_000 + "}", "rust"
            )

    def test_native_evidence_does_not_copy_expect_message(self):
        marker = "never-persist-this-private-message"
        source = '#[actix_web::get("/")]\nfn route() -> String { value.expect("' + marker + '") }'
        findings = scan_repo.find_regex_issues(Path("route.rs"), "route.rs", source)
        target = next(f for f in findings if f.rule_id == "SP621")
        self.assertNotIn(marker, target.evidence)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "route.rs").write_text(source, encoding="utf-8")
            for output in (
                json.dumps(scan_repo.build_sarif_report([target], root)),
                scan_repo.render_fix_prompts(root, [target], as_json=True, context_level="full"),
            ):
                self.assertNotIn(marker, output)

    def test_go_comments_do_not_nest_like_rust_comments(self):
        source = '/* Route example /assets/* is documentation. */\npackage app\nimport "net/http"\nvar s = &http.Server{}\n'
        self.assertEqual(
            [item[0] for item in polyglot_checks.signature_spans(source, "go")], ["SP377"]
        )

    def test_http_parameter_types_do_not_shadow_the_import(self):
        source = 'package app\nimport "net/http"\nvar s = &http.Server{Handler: http.HandlerFunc(handle)}\nfunc handle(w http.ResponseWriter, r *http.Request) {}'
        self.assertEqual(
            [item[0] for item in polyglot_checks.signature_spans(source, "go")], ["SP377"]
        )

    def test_later_var_configuration_and_unkeyed_server_are_unresolved(self):
        for source in (
            'package app\nimport "net/http"\nvar s = &http.Server{}\nfunc init() { s.ReadTimeout = configured }',
            'package app\nimport "net/http"\nvar s = &http.Server{positionalValue}',
        ):
            self.assertEqual(polyglot_checks.signature_spans(source, "go"), [])

    def test_rust_visibility_additional_attributes_and_parameter_shadows(self):
        source = '#[actix_web::get("/")]\n#[allow(dead_code)]\npub(crate) async fn route() -> String { value.unwrap() }'
        self.assertEqual(
            [item[0] for item in polyglot_checks.signature_spans(source, "rust")], ["SP621"]
        )
        source = "use axum::routing::get;\nfn app(get: Factory) { get(helper); }\nfn helper() { value.unwrap(); }"
        self.assertEqual(polyglot_checks.signature_spans(source, "rust"), [])

    def test_large_duration_literals_do_not_use_unbounded_integer_parsing(self):
        source = (
            'package app\nimport "net/http"\nvar s = &http.Server{ReadHeaderTimeout: '
            + "9" * 5000
            + "}"
        )
        self.assertEqual(polyglot_checks.signature_spans(source, "go"), [])
        source = '#[actix_web::get("/")]\n#[cfg(test)]\nfn route() { value.unwrap(); }'
        self.assertEqual(polyglot_checks.signature_spans(source, "rust"), [])


if __name__ == "__main__":
    unittest.main()
