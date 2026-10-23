from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
sys.path.insert(0, str(ROOT / "scripts"))
import dart_transport_checks  # noqa: E402
import polyglot_checks  # noqa: E402
import scan_repo  # noqa: E402
from build_field_cohort_contracts import records  # noqa: E402


class FieldCohortTests(unittest.TestCase):
    def test_authored_contracts_use_the_real_walker(self):
        for row in records():
            for polarity in ("positive", "negative", "adversarial"):
                for case in row[polarity]:
                    with self.subTest(
                        rule=row["rule_id"], polarity=polarity, source=case["source"]
                    ):
                        with tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            path = root / case["path"]
                            path.parent.mkdir(parents=True, exist_ok=True)
                            path.write_text(case["source"], encoding="utf-8")
                            frameworks = case.get(
                                "frameworks", ["nextjs"] if row["rule_id"] == "SP596" else None
                            )
                            if frameworks is not None:
                                dependencies = {
                                    "next" if name == "nextjs" else name: "16.4.2"
                                    if name == "nextjs"
                                    else "19.3.0"
                                    for name in frameworks
                                }
                                (root / "package.json").write_text(
                                    json.dumps({"dependencies": dependencies}), encoding="utf-8"
                                )
                            with patch(
                                "subprocess.run",
                                side_effect=AssertionError("no process during scan"),
                            ):
                                findings, stats = scan_repo.scan_repository(root)
                        self.assertTrue(stats["completeness"]["is_complete"], stats)
                        hits = [hit for hit in findings if hit.rule_id == row["rule_id"]]
                        expected = (
                            case["expected"]
                            if polarity == "adversarial"
                            else polarity == "positive"
                        )
                        self.assertEqual(len(hits), int(expected))
                        if hits:
                            self.assertEqual(hits[0].proof_level, "L1")
                            self.assertEqual(
                                hits[0].tier, "gate" if row["blocking_eligible"] else "advisory"
                            )
                            if not row["blocking_eligible"]:
                                for floor in ("critical", "high", "medium", "low"):
                                    for proof in ("L0", "L1", "L2"):
                                        self.assertFalse(
                                            scan_repo.gate_failed(
                                                hits, floor, block_min_proof=proof
                                            )
                                        )

    def test_dart_strings_nested_comments_and_budget_fail_closed(self):
        strings = [
            "'plain'",
            'r"raw \\"',
            "'''multi\nline'''",
            "\"prefix ${choose('quoted', {'key': 1})} suffix\"",
            "r'''/* nested looking */'''",
            "'${f(\"nested ${g('inner')}\")}'",
        ]
        for source in strings:
            self.assertEqual(polyglot_checks.tokens(source, "dart"), [(source, 0, len(source))])
        self.assertEqual(
            polyglot_checks.tokens("/* a /* b */ c */ value", "dart"), [("value", 18, 23)]
        )
        for source in (
            "'unterminated",
            "/* open",
            "'${f()'",
            "/*" * 129 + "*/" * 129,
            "x " * 50001,
        ):
            with (
                self.subTest(source=source[:30]),
                self.assertRaises(polyglot_checks.LexicalLimitError),
            ):
                polyglot_checks.tokens(source, "dart")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "client.dart").write_text(
                "import 'package:http/http.dart' as http;\n// http:\n'broken", encoding="utf-8"
            )
            findings, stats = scan_repo.scan_repository(root)
            self.assertFalse(stats["completeness"]["is_complete"])
            self.assertEqual(stats["completeness"]["parser_limit"], 1)
            self.assertNotIn("SP170", {hit.rule_id for hit in findings})

    def test_dart_cleartext_selector_and_other_languages_unchanged(self):
        for value in (
            "http:///missing",
            "http://localhost.",
            "http://127.1",
            "http://user:pass@service.example.org",
            "http://service.example.org#fragment",
            "https://service.example.org",
        ):
            self.assertFalse(dart_transport_checks.external_http(value), value)
        text = "const help = 'http://api.example.org/help';"
        self.assertNotIn(
            "SP170",
            {
                hit.rule_id
                for hit in scan_repo.find_regex_issues(Path("help.dart"), "help.dart", text)
            },
        )
        self.assertIn(
            "SP170",
            {
                hit.rule_id
                for hit in scan_repo.find_regex_issues(
                    Path("connection.py"), "connection.py", "tel" + "net://z"
                )
            },
        )
        legacy = scan_repo.find_regex_issues(
            Path("connection.dart"), "connection.dart", "tel" + "net://z"
        )
        self.assertIn("SP170", {hit.rule_id for hit in legacy})
        self.assertTrue(
            all(
                hit.proof_level == "L0" and hit.tier == "gate"
                for hit in legacy
                if hit.rule_id == "SP170"
            )
        )

    def test_redaction_fingerprint_and_inline_ignore(self):
        for row in records():
            if row["rule_id"] == "SP596":
                continue
            case = row["positive"][0]
            source = case["source"]
            marker = "private-field-cohort-marker"
            source = source.replace(
                "'Authorization': bearer", "'Authorization': 'Bearer " + marker + "'"
            )
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / case["path"]
                path.write_text(source, encoding="utf-8")
                left = next(
                    hit
                    for hit in scan_repo.scan_repository(root)[0]
                    if hit.rule_id == row["rule_id"]
                )
                path.write_text("// moved\n" + source, encoding="utf-8")
                right = next(
                    hit
                    for hit in scan_repo.scan_repository(root)[0]
                    if hit.rule_id == row["rule_id"]
                )
                self.assertEqual(left.fingerprint, right.fingerprint)
                for result in (
                    left.evidence,
                    json.dumps(scan_repo.build_sarif_report([left], root)),
                    scan_repo.render_fix_prompts(root, [left], as_json=True, context_level="full"),
                ):
                    self.assertNotIn(marker, result)
                lines = source.splitlines()
                lines.insert(
                    left.line - 1,
                    f"// shipproof-ignore {row['rule_id']} independently verified deployment control",
                )
                path.write_text("\n".join(lines), encoding="utf-8")
                self.assertNotIn(
                    row["rule_id"], {hit.rule_id for hit in scan_repo.scan_repository(root)[0]}
                )

    def test_next_boundary_from_client_parent_is_not_inferred_as_server(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            (root / "package.json").write_text(
                '{"dependencies":{"next":"16.4.2","react":"19.3.0"}}', encoding="utf-8"
            )
            (root / "app/page.tsx").write_text(
                "'use client'; import Counter from './Counter'; export default function Page(){ return <Counter/>; }",
                encoding="utf-8",
            )
            (root / "app/Counter.tsx").write_text(
                "import {useState} from 'react'; export default function Counter(){ const [value]=useState(1); return <span>{value}</span>; }",
                encoding="utf-8",
            )
            findings, _ = scan_repo.scan_repository(root)
            self.assertNotIn("SP596", {hit.rule_id for hit in findings})

    def test_builder_is_current(self):
        result = subprocess.run(
            [sys.executable, "scripts/build_field_cohort_contracts.py", "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
