from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("field_replay", ROOT / "scripts/eval-field-cohort.py")
assert SPEC and SPEC.loader
REPLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPLAY)


class FieldReplayTests(unittest.TestCase):
    def test_existing_report_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            output.write_text("original evidence", encoding="utf-8")
            with patch(
                "sys.argv", ["eval-field-cohort", "--workspace", directory, "--output", str(output)]
            ):
                self.assertEqual(REPLAY.main(), 2)
            self.assertEqual(output.read_text(encoding="utf-8"), "original evidence")

    def projection(self, root):
        source = b"const score = 1;\n"
        context = b'{"dependencies":{"react":"19.3.0"}}'
        license_text = b"Synthetic test license identity\n"
        (root / "page.ts").write_bytes(source)
        (root / "package.json").write_bytes(context)
        (root / "LICENSE").write_bytes(license_text)

        def sha(value):
            return hashlib.sha256(value).hexdigest()

        return {
            "source_extensions": [".ts"],
            "expected_source_files": 1,
            "source_tree_sha256": sha(f"page.ts\0{sha(source)}\n".encode()),
            "context_files": {"package.json": sha(context), "LICENSE": sha(license_text)},
            "license_path": "LICENSE",
            "license_sha256": sha(license_text),
        }

    def test_exact_source_and_framework_context_are_both_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = self.projection(root)
            self.assertEqual(REPLAY.verify_projection(root, spec), frozenset({"page.ts"}))
            (root / "package.json").write_text(
                '{"dependencies":{"next":"16.4.2"}}', encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "context file"):
                REPLAY.verify_projection(root, spec)

    def test_changed_extra_missing_source_never_reuses_an_old_receipt(self):
        for change in ("changed", "extra", "missing"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                spec = self.projection(root)
                if change == "changed":
                    (root / "page.ts").write_text("modified", encoding="utf-8")
                elif change == "extra":
                    (root / "extra.ts").write_text("export {};", encoding="utf-8")
                else:
                    (root / "page.ts").unlink()
                with self.assertRaisesRegex(ValueError, "pinned source inventory"):
                    REPLAY.verify_projection(root, spec)

    def test_context_path_traversal_and_missing_context_fail(self):
        for path in ("../outside", "/absolute", "C:/outside", "parent\\file"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                REPLAY.relative_name(path)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spec = self.projection(root)
            spec["context_files"] = {}
            with self.assertRaisesRegex(ValueError, "context hashes"):
                REPLAY.verify_projection(root, spec)


if __name__ == "__main__":
    unittest.main()
